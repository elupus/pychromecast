"""
Example that streams Opus audio to a cast device over Cast Streaming (RTP).

This is the "mirroring" protocol implemented by Open Screen's
cast/standalone_sender:

1. Launch the Cast Streaming receiver app: audio-only (85CDB22F) on speakers,
   audio/video (0F5096E8) on devices with a screen.
2. Send an OFFER on urn:x-cast:com.google.cast.webrtc and wait for the ANSWER,
   which carries the UDP port to stream to.
3. Send AES-128-CTR encrypted Opus frames as Cast RTP packets, plus RTCP
   Sender Reports, and resend packets the receiver NACKs.

Audio is encoded by ffmpeg (needs libopus); by default a sine tone is sent.
Devices with a screen show black for audio only; --image or --test-pattern
adds a low frame rate VP8 video stream (needs libvpx) to show instead.
"""

# pylint: disable=invalid-name

from __future__ import annotations

import argparse
import array
import importlib
import itertools
import json
import logging
import os
import random
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import wave
from collections.abc import Generator, Iterator
from typing import IO, Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import pychromecast
from pychromecast.const import CastCapability
from pychromecast.controllers import BaseController
from pychromecast.generated.cast_channel_pb2 import (  # pylint: disable=no-name-in-module
    CastMessage,
)

from .common import (
    add_log_arguments,
    add_network_arguments,
    configure_logging,
    create_zeroconf,
)

_LOGGER = logging.getLogger(__name__)

APP_ID_AUDIO_ONLY = "85CDB22F"
# Devices with a screen only know this one, an audio-only offer works with it.
APP_ID_AUDIO_VIDEO = "0F5096E8"
NS_WEBRTC = "urn:x-cast:com.google.cast.webrtc"

SAMPLE_RATE = 48000
CHANNELS = 2
FRAME_MS = 20
VIDEO_TIMEBASE = 90000
# The default payload types of Open Screen senders (use_android_rtp_hack).
AUDIO_PAYLOAD_TYPE = 127
VIDEO_PAYLOAD_TYPE = 96
MAX_PACKET_SIZE = 1500 - 20 - 8
RTP_HEADER_SIZE = 12
CAST_HEADER_SIZE = 7
MAX_PAYLOAD_SIZE = MAX_PACKET_SIZE - RTP_HEADER_SIZE - CAST_HEADER_SIZE
RTCP_INTERVAL = 0.5
FRAME_HISTORY = 100
NTP_EPOCH_OFFSET = 2208988800
# Receiver log event types: legacy audio, legacy video and unified codes.
RECEIVER_LOG_EVENTS = {
    1: "ack sent",
    5: "ack sent",
    11: "ack sent",
    2: "played out",
    6: "played out",
    12: "played out",
    3: "decoded",
    7: "decoded",
    13: "decoded",
    4: "packet received",
    8: "packet received",
    14: "packet received",
}

# --------------------------------------------------------------------------
# Frame encryption.
# --------------------------------------------------------------------------


def frame_crypt(aes_key: bytes, iv_mask: bytes, frame_id: int, data: bytes) -> bytes:
    """AES-CTR as in Open Screen's FrameCrypto: nonce = iv_mask ^ frame_id at [8:12]."""
    nonce = bytearray(iv_mask)
    for i, b in enumerate(struct.pack(">I", frame_id & 0xFFFFFFFF)):
        nonce[8 + i] ^= b
    encryptor = Cipher(algorithms.AES(aes_key), modes.CTR(bytes(nonce))).encryptor()
    return encryptor.update(data) + encryptor.finalize()


# --------------------------------------------------------------------------
# Encoded frames from ffmpeg.
# --------------------------------------------------------------------------


def run_ffmpeg(args: list[str]) -> subprocess.Popen[bytes]:
    """Start ffmpeg writing to a pipe."""
    cmd = ["ffmpeg", "-hide_banner", "-loglevel", "error", *args, "-"]
    _LOGGER.debug("Running %s", cmd)
    # ffmpeg reads keyboard commands from stdin, keep it off the terminal.
    return subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE)


def ogg_packets(stream: IO[bytes]) -> Iterator[bytes]:
    """Yield the packets of an Ogg stream."""
    partial = b""
    while True:
        header = stream.read(27)
        if len(header) < 27:
            return
        if header[:4] != b"OggS":
            raise ValueError("Lost Ogg sync")
        segments = stream.read(header[26])
        body = stream.read(sum(segments))
        pos = 0
        for lacing in segments:
            partial += body[pos : pos + lacing]
            pos += lacing
            if lacing < 255:
                yield partial
                partial = b""


# Samples per frame, ffmpeg's AAC encoder always makes 1024.
FRAME_SAMPLES = {"opus": SAMPLE_RATE * FRAME_MS // 1000, "aac": 1024}


def audio_frames(args: argparse.Namespace, ffmpeg_input: list[str]) -> Generator[bytes]:
    """Encoded audio frames in the codec chosen by --audio-codec."""
    if args.audio_codec == "aac":
        return aac_frames(ffmpeg_input, args.bitrate, args.aac_raw)
    return opus_frames(ffmpeg_input, args.bitrate)


def aac_frames(ffmpeg_input: list[str], bitrate: int, raw: bool) -> Generator[bytes]:
    """Run ffmpeg and yield AAC frames, with their ADTS header unless raw."""
    with run_ffmpeg(
        [
            *ffmpeg_input,
            "-vn",
            "-ac",
            str(CHANNELS),
            "-ar",
            str(SAMPLE_RATE),
            "-c:a",
            "aac",
            "-b:a",
            str(bitrate),
            "-f",
            "adts",
        ]
    ) as proc:
        try:
            assert proc.stdout is not None
            while True:
                header = proc.stdout.read(7)
                if len(header) < 7:
                    return
                if header[0] != 0xFF or header[1] & 0xF0 != 0xF0:
                    raise ValueError("Lost ADTS sync")
                # 13 bit frame length, header included.
                length = (header[3] & 0x03) << 11 | header[4] << 3 | header[5] >> 5
                body = proc.stdout.read(length - 7)
                # Bit 0 of byte 1 clear: a 2 byte CRC follows the header.
                header_size = 7 if header[1] & 0x01 else 9
                yield (header + body)[header_size:] if raw else header + body
        finally:
            proc.kill()


def opus_frames(ffmpeg_input: list[str], bitrate: int) -> Generator[bytes]:
    """Run ffmpeg and yield raw 20 ms Opus frames."""
    with run_ffmpeg(
        [
            *ffmpeg_input,
            "-vn",
            "-ac",
            str(CHANNELS),
            "-ar",
            str(SAMPLE_RATE),
            "-c:a",
            "libopus",
            "-b:a",
            str(bitrate),
            "-frame_duration",
            str(FRAME_MS),
            "-f",
            "ogg",
        ]
    ) as proc:
        try:
            assert proc.stdout is not None
            packets = ogg_packets(proc.stdout)
            head = next(packets, b"")
            if not head.startswith(b"OpusHead"):
                raise ValueError("ffmpeg did not produce an Opus stream")
            next(packets, None)  # OpusTags
            yield from packets
        finally:
            proc.kill()


def vp8_frames(
    ffmpeg_input: list[str], width: int, height: int, fps: float, bitrate: int
) -> Iterator[tuple[bool, bytes]]:
    """Run ffmpeg and yield (is_key_frame, frame) of VP8 video from IVF."""
    scale = (
        f"scale={width}:{height}:force_original_aspect_ratio=decrease,"
        f"pad={width}:{height}:(ow-iw)/2:(oh-ih)/2,fps={fps}"
    )
    with run_ffmpeg(
        [
            *ffmpeg_input,
            "-an",
            "-vf",
            scale,
            "-c:v",
            "libvpx",
            "-deadline",
            "realtime",
            "-cpu-used",
            "8",
            "-b:v",
            str(bitrate),
            "-g",
            str(max(1, round(fps * 2))),
            # Only reference the previous frame, as Cast Streaming signals.
            "-auto-alt-ref",
            "0",
            "-lag-in-frames",
            "0",
            "-f",
            "ivf",
        ]
    ) as proc:
        try:
            assert proc.stdout is not None
            if proc.stdout.read(32)[:4] != b"DKIF":
                raise ValueError("ffmpeg did not produce an IVF stream")
            while True:
                header = proc.stdout.read(12)
                if len(header) < 12:
                    return
                (size,) = struct.unpack_from("<I", header)
                frame = proc.stdout.read(size)
                # VP8 frame tag: bit 0 clear means key frame.
                yield not frame[0] & 1, frame
        finally:
            proc.kill()


# --------------------------------------------------------------------------
# Session negotiation.
# --------------------------------------------------------------------------


class CastStreamingController(BaseController):
    """Sends OFFER and receives ANSWER on the webrtc namespace."""

    def __init__(self, app_id: str) -> None:
        super().__init__(NS_WEBRTC, app_id, app_must_match=True)
        self.answer: dict | None = None
        self.answer_event = threading.Event()

    def receive_message(self, _message: CastMessage, data: dict) -> bool:
        _LOGGER.info("Received %s", data)
        if data.get("type") == "ANSWER":
            self.answer = data
            self.answer_event.set()
        return True


class StreamConfig:  # pylint: disable=too-few-public-methods
    """One offered stream with its own SSRC and encryption keys."""

    def __init__(self, index: int, payload_type: int, timebase: int) -> None:
        self.index = index
        self.payload_type = payload_type
        self.timebase = timebase
        self.ssrc = random.randint(1, 50000)
        self.aes_key = os.urandom(16)
        self.iv_mask = os.urandom(16)

    def offer_fields(self, target_delay: int, event_log: bool) -> dict:
        """Fields shared by audio and video streams in the OFFER."""
        return {
            "index": self.index,
            "codecParameter": "",
            "rtpPayloadType": self.payload_type,
            "rtpProfile": "cast",
            "ssrc": self.ssrc,
            "targetDelay": target_delay,
            "aesKey": self.aes_key.hex(),
            "aesIvMask": self.iv_mask.hex(),
            "receiverRtcpEventLog": event_log,
            "timeBase": f"1/{self.timebase}",
        }


def build_offer(
    audio: StreamConfig,
    video: StreamConfig | None,
    args: argparse.Namespace,
    target_delay: int,
) -> dict:
    """Build a mirroring OFFER, same fields as Open Screen."""
    streams = [
        {
            **audio.offer_fields(target_delay, args.event_log),
            "type": "audio_source",
            "codecName": args.audio_codec,
            "channels": CHANNELS,
            "bitRate": args.bitrate,
        }
    ]
    if video:
        streams.append(
            {
                **video.offer_fields(target_delay, args.event_log),
                "type": "video_source",
                "codecName": "vp8",
                "channels": 1,
                "maxFrameRate": "30/1",
                "maxBitRate": args.video_bitrate,
                "resolutions": [{"width": args.width, "height": args.height}],
            }
        )
    return {
        "type": "OFFER",
        "seqNum": 1,
        "offer": {"castMode": "mirroring", "supportedStreams": streams},
    }


# --------------------------------------------------------------------------
# RTP / RTCP sender.
# --------------------------------------------------------------------------


# Our wall clock is read once and then advanced by the monotonic clock, which
# also paces the RTP timestamps, so the system adjusting its time mid-session
# can't skew the Sender Reports against the RTP timeline.
WALL_EPOCH = time.time() - time.monotonic()


def wall_clock(monotonic: float | None = None) -> float:
    """Wall clock time of a monotonic time, default now."""
    return WALL_EPOCH + (time.monotonic() if monotonic is None else monotonic)


def ntp_now() -> int:
    """Wall clock as a 64 bit NTP timestamp."""
    now = wall_clock() + NTP_EPOCH_OFFSET
    return int(now * (1 << 32)) & 0xFFFFFFFFFFFFFFFF


class RtpSender:  # pylint: disable=too-many-instance-attributes
    """Packetizes, encrypts and sends the frames of one stream; answers NACKs."""

    def __init__(
        self,
        name: str,
        sock: socket.socket,
        dest: tuple[str, int],
        config: StreamConfig,
        receiver_ssrc: int,
    ) -> None:
        self.name = name
        self.sock = sock
        self.dest = dest
        self._config = config
        self._receiver_ssrc = receiver_ssrc
        self._seq = random.randrange(1 << 16)
        # The receiver treats RTP time as media time, so like Open Screen all
        # streams start at 0 at the same moment, see run_session().
        self.origin = time.monotonic()
        # Ticks added to every RTP timestamp from some point, see --timestamp-jump.
        self.rtp_jump = 0
        self._lock = threading.Lock()
        # frame id -> (rtp timestamp, is key frame, encrypted data)
        self._history: dict[int, tuple[int, bool, bytes]] = {}
        self._latest_frame_id = -1
        self.packet_count = 0
        self.octet_count = 0
        self.retransmits = 0
        self.checkpoint = -1
        self.rtt: float | None = None
        self.clock_offsets: list[float] = []
        # (our time in seconds, offset) to see the receiver clock's rate
        self.clock_samples: list[tuple[float, float]] = []
        # Our wall clock when the receiver answered, its RTCP session started
        # shortly before.
        self.session_start: float | None = None
        # rtp timestamp -> our wall clock time of capture
        self.capture_times: dict[int, float] = {}
        # (rtp timestamp, event, ms since receiver session start, value)
        self.events: list[tuple[int, str, int, int]] = []

    def rtp_timestamp_at(self, t: float) -> int:
        """RTP timestamp of monotonic time t."""
        ticks = round((t - self.origin) * self._config.timebase)
        return (ticks + self.rtp_jump) & 0xFFFFFFFF

    def send_sender_report(self) -> None:
        """Send an RTCP Sender Report for the current instant."""
        with self._lock:
            ntp = ntp_now()
            rtp = self.rtp_timestamp_at(time.monotonic())
            packet = struct.pack(
                ">BBHIQIII",
                0x80,
                200,
                6,
                self._config.ssrc,
                ntp,
                rtp,
                self.packet_count,
                self.octet_count,
            )
            self.sock.sendto(packet, self.dest)

    def _num_packets(self, size: int) -> int:
        return max(1, -(-size // MAX_PAYLOAD_SIZE))

    def _send_packet(self, frame_id: int, packet_id: int) -> None:
        rtp_ts, key_frame, data = self._history[frame_id]
        num_packets = self._num_packets(len(data))
        chunk = data[packet_id * MAX_PAYLOAD_SIZE : (packet_id + 1) * MAX_PAYLOAD_SIZE]
        marker = 0x80 if packet_id == num_packets - 1 else 0
        # Key frames reference themselves, others the previous frame.
        referenced = frame_id if key_frame else frame_id - 1
        packet = (
            struct.pack(
                ">BBHII",
                0x80,
                marker | self._config.payload_type,
                self._seq,
                rtp_ts,
                self._config.ssrc,
            )
            + struct.pack(
                ">BBHHB",
                (0x80 if key_frame else 0) | 0x40,  # has reference frame id
                frame_id & 0xFF,
                packet_id,
                num_packets - 1,
                referenced & 0xFF,
            )
            + chunk
        )
        self._seq = (self._seq + 1) & 0xFFFF
        self.packet_count += 1
        self.octet_count += len(chunk)
        self.sock.sendto(packet, self.dest)

    def send_frame(  # pylint: disable=too-many-arguments
        self,
        frame_id: int,
        capture_time: float,
        data: bytes,
        key_frame: bool = True,
        spread: float = 0.0,
    ) -> None:
        """Encrypt and send all packets of a frame, evenly over spread seconds."""
        encrypted = frame_crypt(
            self._config.aes_key, self._config.iv_mask, frame_id, data
        )
        with self._lock:
            rtp_ts = self.rtp_timestamp_at(capture_time)
            self._history[frame_id] = (rtp_ts, key_frame, encrypted)
            self.capture_times[rtp_ts] = wall_clock(capture_time)
            self._history.pop(frame_id - FRAME_HISTORY, None)
            self._latest_frame_id = frame_id
        num_packets = self._num_packets(len(encrypted))
        start = time.monotonic()
        for packet_id in range(num_packets):
            # Sent at its turn, not as one burst the network or receiver drops.
            delay = start + packet_id * spread / num_packets - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            with self._lock:
                self._send_packet(frame_id, packet_id)

    def _expand(self, truncated: int, ref: int) -> int:
        """Expand an 8 bit frame id to the value closest to ref."""
        value = (ref & ~0xFF) | truncated
        if value > ref + 127:
            value -= 256
        elif value < ref - 128:
            value += 256
        return value

    def handle_rtcp(self, data: bytes, arrival_ntp: int) -> None:
        """Parse a compound RTCP packet, use the parts meant for this stream."""
        pos = 0
        while pos + 4 <= len(data):
            first, ptype, length = struct.unpack_from(">BBH", data, pos)
            end = pos + 4 + length * 4
            body = data[pos + 4 : end]
            pos = end
            subtype = first & 0x1F
            reporter = struct.unpack_from(">I", body)[0] if len(body) >= 4 else None
            if reporter != self._receiver_ssrc:
                continue
            if ptype == 206 and subtype == 15 and body[8:12] == b"CAST":
                self._handle_cast_feedback(body)
            elif ptype == 204 and subtype == 2 and body[4:8] == b"CAST":
                self._handle_receiver_log(body)
            elif ptype == 206 and subtype == 1:
                _LOGGER.info("%s: receiver asked for a key frame", self.name)
            elif ptype == 201:
                self._handle_receiver_report(body, subtype, arrival_ntp)
            elif ptype == 207:
                self._handle_extended_report(body, arrival_ntp)
            else:
                _LOGGER.debug("RTCP packet type %s/%s ignored", ptype, subtype)

    def _handle_receiver_log(self, body: bytes) -> None:
        """Collect the receiver's frame and packet events."""
        pos = 8
        while pos + 8 <= len(body):
            rtp_ts, word = struct.unpack_from(">II", body, pos)
            pos += 8
            base_ms = word & 0xFFFFFF
            for _ in range((word >> 24) + 1):
                if pos + 4 > len(body):
                    return
                value, type_and_delta = struct.unpack_from(">HH", body, pos)
                pos += 4
                event = RECEIVER_LOG_EVENTS.get(type_and_delta >> 12, "unknown")
                if event == "played out":
                    # Milliseconds late (positive) or early (negative).
                    value = value - 0x10000 if value & 0x8000 else value
                self.events.append(
                    (rtp_ts, event, base_ms + (type_and_delta & 0xFFF), value)
                )

    def _handle_receiver_report(
        self, body: bytes, report_count: int, arrival_ntp: int
    ) -> None:
        """Compute the round trip time from the echo of our Sender Report."""
        for i in range(report_count):
            block = body[4 + 24 * i : 28 + 24 * i]
            ssrc, lsr, dlsr = struct.unpack_from(">I12xII", block)
            if ssrc != self._config.ssrc or lsr == 0:
                continue
            # LSR, DLSR and the middle 32 bits of the NTP time are 16.16 seconds.
            rtt = ((arrival_ntp >> 16) - lsr - dlsr) & 0xFFFFFFFF
            self.rtt = rtt / 65536
            _LOGGER.debug("%s: round trip time %.1f ms", self.name, self.rtt * 1000)

    def _handle_extended_report(self, body: bytes, arrival_ntp: int) -> None:
        """Compare the Receiver Reference Time with our clock."""
        pos = 4
        while pos + 4 <= len(body):
            block_type, block_words = struct.unpack_from(">B1xH", body, pos)
            if block_type == 4 and block_words == 2:
                (receiver_ntp,) = struct.unpack_from(">Q", body, pos + 4)
                one_way = (self.rtt or 0) / 2
                offset = (receiver_ntp - arrival_ntp) / (1 << 32) + one_way
                self.clock_offsets.append(offset)
                self.clock_samples.append((arrival_ntp / (1 << 32), offset))
            pos += 4 + block_words * 4

    def _handle_cast_feedback(self, body: bytes) -> None:
        if struct.unpack_from(">I", body, 4)[0] != self._config.ssrc:
            return
        ckpt8, num_losses, delay_ms = struct.unpack_from(">BBH", body, 12)
        with self._lock:
            self.checkpoint = self._expand(ckpt8, self._latest_frame_id)
            for i in range(num_losses):
                frame8, packet_id, bits = struct.unpack_from(">BHB", body, 16 + 4 * i)
                frame_id = self._expand(frame8, self._latest_frame_id)
                if frame_id not in self._history:
                    continue
                num_packets = self._num_packets(len(self._history[frame_id][2]))
                if packet_id == 0xFFFF:
                    lost = list(range(num_packets))
                else:
                    lost = [packet_id] + [
                        packet_id + 1 + bit for bit in range(8) if bits & (1 << bit)
                    ]
                for pid in lost:
                    if pid < num_packets:
                        self._send_packet(frame_id, pid)
                        self.retransmits += 1
        _LOGGER.debug(
            "%s feedback: checkpoint %s, %s losses, playout delay %s ms",
            self.name,
            self.checkpoint,
            num_losses,
            delay_ms,
        )


def rtcp_receiver(
    sock: socket.socket, senders: list[RtpSender], stop: threading.Event
) -> None:
    """Receive RTCP from the cast device and hand it to every stream."""
    sock.settimeout(0.2)
    while not stop.is_set():
        try:
            data, _addr = sock.recvfrom(2048)
        except TimeoutError:
            continue
        except OSError:
            return
        arrival = ntp_now()
        for sender in senders:
            sender.handle_rtcp(data, arrival)


class Device:  # pylint: disable=too-few-public-methods
    """A cast device we stream to, with its own session and audio source."""

    def __init__(
        self, cast: pychromecast.Chromecast, app_id: str, audio_input: list[str]
    ) -> None:
        self.cast = cast
        self.app_id = app_id
        self.audio_input = audio_input
        self.name = cast.cast_info.friendly_name or cast.cast_info.host
        # Audio first, then video if the receiver accepted it.
        self.senders: list[RtpSender] = []
        # Seconds this device's whole timeline runs behind the others.
        self.delay = 0.0
        self.target_delay = 400


def negotiate(device: Device, args: argparse.Namespace) -> None:
    """Launch the receiver app, exchange OFFER/ANSWER and set up the senders."""
    cast, app_id = device.cast, device.app_id
    controller = CastStreamingController(app_id)
    cast.register_handler(controller)

    if cast.status is not None and cast.status.app_id == app_id:
        # A session left by an earlier sender doesn't answer a new OFFER.
        _LOGGER.info("Restarting the %s session already running", app_id)
        cast.quit_app()
        deadline = time.monotonic() + 10
        while cast.status.app_id == app_id and time.monotonic() < deadline:
            time.sleep(0.1)
    cast.start_app(app_id, timeout=20)
    socket_client = cast.socket_client
    if cast.status is None or cast.status.app_id != app_id:
        raise RuntimeError(f"Failed to launch {app_id}: {cast.status}")
    _LOGGER.info(
        "Launched %s, namespaces %s", cast.status.display_name, cast.status.namespaces
    )
    if socket_client.destination_id is None:
        raise RuntimeError("Not connected to the receiver app")

    audio = StreamConfig(0, args.payload_type, SAMPLE_RATE)
    video = (
        StreamConfig(1, VIDEO_PAYLOAD_TYPE, VIDEO_TIMEBASE)
        if args.video_input
        else None
    )
    offer = build_offer(audio, video, args, device.target_delay)
    _LOGGER.info("Sending %s", json.dumps(offer))
    # Sent directly: the app does not necessarily list the namespace.
    socket_client.send_message(
        socket_client.destination_id, NS_WEBRTC, offer, no_add_request_id=True
    )
    if not controller.answer_event.wait(10) or controller.answer is None:
        raise RuntimeError("No ANSWER received")
    answer_time = wall_clock()
    if controller.answer.get("result") != "ok":
        raise RuntimeError(f"Offer rejected: {controller.answer}")

    device.senders = make_senders(
        device.name, cast.cast_info.host, controller.answer["answer"], audio, video
    )
    for sender in device.senders:
        sender.session_start = answer_time


def make_senders(
    device_name: str,
    host: str,
    answer: dict,
    audio: StreamConfig,
    video: StreamConfig | None,
) -> list[RtpSender]:
    """Create a sender for each stream the receiver accepted, audio first."""
    send_indexes = answer.get("sendIndexes", [])
    if audio.index not in send_indexes:
        raise RuntimeError(f"Receiver did not accept the audio stream: {answer}")
    dest = (host, answer["udpPort"])
    _LOGGER.info("Streaming to %s at %s:%s", device_name, *dest)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", 0))
    senders = []
    for name, config in (("audio", audio), ("video", video)):
        if config is None:
            continue
        if config.index not in send_indexes:
            _LOGGER.warning("Receiver did not accept the %s stream", name)
            continue
        receiver_ssrc = answer["ssrcs"][send_indexes.index(config.index)]
        senders.append(
            RtpSender(f"{device_name} {name}", sock, dest, config, receiver_ssrc)
        )
    return senders


def log_clock_offset(path: str, device: str, offset: float, spread: float) -> None:
    """Append this run's offset and print the wall clock error over all runs.

    The receiver's RTCP clock is its wall clock truncated to whole seconds at
    session start, so each run bounds the error e of its wall clock relative
    to ours by offset <= e < offset + 1. Intersecting runs narrows that down.
    """
    with open(path, "a", encoding="utf-8") as file:
        file.write(
            json.dumps(
                {
                    "time": time.time(),
                    "device": device,
                    "offset": offset,
                    "spread": spread,
                }
            )
            + "\n"
        )
    with open(path, encoding="utf-8") as file:
        entries = [json.loads(line) for line in file if line.strip()]
    # Entries without a device are from single device runs before it was logged.
    offsets = [
        entry["offset"] for entry in entries if entry.get("device", device) == device
    ]
    low, high = max(offsets), min(offsets) + 1
    if low >= high:
        _LOGGER.warning(
            "%s runs disagree (%.3f >= %.3f s): the clock is not truncated wall "
            "time, or the receiver's wall clock moved between runs",
            device,
            low,
            high,
        )
        return
    _LOGGER.info(
        "%s wall clock is %+.3f to %+.3f s from ours over %s runs",
        device,
        low,
        high,
        len(offsets),
    )


NPE_MESSAGE = b"GoogleNPE_Eric_Wayne"
NPE_BEACON_PORT = 9478
NPE_SOURCE_PORT = 9487


def npe_probe(host: str, stop: threading.Event) -> None:
    """Send the hub's own broadcast beacon back to it by unicast, log replies.

    Nest hubs broadcast NPE_MESSAGE from port 9487 to port 9478 once a minute.
    We send from 9487 too, so replies addressed to that port reach us.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("", NPE_SOURCE_PORT))
    except OSError as err:
        _LOGGER.warning("NPE probe: can't bind %s (%s)", NPE_SOURCE_PORT, err)
        sock.bind(("", 0))
    sock.settimeout(0.2)
    next_send = time.monotonic()
    sends = 0
    with sock:
        while not stop.is_set():
            if sends < 3 and time.monotonic() >= next_send:
                for port in (NPE_BEACON_PORT, NPE_SOURCE_PORT):
                    sock.sendto(NPE_MESSAGE, (host, port))
                _LOGGER.info("NPE probe: sent %s to %s", NPE_MESSAGE, host)
                sends += 1
                next_send += 1.0
            try:
                data, addr = sock.recvfrom(2048)
            except TimeoutError:
                continue
            _LOGGER.info("NPE probe: reply from %s:%s: %r", *addr, data)


def stream_video(
    args: argparse.Namespace, sender: RtpSender, start: float, stop: threading.Event
) -> None:
    """Send video frames at their capture times until stopped."""
    next_report = start
    frames = vp8_frames(
        args.video_input, args.width, args.height, args.fps, args.video_bitrate
    )
    for frame_id, (key_frame, frame) in enumerate(frames):
        capture_time = start + frame_id / args.fps
        while time.monotonic() < capture_time:
            if time.monotonic() >= next_report:
                sender.send_sender_report()
                next_report += RTCP_INTERVAL
            if stop.wait(min(capture_time, next_report) - time.monotonic()):
                return
        # Also before the first frame: the receiver drops frames until then.
        if time.monotonic() >= next_report:
            sender.send_sender_report()
            next_report += RTCP_INTERVAL
        spread = min(args.pacing_ms / 1000, 0.5 / args.fps)
        sender.send_frame(frame_id, capture_time, frame, key_frame, spread)
        if frame_id % max(1, round(args.fps * 5)) == 0:
            _LOGGER.info(
                "Sent video frame %s (%s bytes), receiver checkpoint %s",
                frame_id,
                len(frame),
                sender.checkpoint,
            )


def clock_rate_ppm(samples: list[tuple[float, float]]) -> float | None:
    """Rate of the receiver's clock against ours, None if under 30 s of samples.

    Network delay only ever makes the offset smaller, so the largest offset in
    each 5 s window is the least delayed sample; those are fitted to a line.
    """
    if not samples or samples[-1][0] - samples[0][0] < 30:
        return None
    windows: dict[int, tuple[float, float]] = {}
    for at, offset in samples:
        key = int((at - samples[0][0]) // 5)
        if key not in windows or offset > windows[key][1]:
            windows[key] = (at, offset)
    return linear_slope(list(windows.values())) * 1e6


def linear_slope(points: list[tuple[float, float]]) -> float:
    """Least squares slope of y over x."""
    mean_x = statistics.fmean(x for x, _ in points)
    mean_y = statistics.fmean(y for _, y in points)
    return sum((x - mean_x) * (y - mean_y) for x, y in points) / sum(
        (x - mean_x) ** 2 for x, _ in points
    )


def report_clock(args: argparse.Namespace, device: Device) -> None:
    """Log how the receiver's RTCP clock relates to ours."""
    sender = device.senders[0]
    if not sender.clock_offsets:
        return
    offset = statistics.median(sender.clock_offsets)
    receiver_now = wall_clock() + offset
    spread = max(sender.clock_offsets) - min(sender.clock_offsets)
    rate = clock_rate_ppm(sender.clock_samples)
    if rate is not None:
        _LOGGER.info(
            "%s clock runs %+.1f ppm against ours (system clock, not its audio output)",
            device.name,
            rate,
        )
    _LOGGER.info(
        "%s clock is %+.3f s from ours (%s samples, spread %.1f ms, "
        "rtt %s), receiver time now %s",
        device.name,
        offset,
        len(sender.clock_offsets),
        spread * 1000,
        "unknown" if sender.rtt is None else f"{sender.rtt * 1000:.1f} ms",
        time.strftime("%H:%M:%S", time.localtime(receiver_now))
        + f".{int(receiver_now % 1 * 1000):03d}",
    )
    if args.clock_log:
        log_clock_offset(args.clock_log, device.name, offset, spread)


def report_events(sender: RtpSender) -> None:
    """Summarize the receiver's event log for one stream."""
    if not sender.events:
        return
    counts: dict[str, int] = {}
    for _, event, _, _ in sender.events:
        counts[event] = counts.get(event, 0) + 1
    _LOGGER.info("%s receiver events: %s", sender.name, counts)
    late = [value for _, event, _, value in sender.events if event == "played out"]
    if late:
        _LOGGER.info(
            "%s played out: median %s ms late, max %s ms, %s of %s frames late",
            sender.name,
            statistics.median(late),
            max(late),
            sum(1 for value in late if value > 0),
            len(late),
        )
    if not sender.clock_offsets or sender.session_start is None:
        return
    # Event times count from the receiver's session start, which is also when
    # its NTP clock was anchored to whole seconds of its wall clock.
    offset = statistics.median(sender.clock_offsets)
    anchor = round(sender.session_start + NTP_EPOCH_OFFSET + offset - 0.1)
    latencies: dict[str, list[float]] = {}
    for rtp_ts, event, event_ms, _ in sender.events:
        if rtp_ts not in sender.capture_times:
            continue
        event_time = anchor + event_ms / 1000 - offset - NTP_EPOCH_OFFSET
        latency = event_time - sender.capture_times[rtp_ts]
        latencies.setdefault(event, []).append(latency * 1000)
    for event, values in latencies.items():
        _LOGGER.info(
            "%s capture to %s: median %.1f ms, min %.1f, max %.1f",
            sender.name,
            event,
            statistics.median(values),
            min(values),
            max(values),
        )


SYNC_FREQUENCIES = (1000, 2500, 4000)
SYNC_BURST = 0.04
SYNC_BANDWIDTH = 300


def sync_test_input(frequency: int) -> list[str]:
    """A soft edged tone burst at the start of every second of media time."""
    expr = (
        f"if(lt(mod(t,1),{SYNC_BURST}),"
        f"0.5*sin(2*PI*{frequency}*t)*(0.5-0.5*cos(2*PI*mod(t,1)/{SYNC_BURST})),0)"
    )
    return ["-f", "lavfi", "-i", f"aevalsrc=exprs='{expr}':s={SAMPLE_RATE}"]


class MicRecorder:
    """Record the microphone to a 48 kHz mono WAV file.

    Uses the sounddevice package (Core Audio through PortAudio): ffmpeg's
    avfoundation capture silently lost about 11% of the audio.
    """

    def __init__(self, mic: str | None, path: str) -> None:
        try:
            sounddevice = importlib.import_module("sounddevice")
        except ImportError:
            raise SystemExit("--record needs: pip install sounddevice") from None
        self._path = path
        self._chunks: list[bytes] = []
        self.overflows = 0
        device = int(mic) if mic and mic.isdigit() else mic
        self._stream = sounddevice.RawInputStream(
            samplerate=SAMPLE_RATE,
            channels=1,
            dtype="int16",
            device=device,
            callback=self._callback,
        )
        self._stream.start()
        self.started = time.monotonic()
        self.stopped = self.started

    def _callback(self, data: Any, _frames: int, _time: Any, status: Any) -> None:
        if status.input_overflow:
            self.overflows += 1
        self._chunks.append(bytes(data))

    def stop(self) -> None:
        """Stop recording and write the WAV file."""
        self.stopped = time.monotonic()
        self._stream.stop()
        self._stream.close()
        with wave.Wave_write(self._path) as file:
            file.setnchannels(1)
            file.setsampwidth(2)
            file.setframerate(SAMPLE_RATE)
            file.writeframes(b"".join(self._chunks))
        if self.overflows:
            _LOGGER.warning("Recording overflowed %s times", self.overflows)


def load_recording(path: str) -> array.array:
    """Read any audio file ffmpeg understands as 48 kHz mono samples."""
    with run_ffmpeg(
        ["-i", path, "-ac", "1", "-ar", str(SAMPLE_RATE), "-f", "s16le"]
    ) as proc:
        assert proc.stdout is not None
        data = proc.stdout.read()
    samples = array.array("h")
    samples.frombytes(data[: len(data) // 2 * 2])
    if sys.byteorder == "big":
        samples.byteswap()
    return samples


def band_envelope(samples: array.array, frequency: int) -> list[float]:
    """Energy around one frequency in 1 ms steps.

    The band pass has the same width at every frequency, so each one delays
    its bursts by the same amount and the comparison stays fair.
    """
    data = array.array("h", samples)
    if sys.byteorder == "big":
        data.byteswap()
    band = f"bandpass=f={frequency}:width_type=h:w={SYNC_BANDWIDTH}"
    filtered = subprocess.run(
        ["ffmpeg", "-hide_banner", "-loglevel", "error"]
        + ["-f", "s16le", "-ar", str(SAMPLE_RATE), "-ac", "1", "-i", "-"]
        + ["-af", f"{band},{band}", "-f", "s16le", "-"],
        input=data.tobytes(),
        capture_output=True,
        check=True,
    ).stdout
    out = array.array("h")
    out.frombytes(filtered[: len(filtered) // 2 * 2])
    if sys.byteorder == "big":
        out.byteswap()
    step = SAMPLE_RATE // 1000
    return [
        sum(x * x for x in out[i : i + step]) / step
        for i in range(0, len(out) - step + 1, step)
    ]


def burst_onsets(envelope: list[float]) -> list[float]:
    """Seconds into the recording where each burst starts.

    A burst is the loudest point within 0.4 s either side, well above the
    noise floor; it starts where it first rises to half its own peak.
    """
    if not envelope:
        return []
    floor = sorted(envelope)[len(envelope) // 2] or 1.0
    onsets: list[float] = []
    for i, level in enumerate(envelope):
        if level < floor * 30:
            continue
        if level < max(envelope[max(0, i - 400) : i + 401]):
            continue
        half = level / 2
        j = i
        while j > 0 and envelope[j - 1] >= half:
            j -= 1
        before = envelope[j - 1] if j > 0 else 0.0
        fraction = (
            (half - before) / (envelope[j] - before) if envelope[j] > before else 0
        )
        onsets.append((j - 1 + fraction) / 1000)
    return onsets


def analyze_sync(samples: array.array, names: list[str]) -> None:
    """Compare when each device's bursts reached the microphone."""
    _LOGGER.info(
        "Analyzing %.1f s of microphone audio for %s",
        len(samples) / SAMPLE_RATE,
        ", ".join(names),
    )
    if not names or len(samples) < SAMPLE_RATE:
        _LOGGER.warning("Nothing to analyze")
        return
    onsets = []
    for name, frequency in zip(names, SYNC_FREQUENCIES, strict=False):
        found = burst_onsets(band_envelope(samples, frequency))
        gaps = [b - a for a, b in itertools.pairwise(found)]
        _LOGGER.info(
            "%s: %s bursts at %s Hz, spacing %s",
            name,
            len(found),
            frequency,
            f"{min(gaps):.3f}-{max(gaps):.3f} s, median {statistics.median(gaps):.4f}"
            if gaps
            else "-",
        )
        onsets.append(found)
    for name, found in zip(names[1:], onsets[1:], strict=False):
        report_offsets(name, names[0], pair_onsets(onsets[0], found))


def pair_onsets(
    reference: list[float], found: list[float]
) -> list[tuple[float, float]]:
    """(reference time, offset in ms) for each burst matched to a reference one."""
    pairs = []
    for onset in found:
        distance, nearest = min(
            ((abs(ref - onset), ref) for ref in reference), default=(1.0, 0.0)
        )
        # Half the burst period: any further and it's the neighbouring burst.
        if distance < 0.5:
            pairs.append((nearest, (onset - nearest) * 1000))
    return pairs


def report_offsets(name: str, reference: str, pairs: list[tuple[float, float]]) -> None:
    """Log how a device's bursts relate to the reference device's, also over time."""
    if len(pairs) < 2:
        _LOGGER.warning("%s: too few bursts to compare", name)
        return
    diffs = [d for _, d in pairs]
    windows: dict[int, list[float]] = {}
    for at, diff in pairs:
        windows.setdefault(int(at // 5) * 5, []).append(diff)
    _LOGGER.info(
        "%s offset by 5 s of recording: %s",
        name,
        ", ".join(
            f"{at}s {statistics.median(values):+.0f}"
            for at, values in sorted(windows.items())
        ),
    )
    slope = linear_slope(pairs)
    _LOGGER.info(
        "%s vs %s: %+.1f ms (median, %s bursts, stdev %.1f ms, range %+.1f to "
        "%+.1f), drift %+.2f ms/min (%+.0f ppm)",
        name,
        reference,
        statistics.median(diffs),
        len(diffs),
        statistics.pstdev(diffs),
        min(diffs),
        max(diffs),
        slope * 60,
        slope * 1000,
    )


def run_session(args: argparse.Namespace, devices: list[Device]) -> None:
    """Stream to all devices on one timeline until audio ends or duration elapses."""
    stop = threading.Event()
    threads = [
        threading.Thread(
            target=rtcp_receiver,
            args=(device.senders[0].sock, device.senders, stop),
            daemon=True,
        )
        for device in devices
    ]
    if args.npe_probe:
        host = devices[0].senders[0].dest[0]
        threads.append(
            threading.Thread(target=npe_probe, args=(host, stop), daemon=True)
        )
    recording = args.save_recording or os.path.join(
        tempfile.gettempdir(), f"cast_sync_{os.getpid()}.wav"
    )
    recorder = MicRecorder(args.mic, recording) if args.record else None

    start = time.monotonic()
    for device in devices:
        for sender in device.senders:
            sender.origin = start + device.delay
    threads += [
        threading.Thread(
            target=stream_video,
            args=(args, sender, start + device.delay, stop),
            daemon=True,
        )
        for device in devices
        for sender in device.senders[1:]
    ]
    for thread in threads:
        thread.start()

    try:
        stream_audio(args, devices, start)
    finally:
        stop.set()
        for thread in threads:
            thread.join()
        for device in devices:
            device.senders[0].sock.close()
    for device in devices:
        report_device(args, device)
    if recorder:
        finish_recording(args, recorder, recording, devices)


def finish_recording(
    args: argparse.Namespace, recorder: MicRecorder, path: str, devices: list[Device]
) -> None:
    """Stop recording once the last bursts have played, then analyze it."""
    delay = max(device.delay for device in devices)
    target_delay = max(device.target_delay for device in devices)
    time.sleep(delay + target_delay / 1000 + 0.5)
    recorder.stop()
    samples = load_recording(path)
    recorded = len(samples) / SAMPLE_RATE
    elapsed = recorder.stopped - recorder.started
    _LOGGER.info(
        "Recorded %.1f s of audio in %.1f s (%.0f%%), less means lost audio",
        recorded,
        elapsed,
        100 * recorded / elapsed,
    )
    if args.save_recording:
        _LOGGER.info("Saved the recording to %s", path)
    else:
        os.remove(path)
    analyze_sync(samples, [device.name for device in devices])


def stream_audio(args: argparse.Namespace, devices: list[Device], start: float) -> None:
    """Send each device the same frames, on its own possibly delayed timeline.

    Frame n has the same RTP timestamp everywhere; a device with a delay gets
    it, and Sender Reports matching it, that much later.
    """
    sources = [audio_frames(args, device.audio_input) for device in devices]
    frame_ids = [0] * len(devices)
    # Capture time of each device's next frame, on its own timeline.
    next_frame = [start + device.delay for device in devices]
    # The receiver drops frames until it has seen a Sender Report.
    next_report = list(next_frame)
    active = set(range(len(devices)))
    try:
        while active:
            send_times = [
                send_time(args, i, frame_ids[i], next_frame[i])
                for i in range(len(devices))
            ]
            index = min(active, key=send_times.__getitem__)
            sender = devices[index].senders[0]
            time.sleep(max(0.0, send_times[index] - time.monotonic()))
            frame_id = frame_ids[index]
            if index == 0 and apply_timestamp_jump(args, sender, frame_id):
                # A Sender Report with the new mapping before the first frame.
                next_report[index] = time.monotonic()
            if time.monotonic() >= next_report[index]:
                sender.send_sender_report()
                next_report[index] += RTCP_INTERVAL
            opus = next(sources[index], None)
            if opus is None or (
                args.duration and frame_id * args.frame_seconds >= args.duration
            ):
                active.discard(index)
                continue
            sender.send_frame(frame_id, next_frame[index], opus)
            if frame_id % 250 == 0:
                _LOGGER.info(
                    "Sent %s frame %s, receiver checkpoint %s, %s retransmits",
                    sender.name,
                    frame_id,
                    sender.checkpoint,
                    sender.retransmits,
                )
            frame_ids[index] += 1
            next_frame[index] += args.frame_seconds
    finally:
        for source in sources:
            source.close()


def apply_timestamp_jump(
    args: argparse.Namespace, sender: RtpSender, frame_id: int
) -> bool:
    """Start --timestamp-jump at its frame, True if it started now."""
    if not args.timestamp_jump:
        return False
    at, jump_ms = args.timestamp_jump
    if frame_id != round(at / args.frame_seconds):
        return False
    sender.rtp_jump = round(jump_ms * SAMPLE_RATE / 1000)
    _LOGGER.info("%s timestamps jump %s ms", sender.name, jump_ms)
    return True


def send_time(
    args: argparse.Namespace, index: int, frame_id: int, capture_time: float
) -> float:
    """When to send a frame: at capture, or early inside a --send-ahead window."""
    if index == 0 and args.send_ahead:
        at, ahead_ms = args.send_ahead
        frame_seconds = float(args.frame_seconds)
        first = int(at / frame_seconds)
        if first <= frame_id < first + int(ahead_ms / 1000 / frame_seconds):
            return capture_time - (frame_id - first) * frame_seconds
    return capture_time


def report_device(args: argparse.Namespace, device: Device) -> None:
    """Log the outcome of each stream of a device."""
    for sender in device.senders:
        _LOGGER.info(
            "Done %s: checkpoint %s, %s packets, %s retransmits",
            sender.name,
            sender.checkpoint,
            sender.packet_count,
            sender.retransmits,
        )
        report_events(sender)
    report_clock(args, device)


def set_ffmpeg_inputs(args: argparse.Namespace) -> None:
    """Translate the source arguments to ffmpeg input arguments."""
    args.frame_seconds = FRAME_SAMPLES[args.audio_codec] / SAMPLE_RATE
    if args.input:
        args.ffmpeg_input = ["-i", args.input]
    else:
        args.ffmpeg_input = [
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:sample_rate=48000",
        ]
    if args.image:
        args.video_input = ["-loop", "1", "-i", args.image]
    elif args.test_pattern:
        args.video_input = ["-f", "lavfi", "-i", "testsrc2=size=1280x720:rate=30"]
    else:
        args.video_input = None


def at_ms(value: str) -> tuple[float, float]:
    """Parse AT:MS, seconds into the stream and milliseconds."""
    at, _, ms = value.partition(":")
    try:
        return float(at), float(ms)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected AT:MS, got {value}") from None


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the command line arguments."""
    parser.add_argument(
        "--cast",
        action="append",
        required=True,
        help="Name of cast device, repeat to stream to several in sync",
    )
    parser.add_argument(
        "--known-host",
        help="Add known host (IP), can be used multiple times",
        action="append",
    )
    parser.add_argument(
        "--input",
        help="File or URL to play instead of a sine tone (anything ffmpeg reads)",
    )
    parser.add_argument(
        "--duration", type=float, default=10.0, help="Seconds to stream, 0 for all"
    )
    parser.add_argument("--bitrate", type=int, default=128000)
    parser.add_argument("--audio-codec", choices=("opus", "aac"), default="opus")
    parser.add_argument(
        "--aac-raw",
        action="store_true",
        help="Send AAC frames without their ADTS header",
    )
    parser.add_argument(
        "--target-delay", type=int, default=400, help="Playout delay in ms"
    )
    parser.add_argument(
        "--extra-delay",
        action="append",
        default=[],
        metavar="NAME=MS",
        help="Send this device everything later, to line it up with slower ones",
    )
    parser.add_argument(
        "--timestamp-jump",
        type=at_ms,
        metavar="AT:MS",
        help="First device: from AT s into the stream, RTP time runs MS ahead",
    )
    parser.add_argument(
        "--send-ahead",
        type=at_ms,
        metavar="AT:MS",
        help="First device: at AT s, send the next MS of frames immediately",
    )
    parser.add_argument(
        "--target-delay-for",
        action="append",
        default=[],
        metavar="NAME=MS",
        help="Target playout delay for one device instead of --target-delay",
    )
    parser.add_argument("--payload-type", type=int, default=AUDIO_PAYLOAD_TYPE)
    video = parser.add_mutually_exclusive_group()
    video.add_argument("--image", help="Still image to show while playing")
    video.add_argument(
        "--test-pattern", action="store_true", help="Show a moving test pattern"
    )
    parser.add_argument("--fps", type=float, default=2.0, help="Video frame rate")
    parser.add_argument("--width", type=int, default=1280)
    parser.add_argument("--height", type=int, default=720)
    parser.add_argument("--video-bitrate", type=int, default=500000)
    parser.add_argument(
        "--pacing-ms",
        type=float,
        default=50.0,
        help="Spread each video frame's packets over this long, 0 sends a burst",
    )
    parser.add_argument(
        "--sync-test",
        action="store_true",
        help="Play a once a second tone burst, a different pitch on each device",
    )
    parser.add_argument(
        "--record",
        action="store_true",
        help="Record the microphone and measure when each device's bursts arrive",
    )
    parser.add_argument("--save-recording", help="WAV file to keep the recording in")
    parser.add_argument(
        "--analyze",
        help="Only analyze a saved recording, --cast names the devices in order",
    )
    parser.add_argument(
        "--mic",
        help="Microphone name or number (default: system default), list with: "
        "python -m sounddevice",
    )
    parser.add_argument(
        "--npe-probe",
        action="store_true",
        help="Send the hub's GoogleNPE beacon to it during playback, log replies",
    )
    parser.add_argument(
        "--event-log",
        action="store_true",
        help="Ask the receiver for its RTCP event log, summarize playout timing",
    )
    parser.add_argument(
        "--clock-log",
        help="File to collect receiver clock offsets in, prints the bound over runs",
    )
    parser.add_argument(
        "--app-id",
        choices=(APP_ID_AUDIO_ONLY, APP_ID_AUDIO_VIDEO),
        help="Receiver app (default: picked from the device's capabilities)",
    )
    parser.add_argument(
        "--keep-app", action="store_true", help="Don't stop the app when done"
    )
    add_log_arguments(parser)
    add_network_arguments(parser)


def default_app_id(cast: pychromecast.Chromecast) -> str:
    """The streaming app the device supports."""
    capabilities = cast.cast_info.device_capabilities
    has_video = capabilities is not None and CastCapability.VIDEO_OUT in capabilities
    return APP_ID_AUDIO_VIDEO if has_video else APP_ID_AUDIO_ONLY


def parse_per_device(
    parser: argparse.ArgumentParser, args: argparse.Namespace, option: str
) -> dict[str, int]:
    """Device name to milliseconds from a repeatable NAME=MS option."""
    values = {}
    for item in getattr(args, option.lstrip("-").replace("-", "_")):
        name, _, value = item.rpartition("=")
        if name not in args.cast or not value.isdigit():
            parser.error(f"{option} {item}: expected one of the --cast names=MS")
        values[name] = int(value)
    return values


def main() -> None:
    """Launch the streaming apps, negotiate and stream."""
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    add_arguments(parser)
    args = parser.parse_args()
    configure_logging(args)
    set_ffmpeg_inputs(args)
    if args.sync_test and len(args.cast) > len(SYNC_FREQUENCIES):
        parser.error(f"--sync-test supports up to {len(SYNC_FREQUENCIES)} devices")
    extra_delays = parse_per_device(parser, args, "--extra-delay")
    target_delays = parse_per_device(parser, args, "--target-delay-for")
    if args.analyze:
        analyze_sync(load_recording(args.analyze), args.cast)
        return

    chromecasts, browser = pychromecast.get_listed_chromecasts(
        # A copy: found names are removed from the list passed in.
        friendly_names=list(args.cast),
        known_hosts=args.known_host,
        zeroconf_instance=create_zeroconf(args),
    )
    by_name = {cast.cast_info.friendly_name: cast for cast in chromecasts}
    missing = [name for name in args.cast if name not in by_name]
    if missing:
        print(f"No chromecast discovered with name: {', '.join(missing)}")
        browser.stop_discovery()
        sys.exit(1)

    devices = []
    _LOGGER.info("Streaming to %s", ", ".join(args.cast))
    for index, name in enumerate(args.cast):
        cast = by_name[name]
        cast.wait()
        audio_input = (
            sync_test_input(SYNC_FREQUENCIES[index])
            if args.sync_test
            else args.ffmpeg_input
        )
        device = Device(cast, args.app_id or default_app_id(cast), audio_input)
        device.delay = extra_delays.get(name, 0) / 1000
        device.target_delay = target_delays.get(name, args.target_delay)
        if device.delay:
            _LOGGER.info("%s gets everything %s ms later", name, device.delay * 1000)
        devices.append(device)

    try:
        for device in devices:
            negotiate(device, args)
        run_session(args, devices)
    finally:
        for device in devices:
            status = device.cast.status
            if not args.keep_app and status and status.app_id == device.app_id:
                device.cast.quit_app()
        time.sleep(1)
        browser.stop_discovery()


if __name__ == "__main__":
    main()
