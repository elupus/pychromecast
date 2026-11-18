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
import json
import logging
import os
import random
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from typing import IO

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
    return subprocess.Popen(cmd, stdout=subprocess.PIPE)


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


def opus_frames(ffmpeg_input: list[str], bitrate: int) -> Iterator[bytes]:
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
    audio: StreamConfig, video: StreamConfig | None, args: argparse.Namespace
) -> dict:
    """Build a mirroring OFFER, same fields as Open Screen."""
    streams = [
        {
            **audio.offer_fields(args.target_delay, args.event_log),
            "type": "audio_source",
            "codecName": "opus",
            "channels": CHANNELS,
            "bitRate": args.bitrate,
        }
    ]
    if video:
        streams.append(
            {
                **video.offer_fields(args.target_delay, args.event_log),
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


def ntp_now() -> int:
    """Wall clock as a 64 bit NTP timestamp."""
    now = time.time() + NTP_EPOCH_OFFSET
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
        # Our wall clock when the receiver answered, its RTCP session started
        # shortly before.
        self.session_start: float | None = None
        # rtp timestamp -> our wall clock time of capture
        self.capture_times: dict[int, float] = {}
        # (rtp timestamp, event, ms since receiver session start, value)
        self.events: list[tuple[int, str, int, int]] = []

    def rtp_timestamp_at(self, t: float) -> int:
        """RTP timestamp of monotonic time t."""
        return round((t - self.origin) * self._config.timebase) & 0xFFFFFFFF

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
            self.capture_times[rtp_ts] = time.time() - (time.monotonic() - capture_time)
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


def negotiate(
    cast: pychromecast.Chromecast, args: argparse.Namespace, app_id: str
) -> list[RtpSender]:
    """Launch the receiver app, exchange OFFER/ANSWER and set up the senders.

    The first sender is audio, the second, if any, video.
    """
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
    offer = build_offer(audio, video, args)
    _LOGGER.info("Sending %s", json.dumps(offer))
    # Sent directly: the app does not necessarily list the namespace.
    socket_client.send_message(
        socket_client.destination_id, NS_WEBRTC, offer, no_add_request_id=True
    )
    if not controller.answer_event.wait(10) or controller.answer is None:
        raise RuntimeError("No ANSWER received")
    answer_time = time.time()
    if controller.answer.get("result") != "ok":
        raise RuntimeError(f"Offer rejected: {controller.answer}")

    senders = make_senders(
        cast.cast_info.host, controller.answer["answer"], audio, video
    )
    for sender in senders:
        sender.session_start = answer_time
    return senders


def make_senders(
    host: str, answer: dict, audio: StreamConfig, video: StreamConfig | None
) -> list[RtpSender]:
    """Create a sender for each stream the receiver accepted, audio first."""
    send_indexes = answer.get("sendIndexes", [])
    if audio.index not in send_indexes:
        raise RuntimeError(f"Receiver did not accept the audio stream: {answer}")
    dest = (host, answer["udpPort"])
    _LOGGER.info("Streaming to %s:%s", *dest)

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
        senders.append(RtpSender(name, sock, dest, config, receiver_ssrc))
    return senders


def log_clock_offset(path: str, offset: float, spread: float) -> None:
    """Append this run's offset and print the wall clock error over all runs.

    The receiver's RTCP clock is its wall clock truncated to whole seconds at
    session start, so each run bounds the error e of its wall clock relative
    to ours by offset <= e < offset + 1. Intersecting runs narrows that down.
    """
    with open(path, "a", encoding="utf-8") as file:
        file.write(
            json.dumps({"time": time.time(), "offset": offset, "spread": spread}) + "\n"
        )
    with open(path, encoding="utf-8") as file:
        offsets = [json.loads(line)["offset"] for line in file if line.strip()]
    low, high = max(offsets), min(offsets) + 1
    if low >= high:
        _LOGGER.warning(
            "Runs disagree (%.3f >= %.3f s): the clock is not truncated wall "
            "time, or the receiver's wall clock moved between runs",
            low,
            high,
        )
        return
    _LOGGER.info(
        "Receiver wall clock is %+.3f to %+.3f s from ours over %s runs",
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
        spread = min(args.pacing_ms / 1000, 0.5 / args.fps)
        sender.send_frame(frame_id, capture_time, frame, key_frame, spread)
        if frame_id % max(1, round(args.fps * 5)) == 0:
            _LOGGER.info(
                "Sent video frame %s (%s bytes), receiver checkpoint %s",
                frame_id,
                len(frame),
                sender.checkpoint,
            )


def report_clock(args: argparse.Namespace, sender: RtpSender) -> None:
    """Log how the receiver's RTCP clock relates to ours."""
    if not sender.clock_offsets:
        return
    offset = statistics.median(sender.clock_offsets)
    receiver_now = time.time() + offset
    spread = max(sender.clock_offsets) - min(sender.clock_offsets)
    _LOGGER.info(
        "Receiver clock is %+.3f s from ours (%s samples, spread %.1f ms, "
        "rtt %s), receiver time now %s",
        offset,
        len(sender.clock_offsets),
        spread * 1000,
        "unknown" if sender.rtt is None else f"{sender.rtt * 1000:.1f} ms",
        time.strftime("%H:%M:%S", time.localtime(receiver_now))
        + f".{int(receiver_now % 1 * 1000):03d}",
    )
    if args.clock_log:
        log_clock_offset(args.clock_log, offset, spread)


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


def run_session(args: argparse.Namespace, senders: list[RtpSender]) -> None:
    """Stream until the audio input ends or duration elapses."""
    audio = senders[0]
    stop = threading.Event()
    threads = [
        threading.Thread(
            target=rtcp_receiver, args=(audio.sock, senders, stop), daemon=True
        )
    ]
    if args.npe_probe:
        threads.append(
            threading.Thread(target=npe_probe, args=(audio.dest[0], stop), daemon=True)
        )

    start = time.monotonic()
    for sender in senders:
        sender.origin = start
    # The receiver drops frames until it has seen a Sender Report.
    for sender in senders:
        sender.send_sender_report()
    next_report = start + RTCP_INTERVAL
    for sender in senders[1:]:
        threads.append(
            threading.Thread(
                target=stream_video, args=(args, sender, start, stop), daemon=True
            )
        )
    for thread in threads:
        thread.start()

    frame_id = 0
    try:
        for opus in opus_frames(args.ffmpeg_input, args.bitrate):
            capture_time = start + frame_id * FRAME_MS / 1000
            if args.duration and capture_time - start >= args.duration:
                break
            delay = capture_time - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            audio.send_frame(frame_id, capture_time, opus)
            if time.monotonic() >= next_report:
                audio.send_sender_report()
                next_report += RTCP_INTERVAL
            if frame_id % 250 == 0:
                _LOGGER.info(
                    "Sent audio frame %s, receiver checkpoint %s, %s retransmits",
                    frame_id,
                    audio.checkpoint,
                    audio.retransmits,
                )
            frame_id += 1
    finally:
        stop.set()
        for thread in threads:
            thread.join()
        audio.sock.close()
    report_session(args, senders)


def report_session(args: argparse.Namespace, senders: list[RtpSender]) -> None:
    """Log the outcome of each stream."""
    for sender in senders:
        _LOGGER.info(
            "Done %s: checkpoint %s, %s packets, %s retransmits",
            sender.name,
            sender.checkpoint,
            sender.packet_count,
            sender.retransmits,
        )
        report_events(sender)
    report_clock(args, senders[0])


def set_ffmpeg_inputs(args: argparse.Namespace) -> None:
    """Translate the source arguments to ffmpeg input arguments."""
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


def main() -> None:
    """Launch the streaming app, negotiate and stream."""
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("--cast", help="Name of cast device", default="Living Room")
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
    parser.add_argument(
        "--target-delay", type=int, default=400, help="Playout delay in ms"
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
    args = parser.parse_args()
    configure_logging(args)
    set_ffmpeg_inputs(args)

    chromecasts, browser = pychromecast.get_listed_chromecasts(
        friendly_names=[args.cast],
        known_hosts=args.known_host,
        zeroconf_instance=create_zeroconf(args),
    )
    if not chromecasts:
        print(f'No chromecast with name "{args.cast}" discovered')
        sys.exit(1)
    cast = chromecasts[0]
    cast.wait()

    app_id = args.app_id
    if app_id is None:
        capabilities = cast.cast_info.device_capabilities
        has_video = (
            capabilities is not None and CastCapability.VIDEO_OUT in capabilities
        )
        app_id = APP_ID_AUDIO_VIDEO if has_video else APP_ID_AUDIO_ONLY

    try:
        run_session(args, negotiate(cast, args, app_id))
    finally:
        if not args.keep_app and cast.status and cast.status.app_id == app_id:
            cast.quit_app()
            time.sleep(1)
        browser.stop_discovery()


if __name__ == "__main__":
    main()
