# Cast Streaming findings

Notes from experiments with `cast_streaming_audio_example.py`, a Python
sender for the Cast Streaming ("mirroring") protocol modelled on Open
Screen's `cast/standalone_sender`.

Tested on three devices on the same LAN: a **Nest Hub**, a **Chromecast
on a TV** (sound through the TV's speakers over HDMI) and an **audio-only
Cast receiver** (no screen; it was muted, so only its RTCP reports were
used). They turned out to behave quite differently; other models may
differ again.

| | Nest Hub | Chromecast on a TV | Audio-only receiver |
|---|---|---|---|
| Receiver app | `0F5096E8` (audio/video) | `0F5096E8` | `85CDB22F` (audio-only) |
| Event log | packet received, ack sent | declined in the ANSWER | all, including played out |
| `targetDelay` | ignored | ignored | honoured |
| Playout | starts on arrival | starts on arrival | on schedule, never late |

**It is the device, not the app.** The audio-only receiver also runs the
audio/video app `0F5096E8` ("Chrome Mirroring", `appType: WEB` there too)
and behaves exactly the same with it: same ANSWER, playout at capture +
`targetDelay`, never late. So the streaming receiver in each device's
firmware decides, not the app ID. The ANSWER may tell them apart up
front: the device that schedules answered with `castMode`,
`rtpExtensions` and `receiverRtcpEventLog`, both play-on-arrival
devices with a `display` block (only three devices, so a hint, not a
rule).

Unless noted, timing numbers come from the `--sync-test --record`
measurements with the Core Audio recorder (see "Measuring" below), not
from the earlier ffmpeg recorder, which silently lost audio.

## Protocol

- **Receiver app.** The audio-only streaming app `85CDB22F` is rejected
  with `NOT_FOUND` by the Nest Hub. Devices with a screen need the
  audio/video app `0F5096E8` ("Chrome Mirroring"), which accepts an
  OFFER with only an audio stream; the screen then stays black. The
  audio-only receiver runs `85CDB22F`.
- **ANSWER contents differ.** The audio-only receiver's ANSWER also
  carries `castMode`, `rtpExtensions` and `receiverRtcpEventLog`; the
  screen devices send a `display` block instead (1280x720 and
  `scaling: receiver` on the Nest Hub, 3840x2160 and `scaling: sender`
  on the TV), suggesting different receiver implementations or versions.
- **`rtpProfile`** is always `cast`; Open Screen writes it but never reads
  it.
- **Namespace.** OFFER and ANSWER go over
  `urn:x-cast:com.google.cast.webrtc`, but this is Cast Streaming, not
  WebRTC: no ICE, DTLS or SRTP. Libraries such as aiortc don't apply.
- **Payload types.** Like Open Screen's default ("Android RTP hack"):
  127 for audio, 96 for video.
- **Codecs.** Opus and AAC (ADTS framing) audio both play; VP8 video
  plays. Open Screen's OFFER parser knows no raw PCM codec.
- **Encryption.** AES-128-CTR per frame, with the nonce being the
  `aesIvMask` XOR'ed with the 32-bit frame id at bytes 8-11.
- **RTP timestamps must start at 0, at the same moment, for all streams**,
  as Open Screen's encoders do. With random starting points, audio-only
  plays, but an audio+video session stalls silently: the player takes
  about 20 video frames and never starts, so audio stays silent too.
- **Sender Reports.** The receiver drops frames until it has seen a
  Sender Report, so one must go out before the first frame of every
  stream.
- **Flow control.** The receiver holds at most 120 frames beyond the last
  one its player consumed; a stalled player shows up as a checkpoint
  that stops advancing without any NACKs.
- **Video packets.** Sending a frame's packets in one burst cost ~16%
  retransmits; spreading them over ~50 ms brought that to ~1-2%.
- **A leftover session** from an earlier sender doesn't answer a new
  OFFER; the script restarts it first.

## Receiver event log (`receiverRtcpEventLog`)

- The Nest Hub sends "packet received" and "ack sent" events, never
  "decoded" or "played out" ones. In Open Screen those two are what the
  receiver logs by itself; "played out" needs the player to call
  `ReportPlayoutEvent()`, which the hub's player doesn't, and Open Screen
  has no way to report "decoded" at all.
- The Nest Hub's ANSWER listed only the audio stream in
  `receiverRtcpEventLog`, yet video events arrived too.
- The TV's ANSWER has no `receiverRtcpEventLog`: it declines, and sends
  no log.
- The audio-only receiver sends every event type, one per frame,
  including "played out" with its lateness (0 of 500 frames late).
- Event times are milliseconds on the receiver's own clock. The script
  measures each event from the frame's first packet arriving, plus half
  the round trip, which works whatever the receiver's clock is like.
  Capture to packet arrival is ~3-5 ms on this LAN.

## Receiver clocks

- The receiver's RTCP (NTP) clock is its **wall clock truncated to whole
  seconds at session start**, then advanced by a monotonic clock (as in
  Open Screen's `NtpTimeConverter`). Each session's measured offset
  therefore only bounds the wall clock error `e` to
  `offset <= e < offset + 1`; intersecting runs narrows it
  (`--clock-log`). The Nest Hub came out within -26 to +19 ms of the
  sender's wall clock.
- The audio-only receiver doesn't seem to do this: two separate sessions
  measured +0.387 and +0.393 s, which suggests a continuous clock that
  is really ~390 ms ahead of the sender's (one more run would confirm).
  The whole-second bound doesn't apply to it.
- Both devices' clocks ran within a few ppm of the sender's.
- The sender's wall clock can be slewed by the OS mid-run (both devices
  suddenly appeared ~140 ppm off). Sender Report times now follow the
  monotonic clock, anchored to wall time once.
- The receiver smooths its clock offset estimate with a 30 s exponential
  moving average, starting from the first Sender Report (Open Screen's
  `ClockDriftSmoother`).

## Playout timing

- **The audio-only receiver plays on schedule.** Its played-out events
  came 394 ms after arrival with a 400 ms `targetDelay`, and 794 ms with
  800 ms, i.e. at capture + `targetDelay` (from capture: 798.7 ms
  median), never late, while packet arrival jittered by tens of ms. It
  works the way Open Screen's design intends.
- **On the Nest Hub and the TV, `targetDelay` does not change when sound
  comes out.** The Nest Hub
  accepts it (its RTCP feedback reports the requested value), but
  100, 400, 800 and 2000 ms all gave the same playout timing, with no
  slow steering towards the target either. The TV also showed no change
  at 800 ms (measured with the older, lossy recorder).
- **Timestamp gaps are ignored.** A 300 ms jump in RTP time mid-stream
  inserted no silence, with Opus and with AAC.
- So those two players start on arrival and then play at their own pace;
  the OFFER's playout delay only matters inside the receiver (for
  example how long it waits for retransmits).
- **Sending later is the lever that works.** Delaying everything sent to
  one device (frames and matching Sender Reports, `--extra-delay`)
  shifted its playout by that amount on both devices.

## Two devices in sync

- With identical input, the TV plays **~395-414 ms after the Nest Hub**:
  about 5 ms between runs, about 3 ms burst-to-burst scatter within a
  run. Launch order makes no difference, so this is latency in the TV's
  path (likely the TV's own audio processing), not session start-up.
- Network delay is negligible here: ~5-6 ms round trip to each device.
- Compensating with `--extra-delay` brings the devices within a few tens
  of ms, but see the open questions.
- A group mixing both kinds of player would need both mechanisms: one
  shared timeline and `targetDelay` for devices that play on schedule
  (plus a fixed offset for their output latency), and send timing
  (`--extra-delay`) for devices that play on arrival.

## Open questions

- **Drift during a compensated run.** With the Nest Hub delayed by
  411 ms, the offset went from about -11 to -58 ms within 30 s, i.e. the
  delayed device got later. Uncompensated runs drift less (+10 to
  +13 ms/min the other way). Not yet known whether this is gradual or in
  frame-sized steps, nor whether it settles.
- **Frame-sized steps.** The Nest Hub occasionally shifted by ~20 ms (one
  Opus frame) and stayed there, which looks like the player dropping or
  inserting a frame to manage its buffer.
- **A periodic glitch** on the Nest Hub: every ~8 s one burst arrived
  ~40 ms early, the next on time. Could be the detector or the device.
- **Drift over minutes** needs a long recorded run.
- **Remoting mode** (`urn:x-cast:com.google.cast.remoting`) has the
  receiver act as a media player that reports its media time back, which
  might give real playout feedback.

## Measuring

- `--sync-test` plays a 40 ms tone burst once per second of media time,
  at a different pitch per device; `--record` records the microphone and
  compares when each device's bursts arrive (`--analyze` reruns that on a
  saved recording). Keep the microphone roughly equally far from both
  devices: each metre of difference adds ~3 ms.
- **ffmpeg's avfoundation microphone capture lost ~11% of the audio** on
  the test Mac, in chunks, without any warning, even run on its own; its
  `-t` limit still looks right because it counts timestamps, not
  samples. Recording now uses the `sounddevice` package (Core Audio),
  which records 20.0 s of audio in 20.0 s.
- Don't change a device's volume during a run; volume ramps and click
  sounds confuse the burst detection.
- `get_listed_chromecasts()` removes the names it finds from the
  `friendly_names` list it is given, so pass a copy.

## Unrelated traffic seen

While capturing during group playback the Nest Hub sent nothing that
looked like playback sync, only once-a-minute discovery broadcasts:
a TP-Link Kasa discovery probe (UDP 9999, XOR-obfuscated
`{"system":{"get_sysinfo":{}}}`) and a fixed string on UDP 9487 to 9478.
Sync between speakers in Google's own groups is presumably unicast and
wasn't visible from a laptop on the same network.
