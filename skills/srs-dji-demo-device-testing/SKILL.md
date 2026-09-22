---
name: srs-dji-demo-device-testing
description: Test SRS DJI Demo end to end on a physical Android phone with a real DJI aircraft and a local SRS server — build, install, publish RTMP and WHIP, and verify playback. Use this for any "test the demo", "verify the publish path", or "is RTMP/WHIP working" request.
---

# Testing SRS DJI Demo on a phone

This demo takes the aircraft's compressed H.264 off the MSDK and publishes it as RTMP and WHIP.
Testing it means proving media actually arrives at a server and decodes — not that the app launched.

**A physical Android phone is required.** No emulator or simulator can do this: MSDK registration,
the camera tap and the publish path all need the real aircraft and its controller attached. The
aircraft may stay on the ground.

## Before you start

- Phone connected over ADB, aircraft powered on, controller attached to the phone.
- `local.properties` contains `AIRCRAFT_API_KEY=<your key>`. It is gitignored; the tracked
  `gradle.properties` holds only a placeholder. Request your own key for your own `applicationId`
  at <https://developer.dji.com> — a key is bound to its package name.
- A reachable SRS server. Locally, from an SRS checkout:

  ```bash
  cd <srs>/trunk && CANDIDATE=<server-ip> ./objs/srs -c conf/console.conf
  ```

  `CANDIDATE` must be the address the phone will reach, or WHIP's ICE will not connect.

## Run the test

```bash
./gradlew clean assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am force-stop dji.go.v5          # see gotchas
adb shell am start -S -W -n io.ossrs.djidemo/.MainActivity
```

Confirm the key reached the APK if registration misbehaves:

```bash
aapt2 dump xmltree --file AndroidManifest.xml app/build/outputs/apk/debug/app-debug.apk | grep -A2 API_KEY
```

Then drive the UI: screenshot, pick a target with **Select**, tap **Start**, and watch the status
column reach `live`. Test **both** protocols, one at a time, stopping cleanly between them. The
built-in default URLs only need their host corrected to your server.

## Verify — counters are not a picture

Two separate checks. Ingest proves the protocol worked; playback proves the bytes were valid.

**Ingest**, from the server:

```bash
curl -s http://<server-ip>:1985/api/v1/streams/
```

Expect `publish.active: true`, a rising frame count, `H264`, and the aircraft's real resolution.

**Playback**, which is the check that actually matters:

```bash
ffmpeg -i rtmp://<server-ip>:1935/live/livestream -t 5 -c copy /tmp/cap.flv   # or the .flv URL for WHIP
ffmpeg -v error -i /tmp/cap.flv -f null -                                     # no output = no decode errors
ffmpeg -i /tmp/cap.flv -vf 'select=eq(n\,40)' -frames:v 1 /tmp/frame.png      # then look at it
```

Compare the extracted frame against a screenshot of the on-phone preview. Compare the played-back
frame rate and bitrate against the app's own `TAP` line: RTMP should match it closely, and a large
WHIP shortfall means packet loss, since the publisher does not answer RTCP PLI or NACK.

## Gotchas that will waste your time

- **`flash-publish` is what SRS calls an RTMP publisher.** Not Flash, not an error. Grepping the
  clients API for `rtmp-publish` finds nothing while a publish is running.
- **`uiautomator dump` is unreliable here.** The live `SurfaceView` keeps the window from going
  idle, so dumps fail or return a stale hierarchy. Tap fixed coordinates read off a fresh
  `adb exec-out screencap -p`, and verify with another screenshot.
- **DJI's own flight app auto-launches on accessory attach** and takes the aircraft link, killing
  this app's task. Force-stop it before each run; expect it back whenever the accessory
  re-enumerates.
- **Start can be greyed out while video is arriving.** It waits for SPS/PPS, which arrive only with
  a keyframe, and this aircraft's keyframe interval is several seconds. Wait, or tap again.
- **Switching protocols needs the previous publisher actually gone.** An `EOFException` right after
  the RTMP handshake means the server rejected the publish — usually the stream name is still held
  by the previous session. Read the server log before suspecting the client.
- **WHEP playback needs a video-only offer.** DJI aircraft have no microphone, so the stream carries
  no audio track, and a player that offers audio will fail to negotiate. Offer video only.

## Report honestly

Say which evidence establishes each claim, and keep ingest and playback separate — one does not
imply the other. Name what you did not test: playback of a protocol you only ingested, weak
networks, reconnection, long runs, and anything in flight. A single grounded indoor session on one
network is exactly that, and nothing measured on one phone is evidence about another.
