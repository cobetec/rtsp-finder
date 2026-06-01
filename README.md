# rtsp-finder

A small stdlib-only Python tool to find RTSP cameras on your LAN and tell whether
their stream is actually real.

I kept running into cheap IP cameras that answer `DESCRIBE` with a clean `200 OK`
and a full SDP on basically every path you try. Looks like a working stream. Point
VLC at it and... nothing. Turns out a lot of these are stubs: the server walks
through OPTIONS / DESCRIBE / SETUP / PLAY, says 200 to all of it, and then never
sends a single RTP packet. The only way to know for sure is to do the whole
handshake and count the media that actually comes back.

That's what this does.

## What it does

1. Scans your /24 (or a host you name) for camera-ish ports (554 RTSP and friends).
2. On 554 it sends a real RTSP `DESCRIBE` to a list of common paths and shows the
   replies.
3. With `--play` it runs the full handshake (`DESCRIBE -> SETUP -> PLAY`) over TCP,
   then UDP, and reports how many RTP bytes really arrived. A path that streams
   prints a WORKING URL you can paste straight into OBS / VLC / ffmpeg.

## Usage

Run it on the same LAN as the camera.

```
python rtsp_finder.py                       # scan local /24, then probe what answers
python rtsp_finder.py 192.168.1.50          # probe one known IP
python rtsp_finder.py --play 192.168.1.50   # full handshake, prove it streams
python rtsp_finder.py --play --user admin --pw 123456 192.168.1.50
```

`--path` lets you test one exact path, `--port` if RTSP isn't on 554.

## Reading the output

- **Real RTP after PLAY** -> it's a usable stream, you get a URL.
- **DESCRIBE 200 but no RTP** -> it's a stub. Don't waste time on it.

The dead giveaway for a stub: it ignores the transport you asked for and echoes
back something canned like `interleaved=255-255`, then goes quiet. A working
server honours your `interleaved=` or `client_port=` and starts sending bytes.

## Notes

- Stdlib only, Python 3. No pip installs.
- This pokes ports and does RTSP handshakes. Only run it against cameras you own.
- Tested against a handful of cheap cams I had on hand. Your camera's quirks may
  differ; the path list is just the common suspects.
