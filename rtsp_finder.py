#!/usr/bin/env python3
"""
rtsp-finder -- find RTSP cameras on your LAN and check if their stream is real.

Cheap IP cameras love to answer DESCRIBE with a nice 200 + SDP on every path you
throw at them, which makes you think you've found a working stream. A lot of the
time it's a stub: the server completes OPTIONS/DESCRIBE/SETUP/PLAY but never sends
a single byte of RTP. This tool tells the difference by doing the FULL handshake
and counting the media that actually arrives.

Stdlib only, no installs.

  1. Scan your /24 (or a host you name) for camera-ish ports (554 RTSP, etc).
  2. On 554, send a real RTSP DESCRIBE to a list of common paths and show replies.
  3. --play: run the whole handshake (DESCRIBE -> SETUP -> PLAY) over TCP and then
     UDP, and report how many RTP bytes really came back. A path that streams video
     prints a WORKING URL you can drop straight into OBS/VLC/ffmpeg.

Run (on the SAME LAN as the camera):
    python rtsp_finder.py                      # scan local /24, then probe hits
    python rtsp_finder.py 192.168.1.50          # probe one known IP
    python rtsp_finder.py --play 192.168.1.50    # full handshake, prove it streams
    python rtsp_finder.py --play --user admin --pw 123456 192.168.1.50

Real RTP after PLAY = it's a usable stream. DESCRIBE 200 but no RTP = it's a stub.
"""

import argparse
import socket
import sys
import threading
import time

# Ports worth checking on a camera. 554=RTSP, 8554/555=alt RTSP, 2020/8000=ONVIF-ish,
# 6668=Tuya local control (a hint the cam is a Tuya-based device), 80/443/8080=web UI.
PORTS = [554, 8554, 555, 80, 443, 8080, 8000, 8899, 2020, 6668, 5000, 8888]
STREAM_HINT = {554, 8554, 555}

# Candidate RTSP paths seen across ONVIF / Hikvision / Dahua / generic IP cams.
RTSP_PATHS = [
    "/", "/onvif1", "/onvif2", "/live", "/live/ch0", "/live/ch00_0",
    "/h264", "/h264_stream", "/video", "/video1", "/stream1", "/stream2",
    "/11", "/12", "/av0_0", "/cam/realmonitor?channel=1&subtype=0",
    "/Streaming/Channels/101", "/ch0_0.h264", "/media/video1",
]


def local_ipv4():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def tcp_open(ip, port, timeout=0.4):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        s.close()


def scan_subnet(base_ip):
    """Return list of IPs in base_ip's /24 with any candidate port open."""
    prefix = base_ip.rsplit(".", 1)[0]
    found = {}
    lock = threading.Lock()
    quick = [554, 8554, 6668, 80]  # fast first-pass triage ports

    def worker(host):
        ip = f"{prefix}.{host}"
        openp = [p for p in quick if tcp_open(ip, p, 0.3)]
        if openp:
            with lock:
                found[ip] = openp

    threads = [threading.Thread(target=worker, args=(h,)) for h in range(1, 255)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return found


def rtsp_request(ip, port, path, method, user=None, pw=None, cseq=1):
    url = f"rtsp://{ip}:{port}{path}"
    lines = [f"{method} {url} RTSP/1.0", f"CSeq: {cseq}",
             "User-Agent: rtsp-finder"]
    if method == "DESCRIBE":
        lines.append("Accept: application/sdp")
    req = ("\r\n".join(lines) + "\r\n\r\n").encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect((ip, port))
        s.sendall(req)
        return s.recv(4096).decode(errors="replace")
    except OSError as e:
        return f"<no reply: {e}>"
    finally:
        s.close()


def probe_rtsp(ip, port, user, pw):
    print(f"  [RTSP] trying {ip}:{port} ...")
    opts = rtsp_request(ip, port, "/", "OPTIONS", user, pw, 1)
    first = opts.splitlines()[0] if opts.strip() else "<empty>"
    print(f"    OPTIONS / -> {first}")
    if "RTSP/1.0" not in opts:
        print("    (no RTSP server here)")
        return False
    hit = False
    for path in RTSP_PATHS:
        resp = rtsp_request(ip, port, path, "DESCRIBE", user, pw, 2)
        status = resp.splitlines()[0] if resp.strip() else "<empty>"
        if "200" in status:
            print(f"    *** DESCRIBE {path} -> {status}")
            print(f"        SDP looks playable: rtsp://{ip}:{port}{path}")
            if "m=video" in resp:
                for ln in resp.splitlines():
                    if ln.startswith(("m=", "a=rtpmap", "a=control")):
                        print(f"          {ln}")
            hit = True
        elif "401" in status:
            print(f"    DESCRIBE {path} -> 401 (needs user/pw; pass --user/--pw)")
        elif "RTSP/1.0" in status and "404" not in status:
            print(f"    DESCRIBE {path} -> {status}")
    if hit:
        print("    NOTE: a 200 + SDP does NOT prove it streams. Run --play to be sure.")
    return hit


def _basic_auth(user, pw):
    import base64
    tok = base64.b64encode(f"{user or ''}:{pw or ''}".encode()).decode()
    return f"Basic {tok}"


class RTSPClient:
    """Minimal RTSP-over-TCP client: does the full handshake and reports
    whether interleaved RTP data actually arrives after PLAY."""

    def __init__(self, ip, port, path, user=None, pw=None):
        self.ip, self.port, self.path = ip, port, path
        self.user, self.pw = user, pw
        self.url = f"rtsp://{ip}:{port}{path}"
        self.sock = socket.create_connection((ip, port), timeout=4.0)
        self.sock.settimeout(4.0)
        self.buf = b""
        self.cseq = 0
        self.session = None
        self.base = self.url  # overridden by Content-Base if present

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def _send(self, method, url, extra=None):
        self.cseq += 1
        lines = [f"{method} {url} RTSP/1.0", f"CSeq: {self.cseq}",
                 "User-Agent: rtsp-finder"]
        if self.session:
            lines.append(f"Session: {self.session}")
        if self.user or self.pw:
            lines.append(f"Authorization: {_basic_auth(self.user, self.pw)}")
        for k, v in (extra or []):
            lines.append(f"{k}: {v}")
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())

    def _read_response(self):
        """Read one RTSP text response (+ body if Content-Length). Returns
        (status_line, headers_dict, body_str)."""
        while b"\r\n\r\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise OSError("connection closed")
            self.buf += chunk
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        text = head.decode(errors="replace")
        lines = text.split("\r\n")
        status = lines[0]
        headers = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        body = ""
        clen = int(headers.get("content-length", 0) or 0)
        if clen:
            while len(self.buf) < clen:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                self.buf += chunk
            body, self.buf = self.buf[:clen].decode(errors="replace"), self.buf[clen:]
        return status, headers, body

    def _resolve_track_url(self, control):
        if not control or control == "*":
            return self.base
        if control.lower().startswith("rtsp://"):
            return control
        if self.base.endswith("/"):
            return self.base + control
        return self.base + "/" + control

    def play_test(self, duration=6.0, mode="tcp"):
        """Full handshake; returns (ok, message). mode='tcp' uses RTP
        interleaved over the RTSP socket; mode='udp' binds local UDP ports
        (what VLC does by default). Reports bytes received + server Transport."""
        # Skip OPTIONS: some cameras answer it 400 and then drop the socket.
        # RTSP allows DESCRIBE as the first request.
        self._send("DESCRIBE", self.url, [("Accept", "application/sdp")])
        st, hdr, sdp = self._read_response()
        if "401" in st:
            return False, "DESCRIBE -> 401 (needs --user/--pw)"
        if "200" not in st:
            return False, f"DESCRIBE -> {st}"
        if "content-base" in hdr:
            self.base = hdr["content-base"]

        # Parse SDP media sections -> control attrs, in order.
        controls = []
        cur = None
        for ln in sdp.splitlines():
            if ln.startswith("m="):
                cur = {"media": ln, "control": None}
                controls.append(cur)
            elif ln.startswith("a=control:") and cur is not None:
                cur["control"] = ln.split(":", 1)[1].strip()
        if not controls:
            return False, "DESCRIBE 200 but SDP had no media tracks"

        # SETUP each track. chan = TCP interleaved channel pair; for UDP we
        # bind a local socket per track and ask the server to send there.
        chan = 0
        cport = 50000
        set_up = 0
        udp_socks = {}      # channel -> udp socket (mode=udp)
        srv_transport = ""
        for c in controls:
            track_url = self._resolve_track_url(c["control"])
            if mode == "udp":
                us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                us.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    us.bind(("0.0.0.0", cport))
                except OSError:
                    cport += 2
                    us.bind(("0.0.0.0", cport))
                us.settimeout(1.0)
                transport = f"RTP/AVP;unicast;client_port={cport}-{cport+1}"
            else:
                transport = f"RTP/AVP/TCP;unicast;interleaved={chan}-{chan+1}"
            self._send("SETUP", track_url, [("Transport", transport)])
            try:
                st, hdr, _ = self._read_response()
            except OSError as e:
                return False, f"SETUP {track_url} -> {e}"
            if "200" not in st:
                if set_up == 0:
                    return False, f"SETUP {track_url} -> {st}"
                break
            if not srv_transport:
                srv_transport = hdr.get("transport", "")
            if "session" in hdr and not self.session:
                self.session = hdr["session"].split(";")[0].strip()
            if mode == "udp":
                udp_socks[chan] = us
            set_up += 1
            chan += 2
            cport += 2

        self._send("PLAY", self.base, [("Range", "npt=0.000-")])
        st, _, _ = self._read_response()
        if "200" not in st:
            return False, f"PLAY -> {st} [server Transport: {srv_transport}]"

        tnote = f" [server Transport: {srv_transport}]" if srv_transport else ""

        if mode == "udp":
            counts = {}
            pkts = 0
            deadline = time.time() + duration
            while time.time() < deadline:
                got = False
                for ch, us in udp_socks.items():
                    try:
                        pkt, _ = us.recvfrom(65535)
                    except socket.timeout:
                        continue
                    except OSError:
                        continue
                    if pkt:
                        counts[ch] = counts.get(ch, 0) + len(pkt)
                        pkts += 1
                        got = True
                if not got:
                    time.sleep(0.01)
            for us in udp_socks.values():
                us.close()
            vid = counts.get(0, 0)
            aud = counts.get(2, 0)
            if vid > 0:
                return True, (f"UDP RTP FLOWING: {pkts} pkts, video={vid} B, "
                              f"audio={aud} B{tnote}")
            if pkts > 0:
                return True, (f"UDP RTP on channels {sorted(counts)} "
                              f"({pkts} pkts){tnote}")
            return False, (f"PLAY 200 but NO UDP RTP arrived (firewall may block "
                           f"inbound UDP, or the server only streams over TCP){tnote}")

        # Read interleaved RTP for `duration` seconds; count bytes per channel.
        counts = {}
        pkts = 0
        deadline = time.time() + duration
        data = self.buf
        self.buf = b""
        while time.time() < deadline:
            # Need at least a 4-byte interleaved header: '$' chan len(2 BE).
            while len(data) < 4:
                try:
                    chunk = self.sock.recv(8192)
                except socket.timeout:
                    chunk = b""
                if not chunk:
                    break
                data += chunk
            if len(data) < 4 or data[0:1] != b"$":
                # Resync to next '$'.
                idx = data.find(b"$", 1)
                if idx < 0:
                    data = b""
                    try:
                        chunk = self.sock.recv(8192)
                    except socket.timeout:
                        chunk = b""
                    if not chunk:
                        break
                    data += chunk
                    continue
                data = data[idx:]
                continue
            ch = data[1]
            length = (data[2] << 8) | data[3]
            while len(data) < 4 + length:
                try:
                    chunk = self.sock.recv(8192)
                except socket.timeout:
                    chunk = b""
                if not chunk:
                    break
                data += chunk
            if len(data) < 4 + length:
                break
            counts[ch] = counts.get(ch, 0) + length
            pkts += 1
            data = data[4 + length:]

        vid = counts.get(0, 0)
        aud = counts.get(2, 0)
        if vid > 0:
            return True, (f"RTP FLOWING: {pkts} pkts, video={vid} B, audio={aud} B"
                          f"{tnote}")
        if pkts > 0:
            return True, (f"RTP flowing but only on channels {sorted(counts)} "
                          f"({pkts} pkts){tnote}")
        return False, f"PLAY 200 but NO interleaved RTP arrived{tnote}"


def play_mode(ip, port, paths, user, pw):
    """Walk paths over TCP then UDP; stop at first that actually streams RTP."""
    for mode, label in (("tcp", "TCP interleaved"), ("udp", "UDP (VLC default)")):
        print(f"\n=== Full RTSP play-test {ip}:{port} -- {label} ===")
        for path in paths:
            c = None
            try:
                c = RTSPClient(ip, port, path, user, pw)
                ok, msg = c.play_test(mode=mode)
            except OSError as e:
                ok, msg = False, f"<error: {e}>"
            finally:
                if c:
                    c.close()
            flag = "***" if ok else "   "
            print(f"  {flag} {path:42s} {msg}")
            if ok:
                xport = "tcp" if mode == "tcp" else "udp"
                print(f"\n  WORKING URL:  rtsp://{ip}:{port}{path}")
                print(f"  Transport:    {xport}  "
                      f"(OBS/ffmpeg: rtsp_transport={xport}; "
                      f"VLC: {'--rtsp-tcp ' if xport=='tcp' else ''}<url>)")
                return True
    print("\n  No path produced live RTP over TCP or UDP. The server answers "
          "DESCRIBE/SETUP/PLAY but never pushes media -- i.e. it's a stub, not a "
          "real stream. Common reasons: the camera only streams once you ENABLE "
          "ONVIF/RTSP in its companion app (often Settings -> Advanced -> ONVIF, "
          "which usually also sets a username/password -- then re-run with "
          "--user/--pw), or the device is cloud-only and the open 554 is a decoy. "
          "If ONLY the UDP pass failed, allow your Python through the firewall for "
          "inbound UDP.")
    return False


def probe_host(ip, user, pw):
    print(f"\n=== Probing {ip} ===")
    openp = []
    for p in PORTS:
        if tcp_open(ip, p, 0.5):
            openp.append(p)
    if not openp:
        print("  no candidate ports open.")
        return
    print(f"  open ports: {openp}")
    if 6668 in openp:
        print("  -> port 6668 open = likely a Tuya-based cam (local control channel).")
    for p in openp:
        if p in STREAM_HINT:
            probe_rtsp(ip, p, user, pw)
    if not any(p in STREAM_HINT for p in openp):
        print("  no RTSP-style port open here.")


def main():
    ap = argparse.ArgumentParser(
        prog="rtsp_finder.py",
        description="Find RTSP cameras on the LAN and verify the stream is real.")
    ap.add_argument("ip", nargs="?", help="camera IP (omit to scan local /24)")
    ap.add_argument("--user", help="RTSP/ONVIF username (if the camera asks)")
    ap.add_argument("--pw", help="RTSP/ONVIF password")
    ap.add_argument("--play", action="store_true",
                    help="do the FULL handshake (SETUP+PLAY, TCP then UDP) and "
                         "report whether real RTP actually flows")
    ap.add_argument("--path", help="test only this single RTSP path with --play")
    ap.add_argument("--port", type=int, default=554, help="RTSP port (default 554)")
    args = ap.parse_args()

    if args.play:
        if not args.ip:
            print("--play needs an IP, e.g. python rtsp_finder.py --play 192.168.1.50")
            return 1
        paths = [args.path] if args.path else RTSP_PATHS
        play_mode(args.ip, args.port, paths, args.user, args.pw)
        return 0

    if args.ip:
        probe_host(args.ip, args.user, args.pw)
        return 0

    me = local_ipv4()
    if not me:
        print("Could not determine local IP. Pass the camera IP explicitly.")
        return 1
    print(f"Local IP {me}; scanning {me.rsplit('.',1)[0]}.0/24 for cameras ...")
    t0 = time.time()
    found = scan_subnet(me)
    print(f"Scan done in {time.time()-t0:.1f}s. Candidates: "
          f"{list(found.keys()) or 'none'}")
    for ip in found:
        probe_host(ip, args.user, args.pw)
    if not found:
        print("\nNothing camera-ish found. Make sure the camera is powered on and "
              "on this same LAN, or pass its IP directly.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
