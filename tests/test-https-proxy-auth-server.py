#!/usr/bin/env python3
"""
Test server for HTTPS proxy authentication (Issue #711)

This script creates:
1. An HTTP proxy server that requires Basic authentication for CONNECT
2. An HTTPS target server

Usage: test-https-proxy-auth-server.py <proxy_port> <target_port> <certfile> <keyfile>
"""

import sys
import http.server
import ssl
import socketserver
import base64
import threading
import os
import signal
import socket
import select

PROXY_USERNAME = "testuser"
PROXY_PASSWORD = "testpass"
PROXY_CREDENTIALS = base64.b64encode(f"{PROXY_USERNAME}:{PROXY_PASSWORD}".encode()).decode()

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    """Simple CONNECT proxy that requires Basic authentication."""

    def log_message(self, format, *args):
        # Suppress logging
        pass

    def _send_auth_required(self):
        """Send 407 Proxy Authentication Required response."""
        self.send_response(407)
        self.send_header("Proxy-Authenticate", 'Basic realm="proxy"')
        self.send_header("Connection", "close")
        self.end_headers()

    def do_CONNECT(self):
        # Check and validate Proxy-Authorization header
        auth_header = self.headers.get("Proxy-Authorization", "")

        if not auth_header.startswith("Basic "):
            self._send_auth_required()
            return

        # Validate credentials
        provided_creds = auth_header.replace("Basic ", "", 1)
        if provided_creds != PROXY_CREDENTIALS:
            self._send_auth_required()
            return

        # Authentication successful - establish tunnel
        self.send_response(200, "Connection established")
        self.end_headers()

        # Parse target and connect
        host, port = self.path.split(':')
        target_sock = None

        try:
            target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_sock.connect((host, int(port)))
            self._tunnel(self.connection, target_sock)
        except (OSError, ValueError):
            pass
        finally:
            if target_sock:
                target_sock.close()

    def _tunnel(self, client_sock, target_sock):
        """Tunnel data between client and target."""
        sockets = [client_sock, target_sock]

        try:
            while True:
                readable, _, exceptional = select.select(sockets, [], sockets, 60.0)

                if exceptional or not readable:
                    break

                for sock in readable:
                    data = sock.recv(8192)
                    if not data:
                        return

                    other = target_sock if sock is client_sock else client_sock
                    other.sendall(data)
        except (OSError, ValueError):
            pass

class ThreadedHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

class TargetHandler(http.server.BaseHTTPRequestHandler):
    """Simple HTTPS target server."""

    def log_message(self, format, *args):
        pass  # Suppress logging

    def do_GET(self):
        content = b"Success: HTTPS proxy authentication working!\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

def run_proxy(port):
    """Run the proxy server."""
    server = ThreadedHTTPServer(("127.0.0.1", port), ProxyHandler)
    server.serve_forever()

def run_target(port, certfile, keyfile):
    """Run the HTTPS target server."""
    server = ThreadedHTTPServer(("127.0.0.1", port), TargetHandler)

    # Wrap with SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    server.serve_forever()

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print(f"Usage: {sys.argv[0]} <proxy_port> <target_port> <certfile> <keyfile>", file=sys.stderr)
        sys.exit(1)

    proxy_port = int(sys.argv[1])
    target_port = int(sys.argv[2])
    certfile = sys.argv[3]
    keyfile = sys.argv[4]

    # Verify cert files exist
    if not os.path.exists(certfile) or not os.path.exists(keyfile):
        print(f"Certificate files not found: {certfile} or {keyfile}", file=sys.stderr)
        sys.exit(1)

    # Start proxy in a thread
    proxy_thread = threading.Thread(target=run_proxy, args=(proxy_port,), daemon=True)
    proxy_thread.start()

    # Start target in a thread
    target_thread = threading.Thread(target=run_target, args=(target_port, certfile, keyfile), daemon=True)
    target_thread.start()

    # Print ready signal
    print(f"READY:{PROXY_USERNAME}:{PROXY_PASSWORD}")
    sys.stdout.flush()

    # Wait for signal
    signal.pause()
