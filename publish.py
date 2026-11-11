# SPDX-License-Identifier: GPL-3.0-or-later
"""--publish: a TCP port on the host that reaches a server inside the sandbox.

The host accepts the connection and checks the first request head. It then sends a random
token on the control channel (a SEQPACKET socketpair whose other end only bridge.py holds).
The bridge connects to the server inside, then to publish.sock with the token and one status
byte, and the host relays the two. Only bytes cross into the sandbox, never host sockets.

The token pairs the two halves of a connection; it is not a secret. The agent runs as the same
user as the bridge and can take its fds, but a token only hands it a connection its own server
would get anyway.
"""

import ipaddress
import os
import re
import secrets
import socket
import threading
import time

from config import ConfigError, clean

TOKEN_LEN = 16
HEAD_LIMIT = 16 * 1024
HEAD_TIMEOUT = 10
PAIR_TIMEOUT = 10
PENDING_MAX = 64  # connections waiting for the bridge
CONNECTIONS_MAX = 128  # open connections; each takes two threads in the launcher
REFUSED_LOG_MAX = 200  # a flood from the LAN must not fill the session log
STATUS_OK, STATUS_REFUSED = b"1", b"0"

LOOPBACK_NAMES = ("localhost", "127.0.0.1", "::1")
PORT = re.compile(r"[1-9][0-9]{0,4}")
SPEC = re.compile(r"(?:\[(?P<v6>[0-9a-fA-F:.]+)\]|(?P<v4>[0-9.]+)):(?P<port>[^:]*)")
REQUEST_LINE = re.compile(r"[A-Z]+ /\S* HTTP/1\.[01]")


def parse_spec(value, reserved=()):
    """(address, port) from "PORT", "IPv4:PORT" or "[IPv6]:PORT". The address must be one IP
    that browsers can name in a Host header: no names, no wildcard, no multicast."""
    addr, port = "127.0.0.1", value
    if not PORT.fullmatch(value):
        m = SPEC.fullmatch(value)
        if not m:
            raise ConfigError(f"--publish: expected PORT or IP:PORT, got {clean(value)!r}")
        addr, port = m["v6"] or m["v4"], m["port"]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            raise ConfigError(f"--publish: {clean(addr)!r} is not an IP address")
        if (ip.version == 6) != bool(m["v6"]):
            raise ConfigError("--publish: write IPv6 addresses as [ADDR]:PORT")
        if ip.is_unspecified or ip.is_multicast:
            raise ConfigError(f"--publish: {addr} is not a single address; give the one to "
                              "listen on, e.g. 192.168.1.10:4096")
        addr = str(ip)
    if not PORT.fullmatch(port) or int(port) > 65535:
        raise ConfigError(f"--publish: bad port {clean(port)!r}")
    if int(port) in reserved:
        raise ConfigError(f"--publish: port {port} is the sandbox's proxy port; pick another")
    return addr, int(port)


def is_loopback(addr):
    return ipaddress.ip_address(addr).is_loopback


def allowed_names(addr):
    return frozenset((*LOOPBACK_NAMES, addr))


def _host_name(value):
    """The name in a Host header value, without the port; None if malformed."""
    m = re.fullmatch(r"(?:\[([0-9a-fA-F:.]+)\]|([A-Za-z0-9.-]+))(?::[0-9]{1,5})?", value)
    return (m[1] or m[2]).lower() if m else None


def refusal(head, names):
    """Why this request head must not reach the sandbox, or None. A browser keeps separate
    connections per top-level site, so checking a connection's first request is enough."""
    lines = head.decode("latin-1").split("\r\n")
    if not REQUEST_LINE.fullmatch(lines[0]):
        return "not an HTTP request to a path"
    headers = {}
    for line in lines[1:]:
        if line:
            name, _, value = line.partition(":")
            headers.setdefault(name.strip().lower(), []).append(value.strip())
    hosts = headers.get("host", [])
    if len(hosts) != 1 or _host_name(hosts[0]) not in names:
        return "Host is not this machine (DNS rebinding?)"
    origins = headers.get("origin", [])
    if len(origins) > 1 or origins and origins[0].lower() != "http://" + hosts[0].lower():
        return "cross-origin request"
    sites = headers.get("sec-fetch-site", [])
    if len(sites) > 1 or sites and sites[0] not in ("same-origin", "none"):
        return "cross-site request"
    return None


def _respond(conn, status, reason):
    body = f"pithos: {reason}\n".encode()
    try:
        conn.sendall(f"HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\n"
                     f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
    except OSError:
        pass


def _read_head(conn):
    """The request head up to and including the blank line, plus anything after it.
    HEAD_TIMEOUT is for the whole head: a byte every few seconds must not hold a slot."""
    deadline = time.monotonic() + HEAD_TIMEOUT
    data = b""
    while b"\r\n\r\n" not in data:
        if len(data) > HEAD_LIMIT:
            raise OverflowError
        left = deadline - time.monotonic()
        if left <= 0:
            raise socket.timeout
        conn.settimeout(left)
        chunk = conn.recv(4096)
        if not chunk:
            raise ConnectionError
        data += chunk
    return data


def _pump(src, dst):
    try:
        while data := src.recv(65536):
            dst.sendall(data)
        dst.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def relay(a, b):
    t = threading.Thread(target=_pump, args=(b, a), daemon=True)
    t.start()
    _pump(a, b)
    t.join()


class _Pending:
    def __init__(self):
        self.ready = threading.Event()
        self.upstream = None
        self.ok = False


class PublishServer:
    def __init__(self, addr, port, socket_path, log=None):
        self.addr, self.port, self.socket_path = addr, port, socket_path
        self.log = log or (lambda **event: None)
        self.names = allowed_names(addr)
        self.lock = threading.Lock()
        self.pending = {}
        self.open = set()
        self.refused = 0
        self.listener = self.unix = self.ctrl = None

    def start(self):
        """Listen; returns the sandbox's end of the control channel, for bwrap's pass_fds."""
        family = socket.AF_INET6 if ":" in self.addr else socket.AF_INET
        try:
            self.listener = socket.create_server((self.addr, self.port), family=family,
                                                 backlog=128)
        except OSError as e:
            raise ConfigError(f"--publish: can't listen on {self.addr}:{self.port}: {e.strerror}")
        self.port = self.listener.getsockname()[1]
        self.unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.unix.bind(self.socket_path)
        self.unix.listen(128)
        self.ctrl, sandbox_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.ctrl.setblocking(False)
        threading.Thread(target=self._accept_tcp, name="pithos-publish", daemon=True).start()
        threading.Thread(target=self._accept_unix, name="pithos-publish-sock", daemon=True).start()
        return sandbox_end.detach()

    def stop(self):
        for sock in (self.listener, self.unix, self.ctrl):
            if sock:
                try:
                    sock.shutdown(socket.SHUT_RDWR)  # close() alone doesn't wake accept()
                except OSError:
                    pass
                sock.close()
        with self.lock:
            for conn in list(self.open):
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    # -- browser side -------------------------------------------------------

    def _accept_tcp(self):
        while True:
            try:
                conn, peer = self.listener.accept()
            except OSError:
                return
            with self.lock:
                full = len(self.open) >= CONNECTIONS_MAX
                if not full:
                    self.open.add(conn)
            if full:
                _respond(conn, 503, "too many connections")
                conn.close()
                continue
            threading.Thread(target=self._serve, args=(conn, peer[0]), daemon=True).start()

    def _refuse(self, conn, peer, status, reason):
        _respond(conn, status, reason)
        with self.lock:
            self.refused += 1
            logged = self.refused <= REFUSED_LOG_MAX
        if logged:
            self.log(action="publish-refused", peer=peer, port=self.port, status=status,
                     reason=reason)

    def _serve(self, conn, peer):
        upstream = None
        try:
            try:
                data = _read_head(conn)
            except OverflowError:
                return self._refuse(conn, peer, 431, "request head too large")
            except socket.timeout:
                return self._refuse(conn, peer, 408, "request head too slow")
            except (ConnectionError, OSError):
                return
            why = refusal(data.split(b"\r\n\r\n", 1)[0], self.names)
            if why:
                return self._refuse(conn, peer, 403, why)
            upstream = self._pair(conn, peer)
            if upstream:
                conn.settimeout(None)
                upstream.sendall(data)
                relay(conn, upstream)
        except OSError:
            pass
        finally:
            with self.lock:
                self.open.discard(conn)
            if upstream:
                upstream.close()
            conn.close()

    def _pair(self, conn, peer):
        """Ask the bridge for a connection to the server inside; the upstream socket or None."""
        token = secrets.token_bytes(TOKEN_LEN)
        slot = _Pending()
        with self.lock:
            if len(self.pending) >= PENDING_MAX:
                slot = None
            else:
                self.pending[token] = slot
        if slot is None:
            self._refuse(conn, peer, 503, "too many connections waiting for the sandbox")
            return None
        try:
            self.ctrl.send(token)  # one message: whole or not at all
            slot.ready.wait(PAIR_TIMEOUT)
        except OSError:
            pass
        with self.lock:  # after this, _claim can no longer hand this slot a socket
            self.pending.pop(token, None)
        if slot.upstream is None:
            self._refuse(conn, peer, 504, "the sandbox did not answer")
            return None
        if not slot.ok:
            slot.upstream.close()
            self._refuse(conn, peer, 502, "nothing is listening on that port in the sandbox")
            return None
        slot.upstream.settimeout(None)
        return slot.upstream

    # -- sandbox side -------------------------------------------------------

    def _accept_unix(self):
        while True:
            try:
                conn, _ = self.unix.accept()
            except OSError:
                return
            with self.lock:
                full = len(self.open) >= CONNECTIONS_MAX
                if not full:
                    self.open.add(conn)
            if full:
                conn.close()
                continue
            threading.Thread(target=self._claim, args=(conn,), daemon=True).start()

    def _claim(self, conn):
        """Hand an incoming sandbox connection to the browser connection its token names."""
        slot = None
        try:
            conn.settimeout(PAIR_TIMEOUT)
            data = b""
            while len(data) < TOKEN_LEN + 1:
                chunk = conn.recv(TOKEN_LEN + 1 - len(data))
                if not chunk:
                    break
                data += chunk
            with self.lock:
                if len(data) == TOKEN_LEN + 1:
                    slot = self.pending.pop(data[:TOKEN_LEN], None)
                if slot:
                    slot.upstream, slot.ok = conn, data[TOKEN_LEN:] == STATUS_OK
        except OSError:
            pass
        finally:
            with self.lock:
                self.open.discard(conn)
        if slot is None:
            conn.close()
            return
        slot.ready.set()
