# SPDX-License-Identifier: GPL-3.0-or-later
"""Allowlisting HTTP proxy: the only network exit of the sandbox.

Listens on a UNIX socket (bound into the sandbox) and accepts two request forms:
  CONNECT host:port   -> TCP tunnel; on TLS ports the ClientHello SNI must equal host
  GET http://host/... -> plain HTTP forward (only for hosts listed with port 80)
Anything else is refused. TLS is never terminated: the proxy only sees host names.
"""

import asyncio
import ipaddress
import json
import os
import re
import socket
import threading
import time
import urllib.parse

HEADER_LIMIT = 16 * 1024
HEADER_TIMEOUT = 30
MAX_CONNECTIONS = 256
TLS_RECORD_LIMIT = 16384 + 2048
NOT_LISTED = "not in net.allow"
NON_PUBLIC = "resolves to a non-public address"
SNI_MISMATCH = "TLS SNI does not match the CONNECT host"
BLOCKED_LIMIT = 200

_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


class Denied(Exception):
    def __init__(self, status, reason):
        super().__init__(reason)
        self.status = status
        self.reason = reason


def normalize_host(raw):
    """Return ("ip", text) or ("name", text) for a host, or raise ValueError.

    Names are lower-cased, lose one trailing dot and must end in a label starting
    with a letter, so numeric tricks like "0x7f.1" or "2130706433" are rejected.
    """
    if not isinstance(raw, str) or not raw:
        raise ValueError("empty host")
    host = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
    try:
        return "ip", str(ipaddress.ip_address(host))
    except ValueError:
        pass
    host = host.lower()
    if host.endswith("."):
        host = host[:-1]
    if not host or len(host) > 253 or not host.isascii():
        raise ValueError("invalid host name")
    labels = host.split(".")
    if not all(_LABEL.match(label) for label in labels):
        raise ValueError("invalid host name")
    if not labels[-1][0].isalpha():
        raise ValueError("numeric top-level label")
    return "name", host


def split_host_port(target, default_port=None):
    """Split "host:port" / "[v6]:port" / "host" into (host, port)."""
    if target.startswith("["):
        end = target.find("]")
        if end < 0:
            raise ValueError("unterminated IPv6 literal")
        host, rest = target[: end + 1], target[end + 1 :]
        if rest and not rest.startswith(":"):
            raise ValueError("garbage after IPv6 literal")
        port = rest[1:] if rest else None
    elif target.count(":") == 1:
        host, port = target.split(":")
    elif ":" in target:
        host, port = target, None  # bare IPv6 without brackets
    else:
        host, port = target, None
    if port is None:
        if default_port is None:
            raise ValueError("missing port")
        return host, default_port
    if not (port.isascii() and port.isdigit()) or not 0 < int(port) < 65536:
        raise ValueError("invalid port")
    return host, int(port)


class Allowlist:
    """Entries: "host[:port]", "*.suffix[:port]" or "ip[:port]"; port defaults to 443."""

    def __init__(self, entries):
        self.exact = set()  # (kind, host, port)
        self.suffixes = set()  # (suffix, port)
        for entry in entries:
            if not isinstance(entry, str):
                raise ValueError(f"net.allow entry must be a string: {entry!r}")
            host, port = split_host_port(entry, default_port=443)
            if host.startswith("*."):
                kind, suffix = normalize_host(host[2:])
                if kind != "name":
                    raise ValueError(f"wildcard needs a host name: {entry!r}")
                self.suffixes.add((suffix, port))
            else:
                kind, value = normalize_host(host)
                self.exact.add((kind, value, port))

    def allows(self, kind, host, port):
        if (kind, host, port) in self.exact:
            return True
        if kind != "name":
            return False
        return any(port == p and host.endswith("." + s) for s, p in self.suffixes)


def _is_public(ip_text):
    ip = ipaddress.ip_address(ip_text)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def live_entry(host, port):
    """Format an allowlist entry; IPv6 needs brackets to parse back as host and port."""
    return f"[{host}]:{port}" if ":" in str(host) else f"{host}:{port}"


def check_live_entry(entry):
    """Return the canonical form of an entry approved during a session, or raise ValueError.

    Stricter than profiles: a sandbox can provoke a denial and then ask for approval, so a
    host-loopback or metadata address must be listed in a profile on purpose.
    """
    if not isinstance(entry, str):
        raise ValueError(f"entry must be a string: {entry!r}")
    host, port = split_host_port(entry, default_port=443)
    Allowlist([entry])  # same syntax rules as a profile
    if host.startswith("*."):
        suffix = normalize_host(host[2:])[1]
        if "." not in suffix:
            raise ValueError(f"wildcard is too broad: {entry!r}")
        return f"*.{suffix}:{port}"
    kind, value = normalize_host(host)
    if kind == "ip" and not _is_public(value):
        raise ValueError(f"non-public address {value}: list it in a profile if you mean it")
    return live_entry(value, port)


class LiveAllowlist:
    """A fixed Allowlist plus entries approved while the session runs.

    read_sources() returns {source name: list of entries, or None if unreadable}. It is called
    only when one of the watched files changes, so approvals and revocations apply to the next
    connection. A source that is unreadable or holds a bad entry adds nothing.
    """

    def __init__(self, base, watched, read_sources):
        self.base = base
        self.watched = watched
        self.read_sources = read_sources
        self.log = lambda **event: None
        self.signature = None
        self.entries = []
        self.problems = []
        self.current = Allowlist([])

    def _signature(self):
        out = []
        for path in self.watched:
            try:
                st = os.stat(path)
                out.append((st.st_ino, st.st_mtime_ns, st.st_size))
            except OSError:
                out.append(None)
        return out

    def refresh(self):
        signature = self._signature()  # taken before reading: a later write is seen next time
        if signature == self.signature:
            return
        self.signature = signature
        entries, problems = [], []
        for source, values in self.read_sources().items():
            try:
                if not isinstance(values, list):
                    raise ValueError("unreadable or not a list")
                entries += [check_live_entry(value) for value in values]
            except ValueError as e:
                problems.append(f"ignoring {source}: {e}")
        entries = list(dict.fromkeys(entries))
        if entries != self.entries or problems != self.problems:
            self.log(action="live_allow", entries=entries, problems=problems)
        self.entries, self.problems = entries, problems
        self.current = Allowlist(entries)

    def allows(self, kind, host, port):
        if self.base.allows(kind, host, port):
            return True
        self.refresh()
        return self.current.allows(kind, host, port)


def parse_client_hello_sni(record):
    """Return the SNI host name from a TLS record holding a ClientHello, else None."""
    try:
        if len(record) < 5 or record[0] != 0x16:
            return None
        rec_len = int.from_bytes(record[3:5], "big")
        body = record[5 : 5 + rec_len]
        if len(body) < rec_len or body[0] != 0x01:
            return None
        hs_len = int.from_bytes(body[1:4], "big")
        hello = body[4 : 4 + hs_len]
        if len(hello) < hs_len:
            return None  # ClientHello split over several records: refuse
        pos = 2 + 32  # client_version, random
        pos += 1 + hello[pos]  # session_id
        pos += 2 + int.from_bytes(hello[pos : pos + 2], "big")  # cipher_suites
        pos += 1 + hello[pos]  # compression_methods
        ext_end = pos + 2 + int.from_bytes(hello[pos : pos + 2], "big")
        pos += 2
        if ext_end > len(hello):
            return None
        while pos + 4 <= ext_end:
            ext_type = int.from_bytes(hello[pos : pos + 2], "big")
            ext_len = int.from_bytes(hello[pos + 2 : pos + 4], "big")
            data = hello[pos + 4 : pos + 4 + ext_len]
            pos += 4 + ext_len
            if ext_type != 0:
                continue
            # server_name_list: len(2) then entries type(1) len(2) name
            p = 2
            while p + 3 <= len(data):
                name_type = data[p]
                name_len = int.from_bytes(data[p + 1 : p + 3], "big")
                name = data[p + 3 : p + 3 + name_len]
                p += 3 + name_len
                if name_type == 0 and len(name) == name_len:
                    return name.decode("ascii")
            return None
        return None
    except (IndexError, UnicodeDecodeError):
        return None


class Logger:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()

    def __call__(self, **event):
        if self.path is None:
            return
        event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **event}
        line = json.dumps(event, ensure_ascii=True) + "\n"
        with self.lock, open(self.path, "a", encoding="ascii") as f:
            f.write(line)


def append_line(path, line):
    """Append to a file bound into the sandbox. It is appended to in place, never replaced: the
    bind pins the inode. A failed write loses only the notice, never what it reports on."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
    except OSError:
        pass


class CappedFile:
    """A notice file for the agent: at most `limit` lines, then `closing` once. A path of None
    writes nothing."""

    def __init__(self, path, limit, closing):
        self.path, self.limit, self.closing = path, limit, closing
        self.lines = 0
        self.closed = path is None

    def write(self, line):
        """Append line; False if it was not written because the file is full."""
        if self.closed:
            return False
        if self.lines >= self.limit:
            self.closed = True
            append_line(self.path, self.closing)
            return False
        self.lines += 1
        append_line(self.path, line)
        return True


class BlockedList:
    """The hosts refused this session, one "host:port<TAB>reason" line each, for the agent.

    The sandbox picks these names and an agent reads them: callers pass only normalized hosts
    and fixed reasons.
    """

    def __init__(self, path):
        self.file = CappedFile(path, BLOCKED_LIMIT, "list truncated, the user can see the rest "
                                                    "with: pithos log --denied\n")
        self.seen = set()

    def add(self, host, port, reason):
        if (host, port) not in self.seen and \
                self.file.write(f"{live_entry(host, port)}\t{reason}\n"):
            self.seen.add((host, port))


class ProxyServer:
    """Runs the proxy event loop in a background thread."""

    def __init__(self, allowlist, log_path=None, resolver=None, allow_private=False,
                 tls_ports=(443,), blocked_path=None):
        self.allowlist = allowlist
        self.log = Logger(log_path)
        self.blocked = BlockedList(blocked_path)
        self.resolver = resolver  # tests only: callable(host, port) -> [ip, ...]
        self.allow_private = allow_private  # tests only
        self.tls_ports = set(tls_ports)
        self.loop = None
        self.thread = None
        self.server = None

    # -- lifecycle ---------------------------------------------------------

    def start(self, socket_path):
        ready = threading.Event()
        errors = []

        def run():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            try:
                self.server = self.loop.run_until_complete(asyncio.start_unix_server(
                    self._handle, path=socket_path, limit=HEADER_LIMIT))
            except Exception as e:  # surfaced to the caller below
                errors.append(e)
                self.loop.close()
                self.loop = None
                ready.set()
                return
            self.semaphore = asyncio.Semaphore(MAX_CONNECTIONS)
            ready.set()
            self.loop.run_forever()
            self.loop.close()

        self.thread = threading.Thread(target=run, name="pithos-proxy", daemon=True)
        self.thread.start()
        ready.wait()
        if errors:
            raise errors[0]

    def stop(self):
        if self.loop is None:
            return

        async def shutdown():
            self.server.close()
            tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        asyncio.run_coroutine_threadsafe(shutdown(), self.loop).result(timeout=5)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(timeout=5)

    # -- request handling --------------------------------------------------

    async def _handle(self, reader, writer):
        async with self.semaphore:
            try:
                await self._serve(reader, writer)
            except Denied as e:
                await self._respond(writer, e.status, e.reason)
            except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError):
                pass
            finally:
                writer.close()

    async def _serve(self, reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEADER_TIMEOUT)
        except asyncio.LimitOverrunError:
            raise Denied(431, "request header too large")
        lines = head.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
            raise Denied(400, "malformed request line")
        method, target, version = parts
        if method == "CONNECT":
            await self._connect(reader, writer, target)
        elif target.lower().startswith("http://"):
            await self._forward_http(reader, writer, method, target, version, lines[1:])
        else:
            raise Denied(400, "only CONNECT and http:// absolute URIs are supported")

    def _check(self, raw_host, port):
        try:
            kind, host = normalize_host(raw_host)
        except ValueError as e:
            self.log(action="deny", host=raw_host[:255], port=port, reason=str(e))
            raise Denied(403, f"{e}")
        if not self.allowlist.allows(kind, host, port):
            self.log(action="deny", host=host, port=port, reason=NOT_LISTED)
            self.blocked.add(host, port, NOT_LISTED)
            raise Denied(403, f"{host}:{port} is {NOT_LISTED}; "
                              "to approve it, run `pithos allow` outside the sandbox")
        return kind, host

    async def _open_upstream(self, kind, host, port):
        if kind == "ip":
            addrs = [host]  # listed explicitly: no public-address check
        else:
            try:
                if self.resolver:
                    addrs = self.resolver(host, port)
                else:
                    infos = await asyncio.get_running_loop().getaddrinfo(
                        host, port, type=socket.SOCK_STREAM)
                    addrs = list(dict.fromkeys(info[4][0] for info in infos))
            except OSError as e:
                self.log(action="deny", host=host, port=port, reason=f"resolve failed: {e}")
                raise Denied(502, f"cannot resolve {host}")
            bad = [a for a in addrs if not _is_public(a)]
            if bad and not self.allow_private:
                self.log(action="deny", host=host, port=port, reason=f"non-public address {bad[0]}")
                self.blocked.add(host, port, NON_PUBLIC)
                raise Denied(403, f"{host} resolves to a non-public address")
        last = None
        for addr in addrs:
            try:
                return await asyncio.wait_for(asyncio.open_connection(addr, port), HEADER_TIMEOUT)
            except (OSError, asyncio.TimeoutError) as e:
                last = e
        self.log(action="error", host=host, port=port, reason=f"connect failed: {last}")
        raise Denied(502, f"cannot connect to {host}:{port}")

    async def _connect(self, reader, writer, target):
        try:
            raw_host, port = split_host_port(target)
        except ValueError as e:
            raise Denied(400, str(e))
        kind, host = self._check(raw_host, port)
        up_reader, up_writer = await self._open_upstream(kind, host, port)
        try:
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()
            first = b""
            if port in self.tls_ports and kind == "name":
                first = await asyncio.wait_for(self._read_tls_record(reader), HEADER_TIMEOUT)
                sni = parse_client_hello_sni(first)
                try:
                    sni_norm = normalize_host(sni)[1] if sni else None
                except ValueError:
                    sni_norm = None
                if sni_norm != host:
                    self.log(action="deny", host=host, port=port,
                             reason=f"TLS SNI {str(sni)[:255]!r} does not match")
                    self.blocked.add(host, port, SNI_MISMATCH)
                    return
            self.log(action="allow", host=host, port=port)
            up_writer.write(first)
            await self._pipe_both(reader, writer, up_reader, up_writer)
        finally:
            up_writer.close()

    async def _read_tls_record(self, reader):
        header = await reader.readexactly(5)
        length = int.from_bytes(header[3:5], "big")
        if header[0] != 0x16 or length > TLS_RECORD_LIMIT:
            return header
        return header + await reader.readexactly(length)

    async def _forward_http(self, reader, writer, method, target, version, header_lines):
        try:
            url = urllib.parse.urlsplit(target)
            raw_host, port = url.hostname or "", url.port or 80
        except ValueError as e:
            raise Denied(400, str(e))
        if url.username or url.password:
            raise Denied(400, "credentials in URL are not supported")
        kind, host = self._check(raw_host, port)
        up_reader, up_writer = await self._open_upstream(kind, host, port)
        try:
            path = url.path or "/"
            if url.query:
                path += "?" + url.query
            kept = [h for h in header_lines if h and not h.lower().startswith(
                ("proxy-", "connection:", "keep-alive:"))]
            head = "\r\n".join([f"{method} {path} {version}", *kept, "Connection: close", "", ""])
            self.log(action="allow", host=host, port=port, method=method)
            up_writer.write(head.encode("latin-1"))
            await self._pipe_both(reader, writer, up_reader, up_writer)
        finally:
            up_writer.close()

    async def _pipe_both(self, r1, w1, r2, w2):
        async def pipe(r, w):
            try:
                while data := await r.read(65536):
                    w.write(data)
                    await w.drain()
                if w.can_write_eof():
                    w.write_eof()
            except (ConnectionError, OSError):
                w.close()

        await asyncio.gather(pipe(r1, w2), pipe(r2, w1))

    async def _respond(self, writer, status, reason):
        text = {400: "Bad Request", 403: "Forbidden", 431: "Request Header Fields Too Large",
                502: "Bad Gateway"}.get(status, "Error")
        body = f"pithos: {reason}\n".encode("ascii", "replace")
        try:
            writer.write(f"HTTP/1.1 {status} {text}\r\nContent-Type: text/plain\r\n"
                         f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                         + body)
            await writer.drain()
        except (ConnectionError, OSError):
            pass
