import json
import os
import socket
import ssl
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import proxy  # noqa: E402
from tests.helpers import scratch_dir  # noqa: E402


def client_hello(server_name):
    """Real ClientHello bytes produced by the ssl module."""
    ctx = ssl.create_default_context()
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname=server_name)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


class NormalizeHost(unittest.TestCase):
    def test_names(self):
        self.assertEqual(proxy.normalize_host("GitHub.COM."), ("name", "github.com"))
        self.assertEqual(proxy.normalize_host("[::1]"), ("ip", "::1"))
        self.assertEqual(proxy.normalize_host("127.0.0.1"), ("ip", "127.0.0.1"))

    def test_rejects_hostile(self):
        for bad in ["", ".", "a..b", "0x7f.1", "2130706433", "127.1", "exa mple.com",
                    "<img src=x onerror=alert(1)>", "evil.com\r\nX: y", "exаmple.com",
                    "a" * 64 + ".com", "-a.com", "a.com:443", "*.github.com"]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                proxy.normalize_host(bad)


class AllowlistTest(unittest.TestCase):
    def setUp(self):
        self.allow = proxy.Allowlist(["github.com", "*.githubusercontent.com", "pypi.org:80",
                                      "10.1.2.3:8080"])

    def check(self, target, port=443):
        try:
            kind, host = proxy.normalize_host(target)
        except ValueError:
            return False
        return self.allow.allows(kind, host, port)

    def test_matching(self):
        self.assertTrue(self.check("github.com"))
        self.assertTrue(self.check("GITHUB.COM."))
        self.assertTrue(self.check("raw.githubusercontent.com"))
        self.assertTrue(self.check("pypi.org", 80))
        self.assertTrue(self.check("10.1.2.3", 8080))

    def test_not_matching(self):
        self.assertFalse(self.check("evil.com.github.com.attacker"))
        self.assertFalse(self.check("api.github.com"))  # exact entries don't cover subdomains
        self.assertFalse(self.check("githubusercontent.com"))  # wildcard is subdomains only
        self.assertFalse(self.check("xgithubusercontent.com"))
        self.assertFalse(self.check("github.com", 22))
        self.assertFalse(self.check("pypi.org", 443))
        self.assertFalse(self.check("127.0.0.1"))
        self.assertFalse(self.check("[::1]"))
        self.assertFalse(self.check("10.1.2.3", 443))

    def test_bad_entries(self):
        for bad in ["*.1.2.3.4", "github.com:0", "github.com:99999", "a b", 42, "*",
                    "github.com:٤٤٣", "github.com:²", "github.com:+443"]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                proxy.Allowlist([bad])


class LiveEntryCheck(unittest.TestCase):
    def test_canonical_form(self):
        for raw, want in [("GitHub.COM.", "github.com:443"), ("example.com:8080", "example.com:8080"),
                          ("*.Example.com", "*.example.com:443"), ("1.1.1.1", "1.1.1.1:443"),
                          ("[2606:4700:4700::1111]:443", "[2606:4700:4700::1111]:443"),
                          ("2606:4700:4700::1111", "[2606:4700:4700::1111]:443")]:
            with self.subTest(raw=raw):
                self.assertEqual(proxy.check_live_entry(raw), want)
                proxy.Allowlist([want])

    def test_refused(self):
        for bad in ["127.0.0.1", "127.0.0.1:631", "[::1]", "::1", "169.254.169.254", "10.0.0.1",
                    "[::ffff:127.0.0.1]", "*.com", "*.com.", "*", "*.1.2.3.4", "a b", "", 42, None,
                    "<img src=x onerror=alert(1)>", "evil.com\r\nX: y", "evil.com:0"]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                proxy.check_live_entry(bad)


class LiveAllowlistTest(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(scratch_dir(self), "live.json")
        self.events = []
        self.live = self.make(lambda: {"src": self.read()})

    def make(self, read_sources):
        live = proxy.LiveAllowlist(proxy.Allowlist(["base.test"]), [self.path], read_sources)
        live.log = lambda **event: self.events.append(event)
        return live

    def read(self):
        try:
            with open(self.path) as f:
                return json.load(f)
        except FileNotFoundError:
            return []
        except ValueError:
            return None

    def put(self, text):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            f.write(text)
        os.replace(tmp, self.path)

    def allows(self, host, port=443):
        return self.live.allows("name", host, port)

    def test_added_then_removed_without_restart(self):
        self.assertFalse(self.allows("new.test"))
        self.put('["new.test"]')
        self.assertTrue(self.allows("new.test"))
        self.assertFalse(self.allows("new.test", 80))
        self.assertFalse(self.allows("sub.new.test"))
        self.put('[]')
        self.assertFalse(self.allows("new.test"))
        self.assertTrue(self.allows("base.test"))
        self.assertEqual([e["entries"] for e in self.events], [["new.test:443"], []])

    def test_damaged_source_adds_nothing(self):
        for text in ['{broken', '{"a": 1}', '"new.test"', '["new.test", 42]', '["new.test", "a b"]',
                     '["new.test", "127.0.0.1"]', '["new.test", "*.com"]']:
            with self.subTest(text=text):
                self.put(text)
                self.assertFalse(self.allows("new.test"))
                self.assertTrue(self.allows("base.test"))
                self.live.refresh()
                self.assertTrue(self.live.problems)

    def test_deleted_file_revokes(self):
        self.put('["new.test"]')
        self.assertTrue(self.allows("new.test"))
        os.unlink(self.path)
        self.assertFalse(self.allows("new.test"))

    def test_one_bad_source_keeps_the_other(self):
        self.put('[]')
        live = self.make(lambda: {"bad": None, "good": ["new.test"]})
        self.assertTrue(live.allows("name", "new.test", 443))
        self.assertEqual(len(live.problems), 1)


class BlockedListTest(unittest.TestCase):
    def test_size_is_capped(self):
        path = os.path.join(scratch_dir(self), "blocked")
        blocked = proxy.BlockedList(path)
        for n in range(proxy.BLOCKED_LIMIT + 50):
            blocked.add(f"h{n}.test", 443, proxy.NOT_LISTED)
        with open(path) as f:
            lines = f.read().splitlines()
        self.assertEqual(len(lines), proxy.BLOCKED_LIMIT + 1)
        self.assertIn("truncated", lines[-1])

    def test_ipv6_stays_parseable(self):
        path = os.path.join(scratch_dir(self), "blocked")
        proxy.BlockedList(path).add("2001:db8::1", 443, proxy.NOT_LISTED)
        with open(path) as f:
            self.assertTrue(f.read().startswith("[2001:db8::1]:443\t"))


class LoggerTest(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(scratch_dir(self), "s.jsonl")
        self.now = [0.0]

    def make(self, **kw):
        return proxy.Logger(self.path, clock=lambda: self.now[0], **kw)

    def lines(self, suffix=""):
        try:
            with open(self.path + suffix) as f:
                return [json.loads(line) for line in f]
        except FileNotFoundError:
            return []

    def deny(self, log, host="a.test"):
        log(action="deny", host=host, port=443, reason=proxy.NOT_LISTED)

    def test_repeats_become_one_counted_line(self):
        log = self.make()
        for _ in range(5):
            self.deny(log)
        self.assertEqual(len(self.lines()), 1)
        log.flush()
        first, summary = self.lines()
        self.assertNotIn("repeated", first)
        self.assertEqual(summary["repeated"], 4)
        self.assertEqual({k: v for k, v in summary.items() if k not in ("ts", "repeated")},
                         {k: v for k, v in first.items() if k != "ts"})

    def test_flush_writes_pending_counts(self):
        log = self.make()
        self.deny(log)
        self.deny(log)
        self.now[0] = proxy.LOG_FLUSH_SECONDS - 1
        self.deny(log, "b.test")
        self.assertEqual(len(self.lines()), 2)  # not due yet
        self.now[0] = proxy.LOG_FLUSH_SECONDS
        log(action="exit", code=0)
        self.assertEqual([(e["action"], e.get("repeated")) for e in self.lines()],
                         [("deny", None), ("deny", None), ("deny", 1), ("exit", None)])

    def test_flush_twice_writes_once(self):
        log = self.make()
        self.deny(log)
        self.deny(log)
        log.flush()
        log.flush()
        self.assertEqual(len(self.lines()), 2)
        self.deny(log)  # counted again after a flush
        log.flush()
        self.assertEqual([e.get("repeated") for e in self.lines()], [None, 1, 1])

    def test_key_table_is_capped(self):
        log = self.make(keys=3)
        for host in "abcde":
            self.deny(log, f"{host}.test")
            self.deny(log, f"{host}.test")
        log.flush()
        self.assertEqual([(e["host"][0], e.get("repeated")) for e in self.lines()],
                         [("a", None), ("b", None), ("c", None), ("d", None), ("d", None),
                          ("e", None), ("e", None), ("a", 1), ("b", 1), ("c", 1)])
        self.assertEqual(len(log.counts), 3)

    def test_no_path_writes_nothing(self):
        log = proxy.Logger(None)
        log(action="exit", code=0)
        log.flush()


class CappedFileTest(unittest.TestCase):
    def test_capped_then_closed(self):
        path = os.path.join(scratch_dir(self), "list")
        capped = proxy.CappedFile(path, 2, "full\n")
        self.assertEqual([capped.write(f"{n}\n") for n in range(4)], [True, True, False, False])
        with open(path) as f:
            self.assertEqual(f.read(), "0\n1\nfull\n")

    def test_no_path_writes_nothing(self):
        self.assertFalse(proxy.CappedFile(None, 2, "full\n").write("x\n"))

    def test_never_follows_a_link(self):
        root = scratch_dir(self)
        target, link = os.path.join(root, "target"), os.path.join(root, "list")
        open(target, "w").close()
        os.symlink(target, link)
        proxy.CappedFile(link, 2, "full\n").write("x\n")
        self.assertEqual(os.path.getsize(target), 0)


class SniParser(unittest.TestCase):
    def test_real_client_hello(self):
        self.assertEqual(proxy.parse_client_hello_sni(client_hello("api.example.com")),
                         "api.example.com")

    def test_garbage(self):
        for data in [b"", b"GET / HTTP/1.1\r\n\r\n", b"\x16\x03\x01\x00\x05\x01",
                     client_hello("x.example.com")[:40], bytes(range(256))]:
            with self.subTest(data=data[:10]):
                self.assertIsNone(proxy.parse_client_hello_sni(data))


class Upstream:
    """TCP server on 127.0.0.1 recording what it receives and answering with a fixed reply."""

    def __init__(self, reply=b"pong"):
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.received = b""
        self.reply = reply
        self.done = threading.Event()
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        conn, _ = self.sock.accept()
        conn.settimeout(5)
        with conn:
            try:
                while data := conn.recv(65536):
                    self.received += data
                    if self.reply:
                        conn.sendall(self.reply)
                        self.reply = None
            except OSError:
                pass
        self.done.set()


class ProxyEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = scratch_dir(self)
        self.upstream = Upstream()
        self.sock_path = os.path.join(self.tmp, "proxy.sock")
        self.log_path = os.path.join(self.tmp, "log.jsonl")
        self.blocked_path = os.path.join(self.tmp, "blocked")
        open(self.blocked_path, "w").close()
        self.addrs = {"echo.test": ["127.0.0.1"], "rebind.test": ["127.0.0.1"]}

    def blocked(self):
        with open(self.blocked_path) as f:
            return f.read()

    def start(self, entries, allow_private=True, tls_ports=()):
        self.server = proxy.ProxyServer(
            proxy.Allowlist(entries), log_path=self.log_path,
            resolver=lambda host, port: self.addrs[host], allow_private=allow_private,
            tls_ports=tls_ports, blocked_path=self.blocked_path)
        self.server.start(self.sock_path)
        self.addCleanup(self.server.stop)

    def request(self, raw, then=b""):
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(5)
        s.connect(self.sock_path)
        s.sendall(raw)
        head = b""
        while b"\r\n\r\n" not in head:
            data = s.recv(4096)
            if not data:
                break
            head += data
        if then:
            s.sendall(then)
            s.shutdown(socket.SHUT_WR)
        rest = b""
        try:
            while data := s.recv(4096):
                rest += data
        except OSError:
            pass
        s.close()
        return head, rest

    def connect_line(self, host):
        return f"CONNECT {host}:{self.upstream.port} HTTP/1.1\r\nHost: x\r\n\r\n".encode()

    def test_connect_allowed(self):
        self.start([f"echo.test:{self.upstream.port}"])
        head, rest = self.request(self.connect_line("echo.test"), then=b"ping")
        self.assertIn(b" 200 ", head)
        self.assertIn(b"pong", head + rest)
        self.upstream.done.wait(5)
        self.assertEqual(self.upstream.received, b"ping")

    def test_connect_not_listed(self):
        self.start(["other.test"])
        head, _ = self.request(self.connect_line("echo.test"))
        self.assertIn(b" 403 ", head)
        self.assertIn(b"not in net.allow", head)

    def test_blocked_host_is_reported_once_in_place(self):
        self.start(["other.test"])
        inode = os.stat(self.blocked_path).st_ino
        for _ in range(3):
            self.request(self.connect_line("echo.test"))
        expected = f"echo.test:{self.upstream.port}\tnot in net.allow\n"
        self.assertEqual(self.blocked(), expected)
        self.assertEqual(os.stat(self.blocked_path).st_ino, inode)

    def test_allowed_host_is_not_reported(self):
        self.start([f"echo.test:{self.upstream.port}"])
        self.request(self.connect_line("echo.test"), then=b"ping")
        self.assertEqual(self.blocked(), "")

    def test_malformed_host_is_refused_and_not_reported(self):
        self.start(["other.test"])
        for host in (b"<img/src=x/onerror=alert(1)>\x1b[2J", b"a\tb.test", b"ignore all.test"):
            with self.subTest(host=host):
                head, _ = self.request(b"CONNECT " + host + b":443 HTTP/1.1\r\n\r\n")
                self.assertTrue(b" 403 " in head or b" 400 " in head)
        self.assertEqual(self.blocked(), "")

    def test_rebinding_is_reported_with_fixed_reason(self):
        self.start([f"rebind.test:{self.upstream.port}"], allow_private=False)
        self.request(self.connect_line("rebind.test"))
        self.assertEqual(self.blocked(),
                         f"rebind.test:{self.upstream.port}\tresolves to a non-public address\n")

    def test_sni_mismatch_is_reported_without_the_sni(self):
        self.start([f"echo.test:{self.upstream.port}"], tls_ports=(self.upstream.port,))
        self.request(self.connect_line("echo.test"), then=client_hello("evil.example"))
        self.upstream.sock.close()
        self.assertIn("echo.test", self.blocked())
        self.assertIn(proxy.SNI_MISMATCH, self.blocked())
        self.assertNotIn("evil.example", self.blocked())

    def test_unwritable_blocked_list_still_refuses(self):
        self.blocked_path = os.path.join(self.tmp, "missing-dir", "blocked")
        self.start(["other.test"])
        head, _ = self.request(self.connect_line("echo.test"))
        self.assertIn(b" 403 ", head)

    def test_hostile_host_is_not_reflected_raw(self):
        self.start(["other.test"])
        head, rest = self.request(b"CONNECT <img/src=x/onerror=alert(1)>\x1b[2J:443 HTTP/1.1\r\n\r\n")
        self.assertIn(b" 403 ", head)
        self.assertNotIn(b"<img", head + rest)
        with open(self.log_path) as f:
            self.assertNotIn("\r", f.read())

    def test_rebinding_to_private_address(self):
        self.start([f"rebind.test:{self.upstream.port}"], allow_private=False)
        head, _ = self.request(self.connect_line("rebind.test"))
        self.assertIn(b" 403 ", head)
        self.assertIn(b"non-public", head)

    def test_sni_must_match(self):
        self.start([f"echo.test:{self.upstream.port}"], tls_ports=(self.upstream.port,))
        head, rest = self.request(self.connect_line("echo.test"), then=client_hello("evil.example"))
        self.assertIn(b" 200 ", head)
        self.assertEqual(rest, b"")
        self.upstream.sock.close()
        self.assertEqual(self.upstream.received, b"")

    def test_sni_matching_passes_hello(self):
        self.start([f"echo.test:{self.upstream.port}"], tls_ports=(self.upstream.port,))
        hello = client_hello("echo.test")
        self.request(self.connect_line("echo.test"), then=hello)
        self.upstream.done.wait(5)
        self.assertEqual(self.upstream.received, hello)

    def test_non_tls_on_tls_port(self):
        self.start([f"echo.test:{self.upstream.port}"], tls_ports=(self.upstream.port,))
        _, rest = self.request(self.connect_line("echo.test"), then=b"GET / HTTP/1.1\r\n\r\n")
        self.assertEqual(rest, b"")

    def test_plain_http_forward(self):
        self.upstream.reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        self.start([f"echo.test:{self.upstream.port}"])
        req = (f"GET http://echo.test:{self.upstream.port}/a?b=1 HTTP/1.1\r\nHost: echo.test\r\n"
               "Proxy-Authorization: secret\r\nConnection: keep-alive\r\n\r\n").encode()
        head, rest = self.request(req)
        self.assertIn(b"200 OK", head)
        self.upstream.done.wait(5)
        sent = self.upstream.received.decode()
        self.assertTrue(sent.startswith("GET /a?b=1 HTTP/1.1\r\n"))
        self.assertNotIn("Proxy-Authorization", sent)
        self.assertIn("Connection: close", sent)

    def test_plain_http_host_comes_from_the_url(self):
        self.upstream.reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        self.start([f"echo.test:{self.upstream.port}"])
        req = (f"GET http://echo.test:{self.upstream.port}/ HTTP/1.1\r\nHost: evil.example\r\n"
               "HOST : evil.example\r\nAccept: */*\r\n\r\n").encode()
        self.request(req)
        self.upstream.done.wait(5)
        sent = self.upstream.received.decode()
        self.assertNotIn("evil", sent)
        self.assertIn(f"\r\nHost: echo.test:{self.upstream.port}\r\n", sent)
        self.assertIn("\r\nAccept: */*\r\n", sent)

    def test_plain_http_refuses_folded_headers(self):
        self.start([f"echo.test:{self.upstream.port}"])
        req = (f"GET http://echo.test:{self.upstream.port}/ HTTP/1.1\r\nX-A: 1\r\n"
               " Host: evil.example\r\n\r\n").encode()
        head, _ = self.request(req)
        self.assertIn(b" 400 ", head)

    def test_log_is_capped(self):
        self.start(["other.test"])
        self.server.log.limit = 2000
        for n in range(30):  # distinct hosts: repeats of one would only be counted
            self.request(self.connect_line(f"h{n}.test"))
        with open(self.log_path) as f:
            events = [json.loads(line) for line in f]
        self.assertLessEqual(os.path.getsize(self.log_path), 2000 + 100)  # + the last line
        self.assertEqual(events[-1]["action"], "log_truncated")
        self.assertEqual([e["action"] for e in events].count("log_truncated"), 1)

    def test_rejects_other_forms(self):
        self.start(["echo.test"])
        for raw in [b"GET https://echo.test/ HTTP/1.1\r\n\r\n", b"GET / HTTP/1.1\r\n\r\n",
                    b"CONNECT echo.test HTTP/1.1\r\n\r\n", b"garbage\r\n\r\n",
                    b"GET http://user:pw@echo.test/ HTTP/1.1\r\n\r\n"]:
            with self.subTest(raw=raw):
                head, _ = self.request(raw)
                self.assertIn(b" 400 ", head)

    def start_live(self, allow_private=True, tls_ports=()):
        self.live_path = os.path.join(self.tmp, "live.json")

        def read_sources():
            with open(self.live_path) as f:
                return {"live": json.load(f)}

        self.put_live([])
        live = proxy.LiveAllowlist(proxy.Allowlist([]), [self.live_path], read_sources)
        self.server = proxy.ProxyServer(
            live, log_path=self.log_path, resolver=lambda host, port: self.addrs[host],
            allow_private=allow_private, tls_ports=tls_ports)
        live.log = self.server.log
        self.server.start(self.sock_path)
        self.addCleanup(self.server.stop)

    def put_live(self, entries):
        tmp = self.live_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(entries, f)
        os.replace(tmp, self.live_path)

    def test_live_approval_and_revocation(self):
        self.start_live()
        entry = f"echo.test:{self.upstream.port}"
        head, rest = self.request(self.connect_line("echo.test"))
        self.assertIn(b" 403 ", head)
        self.assertIn(b"pithos allow", head + rest)
        self.put_live([entry])
        head, rest = self.request(self.connect_line("echo.test"), then=b"ping")
        self.assertIn(b" 200 ", head)
        self.assertIn(b"pong", head + rest)
        self.put_live([])
        head, _ = self.request(self.connect_line("echo.test"))
        self.assertIn(b" 403 ", head)
        self.server.log.flush()  # the second, identical denial is counted until a flush
        with open(self.log_path) as f:
            events = [json.loads(line) for line in f]
        self.assertEqual([e["entries"] for e in events if e["action"] == "live_allow"],
                         [[entry], []])
        self.assertEqual([(e["action"], e.get("repeated")) for e in events
                          if e.get("host") == "echo.test"],
                         [("deny", None), ("allow", None), ("deny", 1)])

    def test_live_host_still_needs_a_public_address(self):
        self.start_live(allow_private=False)
        self.put_live([f"rebind.test:{self.upstream.port}"])
        head, _ = self.request(self.connect_line("rebind.test"))
        self.assertIn(b" 403 ", head)
        self.assertIn(b"non-public", head)

    def test_live_host_still_needs_matching_sni(self):
        self.start_live(tls_ports=(self.upstream.port,))
        self.put_live([f"echo.test:{self.upstream.port}"])
        _, rest = self.request(self.connect_line("echo.test"), then=client_hello("evil.example"))
        self.assertEqual(rest, b"")
        self.upstream.sock.close()
        self.assertEqual(self.upstream.received, b"")

    def test_header_too_large(self):
        self.start(["echo.test"])
        head, _ = self.request(b"CONNECT echo.test:443 HTTP/1.1\r\nX: " + b"a" * 20000 + b"\r\n\r\n")
        self.assertIn(b" 431 ", head)


if __name__ == "__main__":
    unittest.main()
