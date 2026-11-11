import os
import socket
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bridge  # noqa: E402
import publish  # noqa: E402
from config import ConfigError  # noqa: E402
from tests.helpers import scratch_dir  # noqa: E402

NAMES = publish.allowed_names("127.0.0.1")


def head(*lines, request="GET / HTTP/1.1"):
    return ("\r\n".join((request, *lines)) + "\r\n\r\n").encode("latin-1")


class ParseSpec(unittest.TestCase):
    def test_port_alone_is_loopback(self):
        self.assertEqual(publish.parse_spec("4096", reserved=(3128,)), ("127.0.0.1", 4096))

    def test_addresses(self):
        self.assertEqual(publish.parse_spec("192.168.1.107:4096"), ("192.168.1.107", 4096))
        self.assertEqual(publish.parse_spec("[::1]:4096"), ("::1", 4096))
        self.assertEqual(publish.parse_spec("127.0.0.1:1"), ("127.0.0.1", 1))
        self.assertEqual(publish.parse_spec("65535"), ("127.0.0.1", 65535))

    def test_hostile_values(self):
        for value in ("", "0", "65536", "99999999999", "+4096", "-1", "4096 ", " 4096", "0x10",
                      "٤٠٩٦", "localhost:4096", "example.com:80",
                      "0.0.0.0:4096", "[::]:4096", "224.0.0.1:4096", "1.2.3.4", "1.2.3.4:",
                      "[::1]", "::1:4096", "[::1]4096", "[localhost]:4096", "1.2.3:4096",
                      "1.2.3.4:4096:1", "opencode", "4096\n"):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                publish.parse_spec(value)

    def test_reserved_port_is_refused(self):
        for value in ("3128", "127.0.0.1:3128", "[::1]:3128"):
            with self.subTest(value=value), self.assertRaisesRegex(ConfigError, "proxy"):
                publish.parse_spec(value, reserved=(3128,))

    def test_loopback(self):
        self.assertTrue(publish.is_loopback("127.0.0.1"))
        self.assertTrue(publish.is_loopback("::1"))
        self.assertFalse(publish.is_loopback("192.168.1.107"))


class Refusal(unittest.TestCase):
    def test_same_origin_requests_pass(self):
        for h in (head("Host: localhost:4096"),
                  head("host: localhost:8080"),  # ssh -L 8080:localhost:4096
                  head("Host: 127.0.0.1:4096", "Sec-Fetch-Site: same-origin"),
                  head("Host: [::1]:4096", "Sec-Fetch-Site: none"),
                  head("Host: LOCALHOST:4096"),
                  head("Host: localhost"),
                  head("Host: localhost:4096", "Origin: http://localhost:4096"),
                  head("Host: localhost:4096", request="POST /session HTTP/1.1"),
                  head("Host: localhost:4096", "Upgrade: websocket",
                       "Origin: http://localhost:4096", request="GET /ws HTTP/1.1")):
            with self.subTest(head=h):
                self.assertIsNone(publish.refusal(h, NAMES))

    def test_bind_address_is_a_valid_host(self):
        names = publish.allowed_names("192.168.1.107")
        self.assertIsNone(publish.refusal(head("Host: 192.168.1.107:4096"), names))
        self.assertIsNotNone(publish.refusal(head("Host: 192.168.1.108:4096"), names))

    def test_hostile_requests_are_refused(self):
        for h in (head("Host: evil.com:4096"),  # DNS rebinding
                  head("Host: localhost.evil.com:4096"),
                  head("Host: user@localhost:4096"),
                  head(),
                  head("Host: localhost:4096", "Host: evil.com"),
                  head("Host: localhost:4096", "Origin: http://evil.com"),
                  head("Host: localhost:4096", "Origin: http://localhost:4101"),  # another sandbox
                  head("Host: localhost:4096", "Origin: https://localhost:4096"),
                  head("Host: localhost:4096", "Origin: null"),
                  head("Host: localhost:4096", "Origin: http://localhost:4096",
                       "Origin: http://evil.com"),
                  head("Host: localhost:4096", "Sec-Fetch-Site: cross-site"),
                  head("Host: localhost:4096", "Sec-Fetch-Site: same-site"),
                  head("Host: localhost:4096", "Sec-Fetch-Site: same-origin",
                       "Sec-Fetch-Site: cross-site"),
                  head("Host: localhost:4096", request="GET /"),
                  head("Host: localhost:4096", request="CONNECT github.com:443 HTTP/1.1"),
                  head("Host: localhost:4096", request="GET http://github.com/ HTTP/1.1"),
                  b"\x16\x03\x01\x00\xff\r\n\r\n"):
            with self.subTest(head=h):
                self.assertIsNotNone(publish.refusal(h, NAMES))


class InsideServer:
    """Stands in for the agent's server inside the sandbox: records the request, answers hello."""

    def __init__(self, test):
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.received = []
        test.addCleanup(self.sock.close)
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                self.received.append(data)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")


class Session(unittest.TestCase):
    """The host side (PublishServer) and the real bridge relay loop, over real sockets."""

    def setUp(self):
        self.dir = scratch_dir(self)
        self.events = []
        self.sock_path = os.path.join(self.dir, "publish.sock")

    def start(self, inside_port=None, bridge_running=True):
        server = publish.PublishServer("127.0.0.1", 0, self.sock_path,
                                       log=lambda **e: self.events.append(e))
        fd = server.start()
        self.addCleanup(server.stop)
        self.port = server.port
        if bridge_running:
            threading.Thread(target=bridge.publish_loop,
                             args=(fd, self.sock_path, inside_port or 1), daemon=True).start()
        else:
            self.addCleanup(os.close, fd)
        return server, fd

    def request(self, data=None, timeout=10):
        with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as c:
            c.sendall(data if data is not None else head(f"Host: localhost:{self.port}"))
            out = b""
            while chunk := c.recv(4096):
                out += chunk
            return out

    def test_round_trip(self):
        inside = InsideServer(self)
        self.start(inside.port)
        req = head(f"Host: localhost:{self.port}", "X-Test: 1")
        self.assertTrue(self.request(req).endswith(b"hello"))
        self.assertEqual(inside.received, [req])
        self.assertEqual(self.events, [])

    def test_refused_host_never_reaches_inside(self):
        inside = InsideServer(self)
        self.start(inside.port)
        out = self.request(head("Host: evil.com"))
        self.assertTrue(out.startswith(b"HTTP/1.1 403 "), out)
        self.assertEqual(inside.received, [])
        self.assertEqual(self.events[0]["action"], "publish-refused")

    def test_nothing_listening_inside_is_502_at_once(self):
        free = socket.create_server(("127.0.0.1", 0))
        port = free.getsockname()[1]
        free.close()
        self.start(port)
        began = time.monotonic()
        self.assertTrue(self.request().startswith(b"HTTP/1.1 502 "))
        self.assertLess(time.monotonic() - began, 3)

    def test_no_bridge_is_504(self):
        with mock.patch.object(publish, "PAIR_TIMEOUT", 0.3):
            self.start(bridge_running=False)
            self.assertTrue(self.request().startswith(b"HTTP/1.1 504 "))

    def test_oversized_head_is_431(self):
        self.start(bridge_running=False)
        out = self.request(b"GET / HTTP/1.1\r\nX: " + b"a" * (publish.HEAD_LIMIT + 10))
        self.assertTrue(out.startswith(b"HTTP/1.1 431 "), out)

    def test_slow_head_is_408(self):
        with mock.patch.object(publish, "HEAD_TIMEOUT", 0.3):
            self.start(bridge_running=False)
            self.assertTrue(self.request(b"GET / HTTP/1.1\r\n").startswith(b"HTTP/1.1 408 "))

    def test_trickled_head_is_408(self):
        """One byte at a time, each well within the timeout: the whole head still has one."""
        with mock.patch.object(publish, "HEAD_TIMEOUT", 0.5):
            self.start(bridge_running=False)
            began = time.monotonic()
            with socket.create_connection(("127.0.0.1", self.port), timeout=5) as c:
                try:
                    for byte in b"GET / HTTP/1.1\r\nX: " + b"a" * 100:
                        c.send(bytes([byte]))
                        time.sleep(0.1)
                except OSError:
                    pass  # closed by the server after its 408
                out = c.recv(4096)
            self.assertTrue(out.startswith(b"HTTP/1.1 408 "), out)
            self.assertLess(time.monotonic() - began, 3)

    def test_forged_token_gets_nothing(self):
        inside = InsideServer(self)
        with mock.patch.object(publish, "PAIR_TIMEOUT", 1):
            self.start(bridge_running=False)
            result = []
            client = threading.Thread(target=lambda: result.append(self.request()))
            client.start()
            time.sleep(0.2)
            with socket.socket(socket.AF_UNIX) as s:
                s.settimeout(5)
                s.connect(self.sock_path)
                s.sendall(os.urandom(publish.TOKEN_LEN) + b"1")
                self.assertEqual(s.recv(4096), b"")  # closed, the browser's request not handed over
            client.join()
        self.assertTrue(result[0].startswith(b"HTTP/1.1 504 "))
        self.assertEqual(inside.received, [])

    def test_sandbox_writes_on_the_control_channel_are_ignored(self):
        inside = InsideServer(self)
        _, fd = self.start(inside.port)
        os.write(fd, b"garbage" * 100)
        self.assertTrue(self.request().endswith(b"hello"))

    def test_pending_connections_are_capped(self):
        with mock.patch.object(publish, "PENDING_MAX", 2), \
                mock.patch.object(publish, "PAIR_TIMEOUT", 2):
            self.start(bridge_running=False)
            held = []
            for _ in range(2):
                c = socket.create_connection(("127.0.0.1", self.port))
                c.sendall(head(f"Host: localhost:{self.port}"))
                held.append(c)
            time.sleep(0.3)
            began = time.monotonic()
            self.assertTrue(self.request().startswith(b"HTTP/1.1 503 "))
            self.assertLess(time.monotonic() - began, 1.5)
            for c in held:
                c.close()

    def test_open_connections_are_capped(self):
        with mock.patch.object(publish, "CONNECTIONS_MAX", 3):
            self.start(bridge_running=False)
            held = [socket.create_connection(("127.0.0.1", self.port)) for _ in range(3)]
            time.sleep(0.3)
            self.assertTrue(self.request(b"").startswith(b"HTTP/1.1 503 "))
            for c in held:
                c.close()

    def test_port_in_use_is_a_clear_error(self):
        taken = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(taken.close)
        server = publish.PublishServer("127.0.0.1", taken.getsockname()[1], self.sock_path)
        with self.assertRaisesRegex(ConfigError, "--publish"):
            server.start()

    def test_stop_frees_the_port(self):
        server, fd = self.start(bridge_running=False)
        server.stop()
        socket.create_server(("127.0.0.1", self.port)).close()


class BridgeArgs(unittest.TestCase):
    def test_publish_argument(self):
        self.assertIsNone(bridge.parse_publish("-"))
        self.assertEqual(bridge.parse_publish("4096:7"), (4096, 7))
        for bad in ("", "4096", "x:7", "4096:", ":7", "4096:7:1"):
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                bridge.parse_publish(bad)


if __name__ == "__main__":
    unittest.main()
