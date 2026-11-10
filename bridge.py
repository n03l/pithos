# SPDX-License-Identifier: GPL-3.0-or-later
"""Runs inside the sandbox (stdlib only, started with /usr/bin/python3 -I).

  bridge.py serve SOCK PORT LIMITS CMD...  set the rlimits in LIMITS ("core=0,nproc=N,data=N"),
                                    listen on 127.0.0.1:PORT, relay each connection to the
                                    proxy UNIX socket SOCK, then exec CMD
  bridge.py connect HOST PORT       ssh ProxyCommand: CONNECT through 127.0.0.1:3128, pipe stdio
"""

import os
import resource
import socket
import sys
import threading

PROXY_PORT = 3128
TRACE_START = "/run/pithos/.trace-start"
RLIMITS = {"core": resource.RLIMIT_CORE, "nproc": resource.RLIMIT_NPROC,
           "data": resource.RLIMIT_DATA}


def apply_limits(spec):
    """Set soft and hard limits, so nothing in the sandbox can raise them again. Done here,
    inside the sandbox's user namespace, so RLIMIT_NPROC counts only the sandbox's tasks."""
    for item in spec.split(","):
        name, _, value = item.partition("=")
        if name not in RLIMITS or not (value.isascii() and value.isdigit()):
            sys.exit(f"pithos: bad limit {item!r}")
        limit = int(value)
        hard = resource.getrlimit(RLIMITS[name])[1]
        if hard != resource.RLIM_INFINITY:
            limit = min(limit, hard)
        resource.setrlimit(RLIMITS[name], (limit, limit))


def _pump(src, dst):
    try:
        while data := src.recv(65536):
            dst.sendall(data)
        dst.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def _relay(client, sock_path):
    with client, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as upstream:
        try:
            upstream.connect(sock_path)
        except OSError:
            return
        t = threading.Thread(target=_pump, args=(upstream, client), daemon=True)
        t.start()
        _pump(client, upstream)
        t.join()


def serve(sock_path, port, limits, cmd):
    apply_limits(limits)
    # A lookup that always fails: in the launcher's trace it marks where bwrap's own setup
    # ends and the sandbox begins (pithos.TRACE_START).
    try:
        os.stat(TRACE_START)
    except OSError:
        pass
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(128)
    # Double fork: the relay is reparented to the sandbox init, not to CMD, and dies
    # with the sandbox's PID namespace when CMD exits.
    pid = os.fork()
    if pid == 0:
        if os.fork() != 0:
            os._exit(0)
        devnull = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1):
            os.dup2(devnull, fd)
        while True:
            client, _ = listener.accept()
            threading.Thread(target=_relay, args=(client, sock_path), daemon=True).start()
    os.waitpid(pid, 0)
    listener.close()
    try:
        os.execvp(cmd[0], cmd)
    except OSError as e:
        print(f"pithos: cannot run {cmd[0]!r}: {e.strerror}", file=sys.stderr)
        sys.exit(127)


def connect(host, port):
    sock = socket.create_connection(("127.0.0.1", PROXY_PORT))
    target = f"{host}:{port}"
    sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("ascii"))
    head = b""
    while b"\r\n\r\n" not in head:
        data = sock.recv(4096)
        if not data or len(head) > 16384:
            sys.exit("pithos: proxy closed the connection")
        head += data
    head, rest = head.split(b"\r\n\r\n", 1)
    status = head.split(b"\r\n", 1)[0]
    if b" 200 " not in status + b" ":
        sys.exit(f"pithos: proxy refused {target}: {status.decode('latin-1')}")
    out = sys.stdout.buffer
    out.write(rest)
    out.flush()

    def upload():
        try:
            while data := os.read(0, 65536):
                sock.sendall(data)
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    threading.Thread(target=upload, daemon=True).start()
    while data := sock.recv(65536):
        out.write(data)
        out.flush()


def main(argv):
    if len(argv) >= 5 and argv[0] == "serve":
        serve(argv[1], int(argv[2]), argv[3], argv[4:])
    elif len(argv) == 3 and argv[0] == "connect":
        connect(argv[1], int(argv[2]))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
