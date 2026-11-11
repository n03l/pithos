# SPDX-License-Identifier: GPL-3.0-or-later
"""File access tracing: strace's output, and telling the agent which accesses the sandbox
refused.

strace runs outside the sandbox and reports failed file syscalls live. Each is classified
against the plan, never against the host: checking the host would tell the sandbox which host
paths exist. `pithos --trace` also keeps the whole trace for `pithos report`.
"""

import contextlib
import os
import re
import threading

import proxy
from config import (
    ConfigError, SANDBOX_PYTHON, SYSTEM_FORBIDDEN, TRACE_START, clean, is_sensitive, is_within,
    note,
)


def strace_argv(strace, out_path, argv, failed_only=True):
    """-D keeps bwrap the launcher's direct child, so --die-with-parent, exit codes and signal
    forwarding are unchanged. --seccomp-bpf stops only on file syscalls, -Z prints only the
    failed ones. Never add -v: it would print environment values on execve."""
    opts = [strace, "-D", "-f", "-qq", "-y", "--seccomp-bpf", "-e", "trace=%file",
            "-e", "signal=none"]
    if failed_only:
        opts.append("-Z")
    return [*opts, "-o", out_path, *argv]


def ptrace_allowed():
    """Yama scope 0 or 1 lets strace trace its own children; 2 and 3 need privileges."""
    try:
        with open("/proc/sys/kernel/yama/ptrace_scope") as f:
            return int(f.read().strip()) < 2
    except (OSError, ValueError):
        return True  # no Yama


def create_trace_log(path):
    """Created here so strace's -o can't follow a planted link and the log stays private."""
    try:
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600))
    except OSError as e:
        raise ConfigError(f"cannot create trace log {path}: {e.strerror}")


# -- reading strace's output -----------------------------------------------------------

TRACE_LINE = re.compile(r"(\d+)\s+(.*)$")
TRACE_CALL = re.compile(r"(\w+)\((.*)$")
TRACE_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')
TRACE_DIRFD = re.compile(r"(?:\d+|AT_FDCWD)<(.*?)>, ")
TRACE_ESCAPE = re.compile(r"\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|.)", re.S)
TRACE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "v": "\v", "f": "\f", "a": "\a", "b": "\b"}
TRACE_LINE_MAX = 65536
TRACE_FIFO = "trace.fifo"  # in the runtime dir: strace writes, TraceWatcher reads
TRACE_STARTS = (f'execve("{SANDBOX_PYTHON}"',)  # traces from before the start probe
TRACE_ERROR = re.compile(r"\) += -1 (E[A-Z0-9]+) \([^()]*\)$")
TRACE_WRITE_FLAGS = re.compile(r"\bO_(?:WRONLY|RDWR|CREAT|TRUNC)\b")
TRACE_WRITE_CALLS = re.compile(
    r"(?:mkdir|mknod|unlink|rmdir|rename|link|symlink|creat|truncate|f?chmod|f?chown|lchown|utime)")
TRACE_MISSING = ("ENOENT", "ENOTDIR")
TRACE_GROUPS = ("written", "read", "missing", "refused")


def trace_calls(lines):
    """Yield complete `call(args) = result` texts, joining the halves strace splits when
    threads interleave. Anything else in the file is ignored."""
    pending = {}
    for line in lines:
        m = TRACE_LINE.match(line.rstrip("\n"))
        if not m:
            continue
        pid, text = m.groups()
        if text.endswith(" <unfinished ...>"):
            pending[pid] = text[:-len(" <unfinished ...>")]
        elif text.startswith("<... "):
            head = pending.pop(pid, None)
            if head is not None and " resumed>" in text:
                yield head + text.split(" resumed>", 1)[1]
        else:
            yield text


def trace_unescape(text):
    """Undo strace's C-style string escapes; bytes that aren't UTF-8 stay visible as \\xNN."""
    raw, pos = bytearray(), 0
    for m in TRACE_ESCAPE.finditer(text):
        raw += text[pos:m.start()].encode("utf-8", "surrogateescape")
        code = m.group(1)
        if code[0] == "x" and len(code) == 3:
            raw.append(int(code[1:], 16))
        elif code[0] in "01234567":
            raw.append(int(code, 8) & 0xFF)
        else:
            raw += TRACE_ESCAPES.get(code, code).encode("utf-8", "surrogateescape")
        pos = m.end()
    raw += text[pos:].encode("utf-8", "surrogateescape")
    return raw.decode("utf-8", "backslashreplace")


def parse_trace_call(text):
    """(call, paths, error name or None, writes) for one call, or None if it names no path."""
    m = TRACE_CALL.match(text)
    if not m:
        return None
    call, args = m.groups()
    strings = list(TRACE_STRING.finditer(args))
    if not strings:
        return None
    first = strings[0]
    names = [trace_unescape(s.group(1)) for s in strings]
    if call.startswith(("rename", "link")):
        chosen = names[:2]
    elif call.startswith("symlink"):
        chosen = names[1:2]
    else:
        chosen = names[:1]
    dirfd = TRACE_DIRFD.match(args)
    base = trace_unescape(dirfd.group(1)) if dirfd and dirfd.end() == first.start() else ""
    found = [os.path.join(base, name) for name in chosen if name]
    if not found:
        return None
    error = TRACE_ERROR.search(text)
    flags = args[first.end():].split(") = ", 1)[0]
    writes = bool(TRACE_WRITE_FLAGS.search(flags) or TRACE_WRITE_CALLS.match(call))
    return call, found, error.group(1) if error else None, writes


def classify_trace_call(text):
    """Return (group, paths) for one call, or None if it names no path."""
    parsed = parse_trace_call(text)
    if not parsed:
        return None
    _, found, error, writes = parsed
    if error:
        return ("missing" if error in TRACE_MISSING else "refused"), found
    return ("written" if writes else "read"), found


def sandbox_calls(lines):
    """trace_calls after the sandbox starts. Bwrap's own setup comes before the bridge's start
    probe (older traces: the bridge's execve) and is skipped; so is the probe itself."""
    started = False
    probe = f'"{TRACE_START}"'
    for text in trace_calls(lines):
        if probe in text:
            started = True
        elif started:
            yield text
        else:
            started = text.startswith(TRACE_STARTS)


def summarise_trace(lines):
    """Count paths per group. A trace that never reaches the bridge counts nothing."""
    groups = {name: {} for name in TRACE_GROUPS}
    for text in sandbox_calls(lines):
        result = classify_trace_call(text)
        if result:
            counts = groups[result[0]]
            for path in result[1]:
                counts[path] = counts.get(path, 0) + 1
    return groups


# -- telling the agent about refused file accesses -------------------------------------

NOT_MOUNTED = "not mounted"
HIDDEN = "hidden on purpose"
READ_ONLY = "read-only"
FILE_ERRORS = ("ENOENT", "ENOTDIR", "EROFS", "EACCES", "EPERM")
FILE_PATH_MAX = 4096
BLOCKED_FILES_LIMIT = 2000
BLOCKED_GROUP_LIMIT = 100
FILE_EVENTS_LIMIT = 5000
# Looked up by nearly every program, and never worth mounting.
IGNORED_PROBES = ("/etc/ld.so.preload", "/etc/ld.so.nohwcap", "/etc/selinux", "/selinux",
                  "/etc/gai.conf", "/etc/host.conf", "/etc/resolv.conf",
                  "/$bunfs")  # Bun's embedded files, never on disk
MOUNT_KINDS = {"--bind": "rw", "--ro-bind": "ro", "--tmpfs": "tmpfs", "--symlink": "link"}


class SandboxView:
    """Which part of the sandbox a path falls in, from the plan's mounts."""

    def __init__(self, plan, home):
        self.mounts = {"/": "root", "/proc": "system", "/dev": "system"}
        self.mount_dests = {dest for dest, _, _ in plan.mounts} | set(self.mounts)
        for dest, _, args in plan.mounts:
            kind = MOUNT_KINDS.get(args[0])
            if kind == "tmpfs":
                kind = "home" if dest == home else "system"
            if kind:
                self.mounts[dest] = kind
        self.hidden, self.deny_globs = list(plan.hidden), list(plan.deny_globs)
        self.home, self.project = home, plan.project
        self.path_dirs = {os.path.normpath(p) for p in plan.env.get("PATH", "").split(":")
                          if os.path.isabs(p)}

    def kind(self, path):
        best = max((dest for dest in self.mounts if is_within(path, dest)), key=len)
        return self.mounts[best]

    def is_lookup(self, path):
        """A search through PATH, or upward from the project (node_modules, config files)."""
        parent = os.path.dirname(path)
        if parent in self.path_dirs:
            return True
        return bool(self.project) and parent != self.home and parent != self.project \
            and is_within(self.project, parent) and is_within(parent, self.home)

    def reason(self, path, error, writes):
        """Why the sandbox refused this access, or None if the sandbox didn't cause it."""
        if error not in FILE_ERRORS or not path.startswith("/") or len(path) > FILE_PATH_MAX:
            return None
        path = "/" + os.path.normpath(path).lstrip("/")
        if any(is_within(path, p) for p in SYSTEM_FORBIDDEN):
            return None
        # Never suggest mounting a secret: denied and sensitive paths are reported as deliberate.
        if any(is_within(path, h) for h in self.hidden) or is_sensitive(path, self.deny_globs):
            return HIDDEN
        kind = self.kind(path)
        if kind == "ro" and (error == "EROFS" or (writes and error in ("EACCES", "EPERM"))):
            return READ_ONLY
        if kind in ("root", "home"):
            if any(is_within(path, p) for p in IGNORED_PROBES) or self.is_lookup(path):
                return None
            return NOT_MOUNTED
        return None

    def shown_path(self, path):
        """The first level of a "not mounted" path with nothing mounted at or below it: the
        whole of ~/.npm/_npx/... is one missing ~/.npm. Inside the writable home tmpfs the rest
        is usually what a tool creates as it goes. Never a dir holding a hidden path."""
        path = "/" + os.path.normpath(path).lstrip("/")
        covered = self.mount_dests | set(self.hidden)
        prefix = ""
        for part in path.strip("/").split("/"):
            prefix += "/" + part
            if not any(is_within(dest, prefix) for dest in covered):
                return prefix
        return path


def file_group(path, home):
    """The top-level directory a path is counted under: ~/.npm, /etc, /opt."""
    if is_within(path, home) and path != home:
        return os.path.join(home, os.path.relpath(path, home).split("/")[0])
    return "/" + path.lstrip("/").split("/")[0]


class BlockedFiles:
    """The paths refused this session, one "path<TAB>reason" line each, for the agent. Paths
    are made one line of printable text.

    Agents look up hundreds of optional files at start-up (~/.npm, ~/.claude/...), so each
    top-level directory gets at most BLOCKED_GROUP_LIMIT lines, then one "dir/*" line: a
    noisy tool can't push out the path the agent needs later."""

    def __init__(self, path, home="/nonexistent"):
        self.file = proxy.CappedFile(path, BLOCKED_FILES_LIMIT, "list truncated: the user can "
                                                                "see more with pithos report\n")
        self.home = home
        self.seen = set()
        self.groups = {}

    def add(self, path, reason):
        """Returns True the first time a path is listed."""
        if path in self.seen or self.file.closed:
            return False
        group = file_group(path, self.home)
        count = self.groups.get(group, 0)
        if count > BLOCKED_GROUP_LIMIT:
            return False
        self.groups[group] = count + 1
        if count == BLOCKED_GROUP_LIMIT:
            self.file.write(f"{clean(group, keep='')}/*\tmore paths here, not listed\n")
            return False
        if not self.file.write(f"{clean(path, keep='')}\t{reason}\n"):
            return False
        self.seen.add(path)
        return True


class TraceWatcher:
    """Reads strace's output from a FIFO while the sandbox runs: copies it to the --trace log
    if there is one, and lists refused accesses for the agent and the session log."""

    def __init__(self, fifo, view, denied, log=None, copy_path=None):
        self.fifo, self.view, self.denied, self.log = fifo, view, denied, log
        self.copy_path = copy_path
        self.logged = set()
        self.log_groups = {}
        self.thread = None

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def finish(self, timeout=5):
        """Wait for strace to close the FIFO; unblock the reader if strace never opened it."""
        if self.thread is None:
            return
        self.thread.join(timeout)
        if self.thread.is_alive():
            with contextlib.suppress(OSError):
                os.close(os.open(self.fifo, os.O_WRONLY | os.O_NONBLOCK))
            self.thread.join(timeout)
        self.thread = None

    def _run(self):
        try:
            with open(self.fifo, "rb") as f:
                copy = open(self.copy_path, "ab") if self.copy_path else contextlib.nullcontext()
                with copy:
                    for text in sandbox_calls(self._lines(f, copy if self.copy_path else None)):
                        self.check(text)
        except Exception as e:  # never take the session down: only the notice is lost
            note(f"file notice stopped: {clean(type(e).__name__)}")

    @staticmethod
    def _lines(f, copy):
        """Lines of at most TRACE_LINE_MAX bytes; the rest of a longer line is dropped."""
        whole = True
        while raw := f.readline(TRACE_LINE_MAX):
            if copy:
                copy.write(raw)
            ends = raw.endswith(b"\n")
            if whole and ends:
                yield raw.decode("ascii", "backslashreplace")
            whole = ends

    def check(self, text):
        if " = -1 E" not in text:
            return
        parsed = parse_trace_call(text)
        if not parsed or not parsed[2]:
            return
        _, found, error, writes = parsed
        for path in found:
            reason = self.view.reason(path, error, writes)
            if not reason:
                continue
            if reason == NOT_MOUNTED:
                path = self.view.shown_path(path)
            else:
                path = "/" + os.path.normpath(path).lstrip("/")
            self.denied.add(path, reason)
            if self.log and path not in self.logged and len(self.logged) < FILE_EVENTS_LIMIT:
                self._log(path, reason, error)

    def _log(self, path, reason, error):
        """Like the agent's list, each top-level directory gets BLOCKED_GROUP_LIMIT events."""
        group = file_group(path, self.view.home)
        count = self.log_groups.get(group, 0)
        if count > BLOCKED_GROUP_LIMIT:
            return
        self.log_groups[group] = count + 1
        if count == BLOCKED_GROUP_LIMIT:
            self.log(action="files_capped", group=group)
            return
        self.logged.add(path)
        self.log(action="file", path=path, reason=reason, error=error)


def sum_traces(files):
    totals = {name: {} for name in TRACE_GROUPS}
    for path in files:
        with open(path, encoding="ascii", errors="replace") as f:
            for name, counts in summarise_trace(f).items():
                for item, count in counts.items():
                    totals[name][item] = totals[name].get(item, 0) + count
    return totals
