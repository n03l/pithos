# SPDX-License-Identifier: GPL-3.0-or-later
"""Resource limits: the [limits] table, the systemd scope that enforces it, and the list of
limits hit that the agent can read.

Limits are computed at start from what this machine has, so profiles can say "50%" instead of a
size. The sandbox as a whole runs in a systemd scope (cgroup v2): systemd does the one
privileged step, moving the launcher's child into a cgroup, and the kernel enforces the limits.
pithos has no setuid code. Without a scope pithos refuses to run, unless --no-limits.
"""

import contextlib
import os
import re
import resource
import select
import subprocess
import threading
import time

import proxy
from config import ConfigError, LIMIT_KEYS, SANDBOX_LIMIT_EVENTS, clean


DEFAULT_LIMITS = {"processes": "15%", "memory": "50%", "total": "75%", "tmpfs": "25%",
                  "cpu": "100%"}
LIMIT_FLOORS = {"processes": 512, "memory": 1 << 30, "total": 1 << 30, "tmpfs": 64 << 20,
                "cpu": 100}


SIZE_UNITS = {"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}
SIZE_VALUE = re.compile(r"(\d{1,15})([KMGT]?)", re.ASCII)
PERCENT_VALUE = re.compile(r"(\d{1,3}(?:\.\d{1,2})?)%", re.ASCII)
COUNTED = ("processes", "cpu")  # a count (tasks, cores), not a size


class Machine:
    """What limits are computed against: RAM (lowered by our own cgroup's limit, as in a
    container), how many tasks the user may run and how many CPUs we may use."""

    def __init__(self, ram, tasks, cpus=1):
        self.ram, self.tasks, self.cpus = ram, tasks, cpus

    def base(self, key):
        """The whole of what a limit is a share of. cpu is in percent of one CPU, like
        systemd's CPUQuota: 4 CPUs are 400."""
        return {"processes": self.tasks, "cpu": self.cpus * 100}.get(key, self.ram)


def read_int(path):
    try:
        with open(path) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def cgroup_memory_limit(proc="/proc", sysfs="/sys/fs/cgroup"):
    """The lowest memory.max of our cgroup and its ancestors (cgroup v2), or None."""
    try:
        with open(os.path.join(proc, "self/cgroup")) as f:
            line = next((l for l in f if l.startswith("0::")), "")
    except OSError:
        return None
    rel = os.path.normpath(line[3:].strip() or "/").strip("/")
    limits = []
    while True:
        value = read_int(os.path.join(sysfs, rel, "memory.max"))  # "max" reads as None
        if value:
            limits.append(value)
        if not rel:
            break
        rel = os.path.dirname(rel)
    return min(limits, default=None)


def read_machine(proc="/proc", sysfs="/sys/fs/cgroup"):
    ram = None
    try:
        with open(os.path.join(proc, "meminfo")) as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    ram = int(line.split()[1]) * 1024
                    break
    except (OSError, ValueError, IndexError):
        pass
    if not ram:
        raise ConfigError("cannot read MemTotal from /proc/meminfo to compute [limits]")
    group = cgroup_memory_limit(proc, sysfs)
    soft = resource.getrlimit(resource.RLIMIT_NPROC)[0]
    tasks = [n for n in (None if soft == resource.RLIM_INFINITY else soft,
                         read_int(os.path.join(proc, "sys/kernel/threads-max"))) if n]
    return Machine(min(ram, group or ram), min(tasks, default=1 << 22),
                   len(os.sched_getaffinity(0)) or 1)


def parse_limit(key, value, machine, warnings):
    """Bytes, a task count or a CPU quota (percent of one CPU) for one [limits] value, or None
    for "none". A limit that grants the whole machine is None too: nothing to enforce."""
    where = f"limits.{key}"
    base = machine.base(key)
    if value == "none":
        return None
    if isinstance(value, int):
        amount, absolute = value * (100 if key == "cpu" else 1), True
    elif m := PERCENT_VALUE.fullmatch(value):
        percent = float(m.group(1))
        if not 0 < percent <= 100:
            raise ConfigError(f"{where}: percentage must be between 0 and 100: {clean(value)!r}")
        amount, absolute = int(base * percent / 100), False
    elif (m := SIZE_VALUE.fullmatch(value)) and (key not in COUNTED or not m.group(2)):
        amount = int(m.group(1)) * SIZE_UNITS[m.group(2)] * (100 if key == "cpu" else 1)
        absolute = True
    else:
        example = {"processes": '"4096" or "15%"', "cpu": '"2" (CPUs) or "50%"'}.get(
            key, '"16G" or "50%"')
        raise ConfigError(f"{where}: expected {example} or \"none\", got {clean(value)!r}")
    if amount <= 0:
        raise ConfigError(f"{where}: must be more than 0")
    if absolute and amount > base:
        warnings.append(f"{where}: {clean(value)} is more than this machine has, using "
                        f"{describe_amount(key, base)}")
    # Floors only lift the computed percentage defaults: an explicit value is used as given.
    amount = min(amount if absolute else max(amount, LIMIT_FLOORS[key]), base)
    return None if key == "cpu" and amount >= base else amount


def resolve_limits(cfg, machine, scoped):
    """({key: amount or None}, warnings). Missing keys get DEFAULT_LIMITS."""
    given = cfg.get("limits", {})
    warnings = []
    limits = {key: parse_limit(key, given.get(key, DEFAULT_LIMITS[key]), machine, warnings)
              for key in LIMIT_KEYS}
    # The per-process limit is RLIMIT_DATA, which counts address space reserved, not memory
    # used: Node reserves gigabytes it never touches, and dies at startup under a limit far
    # above what it uses. In a scope, MemoryMax limits real memory and its OOM kills are
    # reported, so RLIMIT_DATA is only the fallback for --no-limits.
    if scoped:
        limits["memory"] = None
    return limits, warnings


def describe_amount(key, amount):
    if amount is None:
        return "unlimited"
    if key == "processes":
        return str(amount)
    if key == "cpu":
        return f"{amount / 100:g} CPUs"
    for unit in ("T", "G", "M", "K"):
        if amount >= SIZE_UNITS[unit]:
            return f"{amount / SIZE_UNITS[unit]:.1f}".removesuffix(".0") + unit
    return str(amount)


LIMIT_NAMES = {"processes": "processes", "memory": "memory per process",
               "total": "memory in total", "tmpfs": "tmpfs each", "cpu": "cpu"}


def describe_limits(limits, keys=LIMIT_KEYS):
    return ", ".join(f"{LIMIT_NAMES[key]} {describe_amount(key, limits[key])}" for key in keys)


def bridge_limits(limits, scoped=True):
    """The rlimits for bridge.py, as "name=value,...". Core dumps are always off: they would
    hold the agent's memory, keys included. In a scope, TasksMax limits processes and reports
    when it is hit; RLIMIT_NPROC is only the fallback for --no-limits."""
    parts = ["core=0"]
    if limits and limits.get("processes") and not scoped:
        parts.append(f"nproc={limits['processes']}")
    if limits and limits.get("memory"):
        parts.append(f"data={limits['memory']}")
    return ",".join(parts)


SYSTEMD_RUN_PATHS = ("/usr/bin/systemd-run", "/bin/systemd-run")


def find_systemd_run():
    """Only from the system's own directories: never PATH, which the user's shell can change."""
    return next((p for p in SYSTEMD_RUN_PATHS if os.access(p, os.X_OK)), None)


def scope_argv(systemd_run, unit, limits):
    """Prefix that runs the rest of the argv in a new systemd scope. --scope execs it in place,
    so bwrap stays the launcher's child and inherits its file descriptors."""
    # Without OOMPolicy=continue, an OOM kill fails the scope and systemd ends the session.
    argv = [systemd_run, "--user", "--scope", "--quiet", "--collect", f"--unit={unit}",
            "-p", "OOMPolicy=continue"]
    if limits.get("total"):
        argv += ["-p", f"MemoryMax={limits['total']}", "-p", "MemorySwapMax=0"]
    if limits.get("processes"):
        argv += ["-p", f"TasksMax={limits['processes']}"]
    if limits.get("cpu"):
        argv += ["-p", f"CPUQuota={limits['cpu']}%"]
    return argv + ["--"]


def check_scope(systemd_run):
    """None if a user scope can be created here, else why not."""
    if not systemd_run:
        return "systemd-run is not installed"
    if not os.path.isabs(os.environ.get("XDG_RUNTIME_DIR", "")):
        return "no systemd user session (XDG_RUNTIME_DIR is not set)"
    try:
        done = subprocess.run([systemd_run, "--user", "--scope", "--quiet", "--collect", "--",
                               "/bin/true"], stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, errors="replace", timeout=15)
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"systemd-run failed: {e}"
    if done.returncode != 0:
        lines = done.stderr.strip().splitlines()
        return f"systemd-run failed: {clean(lines[-1] if lines else done.returncode)}"
    return None


def limits_notice(limits, scoped):
    enforced = [key for key in (LIMIT_KEYS if scoped else ("processes", "memory", "tmpfs"))
                if limits.get(key)]
    if not enforced:
        return ""
    text = f"""
## Resource limits

This sandbox limits {describe_limits(limits, enforced)}. Processes include threads; "memory in
total" includes files in /tmp, /var/tmp, /dev/shm and the home directory, which are in memory;
"tmpfs each" is the size of each of those. When a command ends with "Killed" or exit code 137,
or fails with "Resource temporarily unavailable", "Cannot allocate memory", an out-of-memory
error or "No space left on device" in those directories, it may have hit one of these limits."""
    if scoped:
        text += f""" Read `{SANDBOX_LIMIT_EVENTS}`: it lists, one per line as `time<TAB>limit<TAB>what
happened`, each time a limit stopped something in this session."""
    return text + """ If a limit was hit, tell the user which one and what it stopped; they can
raise it under `[limits]` in their pithos profile. Do not try to get around it.
"""


LIMIT_EVENTS_LIMIT = 200


def limit_hit_text(kind, count, limits):
    """What the kernel did when a limit was hit, as a fixed sentence and numbers."""
    plural = count > 1
    if kind == "memory":
        killed = f"the kernel killed {count} process{'es' if plural else ''}"
        if limits.get("total"):
            return (f"{killed}: the sandbox reached its memory limit "
                    f"({describe_amount('total', limits['total'])})")
        return f"{killed}: the machine ran out of memory"
    return (f"{count} process or thread start{'s' if plural else ''} refused: the sandbox "
            f"reached its limit of {limits.get('processes')} processes")


class LimitEvents:
    """The list of limits hit this session, for the agent. Every byte is pithos's own: a time,
    a fixed text and numbers."""

    def __init__(self, path, limits, log=None, clock=None):
        self.limits, self.log = limits, log
        self.file = proxy.CappedFile(path, LIMIT_EVENTS_LIMIT, "list truncated: the user can "
                                                               "see the rest with pithos report\n")
        self.clock = clock or (lambda: time.strftime("%H:%M:%S"))
        self.totals = {}

    def add(self, kind, count):
        self.totals[kind] = self.totals.get(kind, 0) + count
        if self.log:
            self.log(action="limit", limit=kind, count=count)
        self.file.write(f"{self.clock()}\t{kind}\t{limit_hit_text(kind, count, self.limits)}\n")


LIMIT_COUNTERS = {"memory": ("memory.events", "oom_kill"), "processes": ("pids.events", "max")}
EVENTS_INTERVAL = 1.0  # at most one line per kind and second, however fast a fork loop is


def read_counter(fd, name):
    try:
        text = os.pread(fd, 4096, 0).decode("ascii", "replace")
    except OSError:
        return None
    for line in text.splitlines():
        key, _, value = line.partition(" ")
        if key == name and value.isdigit():
            return int(value)
    return None


class ScopeMonitor:
    """Watches the scope's event counters and reports each increase to LimitEvents. The
    kernel wakes poll() when an events file changes; nothing here enforces anything."""

    def __init__(self, cgroup_dir, events):
        self.dir, self.events = cgroup_dir, events
        self.fds, self.seen = {}, {}
        self.stopping = threading.Event()
        self.thread = None

    def start(self):
        for kind, (name, counter) in LIMIT_COUNTERS.items():
            try:
                fd = os.open(os.path.join(self.dir, name),
                             os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            except OSError:
                continue
            self.fds[kind] = fd
            self.seen[kind] = read_counter(fd, counter) or 0
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def check(self):
        for kind, fd in self.fds.items():
            value = read_counter(fd, LIMIT_COUNTERS[kind][1])
            if value is not None and value > self.seen[kind]:
                self.events.add(kind, value - self.seen[kind])
                self.seen[kind] = value

    def _run(self):
        poller = select.poll()
        for fd in self.fds.values():
            poller.register(fd, select.POLLPRI | select.POLLERR)
        while not self.stopping.is_set():
            try:
                poller.poll(EVENTS_INTERVAL * 1000)
                self.check()
            except Exception:
                pass
            self.stopping.wait(EVENTS_INTERVAL)

    def stop(self):
        self.stopping.set()
        if self.thread:
            self.thread.join(5)
            self.thread = None
        with contextlib.suppress(Exception):
            self.check()  # the files read as errors once the scope is gone
        for fd in self.fds.values():
            os.close(fd)
        self.fds = {}


def scope_cgroup(pid, unit, proc="/proc", sysfs="/sys/fs/cgroup", timeout=5.0):
    """The scope's cgroup directory once systemd-run has moved pid into it, or None."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with open(f"{proc}/{pid}/cgroup") as f:
                rel = next((l[3:].strip() for l in f if l.startswith("0::")), "")
        except OSError:
            return None
        if rel.endswith("/" + unit) and ".." not in rel.split("/"):
            return sysfs + rel
        time.sleep(0.02)
    return None
