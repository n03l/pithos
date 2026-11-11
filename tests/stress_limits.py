"""Bounded stress tests for the cgroup limits. Run: ~/.venv/bin/python tests/stress_limits.py

Every scenario uses strict limits and a fixed, small workload, so the host stays safe: at most
~200 short-lived processes, at most ~1.5 GB allocated, CPU burners bounded in time.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.join(ROOT, "tests/.tmp/stress")
CFG, PROJ, STATE = f"{WORK}/cfg", f"{WORK}/proj", f"{WORK}/state"
BASE_TOML = open(os.path.join(ROOT, "profiles/base.toml")).read()
results = []


def setup():
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(CFG)
    os.makedirs(PROJ)
    subprocess.run(["git", "init", "-q", PROJ], check=True)
    for name in ("base",):
        write_profile()


def write_profile(**limits):
    text = BASE_TOML
    for key, value in {"processes": '"15%"', "memory": '"50%"', "total": '"75%"',
                       "tmpfs": '"25%"', "cpu": '"100%"'}.items():
        text = re.sub(rf"^{key} = .*$", f"{key} = {value}", text, flags=re.M)
    for key, value in limits.items():
        text = re.sub(rf"^{key} = .*$", f'{key} = "{value}"', text, flags=re.M)
    open(f"{CFG}/base.toml", "w").write(text)


def pithos(script, timeout=90, **limits):
    write_profile(**limits)
    env = {**os.environ, "PITHOS_CONFIG": CFG, "PITHOS_STATE": STATE,
           "PITHOS_BWRAP": shutil.which("bwrap")}
    started = time.monotonic()
    done = subprocess.run([os.path.join(ROOT, "pithos"), "-p", "base", "-C", PROJ, "--",
                           "bash", "-c", script], env=env, capture_output=True, text=True,
                          timeout=timeout)
    return done, time.monotonic() - started


def last_log():
    logs = sorted(os.path.join(STATE, "logs", f) for f in os.listdir(f"{STATE}/logs"))
    events = [json.loads(line) for line in open(logs[-1])]
    return events


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if detail else ""))


def forks():
    """At most 200 children, killed at the end; the limit is 64."""
    done, _ = pithos("""
python3 -I -c '
import subprocess
kids = []
try:
    for _ in range(200):
        kids.append(subprocess.Popen(["sleep", "5"]))
except OSError as e:
    print("stopped", e.strerror)
print("started", len(kids))
for k in kids: k.kill(); k.wait()
'
sleep 0.5; cat "$PITHOS_LIMIT_EVENTS" """, processes=64, total="1G", memory="512M")
    started = int(re.search(r"started (\d+)", done.stdout).group(1))
    check("fork storm stops at TasksMax", done.returncode == 0 and 20 <= started < 64,
          f"{started} children, exit {done.returncode}")
    check("fork storm is reported to the agent",
          "processes" in done.stdout and "reached its limit of 64 processes" in done.stdout)
    check("fork storm survives the sandbox", "started" in done.stdout
          and done.stderr.count("Killed") == 0)
    check("fork storm is counted in the log",
          any(e.get("action") == "limit" and e.get("limit") == "processes" for e in last_log()))


def memory():
    """Two children of ~300 MB each against a 512 MB total: the kernel kills, the shell lives."""
    done, _ = pithos("""
python3 -I -c '
import subprocess, sys
code = "import time; b=[bytearray(50<<20) for _ in range(6)]; time.sleep(10)"
procs = [subprocess.Popen([sys.executable, "-I", "-c", code]) for _ in range(2)]
print("exits", [p.wait() for p in procs])
'
echo "alive"; sleep 1; cat "$PITHOS_LIMIT_EVENTS" """, total="512M", memory="512M", processes=128)
    check("OOM kill does not take the session down",
          done.returncode == 0 and "alive" in done.stdout, f"exit {done.returncode}")
    check("OOM kill reaches the agent", "memory\tthe kernel killed" in done.stdout)
    check("OOM kill is counted in the report",
          "at the memory limit:" in subprocess.run(
              [os.path.join(ROOT, "pithos"), "report"], capture_output=True, text=True,
              env={**os.environ, "PITHOS_STATE": STATE, "PITHOS_CONFIG": CFG}).stdout)


def reserved_address_space():
    """4 GB reserved but never touched, as Node does at startup, against a 1 GB total and a
    128 MB per-process setting: a scope limits memory used, not address space reserved."""
    done, _ = pithos("""
python3 -I -c '
import mmap
try:
    m = mmap.mmap(-1, 4 << 30, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
    print("reserved")
except OSError as e:
    print("refused", e.strerror)
'
echo alive""", total="1G", memory="128M")
    check("reserving address space is not limited in a scope",
          "reserved" in done.stdout and "alive" in done.stdout and done.returncode == 0,
          done.stdout.strip().replace("\n", " "))


def tmpfs():
    done, _ = pithos("""
df --output=size -B1 /tmp | tail -1
dd if=/dev/zero of=/tmp/fill bs=1M count=200 status=none 2>&1 | tail -1
echo "exit=$?"; ls -l /tmp/fill | awk '{print $5}'; echo alive""", tmpfs="64M")
    check("tmpfs writes stop at its size",
          "No space left on device" in done.stdout and "alive" in done.stdout)
    check("tmpfs mount has the configured size", " 67108864" in done.stdout)


def readonly():
    done, _ = pithos("""
touch /x 2>&1; touch /dev/x 2>&1; mkdir /newdir 2>&1; echo alive""", processes=128)
    check("root and /dev stay read-only",
          done.stdout.count("Read-only file system") == 3 and "alive" in done.stdout)


def cpu():
    """1 CPU of quota on an 8-CPU machine: four ~1s burners take ~4s instead of ~1."""
    open(f"{PROJ}/burn.py", "w").write(
        "import sys\ns = 0\nfor i in range(int(sys.argv[1])):\n    s += i\nprint(s)\n")
    script = """
python3 -I -c '
import subprocess, sys, time
t = time.time()
procs = [subprocess.Popen([sys.executable, "-I", "burn.py", "10000000"]) for _ in range(4)]
for p in procs: p.wait()
print("wall %.1f" % (time.time() - t))
'
"""
    write_profile(cpu="1")
    env = {**os.environ, "PITHOS_CONFIG": CFG, "PITHOS_STATE": STATE}
    # Inspect the live scope while a session runs.
    proc = subprocess.Popen([os.path.join(ROOT, "pithos"), "-p", "base", "-C", PROJ, "--",
                             "bash", "-c", script], env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    cpu_max, mem_max, pids_max = None, None, None
    for _ in range(100):
        scopes = []
        for root, dirs, _ in os.walk("/sys/fs/cgroup/user.slice"):
            scopes += [os.path.join(root, d) for d in dirs if d.startswith("pithos-")]
        if scopes:
            try:
                cpu_max = open(f"{scopes[0]}/cpu.max").read().strip()
                mem_max = open(f"{scopes[0]}/memory.max").read().strip()
                pids_max = open(f"{scopes[0]}/pids.max").read().strip()
            except OSError:
                pass
            break
        time.sleep(0.05)
    out, err = proc.communicate(timeout=90)
    wall = float(re.search(r"wall ([\d.]+)", out).group(1))
    check("CPU quota is applied", cpu_max == "100000 100000", f"cpu.max={cpu_max}")
    check("memory and process limits are applied", mem_max not in (None, "max")
          and pids_max not in (None, "max"), f"memory.max={mem_max} pids.max={pids_max}")
    check("CPU quota throttles four burners to one CPU", 3.0 <= wall <= 30.0, f"wall {wall:.1f}s")


def exit_codes():
    env = {**os.environ, "PITHOS_CONFIG": CFG, "PITHOS_STATE": STATE}
    run = lambda *cmd: subprocess.run([os.path.join(ROOT, "pithos"), "-p", "base", "-C", PROJ,
                                       "--", *cmd], env=env, capture_output=True,
                                      text=True).returncode
    write_profile(processes=128)
    check("exit code passes through the scope", run("bash", "-c", "exit 42") == 42)
    check("signal death passes through", run("bash", "-c", "kill -TERM $$") == 143)


def concurrency():
    """Two sessions at once: separate scopes, each with its own total and its own list."""
    env = {**os.environ, "PITHOS_CONFIG": CFG, "PITHOS_STATE": STATE}
    write_profile(total="256M", memory="128M", processes=64, tmpfs="32M")
    cmd = [os.path.join(ROOT, "pithos"), "-p", "base", "-C", PROJ, "--", "bash", "-c",
           'cat "$PITHOS_LIMIT_EVENTS"; df --output=size -B1 /tmp | tail -1']
    procs = [subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, text=True) for _ in range(3)]
    outs = [p.communicate(timeout=90)[0] for p in procs]
    check("three sessions run at once, each with its own tmpfs",
          all(o.splitlines() and o.splitlines()[-1].strip() == "33554432" for o in outs),
          f"{[p.returncode for p in procs]}")



def tmpfs_counts_toward_total():
    """256 MB of tmpfs plus a 400 MB process against a 512 MB total: killed, even though the
    process alone is under the total."""
    done, _ = pithos("""
dd if=/dev/zero of=/tmp/fill bs=1M count=200 status=none
python3 -I -c '
import time
b = [bytearray(50 << 20) for _ in range(8)]
time.sleep(10)
' 
echo alive; sleep 1; cat "$PITHOS_LIMIT_EVENTS" """, total="512M", memory="512M", tmpfs="256M",
                  processes=128)
    check("tmpfs pages count toward the memory limit",
          "alive" in done.stdout and "memory\tthe kernel killed" in done.stdout,
          f"exit {done.returncode}")


def signals():
    """SIGTERM to the launcher must take the whole sandbox down and leave no scope behind."""
    write_profile(processes=64)
    env = {**os.environ, "PITHOS_CONFIG": CFG, "PITHOS_STATE": STATE}
    proc = subprocess.Popen([os.path.join(ROOT, "pithos"), "-p", "base", "-C", PROJ, "--",
                             "sleep", "60"], env=env)
    time.sleep(1.5)
    proc.terminate()
    code = proc.wait(timeout=20)

    def leftovers():
        # bwrap for this project, by argv: "pgrep -f sleep 60" would match its own command line.
        left = [pid for pid in os.listdir("/proc") if pid.isdigit() and
                open(f"/proc/{pid}/cmdline", "rb").read().replace(b"\0", b" ").find(
                    b"bwrap") >= 0 and PROJ.encode() in open(f"/proc/{pid}/cmdline", "rb").read()]
        scopes = [d for root, dirs, _ in os.walk("/sys/fs/cgroup/user.slice")
                  for d in dirs if d.startswith("pithos-")]
        return left, scopes

    left, scopes = leftovers()
    for _ in range(50):  # the sandbox goes down just after the launcher returns
        if not left and not scopes:
            break
        time.sleep(0.1)
        left, scopes = leftovers()
    check("SIGTERM to the launcher stops the sandbox", not left and not scopes,
          f"exit {code}, left {left}, scopes {scopes}")

def cleanup():
    scopes = subprocess.run(["systemctl", "--user", "list-units", "pithos-*", "--all",
                             "--no-legend"], capture_output=True, text=True).stdout
    leftovers = [l for l in scopes.splitlines() if "pithos-" in l]
    check("no scopes left behind", not leftovers, " ".join(leftovers))


def report():
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    setup()
    try:
        for scenario in (forks, memory, reserved_address_space, tmpfs, readonly, cpu, exit_codes,
                         tmpfs_counts_toward_total, signals, concurrency):
            print(f"--- {scenario.__name__}")
            scenario()
        cleanup()
    finally:
        shutil.rmtree(WORK, ignore_errors=True)
    sys.exit(report())
