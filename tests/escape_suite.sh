#!/bin/bash
# Runs INSIDE the sandbox (claude profile). Every "deny" check must fail, every "allow" succeed.
fails=0
deny()  { if (eval "$2") >/dev/null 2>&1; then echo "FAIL (escaped): $1"; fails=$((fails+1)); else echo "ok   denied:  $1"; fi; }
allow() { if (eval "$2") >/dev/null 2>&1; then echo "ok   allowed: $1"; else echo "FAIL (blocked): $1"; fails=$((fails+1)); fi; }
py() { /usr/bin/python3 -I -c "$1"; }
slug=$(pwd | sed 's/[^a-zA-Z0-9]/-/g')

deny "read ~/.ssh"                    'ls ~/.ssh || cat ~/.ssh/id_*'
deny "see other agents' state"        'ls ~/.local/share/opencode'
deny "see sandbox state/trust store"  'ls ~/.local/state/pithos'
deny "see host runtime sockets"       'ls /run/user/*'
deny "connect to session D-Bus"       'py "import socket; socket.socket(socket.AF_UNIX).connect(\"/run/user/$(id -u)/bus\")"'
deny "secret .env has content"        'test -s .env'
deny "write /usr"                     'touch /usr/escape'
deny "write claude binary dir"        'touch ~/.local/share/claude/escape'
deny "read Claude prompt history"     'test -s ~/.claude/history.jsonl'
deny "list other projects' sessions"  'ls -A ~/.claude/projects | grep -qvx -e "$slug"'
deny "read file-history snapshots"    'test -n "$(ls -A ~/.claude/file-history)"'
deny "read paste cache"               'test -n "$(ls -A ~/.claude/paste-cache)"'
deny "rewrite ~/.claude/settings.json" 'echo {} >> ~/.claude/settings.json'
deny "plant a git hook"               'echo "curl evil" > .git/hooks/pre-commit'
deny "change .git/config"             'echo "[core] hooksPath=/x" >> .git/config'
deny "rename .git away"               'mv .git .git.x'
deny "rename .claude away"            'mv .claude .claude.x'
deny "rewrite .vscode/settings.json"  'echo {} >> .vscode/settings.json'
deny "edit .pithos.toml"       'echo "[net]" >> .pithos.toml'
deny "see the real state dir"         'ls -A "$(cat .state-path)/sessions" "$(cat .state-path)/logs"'
deny "approve a host for itself"      '
s=$(cat .state-path); mkdir -p "$s/sessions"
printf "{\"%s\": [\"example.com\"]}" "$PWD" > "$s/allowed.json"
for f in "$s"/sessions/*.json; do printf "{\"allow\": [\"example.com\"]}" > "$f"; done
curl -sf --max-time 10 https://example.com'
deny "new user namespace"             'unshare -r true'
deny "see host processes"             'test "$(ls /proc | grep -c "^[0-9]")" -gt 20'
deny "DNS lookup"                     'getent hosts google.com'
deny "raw TCP socket"                 'py "import socket; socket.create_connection((\"1.1.1.1\", 53), timeout=3)"'
deny "raw UDP DNS query"              'py "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3); s.sendto(b\"x\", (\"8.8.8.8\", 53)); s.recv(1)"'
deny "HTTPS to unlisted host"         'curl -sf --max-time 10 https://example.com'
deny "bypass proxy"                   'curl -sf --max-time 10 --noproxy "*" https://api.anthropic.com'
deny "cloud metadata endpoint"        'curl -sf --max-time 10 http://169.254.169.254/'
deny "domain fronting (SNI mismatch)" 'py "
import socket, ssl
s = socket.create_connection((\"127.0.0.1\", 3128), timeout=10)
s.sendall(b\"CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n\"); assert b\" 200 \" in s.recv(4096)
ssl.create_default_context().wrap_socket(s, server_hostname=\"example.com\")"'

deny "edit the blocked list"          'echo fake.example >> "$PITHOS_BLOCKED_HOSTS"'
deny "replace the blocked list"       'mv "$PITHOS_BLOCKED_HOSTS" /run/pithos/x'
deny "rewrite the agent notice"       'echo x >> ~/.claude/CLAUDE.md'
deny "edit the blocked-files list"     'echo /opt/fake >> "$PITHOS_BLOCKED_FILES"'
deny "edit the limit list"             'echo fake >> "$PITHOS_LIMIT_EVENTS"'
deny "replace the limit list"          'mv "$PITHOS_LIMIT_EVENTS" /run/pithos/z'
deny "replace the blocked-files list"  'mv "$PITHOS_BLOCKED_FILES" /run/pithos/y'
deny "see the trace FIFO's fd"        'ls -l /proc/*/fd 2>/dev/null | grep -q "trace.fifo"'
deny "publish socket without --publish" 'test -e /run/pithos/publish.sock'
cat "$(printf '/opt/pithos-a\n/opt/forged\tnot mounted')" 2>/dev/null
cat /opt/pithos-probe 2>/dev/null
sleep 1  # the launcher reads strace's output asynchronously
deny "forge a line in the blocked-files list" 'grep -qx "/opt/forged	not mounted" "$PITHOS_BLOCKED_FILES"'

deny "raise the process limit"        'ulimit -Hu $(( $(ulimit -Hu) + 1 ))'
deny "remove the memory limit"        'ulimit -Hd unlimited'
deny "enable core dumps"              'ulimit -c 1'
deny "write to the sandbox root"      'touch /escape-root'
deny "write to /dev"                  'touch /dev/escape'
deny "rename /home away"              'mv /home /home.x'
allow "home and /tmp are sized"       'test "$(df --output=size -B1 /tmp | tail -1)" -lt "$(awk "/MemTotal/ {print \$2 * 1024 / 2}" /proc/meminfo)" && test "$(df --output=size -B1 ~ | tail -1)" -lt "$(awk "/MemTotal/ {print \$2 * 1024 / 2}" /proc/meminfo)"'
allow "shared memory works"           'py "from multiprocessing import shared_memory as s; m = s.SharedMemory(create=True, size=1 << 20); m.close(); m.unlink()"'
# Bounded: lowers its own limit to 40 tasks and tries at most 60 short-lived children. Passes
# only if the limit stops it, which means only the sandbox's tasks are counted (the host has more).
allow "process limit counts only the sandbox" 'py "
import resource, subprocess
resource.setrlimit(resource.RLIMIT_NPROC, (40, resource.getrlimit(resource.RLIMIT_NPROC)[1]))
kids = []
try:
    for _ in range(60):
        kids.append(subprocess.Popen([\"sleep\", \"5\"]))
except OSError:
    pass
for k in kids:
    k.kill(); k.wait()
assert 5 < len(kids) < 40, len(kids)"'

allow "blocked host is reported"      'grep -q "^example.com:443" "$PITHOS_BLOCKED_HOSTS"'
allow "agent is told about blocks"    'grep -q "pithos allow" ~/.claude/CLAUDE.md'
allow "agent is told about files"     'grep -q "$PITHOS_BLOCKED_FILES" ~/.claude/CLAUDE.md'
allow "agent is told about limits"    'grep -q "$PITHOS_LIMIT_EVENTS" ~/.claude/CLAUDE.md'
allow "unmounted file is reported"    'grep -qx "/opt/pithos-probe	not mounted" "$PITHOS_BLOCKED_FILES"'
allow "read-only write is reported"   'grep -qx "/usr/escape	read-only" "$PITHOS_BLOCKED_FILES"'
allow "secret probe is reported as hidden" 'grep -q "/\.ssh.*	hidden on purpose$" "$PITHOS_BLOCKED_FILES"'
allow "escaped newline stays escaped" 'grep -qF "/opt/pithos-a\\x0a/opt/forged\\x09not mounted	not mounted" "$PITHOS_BLOCKED_FILES"'
allow "HTTPS to allowed host"         'test "$(curl -s -o /dev/null -w "%{http_code}" --max-time 20 https://api.anthropic.com/v1/models)" = 401'
allow "write in project"              'echo ok > written-inside.txt'
allow "git works"                     'git status'
allow "python venv works"             '~/.venv/bin/python -c "import playwright"'
allow "write own session dir"        'touch ~/.claude/projects/$slug/.escape-test'
allow "claude binary runs"            'claude --version'

echo "$fails failure(s)"
exit $((fails > 0))
