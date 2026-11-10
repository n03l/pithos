# pithos

*Pithos* (πίθος) is the jar from the Pandora myth: what is inside stays inside.

`pithos` runs an AI coding agent (Claude Code, opencode, or any command) in a
[bubblewrap](https://github.com/containers/bubblewrap) sandbox. The limits apply to the agent
**and to everything it starts**: shell commands, scripts it writes, test runners, package installs.

- **Files**: the sandbox starts empty. It sees only the paths its profile lists, read-only or
  writable. Everything else, including `~/.ssh`, other repos and the host's sockets, does not exist.
- **Network**: the sandbox has no network at all, only loopback. Its one way out is a proxy on
  the host that allows the hosts you list. Code that ignores `HTTPS_PROXY` just fails.
- **Resources**: total memory, processes (threads included), CPU, and the size of the in-memory
  directories are capped. A fork bomb, a memory leak or a script filling `/tmp` hits the limit,
  not your machine, and the agent is told which one.

```text
pithos ─┬─► bwrap ─► bridge.py ─► claude / opencode / anything
        │              │    ▲                 │
        │              │    └─────────────────┘ 127.0.0.1:3128
        │              │ UNIX socket
        └─► proxy.py ◄─┘   (host side: allowlist, log)
               └─► allowed hosts only
```

HTTPS is never decrypted. Clients send `CONNECT host:443`, the proxy checks the name, then relays
the encrypted bytes, so certificates validate normally.

**Contents:** [Install](#install) · [Usage](#usage) ·
[Web UI and servers](#web-ui-and-servers-in-the-sandbox) · [When a host is blocked](#when-a-host-is-blocked) ·
[When a file is refused](#when-a-file-is-refused) · [Resource limits](#resource-limits) ·
[Profiles](#profiles) · [SSH](#ssh) · [Security model](#security-model) ·
[Reviewing a session](#reviewing-a-session) · [Upgrading](#upgrading) · [Tests](#tests)

## Install

```sh
sudo apt install bubblewrap
sudo apt install strace          # optional: the file notice and --trace
./install.sh            # links ~/.local/bin/pithos, copies profiles to ~/.config/pithos
```

`strace` is optional: without it, the agent isn't told which file accesses the sandbox refused
(see [When a file is refused](#when-a-file-is-refused)). [Resource limits](#resource-limits) need
a systemd user session: without one `pithos` refuses to start, unless you disable them.
bubblewrap 0.6 or newer is needed for the sized tmpfs mounts; older versions are refused at
start-up.

Aliases for the common cases:

```sh
alias cs='pithos -p claude -- claude'
alias ocs='pithos -p opencode -- opencode --standalone'
alias occ='pithos -p opencode-claude -- opencode --standalone'   # opencode with claude-agent models
```

`--standalone` keeps opencode's server inside the sandbox, one per project. Don't connect a
sandboxed project to a server running on the host: that server's tools run outside the sandbox.

## Usage

```sh
cd ~/src/myproject
pithos claude                 # profile guessed from the command name
pithos -p opencode -- opencode run "fix the tests"
pithos -p base                # a shell, to look around
pithos --dry-run claude       # print the bwrap command line
pithos --no-file-notice ...   # skip the file notice, faster builds
pithos --no-limits ...        # run without a cgroup: no total memory or CPU limit
```

The project directory (default: the current one, or `-C PROJECT`) is writable. It can't be your
home directory or a directory that contains your config.

Inside `tmux`, `pithos` names the window after the agent (e.g. `claude`). That needs the
`tmux` setting `setw -g allow-rename on`.

## Web UI and servers in the sandbox

The sandbox has its own network, so a server started in it can't be reached from the host.
`--publish` opens one port on the host and relays it to the same port inside:

```sh
cd ~/src/myproject
pithos -p opencode --publish 4096 -- opencode serve --hostname 127.0.0.1 --port 4096
# open http://localhost:4096 and log in with the "server password" opencode prints
```

- `--publish PORT` listens on `127.0.0.1:PORT`. `--publish IP:PORT` (or `[IPv6]:PORT`)
  listens on that address instead, for example your LAN address, and `pithos` warns: anyone who
  can reach it can use the server, so keep its password on. Host names, `0.0.0.0` and `3128`
  (the sandbox's proxy port) are refused.
- The server inside must listen on `127.0.0.1` and on the same port.
- Run one sandbox per project, each with its own port. Each project then stays in its own
  sandbox, and the browser keeps them apart because each port is its own origin.
- Over SSH, forward the port: `ssh -L 4096:localhost:4096 host`. Another local port works too
  (`-L 8080:localhost:4096`).
- `--publish` is a command-line option only: neither a profile nor `.pithos.toml` can open a
  port.

Only requests a browser would send for a page loaded from that port get through. The first request
on each connection must name this machine in `Host` (`localhost`, `127.0.0.1`, `::1` or the
address you gave). It must not come from another origin (`Origin`) or another site
(`Sec-Fetch-Site`). This keeps out DNS rebinding and other web pages that try to drive the agent
through your browser. Refused requests get `403` and appear in `pithos log`. A program, unlike a
browser, can send any header: that is what the server's own password is for.

Don't point a sandboxed project at an opencode server running on the host: that server's tools
run outside the sandbox. Publishing works the other way round, with the server and its tools
inside.

## When a host is blocked

Sooner or later a tool will need a host that isn't on the list. Most tools hide the proxy's
explanation and report a generic network error, so `pithos` also tells the agent directly.
Inside the sandbox, `/run/pithos/blocked-hosts` (also in `$PITHOS_BLOCKED_HOSTS`) is a
read-only list of the hosts refused in this session, one `host:port<TAB>reason` per line.

The `claude`, `opencode` and `opencode-claude` profiles instruct the agent to read that file when
the network fails, then tell you which host was blocked and that you can run `pithos allow`.
Claude Code gets the instruction through a read-only view of `~/.claude/CLAUDE.md`
(`agent.notice_into`; your file isn't changed), and opencode through `OPENCODE_CONFIG`.

### Allowing a host while a session runs

Run these in a second terminal, outside the sandbox, from the project directory or with
`-C PROJECT`:

```sh
pithos allow                       # asks about each host denied so far: [y]es / [s]ave / [N]o
pithos allow example.com           # allow directly (port 443 unless you give one)
pithos allow --save example.com    # also keep it for future sessions of this project
pithos allow --remove example.com  # revoke; connections already open stay open
pithos allow --list                # what's approved, per session and saved
```

The session keeps running, and its next connection uses the new rules. A request that was already
refused stays refused, so the agent has to retry it.

An approval applies to every running session of that project and lasts until the session ends,
unless you save it. Saved hosts are kept per project path in `~/.local/state/pithos/allowed.json`,
and a session lists them when it starts. They stay separate from your profiles, so `--remove` can't
touch hosts listed in a profile or `.pithos.toml`.

The prompt offers only exact host names with their port. Read each name before you approve it: the
sandbox picks which names get denied, and it can ask you for a host it wants to send data to.

Approvals are stricter than profiles. `pithos allow` refuses private, loopback and link-local IP
addresses and very broad wildcards like `*.com`. Put an entry in a profile if you really mean it.

To allow a host permanently for every project using a profile, run `pithos log --denied`, which
prints the refused hosts ready to paste, and add the line to the profile.

## When a file is refused

A file the profile doesn't mount simply doesn't exist in the sandbox, so a tool fails with "No
such file or directory" and the agent can't tell a missing file from a sandbox rule. `pithos`
watches failed file operations with `strace` from outside the sandbox and lists the ones the
sandbox caused in `/run/pithos/blocked-files` (also in `$PITHOS_BLOCKED_FILES`), one
`path<TAB>reason` per line:

| Reason | Meaning |
|---|---|
| `not mounted` | The path is outside every mount, for example in your home directory or `/opt` |
| `read-only` | A write to a read-only mount, such as `/usr` or `.git/hooks` |
| `hidden on purpose` | A path in `fs.deny`, or credentials such as `~/.ssh` or `.env` |

The file is read-only in the sandbox and the agent profiles tell the agent to read it, the same
way as for blocked hosts. Paths are classified from the profile alone: `pithos` never checks
whether a path the sandbox asked for exists on your machine, since that would tell the sandbox.
So the list also holds normal lookups of optional files, such as `~/.curlrc` or
`~/.config/git/config`: Claude Code alone makes about 500 at start-up. Lookups along `PATH` and
upward searches from the project (`node_modules`) are left out. Each top-level directory
(`~/.npm`, `/etc`) gets at most 100 lines, then one `dir/*` line, so a noisy tool can't push out
the path that matters; the agent is told to search the list for a path rather than read it whole.

To mount a path, add it to `fs.ro` or `fs.rw` and restart the session.

**Cost.** `strace` stops only on file syscalls (`--seccomp-bpf`), so the agent itself barely slows
down, but work that is mostly `stat` and `open` runs about twice as slow: builds, test suites,
`git status` on large trees. Turn it off for a session with `--no-file-notice`, or for a profile
with:

```toml
[agent]
file_notice = false
```

It is also off when `strace` is missing, or when `kernel.yama.ptrace_scope` is 2 or more. It
misses file accesses made through `io_uring`.

## Resource limits

A fork bomb, a memory leak in a test suite or a script filling `/tmp` shouldn't take your machine
down. The sandbox runs in its own systemd scope (a cgroup v2), so the kernel enforces the limits
exactly and immediately:

| Limit | Default | Enforced by |
|---|---|---|
| `total` | 75% of RAM | `MemoryMax` for the scope, swap excluded. Files in tmpfs count |
| `processes` | 15% of `ulimit -u`, at least 512 | `TasksMax`. Threads count too, and a refused start is refused, not killed |
| `cpu` | `100%` (all the CPUs, so no quota) | `CPUQuota`, in percent of one CPU, like systemd: `"200%"` is two CPUs |
| `memory` | 50% of RAM, per process | `RLIMIT_DATA`, inside the sandbox |
| `tmpfs` | 25% of RAM, for each of `~`, `/tmp`, `/var/tmp`, `/dev/shm` | Sized tmpfs mounts (they are RAM). `/` and `/dev` are read-only |

`systemd-run --user --scope` creates the scope, so `pithos` needs a systemd user session:
run it from a login shell or `tmux`. Without one it **refuses to start**, and says so; pass
`--no-limits` (command line only, never a profile or `.pithos.toml`) to run anyway, with only
the per-process memory limit, the process limit and the tmpfs sizes.

Core dumps are always off: they would hold the agent's memory, keys included. The sandbox can
lower these limits but never raise them.

"RAM" is the machine's memory, or your cgroup's memory limit if lower (in a container), so the
defaults fit wherever `pithos` runs. Set your own in a profile:

```toml
[limits]
processes = 4096      # a count, "N%" of ulimit -u, or "none"
memory = "16G"        # "N%" of RAM, an amount (K, M, G, T), or "none"
total = "none"        # the same, for the whole sandbox
tmpfs = "10%"
cpu = "200%"          # percent of one CPU, "2" for two CPUs, or "none"
```

Values above what the machine has are lowered, with a warning, and so is a per-process
`memory` above `total`, which could never be reached before the sandbox limit. `pithos -v` prints
the values in use, and `pithos --dry-run` shows the `systemd-run` line.

### When a limit is hit

The agent is told the limits, and that "Resource temporarily unavailable", "Cannot allocate
memory", "No space left on device" or "Killed" (exit code 137) can come from them. It's also
told about `/run/pithos/limit-events` (also in `$PITHOS_LIMIT_EVENTS`), a read-only file it can
read after such a failure: one `time<TAB>limit<TAB>what happened` line each time a limit stopped
something, written by `pithos` from the scope's own event counters. Every byte in it is text
and numbers from `pithos`: the sandbox can only make a line appear.

An out-of-memory kill takes the one process that grew too far (the scope's `OOMPolicy` is
`continue`), not the whole sandbox. The kernel doesn't say which process it killed, only that
it did, so the agent matches the time against the command that died. `pithos report` shows the
limits a session ran under, and how often the memory and process limits were hit; CPU and tmpfs
throttling have no such counter. Disk use in the project directory is not limited.

## Profiles

A profile is a file at `~/.config/pithos/<name>.toml`. These are installed by default:

| Profile | For | Notes |
|---|---|---|
| `base` | A shell or any other command | The agent profiles build on it |
| `claude` | Claude Code | Mounts its login and this project's transcripts only |
| `opencode` | opencode with API-key providers | Data, state and cache are per project |
| `opencode-claude` | opencode with `claude-agent` models | `opencode` plus the Claude Code binary and login |

A profile can `extends` another, and lists are appended. All the settings:

```toml
extends = "base"

[fs]
ro   = ["~/.opencode"]                 # read-only; absolute, "~/..." or "{project}/..."
rw   = ["~/.cache/mytool"]             # writable
rw_mkdir = ["~/.claude/projects/{project_slug}"]  # writable, created if missing
copy = ["~/.claude.json"]              # writable private copy, discarded on exit
deny = ["~/.aws", "{project}/**/*.pem"]  # hidden even inside allowed paths (globs ok)
ro_in_project = [".git/hooks"]         # read-only inside the writable project (skipped if it isn't writable)

[net]
allow = ["api.example.com", "*.example.org", "github.com:22"]   # port defaults to 443

[env]
pass = ["GOOGLE_GENERATIVE_AI_API_KEY"]  # copied from your environment; nothing else is
set  = { PATH = "~/.opencode/bin:/usr/bin:/bin" }

[ssh]                                   # optional, see SSH below
key = "~/.ssh/id_deploy"
```

`{project_slug}` is the project path with every character except ASCII letters and digits
replaced by `-`, the name Claude Code uses under `~/.claude/projects`.

To give an agent another directory, add it to `ro` or `rw`.

### Per-project rules

Put the same sections (no `extends`) in `<project>/.pithos.toml`. The agent and the
authors of repos you clone can both write that file, so it only applies once you approve it:

```sh
pithos trust      # shows the file and what it adds, records its hash
```

If the file changes, the launcher refuses to start until you trust it again. Inside the
sandbox the file is read-only.

### Agent-specific behavior

**Claude Code** (`claude`, `opencode-claude`):

- Prompt history, `/rewind` checkpoints and todos last only as long as the sandbox. Transcripts
  persist, so `claude --resume` works.
- With `.claude/settings.local.json` read-only, Claude Code can't save "don't ask again" choices
  made inside the sandbox.

**opencode** (`opencode`, `opencode-claude`):

- opencode's data, state and cache live per project under `~/.local/share/pithos-opencode/`,
  including any plugin data there, such as a memory plugin's notes
  (`<slug>/data/opencode-memory/`).
- A login made with `opencode auth` outside the sandbox is not visible inside: pass an API key
  instead.

**`opencode-claude`** is for `claude-agent` models, with the same per-project limits as the
`claude` profile. Use plain `opencode` for other providers. opencode's connection list is per
project, so this profile adds the `claude-agent` connection the first time opencode starts in a
project (`agent.connect_claude_agent`; no secret is stored).

## SSH

Keys are never visible in the sandbox. By default, let the agent commit and push yourself.
For pushing from inside, use a dedicated deploy key:

```toml
[net]
allow = ["github.com:22"]
[ssh]
key = "~/.ssh/id_agent_deploy"        # loaded into a private ssh-agent for this session only
known_hosts = "~/.ssh/known_hosts"    # copied in; host keys are checked strictly
```

Git then uses `ssh` through the proxy. The agent can use the key but never read it, and only
on allowlisted hosts.

## Security model

### What is protected, and how

| Threat | Protection |
|---|---|
| Reading keys, tokens, other repos | Only listed paths are mounted. `deny` hides paths inside them, and the launcher refuses to mount anything inside a denied path. |
| Reading other sessions | The `claude` profile mounts only `.credentials.json` and this project's `~/.claude/projects/<slug>`. History, other projects' transcripts and memory, `file-history` and `paste-cache` stay on the host; the rest of `~/.claude` is a fresh tmpfs. |
| Rewriting its own sandbox | The config dir, the trust store and the runtime sockets are never mounted. Binding them, `~`, `/`, `/run` or `/tmp` writable is refused. |
| Code that runs later, outside the sandbox | `.git/hooks`, `.git/config` (also for submodules under `.git/modules`), `.claude/settings*.json`, `.mcp.json`, `opencode.json`, `.envrc`, `.vscode/{settings,tasks,launch}.json` and `~/.claude/settings.json`, plugins and skills are read-only, and their parent directories can't be renamed away. Ones missing at start-up are moved aside after the session if the sandbox created them. |
| Symlink tricks in the project | Links resolve inside the sandbox, so they can't reach unmounted paths. A `ro_in_project` entry that links outside the project is refused. |
| Exfiltration to arbitrary hosts | Only the allowlist is reachable: no DNS, no raw sockets, no UDP. |
| Approving its own hosts | Approvals live in the state dir, which is never mounted. The sandbox can only get a name denied; you decide from outside. Private and loopback IPs can't be approved this way. |
| DNS rebinding, cloud metadata | A host name that resolves to a private, loopback or link-local address is refused. |
| Domain fronting | On port 443 the TLS SNI must equal the host in `CONNECT`. |
| Web pages driving a published server | `--publish` checks `Host`, `Origin` and `Sec-Fetch-Site` on the host, before anything reaches the sandbox. Only the command line can publish a port. |
| Host sockets (D-Bus, ssh-agent, docker, X11) | `/run`, `/tmp` and `$XDG_RUNTIME_DIR` are fresh in the sandbox. |
| Fork bombs, runaway memory, filling `/tmp` | The sandbox runs in a systemd scope with `TasksMax`, `MemoryMax` and `CPUQuota`, plus per-process memory and tmpfs limits; see [Resource limits](#resource-limits). |
| Escaping via namespaces or the terminal | `--disable-userns`, its own PID namespace, `--new-session` unless the kernel already blocks TIOCSTI. |

### Limits to keep in mind

- **An allowed host can receive data.** `github.com` lets the agent push to any repo your
  credentials reach, or post a gist. Keep the list short and the credentials narrow.
- **The agent can read its own credentials**: `~/.claude/.credentials.json` and any API keys
  you `pass`.
- **The project is agent-written code.** Review the diff before you run `make`, `npm test` and
  so on outside the sandbox.
- **Protected files that don't exist yet can be created.** `ro_in_project` paths that are missing
  at start-up (say, the project has no `.git` yet) can be created during the session. When it
  ends, the launcher moves them aside to `<path>.pithos-quarantine-<session>` and warns. Until
  then, don't run `git` or the agent on the host in that project.
- **Saved approvals follow the project path, not its contents.** A different repo later placed at
  the same path gets them too. Check with `pithos allow --list`.
- **`deny` globs are expanded at start-up.** Files created later are not hidden.
- **`~/.claude.json` is readable.** The `claude` and `opencode-claude` profiles give the sandbox a
  private copy. The agent can read your other project paths and their settings there, but its
  changes are discarded on exit.

## Reviewing a session

Each session leaves a proxy log, `<session>.jsonl`, in `~/.local/state/pithos/logs/`. Run with
`--trace` to also get a file trace, `<session>.trace`, next to it. Both are written from outside
the sandbox, which can't reach that directory.

```sh
pithos --trace claude                 # record file accesses as well as network
pithos report                         # the latest session
pithos report --session 20260101-120000-abc123   # one session; the ID is the log's file name
pithos report --all                   # every session combined
pithos report --explain > notes.md    # report on stderr, the model's Markdown on stdout
```

`pithos report` is offline and rule-based. Without a trace, the detailed file sections are
skipped, but what the file notice saw still appears: hidden paths the agent tried, and refused
paths you might want to mount. For the raw data, `pithos log` prints the events of the last
session, `pithos log --denied` the refused hosts and `pithos log --files` every traced path.

### Reviewing for security

Read the `SECURITY REVIEW` part of the report, most serious sections first:

| Section | What it means | What to do |
|---|---|---|
| Network, policy violations | A TLS SNI that didn't match the requested host, a name resolving to a private address, or an invalid host | Rarely accidental: find out what made the request |
| Sensitive paths touched | Credentials such as `.ssh`, `.aws` or `.env`, or a path in `fs.deny`. `missing` still counts, because those files don't exist in the sandbox and a probe fails with "not found" | Check why the agent looked there |
| Protected project files, write attempts | Attempts on `.git/hooks` or `ro_in_project` paths, which would run later outside the sandbox | Treat as suspicious unless the task explains it |
| Quarantined paths | The sandbox created a protected file, which was moved aside | Inspect it before using it |
| Hosts tried and refused | Names not in `net.allow` | Look for hosts unrelated to the task, such as paste sites |
| Hidden paths the agent tried | Credentials or `fs.deny` paths the file notice saw (without `--trace` too) | Check why the agent looked there |
| Hosts contacted | Allowed connections, with counts | Check the volume looks right for the work |
| Other refused file accesses | Other failed accesses, often harmless (`/dev/tty`) | Scan for patterns |

An empty report doesn't prove a session was clean. The proxy never decrypts TLS, so the log shows
hosts and not what was sent to them: data could still leave through an allowed host. See
[Tracing file accesses](#tracing-file-accesses) for what a trace misses.

### Debugging and tuning a profile

When a tool fails with a network error or can't find a file, run it again with `--trace`, then
read `PROFILE TUNING`:

- **Hosts to consider allowing** are ready to paste into `[net] allow`. Add only the ones you
  expect, or approve one for a running session with `pithos allow`.
- **Looked for, absent in the sandbox, present on the host** are candidates for `fs.ro`. Review
  each one first. Some are normal, like a symlink whose target isn't mounted.
- **Refused file accesses the agent was told about** are the same idea from the file notice, so
  they appear without `--trace` too.
- **Allowed but unused** is evidence from the sessions covered, not a reason on its own to remove
  a rule. Use `--all` over several sessions of the same profile and project before pruning.

These checks use the rules recorded when the session started. Logs from older versions fall back
to the profile as it is now. The checks are skipped when the rules can't be read or `--all` mixes
different rules or projects.

### Tracing file accesses

`pithos --trace CMD` records every file access, not only the failed ones the file notice needs,
and writes the trace to the logs directory, readable only by you (`strace` must be installed).
`pithos log --files` then lists the paths of the last traced session in four groups, with
counts:

- `written` and `read`;
- `missing`: not found, often because the profile doesn't mount them;
- `refused`: other errors, such as writing to a read-only path.

Add `--all` to combine every trace. Paths are as seen inside the sandbox, and relative ones appear
as the program wrote them.

Tracing slows the program down. The trace includes full `execve` command lines, so a secret passed
as an argument ends up in it, but environment values don't. It is a debugging aid for tuning
profiles, not a security audit: file opens made through `io_uring` don't appear, and each open is
recorded rather than each read or write.

### Explaining a session with a model

`pithos report --explain` collects the conversation from the session's time window, from both
Claude Code transcripts and opencode's history, and asks the agent that ran the session, using its
default model and the same profile, which can be one of your own. Both come from the session's
log. Only sessions that ran `claude` or `opencode` can be explained. It asks which findings look
concerning, what the agent was doing at the time, and which allowlist changes the evidence
supports. It works on one session at a time. The report and progress messages go to stderr,
and stdout holds only the explanation in Markdown.

The report and conversation text go to the model provider, so use it only where that's acceptable.
Treat the answer as a lead to verify: the model read untrusted text and can misread the report.

It starts a normal `pithos run`, so it needs the same systemd user session as any other run.

The agent runs in a scratch directory wiped after each run. Its profile's hosts are used without
the ones inherited from `base`, such as GitHub and PyPI, except that opencode keeps
`registry.npmjs.org`, which supplies its provider. With `claude`, the only tool is `Read`. The
agent's own profile still applies otherwise, so it can use that agent's login and reach its API
hosts.
opencode's history is read from a private copy of its database, found through the `XDG_DATA_HOME`
the session logged at start, and only the messages are taken.

## Upgrading

`install.sh` never overwrites your profiles, so new settings don't reach an existing install on
their own. Re-run it to pick up new profiles. If your profiles predate these features, add them
by hand:

| Feature | File | Add |
|---|---|---|
| Blocked-host notice | `claude.toml`, `opencode-claude.toml` | `notice_into = "~/.claude/CLAUDE.md"` under `[agent]` |
| Blocked-host notice | `opencode.toml` | `OPENCODE_CONFIG = "/run/pithos/opencode.json"` in `env.set` |
| `claude-agent` connection | `opencode-claude.toml` | `connect_claude_agent = true` under `[agent]` |

The file notice and resource limits need no profile change: the notice is on unless a profile
sets `file_notice = false`, and the limits use their defaults unless a profile sets `[limits]`.

## Tests

```sh
~/.venv/bin/python -m pytest tests              # unit: config, mounts, proxy, hostile input
tests/run_escape_suite.sh                        # runs real escape attempts inside a sandbox
~/.venv/bin/python tests/stress_limits.py        # bounded stress test of the resource limits
```

The stress test lowers the limits in a throwaway profile and stays bounded (a few hundred short
lived processes, about 2 GB allocated), so it is safe to run on a working machine.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
