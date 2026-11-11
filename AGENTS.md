# AGENTS.md

`pithos` runs an AI coding agent (Claude Code, opencode, any command) and everything it
spawns inside a bubblewrap sandbox. Files are allowlisted, and the only network exit is a proxy
that allowlists host names. User-facing docs are in `README.md`.

## Layout

Flat on purpose: no package directory. Use only the Python standard library (3.11+ for `tomllib`).

- `pithos`: the single entry point (subcommands `run`, `trust`, `log`, `allow`, `report`). It
  builds the sandbox plan and the `bwrap` command line, starts the proxy and runs the session
  (`run_session`), and handles `allow`. It imports the modules below from its own directory
  (it runs with `-I`); none of them imports `pithos`.
- `config.py`: what the other modules share (`ConfigError`, `clean()`, `note()`, where things
  are inside the sandbox), the profile schema, loading profiles and `.pithos.toml`, the trust
  store, and the checks on every path a profile names.
- `resources.py`: `[limits]`, the systemd scope that enforces them, and the limit list for the
  agent (`LimitEvents`, `ScopeMonitor`).
- `filetrace.py`: `strace` and its output, and the file notice for the agent (`SandboxView`,
  `BlockedFiles`, `TraceWatcher`).
- `report.py`: `pithos report`, and the log parsing `allow` shares.
- `proxy.py`: host-side allowlisting proxy. It handles `CONNECT` tunnels with a TLS SNI check,
  plain `http://` forwarding and the JSON-lines log. `LiveAllowlist` adds hosts approved during
  a session by re-reading the state files when they change. `CappedFile` is the append-only,
  capped writer behind all three lists the agent reads.
- `publish.py`: `--publish`, host side. It parses the value, checks the first request head of
  each connection, and pairs it with a connection the bridge opens to `publish.sock`
  (`PublishServer`).
- `bridge.py`: runs inside the sandbox under `/usr/bin/python3 -I`. It makes the trace start
  probe (`TRACE_START`), sets the rlimits, relays `127.0.0.1:3128` to the proxy socket, answers
  `--publish` tokens, then execs the command. Keep it tiny and stdlib-only.
- `profiles/*.toml`: default profiles (`base`, `claude`, `opencode`, `opencode-claude`).
  `install.sh` copies them to `~/.config/pithos/` and never overwrites the copies there.
- `tests/`: unit tests (`test_config.py`, `test_proxy.py`, `test_publish.py`), the escape suite
  (`escape_suite.sh` runs inside the sandbox, `run_escape_suite.sh` drives it from the host) and
  `stress_limits.py`, a bounded end-to-end stress test of the scope limits (fork storm, OOM kill,
  per-process limit, tmpfs, CPU quota, signals, concurrent sessions).

## Commands

```sh
~/.venv/bin/python -m pytest -q tests        # unit tests, about 5 s, no bwrap needed
tests/run_escape_suite.sh                    # real sandbox; needs bwrap; must print "0 failure(s)"
~/.venv/bin/python tests/stress_limits.py    # bounded stress test of the limits
./pithos --dry-run -C <project> claude   # inspect the generated bwrap argv
```

Environment overrides, for tests and development:

- `PITHOS_CONFIG`: profile directory. Point it at `profiles/` to test repo changes
  without installing.
- `PITHOS_STATE`: trust store and logs.
- `PITHOS_BWRAP`: path to a `bwrap` binary.

## Security invariants: don't weaken these

Any change that touches one of these needs a test, both a hostile case and a normal one.

- **Filesystem is allowlist-only.** The sandbox starts empty. `/run`, `/tmp`, `/proc`, `/sys`,
  `/dev` and `/` are never bound from the host. Host sockets live there, and `connect()`
  works even through a read-only bind.
- **The sandbox can't change its own rules.** Never mount these writable, and never mount
  them at all where avoidable:
  - the config dir;
  - the state dir (trust store, logs, `--trace` files);
  - the runtime dir (proxy socket);
  - `$HOME` itself.
- **Other sessions stay out.** The `claude` and `opencode-claude` profiles never mount `~/.claude`
  as a whole: only `.credentials.json`, the read-only user config and `projects/{project_slug}`.
  History, other projects' transcripts and memory, `file-history` and `paste-cache` stay outside.
- **Project config fails closed.** `.pithos.toml` applies only when its SHA-256 matches
  the trust store. It is always bound read-only, may not use `extends`, and must not be a symlink.
- **`deny` wins.** Plain `deny` paths also refuse any bind inside them. `ro_in_project`
  entries must resolve inside the project, so a symlink to `~/.ssh` is refused. Their parent
  directories (`.git`, `.claude`) are bound onto themselves so they can't be renamed away and
  recreated. That pin is writable, so it only happens where the closest profile bind above the
  entry is writable (`enclosing_mode`): in a read-only or unbound project the entries are
  skipped. A parent that is a symlink is refused. Entries missing at start-up are moved aside
  after the session if they appeared (`quarantine`). Submodule git dirs under
  `.git/modules` get the same protection as `.git` (`GITDIR_FILES`); new ones are quarantined.
  Deny globs escape `{project}` and `~`, and a denied symlink also hides its target wherever a
  bind shows it.
- **Binds mount what was checked.** Every profile bind (pins included) is opened by
  `open_nofollow`, one path part at a time with `O_PATH|O_NOFOLLOW`, just before `bwrap`
  starts, and passed as `--bind-fd`/`--ro-bind-fd`. Sources are realpaths, so a link means the
  path changed after `build_plan`: refused. Otherwise another session writing the same project
  could swap `.git/hooks` for a link to `~/.ssh` between the checks and the mount.
- **Network fails closed.** The sandbox has its own net namespace with loopback only. The proxy:
  - requires an allowlist match on host and port;
  - rejects names that resolve to non-public addresses (IP literals pass only if listed);
  - requires on port 443 that the ClientHello SNI equal the `CONNECT` host;
  - never decrypts TLS.
- **The blocked-hosts list is one-way.** Only the proxy writes it (`BlockedList`). It is a single
  file bound read-only at `/run/pithos/blocked-hosts`, never the runtime dir. It holds normalized
  host names and fixed reasons only, is capped, and is appended to in place because the bind
  pins the inode. The agent notice (`agent.notice_into`) is a read-only overlay, and
  `.pithos.toml` may not set it.
- **Published ports only let browsers in from their own origin.** `--publish` is command line
  only: no profile key, and `.pithos.toml` can't set it.
  - The address is one IP literal: no host names, no `0.0.0.0` or `::`, never `PROXY_PORT`.
    A non-loopback address prints a warning.
  - The host, never the sandbox, checks each connection's first request head before any byte
    reaches the sandbox. It requires exactly one `Host` naming loopback or the bound address,
    an `Origin` (if sent) equal to `http://` + `Host`, and a `Sec-Fetch-Site` (if sent) of
    `same-origin` or `none`.
  - Host sockets never enter the sandbox: the host relays bytes to a connection the bridge
    opens to `publish.sock`, which is bound alone and read-only.
  - The control channel is a `SEQPACKET` socketpair. The host only sends on it, and the bridge
    closes it before exec.
  - Tokens pair connections; they are not secrets, because the agent can take the bridge's fds.
  - Pending and open connections are capped, and so are the refusals logged.
- **Approvals only come from outside the sandbox.** `pithos allow` writes
  `sessions/<session>.json` and `allowed.json` in the state dir, and nothing else feeds
  `LiveAllowlist`. Approved hosts pass the same proxy checks as listed ones:
  - `check_live_entry` runs on both write and load, and refuses non-public IP literals and
    single-label wildcards;
  - a damaged source adds nothing;
  - denied names in the logs are chosen by the sandbox, so the prompt offers only well-formed
    host names refused for not being listed, and it defaults to No.
- **Environment is cleared (`--clearenv`).** Only `env.pass` names are copied in. The proxy
  variables are set last so profiles can't override them. Values reach `bwrap` via `--args FD`,
  never its argv (`/proc/<pid>/cmdline` is world-readable), and `--dry-run` redacts them.
- **Tracing leaks no environment.** `strace_argv` must never pass `-v`, or `execve` lines would
  record env values. The `--trace` log is created 0600 with `O_EXCL|O_NOFOLLOW` in the logs dir.
  Its content is chosen by the sandbox, so `pithos log --files` prints it through `clean()`.
- **The file notice is one-way and never asks the host.** `strace` runs outside the sandbox and
  writes to a FIFO in the runtime dir, which is never mounted; `TraceWatcher` reads it. The list
  works like the blocked-hosts list: only `BlockedFiles` writes it, it is a single file bound
  read-only at `/run/pithos/blocked-files`, appended in place, capped, with fixed reasons and
  paths made one line of printable text by `clean(path, keep="")`. `SandboxView` classifies from
  the plan only: never `stat` a path the sandbox named on the host, which would tell it which
  host paths exist (and can hang on FUSE or autofs). Denied and sensitive paths are always
  reported as `hidden on purpose`, never as `not mounted`, so the agent isn't led to ask for
  them. `shown_path` shortens a `not mounted` path to its first unmounted level, never to a
  dir that holds a mount or a hidden path. Everything before the start probe from `bridge.py`
  is setup done by `bwrap` and is ignored.
- **Resource limits can't be loosened from inside.** Every writable tmpfs is sized, and `/` and
  `/dev` (the unsized tmpfs that `bwrap` mounts) are remounted read-only after every mount.
  `bridge.py` sets soft and hard rlimits equal (`RLIMIT_CORE` 0, `RLIMIT_DATA`, and
  `RLIMIT_NPROC` with
  `--no-limits`), never above an existing hard limit. `[limits]` is profile-only: `.pithos.toml`
  may not set it, and `--no-limits` is command line only. The limits themselves are the kernel's,
  through a systemd scope; `systemd-run` is only taken from `/usr/bin` or `/bin`, never `PATH`.
  Without a scope `pithos` refuses to start unless `--no-limits`, so a broken systemd setup fails
  closed instead of silently dropping the memory limit.
- **The limit list is one-way and contains no sandbox text.** `LimitEvents` is the only writer of
  `/run/pithos/limit-events`, a single file bound read-only and appended in place. Each line is a
  time, a fixed sentence and numbers from counted events: nothing from the sandbox reaches it.
  `ScopeMonitor` only reads the scope's `memory.events` and `pids.events` (numbers, `O_NOFOLLOW`)
  and enforces nothing.
- **Shared agent state is never writable.** Global config that later runs code (`~/.claude.json`
  MCP servers, opencode's cache) is a discarded `copy` or a per-project `{project_slug}` dir.
- **The callable surface is closed.** `COMMANDS` and the proxy's accepted request forms are
  fixed. `tests/test_config.py::Surface` fails when a subcommand is added: review the new
  subcommand, then update the test.
- **The report never suggests a secret.** `pithos report` tuning output never suggests
  sensitive paths, `~/.claude`, the config or state dirs.
- **Untrusted text is sanitized before printing.** Log entries, host names and project files
  pass through `clean()` before reaching the terminal.

## Gotchas

- The launcher refuses project directories under `/tmp` and directories that contain the
  config dir. That is why tests use `tests/.tmp/` (gitignored) and why this repo can't be
  the project while `PITHOS_CONFIG` points at its own `profiles/`.
- UNIX socket paths max out at 107 bytes. The runtime dir uses `$XDG_RUNTIME_DIR` or the
  system temp dir, not the state dir.
- Never run `escape_suite.sh` directly on the host. It really tries to write
  `~/.claude/settings.json`, `.git/hooks` and `/usr`. Always use `run_escape_suite.sh`.
- Mount order matters: `bwrap` applies mounts in argv order. `bwrap_argv` sorts by path depth,
  so parents come before children, and `rw` before `ro` at the same depth. Deny overlays go last.
- `GIT_SSH_COMMAND` is shell syntax that `git` runs via `sh`. Test it with `eval` or `git`,
  not a bare `$GIT_SSH_COMMAND`.
- `pithos allow` refuses to run when `PITHOS` is set, which is only to avoid a misleading
  success inside a sandbox: there it could only write to a tmpfs. The barrier is the unmounted
  state dir. Tests that call it must clear the variable.
- The file notice uses `strace` with `--seccomp-bpf`: the kernel stops only on file syscalls, and
  `-Z` prints only failures. It still slows stat-heavy work about 2x (builds, tests, `git status`
  on big trees), hence `--no-file-notice` and `agent.file_notice = false`. LD_PRELOAD doesn't
  work: Bun (Claude Code, opencode) makes most file syscalls directly, not through libc. If
  `strace` dies mid-session, the filter's file syscalls fail with `ENOSYS`.
- `--no-limits` keeps `RLIMIT_NPROC`, which must be set inside the sandbox (`bridge.py`): since
  Linux 5.14 it counts tasks per user namespace. Set in the launcher, the fork that `bwrap` makes
  is checked against all of the user's processes and fails. With a scope, `TasksMax` does the
  job and the kernel reports it in `pids.events`.
- A transient scope must get `-p OOMPolicy=continue`. Default `stop` fails the unit when the
  OOM killer fires and systemd then SIGTERMs everything in it: the session ends and the agent
  can never report it (seen in testing: exit 143). With `continue`, only the offending
  process dies. The unit's `memory.events` / `pids.events` are read live for the agent.
- The scope is created by `systemd-run --user --scope`, which execs in place: `bwrap` stays the
  launcher's child, keeps the `--args` pipe, and exit codes and `--die-with-parent` work. The
  scope's cgroup is found from `/proc/<pid>/cgroup`, so `systemctl` isn't needed. `pithos` must
  still find it before the session ends: the event files vanish with the scope.
- A shell started straight over SSH is not in the delegated systemd user tree, so the
  unprivileged cgroup route (creating a cgroup by hand) only works in `tmux` panes and similar.
  That is why `pithos` uses `systemd-run` and refuses without it.
- `check_bwrap` runs `bwrap --help` and requires `--size`: without it the tmpfs mounts would
  be unlimited RAM, and the error from `bwrap` would not say why. It also requires
  `--ro-bind-fd` (older than `--size`). Tests fake the binary.
- `--dry-run` and the unit tests show binds as paths (`--bind SRC DEST`); only a real run turns
  them into `--bind-fd N DEST`, since the fds are opened right before `bwrap` starts.
- Never test the limits with an unbounded fork bomb or allocation: lower the limit in the test
  and spawn or allocate a fixed amount (see the escape suite).
- When a harness needs a new host, find it with `pithos log --denied` and add the
  narrowest entry, an exact name rather than a `*.` wildcard. Turn off telemetry with
  environment variables instead of allowlisting it.

## Style

- Match the surrounding code: small functions, comments only where the reason isn't obvious.
- Validation errors raise `ConfigError` with a message naming the offending key or path.
- Tests use `unittest` style and run under `pytest`. Fixtures are synthetic and use a fake
  `HOME` under `tests/.tmp/`. Never use real keys or personal data.
- Markdown docs: code font for commands, flags, paths, filenames, environment variables,
  config keys and profile names; plain text for product names such as Claude Code,
  bubblewrap and opencode. This follows the
  [Google developer documentation style guide](https://developers.google.com/style/code-in-text).
