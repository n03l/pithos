# `fs.rw_map` and `fs.ro_map`: mount a host path at a different sandbox path

## Why

Every `[fs]` entry today mounts a path at the same path (`src = realpath(dest)`). Some tools
hard-code where they write. The swarm-tools opencode plugin logs to
`~/.config/swarm-tools/logs/<type>-<date>.log` with no override. Inside the sandbox that path is
on the `~` tmpfs, so the logs are lost; mounting the host dir writable would mix every project's
logs and let each sandbox read the others'. The user wants these logs kept per project, under
`{project_slug}`.

## Goals

- A profile can mount a host directory, writable, at another path inside the sandbox
  (`rw_map`), and a host file or directory read-only at another path (`ro_map`).
- Same guarantees as existing binds: checked sources, fd binds, deny wins, no config or state dir.

## Non-goals

- `.pithos.toml` support (profiles only, like `[limits]` and `[agent]`; easier to loosen later).
- Writable file targets.

## Anti-goals

- A mapped mount that hides, replaces or sits inside another mount (for example covering
  `~/.config/opencode/plugin` or `.git/hooks`).

## Approaches

1. **String tables `[fs.rw_map]` / `[fs.ro_map]`, key = sandbox path, value = host path.**
   Picked. Profiles already have string tables (`[env.set]`); `merge` already merges them
   key by key, so a child profile replaces an entry with the same destination.
2. List entries `"src:dest"`: breaks on paths containing `:`. Rejected.
3. Overriding `HOME` for the tool: can't be scoped to one process from a profile, and breaks
   everything else. Rejected.

## Design

```toml
[fs.rw_map]
"~/.config/swarm-tools/logs" = "~/.local/share/pithos-opencode/{project_slug}/swarm/logs"

[fs.ro_map]
"~/.config/tool/config.toml" = "~/.config/pithos-shared/tool.toml"
```

Both key and value go through `expand_path` (`~`, `{project}`, `{project_slug}`).

| | `rw_map` | `ro_map` |
|---|---|---|
| Mount | `--bind-fd`, writable | `--ro-bind-fd` |
| Source missing | created as a directory (like `rw_mkdir`) | skipped, listed as `(missing)` (like `ro`) |
| Source type | directory only | file or directory |

**Source (host) checks:** `src = realpath(value)`; `check_project_link` and `check_bind` as for
other binds; opened with `open_nofollow` right before `bwrap` like every profile bind.

**Destination (sandbox) checks:**
- `check_bind(dest)` (not `/`, system paths, home itself, config or state dir, inside `deny`).
- Outside the project (`not is_within(dest, project)` and the project not inside it).
- Not equal to, inside, or containing any other mount destination: the `rw`, `rw_mkdir`, `ro`,
  `copy` binds, `ro_in_project` pins, `agent.notice_into`, the other map entries. Invariant: a
  mapped path only lands where nothing else is mounted.
- The same destination in both tables is an error.

**`.pithos.toml`:** `fs.rw_map` / `fs.ro_map` are refused with a `ConfigError`.

Errors name the key (`fs.rw_map`, `fs.ro_map`) and the path, via `clean()`.

## Tests

Normal: rw mount works and the host dir is created; ro file and dir mounts work; missing ro
source is skipped; child profile overrides a destination.

Hostile, each refused: destination inside the project or on `.git/hooks`; destination on,
above or below another mount; source inside `deny`, config or state dir; source a symlink to
`~/.ssh`; a `{project}` source linking out of the project; same destination in both tables;
either table in `.pithos.toml`.

Escape suite: write through an `ro_map` mount fails; writes through an `rw_map` mount land only
in the source dir.

## Docs

`AGENTS.md` invariant ("a mapped path only lands where nothing else is mounted", profile-only),
`README.md` profile reference.

## After the feature (user's own profile, not repo defaults)

`~/.config/pithos/opencode.toml`: `ro` += `~/.local/bin`,
`~/.local/lib/node_modules/opencode-swarm-plugin`; `env.set` `SWARM_DB_PATH` and
`SWARM_SESSIONS_DIR` under `~/.local/share/pithos-opencode/{project_slug}/swarm/`; the `rw_map`
entry above.

## Left to the builder

Where the checks live (`config.py` vs `pithos`), how `SandboxView` and `config.md` list mapped
destinations (as mounted paths, never naming the source on the host).
