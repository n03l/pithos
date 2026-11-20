# `pithos mount`: show a host path in the sandbox by editing `.pithos.toml`

## Why

Giving an agent another directory means editing `<project>/.pithos.toml` by hand and running
`pithos trust`. `pithos allow` already does the equivalent for hosts; this does it for mounts.

## Goals

- `pithos mount [-C PROJECT] [--rw] PATH...` adds paths to `fs.ro` (or `fs.rw` with `--rw`).
- `pithos mount --remove PATH...` takes them out of either list.
- `pithos mount --list` shows the `fs.ro` and `fs.rw` entries of the project file.
- It writes the file, trusts what it wrote, and says the change applies from the next session.

## Non-goals

- Running sessions: mounts are fixed when `bwrap` starts.
- `fs.rw_mkdir`, `fs.copy`, `fs.deny`, `fs.ro_in_project`, `[net]`: edit the file or use
  `pithos allow`.

## Anti-goals

- Trusting a change the user did not make (the file changed since it was trusted).
- Writing a file that `pithos run` then refuses to load.

## Approaches

1. **Edit the text in place, then re-parse and compare.** Picked. The file is reviewed and
   committed, so comments and layout must survive. The comparison is what makes a hand-written
   editor safe: any mismatch aborts before the write.
2. **Rewrite the whole file from the parsed data.** Simpler, always works, loses comments and
   layout. Rejected.

## Design

```
pithos mount [-C PROJECT] PATH...           # add to fs.ro
pithos mount --rw PATH...                   # add to fs.rw
pithos mount --remove PATH...               # remove from fs.ro and fs.rw
pithos mount --list                         # show both lists
```

**Refusals, before anything is written**

- inside the sandbox (`PITHOS` set), like `pithos allow`: the state dir is not mounted there;
- the file exists and its SHA-256 differs from the trust store (`pithos trust` first);
- the file is a symlink (`read_project_file` already refuses it);
- the file does not parse or does not validate (`parse_project_file`);
- `--list` combined with paths, `--rw` or `--remove`; `--remove` with `--rw`.

**Paths**

- A path that is not absolute and does not start with `~` or `{` is taken relative to the project.
- `expand_path` (so `~` and `{project}` work), then `realpath`. It must exist.
- Written shortened: `{project}` for the project itself (how a project file makes it read-only),
  `{project}/…` inside it, `~/…` under home, absolute otherwise (`short_path`). Home itself stays
  absolute, and `check_bind` refuses it anyway.
- Checks, the same a profile entry gets: `check_bind` (system dirs, config, state, home itself)
  and `is_sensitive` with `deny_patterns(data, …)` (the project's own `deny`, credentials such as
  `~/.ssh` or `.env`). A profile's `deny` is still enforced by `build_plan` at run time.

**The change**

- Adding a path already in the target list is a no-op that says so.
- Adding a path in the other list moves it (remove from the other, add to this one).
- Removing a path that is in neither list is an error naming the lists, and points at profiles.

**Editing the text** (`config.edit_list(text, key, add=(), remove=())`)

- Finds the `[fs]` table (refuses `fs.ro = …` dotted keys or an inline `fs = {…}`).
- Finds `key = [ … ]` in that table (refuses any value that is not an array).
- Removes a string by deleting its span and one neighbouring comma; adds one by inserting
  `, "new"` after the last string, or `"new"` into an empty array. Everything else in the file
  is untouched, including comments between entries.
- Creates the key at the end of `[fs]`, or an `[fs]` table at the end of the file, when missing.
- Refuses multi-line basic strings (`"""`), which the span scanner does not read.

**Verification before the write**

Re-parse the new text with `parse_project_file` and compare it with the old data plus exactly the
requested entries. Any difference (or a parse error) aborts with a message to edit the file by
hand, and the file is not touched.

**Write and trust**

`write_project_file` writes atomically into the project directory and keeps the file's mode
(0644 for a new one). `trust_project` records the new digest, the same helper `pithos trust`
uses.

**Output**

One line per entry: `+ fs.ro ~/data`, `- fs.rw ~/data`, `= fs.ro ~/data (already listed)`, then
`trusted <project>/.pithos.toml` and `mounts apply from the next session`. Everything through
`clean()`.

## Tests

Normal: add to `fs.ro` and `fs.rw`; move between lists; add twice; remove; relative path; path
outside home stays absolute; a project symlink is written as its target; `--list` with and
without a file; each command output.

Hostile, each refused and the file left byte-identical: changed since trusted, `PITHOS` set, a
symlinked project file, a missing path, `~/.ssh`, a path the project denies, a dotted or inline
`fs`, an invalid file.

Text editing: exact output for one-line, multi-line and commented arrays, a missing key, a
missing table, a file without a trailing newline, removing the only entry.

## Docs

`README.md` (usage example under "Per-project rules"), `AGENTS.md` (layout line for the editor
and trust helper, plus the invariant "`pithos mount` only rewrites a file it trusts, and trusts
only its own write").
