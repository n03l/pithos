# opencode plugin: sandbox lock

Part of [pithos](../../README.md).

`pithos-lock` adds one indicator to opencode's footer: a lock and a green or red ●. Inside a
`pithos` sandbox it is 🔒 with a green ●, outside it is 🔓 with a red ●. Outside the sandbox it
also alerts you when opencode starts unsandboxed (see `alert` below). It shows the indicator only
when `PITHOS=1` is set and `/run/pithos/blocked-hosts` exists, so a stray `PITHOS=1` on the host
still shows the open lock. Use it with `opencode --standalone`, where the TUI and the server that
runs the tools share the sandbox.

## Install

From the pithos repository root, copy the plugin, not link it, into opencode's config dir, then
list it in `cli.json`:

```sh
mkdir -p ~/.config/opencode/plugins
cp -r opencode-plugin/pithos-lock ~/.config/opencode/plugins/
```

```json
{ "plugins": ["/home/you/.config/opencode/plugins/pithos-lock"] }
```

Outside the sandbox the plugin also alerts you that tools run unsandboxed. Choose the alert with
the `alert` option of the object form; inside the sandbox it shows only the lock and ●:

| `alert` | Outside the sandbox |
| --- | --- |
| `"warning"` (default) | A dialog you dismiss, then opencode continues |
| `"error"` | A modal that reopens when dismissed; `enter` quits opencode |
| `"none"` | No alert, only the open lock and ● |

```json
{
  "plugins": [
    {
      "package": "/home/you/.config/opencode/plugins/pithos-lock",
      "options": { "alert": "error" }
    }
  ]
}
```

A missing or invalid `alert` means `"warning"`, so a typo can't silently remove the only sign
that tools run unsandboxed.

## Why copy it

- The `opencode` profile mounts `~/.config/opencode` read-only, so the sandbox can load the
  copy but can't change it. A symlink back into this repo wouldn't resolve in the sandbox, and
  when the project is this repo, the agent could edit the plugin to always show 🔒.
- The plugin imports `@opencode/plugin/tui`, which resolves from opencode's config dir.

Copy it again after pulling changes to `opencode-plugin/`.

The lock is a hint, not a proof. An agent run outside the sandbox has your user rights and can
edit the plugin or `cli.json` so that later sessions show 🔒. Keeping `~/.config/opencode` in
git makes such an edit show up in `git status`.
