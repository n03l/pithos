#!/bin/bash
# Links the launcher into ~/.local/bin and copies the default profiles, never overwriting yours.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
config=${PITHOS_CONFIG:-$HOME/.config/pithos}
mkdir -p "$HOME/.local/bin" "$config"
ln -sfn "$here/pithos" "$HOME/.local/bin/pithos"
for f in "$here"/profiles/*.toml; do
  if [ -e "$config/$(basename "$f")" ]; then
    echo "kept existing $config/$(basename "$f")"
  else
    install -m 0644 "$f" "$config/"
    echo "installed $config/$(basename "$f")"
  fi
done
command -v bwrap >/dev/null || echo "bubblewrap is missing: sudo apt install bubblewrap"
command -v strace >/dev/null || echo "strace is missing: the agent won't be told which files the sandbox refused"
command -v systemd-run >/dev/null || echo "systemd-run is missing: pithos won't start without a systemd user session (see --no-limits)"
cat <<'MSG'
Add to ~/.bashrc:
  alias cs='pithos -p claude -- claude'
  alias ocs='pithos -p opencode -- opencode --standalone'
  alias occ='pithos -p opencode-claude -- opencode --standalone'
MSG
