#!/bin/bash
# Builds a throwaway project and runs escape_suite.sh in the sandbox with the repo's profiles.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$here/.tmp"
proj=$(mktemp -d "$here/.tmp/escape.XXXXXX")
export PITHOS_STATE=$(mktemp -d "$here/.tmp/state.XXXXXX")  # keep the real trust store clean
# Claude Code's dir for this project, created by the claude profile on the real host.
session_dir="$HOME/.claude/projects/$(realpath "$proj" | sed 's/[^a-zA-Z0-9]/-/g')"
trap 'rm -rf "$proj" "$PITHOS_STATE" "$session_dir"' EXIT
cd "$proj"
git init -q
mkdir .claude .vscode && echo '{}' > .claude/settings.json && echo '{}' > .vscode/settings.json
echo "API_KEY=do-not-leak" > .env
printf '[net]\nallow = []\n' > .pithos.toml
cp "$here/escape_suite.sh" .
printf '%s' "$PITHOS_STATE" > .state-path  # so the suite attacks the state dir in use
export PITHOS_CONFIG=${PITHOS_CONFIG:-$(dirname "$here")/profiles}
"$here/../pithos" trust --yes >/dev/null
hooks_before=$(ls -A .git/hooks | md5sum)
status=0
"$here/../pithos" -p claude -- bash escape_suite.sh || status=1
# Host-side checks: nothing leaked out of the sandbox.
[ "$(ls -A .git/hooks | md5sum)" = "$hooks_before" ] || { echo "FAIL: .git/hooks changed on host"; status=1; }
[ ! -e .git.x ] && [ ! -e .claude.x ] || { echo "FAIL: .git or .claude renamed on host"; status=1; }
grep -q do-not-leak .env || { echo "FAIL: .env changed on host"; status=1; }
[ -f written-inside.txt ] || { echo "FAIL: project write did not reach host"; status=1; }
[ -f "$session_dir/.escape-test" ] || { echo "FAIL: session dir write did not reach host"; status=1; }
[ ! -e /usr/escape ] || { echo "FAIL: /usr/escape exists"; status=1; }
[ ! -e "$PITHOS_STATE/allowed.json" ] || { echo "FAIL: sandbox wrote the saved allowlist"; status=1; }
[ -d "$PITHOS_STATE/logs" ] || { echo "FAIL: no session log on host"; status=1; }
exit $status
