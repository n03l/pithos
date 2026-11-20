# SPDX-License-Identifier: GPL-3.0-or-later
"""Profiles, project files and paths, and the basics every pithos module shares.

ConfigError, clean() and note(), where things live inside the sandbox, the profile schema,
loading and merging profiles, the project's .pithos.toml and its trust store, and the checks on
every path a profile names.
"""

import fnmatch
import glob
import hashlib
import json
import os
import re
import shlex
import sys
import tempfile
import tomllib


# -- where things are ------------------------------------------------------------------

PROJECT_FILE = ".pithos.toml"
PROJECT_FILE_MAX = 1024 * 1024
ALWAYS_RO_IN_PROJECT = [PROJECT_FILE]
# Inside the sandbox: pithos's own files, bound read-only from the host's runtime dir.
SANDBOX_RUN = "/run/pithos"
SANDBOX_BLOCKED_HOSTS = SANDBOX_RUN + "/blocked-hosts"
SANDBOX_NOTICE = SANDBOX_RUN + "/notice.md"
SANDBOX_CONFIG = SANDBOX_RUN + "/config.md"
SANDBOX_OPENCODE_CONFIG = SANDBOX_RUN + "/opencode.json"
SANDBOX_CLAUDE_AGENT = SANDBOX_RUN + "/claude-agent.json"
SANDBOX_BLOCKED_FILES = SANDBOX_RUN + "/blocked-files"
SANDBOX_LIMIT_EVENTS = SANDBOX_RUN + "/limit-events"
# bridge.py probes this path (it never exists) first thing: the trace before it is bwrap's setup.
TRACE_START = SANDBOX_RUN + "/.trace-start"
SANDBOX_PYTHON = "/usr/bin/python3"
# Never bound, whatever a profile says: host sockets (D-Bus, ssh/gpg agents, docker, X11)
# live here, and connect() works even through a read-only bind.
SYSTEM_FORBIDDEN = ["/run", "/var/run", "/tmp", "/var/tmp", "/proc", "/sys", "/dev"]


# -- profiles --------------------------------------------------------------------------

LIST = "list of strings"
MAP = "table of strings"
STR = "string"
BOOL = "boolean"
AMOUNT = "number or string"
LIMIT_KEYS = ("processes", "memory", "total", "tmpfs", "cpu")
SCHEMA = {
    "extends": STR,
    "fs": {"ro": LIST, "rw": LIST, "rw_mkdir": LIST, "copy": LIST, "deny": LIST,
           "ro_in_project": LIST},
    "net": {"allow": LIST},
    "env": {"pass": LIST, "set": MAP},
    "ssh": {"key": STR, "known_hosts": STR},
    "agent": {"notice_into": STR, "connect_claude_agent": BOOL, "file_notice": BOOL},
    "limits": {key: AMOUNT for key in LIMIT_KEYS},
}
PROFILE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Claude Code names per-project dirs (~/.claude/projects/<slug>) this way; longer paths get
# a hash suffix we can't reproduce.
SLUG_MAX = 200


# -- basics ----------------------------------------------------------------------------

class ConfigError(Exception):
    pass


def clean(text, keep="\n\t"):
    """Make untrusted text safe to print on a terminal (no escape sequences). With keep="",
    the result is one line of plain text."""
    return "".join(c if c.isprintable() or c in keep else f"\\x{ord(c):02x}" for c in str(text))


def note(msg):
    print(f"pithos: {msg}", file=sys.stderr)


class Paths:
    def __init__(self, env=None):
        env = os.environ if env is None else env
        home = env.get("HOME", "")
        if not os.path.isabs(home):
            raise ConfigError("HOME must be an absolute path")
        self.home = os.path.realpath(home)
        self.config = os.path.realpath(
            env.get("PITHOS_CONFIG") or os.path.join(self.home, ".config/pithos"))
        self.state = os.path.realpath(
            env.get("PITHOS_STATE") or os.path.join(self.home, ".local/state/pithos"))

    @property
    def trusted(self):
        return os.path.join(self.state, "trusted.json")

    @property
    def logs(self):
        return os.path.join(self.state, "logs")

    @property
    def sessions(self):
        return os.path.join(self.state, "sessions")

    @property
    def allowed(self):
        return os.path.join(self.state, "allowed.json")

    def session_file(self, session):
        return os.path.join(self.sessions, session + ".json")


# -- loading profiles and project files ------------------------------------------------

TYPE_CHECKS = {
    STR: lambda v: isinstance(v, str),
    BOOL: lambda v: isinstance(v, bool),
    AMOUNT: lambda v: isinstance(v, (int, str)) and not isinstance(v, bool),
    LIST: lambda v: isinstance(v, list) and all(isinstance(x, str) for x in v),
    MAP: lambda v: isinstance(v, dict) and all(isinstance(x, str) for x in v.values()),
}
SECTIONS = tuple(key for key, kind in SCHEMA.items() if isinstance(kind, dict))


def validate(data, schema=SCHEMA, where="profile"):
    if not isinstance(data, dict):
        raise ConfigError(f"{where}: expected a table")
    for key, value in data.items():
        if key not in schema:
            raise ConfigError(f"{where}: unknown key {key!r}")
        kind = schema[key]
        name = f"{where}.{key}"
        if isinstance(kind, dict):
            validate(value, kind, name)
        elif not TYPE_CHECKS[kind](value):
            raise ConfigError(f"{name}: expected a {kind}")


def merge(base, over):
    """Lists are joined, tables of strings merged, anything else is replaced by `over`."""
    out = {}
    for section in SECTIONS:
        a, b = base.get(section, {}), over.get(section, {})
        merged = {}
        for key in a.keys() | b.keys():
            if key in a and key in b and isinstance(a[key], list):
                merged[key] = list(dict.fromkeys(a[key] + b[key]))
            elif key in a and key in b and isinstance(a[key], dict):
                merged[key] = {**a[key], **b[key]}
            else:
                merged[key] = b.get(key, a.get(key))
        out[section] = merged
    return out


def load_profile(paths, name, seen=()):
    if not PROFILE_NAME.match(name):
        raise ConfigError(f"invalid profile name {clean(name)!r}")
    if name in seen:
        raise ConfigError(f"profile inheritance loop: {' -> '.join(seen + (name,))}")
    path = os.path.join(paths.config, name + ".toml")
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError:
        raise ConfigError(f"no profile {name!r} in {paths.config}")
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}")
    validate(data, where=name)
    base = load_profile(paths, data["extends"], seen + (name,)) if "extends" in data else {}
    return merge(base, data)


def read_json_table(path):
    """Return the JSON object in path, {} if the file is missing, None if it is unusable."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def read_trusted(paths):
    """{project: sha256 of its trusted .pithos.toml}. A damaged store trusts nothing."""
    data = read_json_table(paths.trusted)
    if data is None:
        note(f"ignoring unreadable {paths.trusted}")
        return {}
    return {k: v for k, v in data.items() if isinstance(v, str)}


def read_project_file(project):
    """Return (bytes, sha256) of the project's config file, or (None, None)."""
    path = os.path.join(project, PROJECT_FILE)
    if not os.path.lexists(path):
        return None, None
    if os.path.islink(path) or not os.path.isfile(path):
        raise ConfigError(f"{path} must be a regular file, not a link")
    with open(path, "rb") as f:
        raw = f.read(PROJECT_FILE_MAX + 1)
    if len(raw) > PROJECT_FILE_MAX:  # a truncated read would be trusted and written back
        raise ConfigError(f"{path} is larger than {PROJECT_FILE_MAX} bytes")
    return raw, hashlib.sha256(raw).hexdigest()


def parse_project_file(project, raw):
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(f"{project}/{PROJECT_FILE}: {e}")
    validate(data, where=PROJECT_FILE)
    if "extends" in data:
        raise ConfigError(f"{PROJECT_FILE}: 'extends' is only allowed in profiles")
    for section in ("agent", "limits"):  # a cloned repo must not loosen these
        if section in data:
            raise ConfigError(f"{PROJECT_FILE}: '{section}' is only allowed in profiles")
    return data


def load_project(paths, project):
    raw, digest = read_project_file(project)
    if raw is None:
        return {}
    if read_trusted(paths).get(project) != digest:
        raise ConfigError(
            f"{project}/{PROJECT_FILE} is new or changed and not trusted.\n"
            f"Review it, then run: pithos trust -C {shlex.quote(project)}")
    return parse_project_file(project, raw)


# -- editing the project file's fs lists -----------------------------------------------

def toml_array_spans(text, start):
    """(spans of the string literals, index of the closing ']') for the TOML array whose
    '[' is at text[start]. Anything but strings, commas, whitespace and comments is refused."""
    if text[start] != "[":
        raise ConfigError(f"{PROJECT_FILE}: expected a list")
    spans, i = [], start + 1
    while i < len(text):
        c = text[i]
        if c in " \t\r\n,":
            i += 1
        elif c == "#":
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
        elif text[i:i + 3] in ('"""', "'''"):
            raise ConfigError(f"{PROJECT_FILE}: multi-line strings are not supported")
        elif c in "\"'":
            j = i + 1
            while j < len(text) and text[j] != c:
                j += 2 if c == '"' and text[j] == "\\" else 1
            if j >= len(text):
                raise ConfigError(f"{PROJECT_FILE}: unterminated string")
            spans.append((i, j + 1))
            i = j + 1
        elif c == "]":
            return spans, i
        else:
            raise ConfigError(f"{PROJECT_FILE}: unsupported value in a list")
    raise ConfigError(f"{PROJECT_FILE}: unterminated list")


def fs_table_span(text):
    """(start, end) of the [fs] table's body: the lines after its header, up to the next
    table header. None when the file has no [fs] table."""
    header = re.search(r"^[ \t]*\[[ \t]*fs[ \t]*\][^\n]*(\n|$)", text, re.M)
    if header is None:
        return None
    nxt = re.search(r"^[ \t]*\[", text[header.end():], re.M)
    return header.end(), header.end() + (nxt.start() if nxt else len(text) - header.end())


def in_comment(text, pos):
    """True when pos is inside a # comment (a # before it on its line)."""
    return "#" in text[text.rfind("\n", 0, pos) + 1:pos]


def drop_span(text, start, s, e, close):
    """Delete text[s:e] and one comma next to it, leaving a valid array. A comma inside a
    comment is not one of ours: deleting it would change a comment the file keeps."""
    before = text.rfind(",", start, s)
    if before >= 0 and not in_comment(text, before) and not text[before + 1:s].strip():
        return text[:before] + text[e:]
    after = text.find(",", e, close)
    if after >= 0 and not in_comment(text, after) and not text[e:after].strip():
        return text[:s] + text[after + 1:]
    return text[:s] + text[e:]


def toml_literal(value):
    return json.dumps(value, ensure_ascii=False)


def edit_list(text, key, add=(), remove=()):
    """Add and remove strings in the `fs.<key>` array of a .pithos.toml text, keeping every
    other byte of the file. Refuses a layout it can't splice, before writing anything."""
    body = fs_table_span(text)
    if body is None:
        if re.search(r"^[ \t]*fs[ \t]*[.=\[]", text, re.M):
            raise ConfigError(f"{PROJECT_FILE}: 'fs' is a dotted or inline key; edit it by hand")
        if not add:
            raise ConfigError(f"{PROJECT_FILE}: no [fs] table to remove fs.{key} from")
        sep = "" if text.endswith("\n") or not text else "\n"
        return text + sep + f"[fs]\n{key} = [" + ", ".join(map(toml_literal, add)) + "]\n"
    start, end = body
    line = re.compile(r"^[ \t]*" + key + r"[ \t]*=[ \t]*", re.M).search(text, start, end)
    if line is None:
        if remove:
            raise ConfigError(f"{PROJECT_FILE}: fs.{key} is not set")
        gap = "" if end == 0 or text[end - 1] == "\n" else "\n"
        new = f"{key} = [" + ", ".join(map(toml_literal, add)) + "]\n"
        return text[:end] + gap + new + text[end:]
    at = line.end()
    if at >= len(text) or text[at] != "[":
        raise ConfigError(f"{PROJECT_FILE}: fs.{key} is not a list; edit it by hand")
    for value in remove:
        spans, close = toml_array_spans(text, at)
        for s, e in spans:
            if tomllib.loads("v = " + text[s:e])["v"] == value:
                text = drop_span(text, at, s, e, close)
                break
        else:
            raise ConfigError(f"{PROJECT_FILE}: fs.{key} has no {clean(value)!r}")
    for value in add:
        spans, close = toml_array_spans(text, at)
        if any(tomllib.loads("v = " + text[s:e])["v"] == value for s, e in spans):
            continue
        literal = toml_literal(value)
        if spans:
            text = text[:spans[-1][1]] + ", " + literal + text[spans[-1][1]:]
        else:
            text = text[:at + 1] + literal + text[at + 1:]
    return text


def short_path(real, project, paths):
    """A path as a project file writes it: {project}, {project}/…, ~/… or absolute."""
    if is_within(real, project):
        return "{project}" + real[len(project):]
    if real != paths.home and is_within(real, paths.home):
        return "~" + real[len(paths.home):]
    return real


def write_private_json(path, data):
    """Replace path atomically; mkstemp makes the file 0600."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def write_project_file(project, text, mode):
    """Replace the project file atomically, keeping its mode."""
    path = os.path.join(project, PROJECT_FILE)
    try:
        fd, tmp = tempfile.mkstemp(dir=project, prefix=".pithos-")
    except OSError as e:
        raise ConfigError(f"can't write {path}: {e.strerror}")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def trust_project(paths, project, raw):
    """Record the digest of the project file that was just read or written."""
    trusted = read_trusted(paths)
    trusted[project] = hashlib.sha256(raw).hexdigest()
    os.makedirs(paths.state, mode=0o700, exist_ok=True)
    write_private_json(paths.trusted, trusted)


# -- paths -----------------------------------------------------------------------------

def is_within(path, parent):
    return path == parent or path.startswith(parent.rstrip("/") + "/")


def project_slug(project):
    """The project's directory name under ~/.claude/projects: like JavaScript's
    path.replace(/[^a-zA-Z0-9]/g, "-"), which works on UTF-16 code units."""
    slug = "".join(c if c.isascii() and c.isalnum() else "-" * (1 + (ord(c) > 0xFFFF))
                   for c in project)
    if len(slug) > SLUG_MAX:
        raise ConfigError(f"project path too long for {{project_slug}}: {clean(project)!r}")
    return slug


def expand(value, project, paths, escape=None):
    """Substitute {project}, {project_slug} and a leading ~. With escape, each substituted
    path goes through it first (glob.escape for deny globs)."""
    escape = escape or (lambda text: text)
    if "{project_slug}" in value:
        value = value.replace("{project_slug}", escape(project_slug(project)))
    if "{project}" in value:
        value = value.replace("{project}", escape(project))
    if value == "~" or value.startswith("~/"):
        value = escape(paths.home) + value[1:]
    if "{" in value or "}" in value:
        raise ConfigError(f"unknown placeholder in {clean(value)!r}")
    return value


def expand_path(value, project, paths, escape=None):
    value = expand(value, project, paths, escape)
    if not os.path.isabs(value):
        raise ConfigError(f"path must be absolute or start with ~ or {{project}}: {clean(value)!r}")
    return os.path.normpath(value)


def expand_glob(value, project, paths):
    """Like expand_path, but the substituted paths are escaped: only the profile's own
    wildcards act as glob syntax (a project named "app[1]" still matches itself)."""
    return expand_path(value, project, paths, glob.escape)


def check_project(project, paths):
    if not os.path.isdir(project):
        raise ConfigError(f"project directory {clean(project)!r} does not exist")
    if is_within(paths.home, project):
        raise ConfigError(f"refusing {project} as project: it contains {paths.home}")
    for p in [paths.config, paths.state] + SYSTEM_FORBIDDEN:
        if is_within(project, p) or is_within(p, project):
            raise ConfigError(f"refusing {project} as project: it is inside or contains {p}")


def check_bind(src, dest, paths, denied):
    """Refuse a bind of anything the sandbox must never see, read-only or not: home itself,
    the config and state dirs, and their subpaths. `ro = ["~"]` would be the whole home."""
    for p in (src, dest):
        if p == "/":
            raise ConfigError("refusing to bind /")
        for f in SYSTEM_FORBIDDEN:
            if is_within(p, f) or is_within(f, p):
                raise ConfigError(f"refusing to bind {p}: it is or contains {f}")
        for d in denied:
            if is_within(p, d):
                raise ConfigError(f"refusing to bind {p}: it is inside denied {d}")
        for f in (paths.home, paths.config, paths.state):
            if is_within(f, p):
                raise ConfigError(f"refusing to bind {p}: it contains {f}")
        for f in (paths.config, paths.state):
            if is_within(p, f):
                raise ConfigError(f"refusing to bind {p}: it is inside {f}")


def check_project_link(where, dest, src, project):
    """A path written with {project} must not resolve outside it: `pithos trust` shows the
    text, and a symlink committed in the repo decides what the path points at."""
    if is_within(dest, project) and not is_within(src, project):
        raise ConfigError(f"{where}: {clean(dest)} links outside the project ({clean(src)})")


def has_glob(value):
    return any(c in value for c in "*?[")


SENSITIVE_NAMES = (".ssh", ".gnupg", ".aws", ".netrc", ".git-credentials", ".env")


def deny_patterns(cfg, project, paths):
    patterns = []
    for entry in cfg.get("fs", {}).get("deny", []):
        if has_glob(entry):
            patterns.append(expand_glob(entry, project, paths))
        else:
            plain = glob.escape(expand_path(entry, project, paths))
            patterns += [plain, plain + "/*"]
    return patterns


def is_sensitive(path, patterns=()):
    """Compared after normpath, so a path can't dodge this with `..`. fnmatch's * crosses /,
    which is what `**` needs here."""
    norm = os.path.normpath(path)
    if any(part in SENSITIVE_NAMES or part.startswith(".env.") for part in norm.split("/")):
        return True
    if "/.config/gcloud/" in f"/{norm}/":
        return True
    return any(fnmatch.fnmatchcase(norm, p) for p in patterns)
