# SPDX-License-Identifier: GPL-3.0-or-later
"""Reading session logs: `pithos report` and the log parsing that `pithos allow` shares.

Logs are written by or for the sandbox: every value read from them is checked before use and
passed through clean() before printing.
"""

import glob
import json
import os
import re

import proxy
from config import (
    ConfigError, LIMIT_KEYS, SYSTEM_FORBIDDEN, clean,
    deny_patterns, expand_path, is_sensitive, is_within, load_profile, load_project, merge,
    validate,
)
from resources import LIMIT_COUNTERS, describe_limits
from filetrace import HIDDEN, NOT_MOUNTED, READ_ONLY


# -- session logs ----------------------------------------------------------------------

def parse_events(lines, stats=None):
    """Yield the JSON objects in a proxy log; anything else is counted in stats["bad"]."""
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            event = None
        if isinstance(event, dict):
            yield event
        elif stats is not None:
            stats["bad"] = stats.get("bad", 0) + 1


def offerable_host(event):
    """(host, port) if this log event may be offered for approval, else None. The sandbox picks
    these names, so only well-formed host names refused for not being listed qualify."""
    if event.get("action") != "deny" or event.get("reason") != proxy.NOT_LISTED:
        return None
    host, port = event.get("host"), event.get("port")
    try:
        if type(port) is not int or not 0 < port < 65536 \
                or proxy.normalize_host(host) != ("name", host):
            return None
    except (ValueError, AttributeError, TypeError):
        return None
    return host, port


# -- the report ------------------------------------------------------------------------

REPORT_LIMIT = 30
SESSION_ID = re.compile(r"\d{8}-\d{6}-[0-9a-f]{6}", re.ASCII)


def select_sessions(args, paths):
    """Log files to report on."""
    if args.session is not None:
        if not SESSION_ID.fullmatch(args.session):
            raise ConfigError(f"invalid session id {clean(args.session)!r}")
        path = os.path.join(paths.logs, args.session + ".jsonl")
        if not os.path.isfile(path):
            raise ConfigError(f"no log for session {args.session}")
        return [path]
    files = sorted(glob.glob(os.path.join(glob.escape(paths.logs), "*.jsonl")))
    return files if args.all else files[-1:]


def collect_logs(files):
    data = {"starts": [], "exits": [], "last_ts": None, "stats": {}, "violations": {},
            "refused": {}, "offers": {}, "allowed": {}, "quarantined": {}, "files": {},
            "limits_hit": {}}

    def bump(table, key):
        table[key] = table.get(key, 0) + 1

    for path in files:
        with open(path, encoding="ascii", errors="replace") as f:
            for event in parse_events(f, data["stats"]):
                action = event.get("action")
                data["last_ts"] = event.get("ts", data["last_ts"])
                host, port = event.get("host"), event.get("port")
                if action == "start":
                    data["starts"].append(event)
                elif action == "exit":
                    data["exits"].append(event)
                elif action == "quarantine":
                    bump(data["quarantined"], str(event.get("path")))
                elif action == "limit" and event.get("limit") in LIMIT_COUNTERS \
                        and type(event.get("count")) is int and event["count"] > 0:
                    hit = data["limits_hit"]
                    hit[event["limit"]] = hit.get(event["limit"], 0) + event["count"]
                elif action == "file" and isinstance(event.get("path"), str) \
                        and event.get("reason") in (NOT_MOUNTED, HIDDEN, READ_ONLY):
                    bump(data["files"], (event["path"], event["reason"]))
                elif action == "allow" and isinstance(host, str) and type(port) is int:
                    bump(data["allowed"], (host, port))
                elif action == "deny":
                    reason = str(event.get("reason"))
                    if reason == proxy.NOT_LISTED:
                        bump(data["refused"], f"{host}:{port}")
                        offer = offerable_host(event)
                        if offer:
                            bump(data["offers"], offer)
                    elif not reason.startswith("resolve failed"):
                        bump(data["violations"], f"{host}:{port}  {reason}")
    return data


def rule_snapshot(cfg):
    """The rules the report checks a session against, as they were when it started."""
    fs = cfg.get("fs", {})
    return {"fs": {key: fs.get(key, []) for key in ("ro", "rw", "rw_mkdir", "deny", "ro_in_project")},
            "net": {"allow": cfg.get("net", {}).get("allow", [])}}


def report_config(paths, data):
    """(cfg, project, None), or (None, project or None, why) when it can't be loaded. Uses the
    rules logged at start if there are any, else the profile as it is now."""
    pairs = {(e.get("profile"), e.get("project"), json.dumps(e.get("rules"), sort_keys=True))
             for e in data["starts"]
             if isinstance(e.get("profile"), str) and isinstance(e.get("project"), str)}
    if not pairs:
        return None, None, "no start event in the log"
    if len(pairs) > 1:
        return None, None, "the sessions used different profiles or projects"
    profile, project, _ = pairs.pop()
    rules = next(e.get("rules") for e in data["starts"] if e.get("project") == project)
    try:
        if rules is None:
            cfg = merge(load_profile(paths, profile), load_project(paths, project))
        else:
            validate(rules, where="logged rules")
            cfg = rules
            data["rules_logged"] = True
        deny_patterns(cfg, project, paths)
        proxy.Allowlist(cfg.get("net", {}).get("allow", []))
        for key in ("ro", "rw", "rw_mkdir"):
            for entry in cfg.get("fs", {}).get(key, []):
                expand_path(entry, project, paths)
        return cfg, project, None
    except (ConfigError, OSError, ValueError) as e:
        return None, project, str(e).split("\n")[0]


def print_section(title, rows, empty="none"):
    print(f"\n{title}")
    rows = list(rows)
    for row in rows[:REPORT_LIMIT]:
        print(clean(f"  {row}"))
    if not rows:
        print(clean(f"  {empty}"))
    elif len(rows) > REPORT_LIMIT:
        print(f"  ... and {len(rows) - REPORT_LIMIT} more")


def by_count(table):
    return sorted(table.items(), key=lambda kv: (-kv[1], str(kv[0])))


def count_rows(table):
    return [f"{count:6}x {key}" for key, count in by_count(table)]


def print_security(data):
    print("\nSECURITY REVIEW")
    used = {proxy.live_entry(*key): count for key, count in data["allowed"].items()}
    print_section("Hosts contacted (allowed connections):", count_rows(used))
    print_section("Network, policy violations:", count_rows(data["violations"]))
    print_section("Hosts tried and refused (not in net.allow):", count_rows(data["refused"]))
    print_section("Quarantined paths:", count_rows(data["quarantined"]))
    print_section("Hidden paths the agent tried (credentials, fs.deny):",
                  [path for path, reason in sorted(data["files"]) if reason == HIDDEN])


def worth_mounting(path, project, paths, patterns):
    """A path that could reasonably be suggested for the profile. Never secrets, other sessions
    or anything the sandbox must not see."""
    norm = os.path.normpath(path)
    if not os.path.isabs(norm) or is_sensitive(norm, patterns) or norm == paths.home:
        return False
    never = [*SYSTEM_FORBIDDEN, paths.config, paths.state, os.path.join(paths.home, ".claude")]
    if project:
        never.append(project)
    return not any(is_within(norm, p) for p in never) and os.path.lexists(norm)


def unused_rules(cfg, data):
    rows = []
    allowed = []
    for (host, port) in data["allowed"]:
        try:
            allowed.append((*proxy.normalize_host(host), port))
        except ValueError:
            continue
    for entry in cfg.get("net", {}).get("allow", []):
        rule = proxy.Allowlist([entry])
        if not any(rule.allows(*item) for item in allowed):
            rows.append(f"net.allow  {entry}")
    return rows


def print_tuning(data, cfg, why, project, paths, patterns):
    print("\nPROFILE TUNING")
    print("\nHosts to consider allowing (add to [net] allow only if expected):")
    if not data["offers"]:
        print("  none")
    for (host, port), count in by_count(data["offers"])[:REPORT_LIMIT]:
        print(clean(f'  "{proxy.live_entry(host, port)}",   # {count}x'))
    if len(data["offers"]) > REPORT_LIMIT:
        print(f"  ... and {len(data['offers']) - REPORT_LIMIT} more")
    refused = [f"{reason:12} {path}" for path, reason in sorted(data["files"])
               if reason != HIDDEN and worth_mounting(path, project, paths, patterns)]
    print_section("Refused file accesses the agent was told about, present on the host:", refused)
    if cfg is None:
        print(clean(f"\nAllowed but unused: skipped: {why}"))
    else:
        print_section("Allowed but unused in these sessions (evidence from these sessions only):",
                      unused_rules(cfg, data))


def print_report(paths, files, data, cfg, why, project):
    names = [os.path.basename(f)[:-len(".jsonl")] for f in files]
    print(clean(f"pithos report: {names[-1] if len(names) == 1 else f'{len(names)} sessions'}"))
    for event in data["starts"][-1:]:
        print(clean(f"profile: {event.get('profile')}  project: {event.get('project')}"))
        print(clean(f"command: {event.get('cmd')}  started: {event.get('ts')}"))
    for event in data["exits"][-1:]:
        print(clean(f"exit code: {event.get('code')}  ended: {event.get('ts')}"))
    for event in data["starts"][-1:]:
        logged = event.get("limits")
        if isinstance(logged, dict):
            limits = {key: value if type(value) is int else None
                      for key in LIMIT_KEYS for value in [logged.get(key)]}
            unenforced = " (not enforced: --no-limits)" if event.get("scoped") is False else ""
            print(f"limits: {describe_limits(limits)}{unenforced}")
    if data["limits_hit"].get("memory"):
        print(f"processes killed by the kernel at the memory limit: {data['limits_hit']['memory']}")
    if data["limits_hit"].get("processes"):
        print(f"process starts refused at the process limit: {data['limits_hit']['processes']}")
    if data["stats"].get("bad"):
        print(f"unreadable log lines: {data['stats']['bad']}")
    if cfg is None:
        print(clean(f"profile checks skipped: {why}"))
    else:
        print("profile checks use the rules recorded when the session started"
              if data.get("rules_logged") else
              "profile checks use the profile as it is now, not as it was during the session")
    patterns = deny_patterns(cfg, project, paths) if cfg else []
    print_security(data)
    print_tuning(data, cfg, why, project, paths, patterns)


def cmd_report(args, paths):
    files = select_sessions(args, paths)
    if not files:
        print("no sessions logged yet")
        return 0
    data = collect_logs(files)
    cfg, project, why = report_config(paths, data)
    print_report(paths, files, data, cfg, why, project)
    return 0
