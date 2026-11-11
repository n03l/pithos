import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import time
import tomllib
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.helpers import ROOT, load_launcher, scratch_dir  # noqa: E402

sb = load_launcher()
import config  # noqa: E402
import filetrace  # noqa: E402
import report  # noqa: E402
import resources  # noqa: E402



class Fixture(unittest.TestCase):
    """A fake HOME with config, state and a project; nothing touches the real home."""

    def setUp(self):
        self.root = scratch_dir(self)
        self.home = os.path.join(self.root, "home")
        self.project = os.path.join(self.home, "src", "proj")
        os.makedirs(os.path.join(self.project, ".git", "hooks"))
        os.makedirs(os.path.join(self.home, ".ssh"))
        open(os.path.join(self.home, ".ssh", "id_ed25519"), "w").close()
        self.config = os.path.join(self.home, ".config", "pithos")
        os.makedirs(self.config)
        self.paths = config.Paths({"HOME": self.home})
        self.runtime = os.path.join(self.root, "rt")
        os.makedirs(self.runtime)
        self.write_profile("base", """
            [fs]
            ro = ["/usr", "~/.gitconfig-missing"]
            rw = ["{project}"]
            deny = ["~/.ssh", "{project}/.env", "{project}/**/secret*"]
            ro_in_project = [".git/hooks"]
            [net]
            allow = ["github.com"]
            [env]
            pass = ["TERM"]
            set = { PATH = "~/bin:/usr/bin" }
        """)

    def write_profile(self, name, text):
        with open(os.path.join(self.config, name + ".toml"), "w") as f:
            f.write("\n".join(line.strip() for line in text.splitlines()))

    def write_project_file(self, text):
        with open(os.path.join(self.project, config.PROJECT_FILE), "w") as f:
            f.write(text)

    def plan(self, profile="base", environ=None):
        cfg = config.merge(config.load_profile(self.paths, profile), config.load_project(self.paths, self.project))
        return sb.build_plan(cfg, self.project, self.paths, self.runtime, environ or {})

    def argv(self, plan):
        return sb.bwrap_argv("bwrap", plan, self.project, ["claude"])


class Profiles(Fixture):
    def test_extends_merges_lists_and_env(self):
        self.write_profile("child", """
            extends = "base"
            [fs]
            rw = ["~/.child"]
            [env]
            set = { X = "{project}/x" }
        """)
        cfg = config.load_profile(self.paths, "child")
        self.assertEqual(cfg["fs"]["rw"], ["{project}", "~/.child"])
        self.assertEqual(cfg["env"]["set"], {"PATH": "~/bin:/usr/bin", "X": "{project}/x"})

    def test_schema_errors(self):
        cases = {
            "unknown key": "[fs]\nrox = []",
            "wrong type": "[fs]\nro = \"/usr\"",
            "non-string item": "[fs]\nro = [1]",
            "unknown section": "[shell]\nx = 1",
            "env.set value": "[env]\nset = { A = 1 }",
            "rw_mkdir type": "[fs]\nrw_mkdir = \"~/x\"",
        }
        for name, text in cases.items():
            with self.subTest(name):
                self.write_profile("bad", text)
                with self.assertRaises(config.ConfigError):
                    config.load_profile(self.paths, "bad")

    def test_profile_names(self):
        for name in ["../base", "/etc/passwd", "Base", "", "a/b", "__proto__"]:
            with self.subTest(name=name), self.assertRaises(config.ConfigError):
                config.load_profile(self.paths, name)

    def test_extends_loop(self):
        self.write_profile("a", 'extends = "b"')
        self.write_profile("b", 'extends = "a"')
        with self.assertRaises(config.ConfigError):
            config.load_profile(self.paths, "a")

    def test_shipped_profiles_are_valid(self):
        paths = config.Paths({"HOME": self.home, "PITHOS_CONFIG": os.path.join(ROOT, "profiles")})
        for name in ("base", "claude", "opencode", "opencode-claude"):
            with self.subTest(name):
                cfg = config.load_profile(paths, name)
                sb.proxy.Allowlist(cfg["net"]["allow"])


class Binds(Fixture):
    def bad(self, text):
        self.write_profile("bad", text)
        cfg = config.load_profile(self.paths, "bad")
        with self.assertRaises(config.ConfigError):
            sb.build_plan(cfg, self.project, self.paths, self.runtime, {})

    def test_refuses_dangerous_binds(self):
        self.bad('[fs]\nrw = ["~"]')
        self.bad('[fs]\nrw = ["~/.config"]')  # would expose the config dir writable
        self.bad('[fs]\nrw = ["~/.local/state/pithos/x"]')
        self.bad('[fs]\nro = ["/"]')
        self.bad('[fs]\nro = ["/run/user"]')
        self.bad('[fs]\nro = ["/var"]')  # contains /var/run
        self.bad('[fs]\nro = ["~/.ssh/id_ed25519"]\ndeny = ["~/.ssh"]')
        self.bad('[fs]\nro = ["relative/path"]')
        self.bad('[fs]\nro = ["{home}/x"]')
        self.bad('[fs]\nro_in_project = ["../escape"]')
        self.bad('[env]\nset = { "BAD NAME" = "x" }')
        self.bad('[env]\npass = ["A=B"]')

    def test_refuses_dangerous_mkdirs(self):
        self.bad('[fs]\nrw_mkdir = ["~/.ssh/new"]\ndeny = ["~/.ssh"]')
        self.bad('[fs]\nrw_mkdir = ["~/.local/state/pithos/x"]')
        self.bad('[fs]\nrw_mkdir = ["~/.config/pithos/x"]')
        self.bad('[fs]\nrw_mkdir = ["/tmp/x"]')
        self.bad('[fs]\nrw_mkdir = ["relative"]')

    def test_creates_missing_dir(self):
        self.write_profile("p", '[fs]\nrw_mkdir = ["~/.cache/agent/{project_slug}"]')
        plan = sb.build_plan(config.load_profile(self.paths, "p"), self.project, self.paths,
                             self.runtime, {})
        path = os.path.join(self.home, ".cache", "agent", config.project_slug(self.project))
        self.assertEqual(plan.mkdirs, [path])
        sb.make_dirs(plan)
        self.assertTrue(os.path.isdir(path))

    def test_symlink_in_project_cannot_expose_outside(self):
        os.symlink(os.path.join(self.home, ".ssh", "id_ed25519"),
                   os.path.join(self.project, ".git", "config"))
        self.write_profile("p", '[fs]\nrw = ["{project}"]\nro_in_project = [".git/config"]')
        cfg = config.load_profile(self.paths, "p")
        with self.assertRaises(config.ConfigError):
            sb.build_plan(cfg, self.project, self.paths, self.runtime, {})

    def test_ro_in_project_ancestors_are_pinned(self):
        # A mount point can't be renamed, so the sandbox can't `mv .git .git.x` and
        # recreate .git/config writable.
        open(os.path.join(self.project, ".git", "config"), "w").close()
        os.makedirs(os.path.join(self.project, "a", "b", "c"))
        open(os.path.join(self.project, config.PROJECT_FILE), "w").close()
        self.write_profile("p", '[fs]\nrw = ["{project}"]\n'
                                'ro_in_project = [".git/hooks", ".git/config", "a/b/c"]')
        plan = sb.build_plan(config.load_profile(self.paths, "p"), self.project, self.paths,
                             self.runtime, {})
        joined = " ".join(self.argv(plan))
        git = os.path.join(self.project, ".git")
        self.assertEqual(joined.count(f"--bind {git} {git} "), 1)
        self.assertLess(joined.index(f"--bind {self.project} "), joined.index(f"--bind {git} "))
        self.assertLess(joined.index(f"--bind {git} "), joined.index(f"--ro-bind {git}/hooks "))
        for anc in ("a", "a/b"):
            path = os.path.join(self.project, anc)
            self.assertIn(f"--bind {path} {path} ", joined)
        self.assertNotIn(f"--bind {self.project}/a/b/c ", joined)
        self.assertIn(f"--ro-bind {self.project}/{config.PROJECT_FILE} ", joined)

    def test_ro_in_project_never_makes_a_read_only_project_writable(self):
        open(os.path.join(self.project, ".git", "config"), "w").close()
        git = os.path.join(self.project, ".git")
        protect = 'ro_in_project = [".git/hooks", ".git/config", ".git/commondir"]'  # last: missing
        for name, binds in (("read-only", 'ro = ["/usr", "{project}"]'), ("unbound", 'ro = ["/usr"]'),
                            ("read-only .git", 'rw = ["{project}"]\nro = ["{project}/.git"]')):
            with self.subTest(name):
                self.write_profile("p", f"[fs]\n{binds}\n{protect}")
                plan = sb.build_plan(config.load_profile(self.paths, "p"), self.project,
                                     self.paths, self.runtime, {})
                joined = " ".join(self.argv(plan))
                self.assertNotIn(f"--bind {git}", joined)
                self.assertNotIn(f"{git}/", joined)
                self.assertEqual([p for p in plan.watch if p.startswith(git)], [])  # can't be created

    def test_ro_in_project_symlinked_ancestor_refused(self):
        # The agent could re-point the link, so the entry inside it can't be protected.
        git = os.path.join(self.project, ".git")
        os.rename(git, os.path.join(self.project, "gitdir"))
        os.symlink("gitdir", git)
        cfg = config.load_profile(self.paths, "base")
        with self.assertRaises(config.ConfigError):
            sb.build_plan(cfg, self.project, self.paths, self.runtime, {})

    def test_mount_order_and_overlays(self):
        for name in (".env", "sub/secret.txt", "sub/secretdir/x"):
            path = os.path.join(self.project, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            open(path, "w").close()
        os.symlink("/etc/hostname", os.path.join(self.project, "secret-link"))
        argv = self.argv(self.plan())
        joined = " ".join(argv)
        self.assertLess(argv.index("--tmpfs"), argv.index("/usr"))
        self.assertLess(joined.index(f"--tmpfs {self.home} "), joined.index(f"--bind {self.project} "))
        self.assertLess(joined.index(f"--bind {self.project} "), joined.index(".git/hooks"))
        self.assertIn(f"--ro-bind {self.runtime}/empty {self.project}/.env", joined)
        self.assertIn(f"--ro-bind {self.runtime}/empty {self.project}/sub/secret.txt", joined)
        self.assertIn(f"--tmpfs {self.project}/sub/secretdir --remount-ro {self.project}/sub/secretdir",
                      joined)
        self.assertNotIn("secret-link", joined)
        self.assertNotIn(".ssh", joined)  # not under any bind: nothing to hide
        self.assertNotIn("gitconfig-missing", joined)
        self.assertLess(joined.index(".git/hooks"), joined.index("/empty"))

    def test_environment(self):
        plan = self.plan(environ={"TERM": "xterm", "SECRET_TOKEN": "s", "HTTPS_PROXY": "http://evil"})
        env = plan.env
        self.assertEqual(env["TERM"], "xterm")
        self.assertNotIn("SECRET_TOKEN", env)
        self.assertEqual(env["HTTPS_PROXY"], sb.PROXY_URL)
        self.assertEqual(env["PATH"], f"{self.home}/bin:/usr/bin")
        argv = self.argv(plan)
        self.assertIn("--clearenv", argv)
        self.assertIn("--disable-userns", argv)
        self.assertIn("--unshare-all", argv)

    def test_env_values_stay_off_argv(self):
        plan = self.plan(environ={"TERM": "secret-term-value"})
        self.assertNotIn("secret-term-value", self.argv(plan))  # --dry-run: redacted
        argv = sb.bwrap_argv("bwrap", plan, self.project, ["claude"], env_fd=7)
        self.assertNotIn("secret-term-value", argv)
        self.assertIn("--args 7", " ".join(argv))
        args = sb.env_args(plan)
        self.assertEqual(args[args.index("TERM") + 1], "secret-term-value")

    def test_binds_are_mounted_by_fd(self):
        plan = self.plan()
        fds = sb.open_binds(plan)
        self.addCleanup(sb.close_fds, fds.values())
        hooks = os.path.join(self.project, ".git", "hooks")
        self.assertEqual(set(fds), {"/usr", self.project, os.path.join(self.project, ".git"), hooks})
        for src, fd in fds.items():
            st, host = os.fstat(fd), os.stat(src)
            self.assertEqual((st.st_dev, st.st_ino), (host.st_dev, host.st_ino), src)
        joined = " ".join(sb.bwrap_argv("bwrap", plan, self.project, ["x"], bind_fds=fds))
        self.assertIn(f"--bind-fd {fds[self.project]} {self.project} ", joined)
        self.assertIn(f"--ro-bind-fd {fds[hooks]} {hooks} ", joined)
        self.assertIn(f"--ro-bind-fd {fds['/usr']} /usr ", joined)
        self.assertNotIn(f"--bind {self.project} ", joined)
        self.assertIn(f"--ro-bind {self.runtime}/notice.md ", joined)  # pithos's own files: paths
        self.assertIn(f"--bind {self.project} ", " ".join(self.argv(plan)))  # --dry-run: paths

    def test_bind_swapped_for_a_link_after_planning_is_refused(self):
        # Another session writes the same project: it can swap .git/hooks for a link to ~/.ssh
        # between build_plan and bwrap. The link must not be followed.
        plan = self.plan()
        hooks = os.path.join(self.project, ".git", "hooks")
        os.rename(hooks, hooks + ".old")
        os.symlink(os.path.join(self.home, ".ssh"), hooks)
        with self.assertRaisesRegex(config.ConfigError, "changed into a link"):
            sb.open_binds(plan)
        os.unlink(hooks)
        git = os.path.join(self.project, ".git")
        os.rename(git, git + ".old")  # a link higher up is refused too
        os.symlink(self.home, git)
        with self.assertRaisesRegex(config.ConfigError, "link"):
            sb.open_nofollow(os.path.join(git, ".ssh"))
        with self.assertRaisesRegex(config.ConfigError, "cannot open"):
            sb.open_nofollow(os.path.join(self.project, "missing"))

    def test_deny_glob_escapes_project_path(self):
        for name in ("p[1]", "b[x-z]c", "plain"):
            with self.subTest(name):
                project = os.path.join(self.home, "src", name)
                os.makedirs(os.path.join(project, "sub"))
                for rel in (".env", "sub/secret.txt"):
                    open(os.path.join(project, rel), "w").close()
                cfg = config.load_profile(self.paths, "base")
                joined = " ".join(sb.bwrap_argv(
                    "bwrap", sb.build_plan(cfg, project, self.paths, self.runtime, {}),
                    project, ["x"]))
                self.assertIn(f"--ro-bind {self.runtime}/empty {project}/.env", joined)
                self.assertIn(f"--ro-bind {self.runtime}/empty {project}/sub/secret.txt", joined)

    def test_denied_symlink_hides_its_target(self):
        dots = os.path.join(self.home, "dotfiles")
        os.makedirs(os.path.join(dots, "ssh"))
        os.rename(os.path.join(self.home, ".ssh", "id_ed25519"),
                  os.path.join(dots, "ssh", "id_ed25519"))
        os.rmdir(os.path.join(self.home, ".ssh"))
        os.symlink("dotfiles/ssh", os.path.join(self.home, ".ssh"))
        self.write_profile("dots", 'extends = "base"\n[fs]\nro = ["~/dotfiles"]')
        joined = " ".join(self.argv(self.plan("dots")))
        self.assertIn(f"--tmpfs {dots}/ssh --remount-ro {dots}/ssh", joined)
        self.assertNotIn(f"--tmpfs {self.home}/.ssh", joined)  # the link itself isn't mounted
        self.bad('[fs]\nro = ["~/dotfiles/ssh/id_ed25519"]\ndeny = ["~/.ssh"]')

    def test_copy_is_private(self):
        host = os.path.join(self.home, ".agent.json")
        with open(host, "w") as f:
            f.write('{"projects": {}}')
        self.write_profile("p", '[fs]\ncopy = ["~/.agent.json", "~/.missing.json"]')
        plan = sb.build_plan(config.load_profile(self.paths, "p"), self.project, self.paths,
                             self.runtime, {})
        copy = os.path.join(self.runtime, "copy-0")
        self.assertIn(f"--bind {copy} {host}", " ".join(self.argv(plan)))
        self.assertNotIn(f"--bind {host} {host}", " ".join(self.argv(plan)))
        self.assertIn(f"copy {self.home}/.missing.json (missing)", plan.skipped)
        sb.make_dirs(plan)
        with open(copy, "a") as f:
            f.write("planted")
        with open(host) as f:
            self.assertEqual(f.read(), '{"projects": {}}')
        self.assertEqual(os.stat(copy).st_mode & 0o777, 0o600)
        self.bad('[fs]\ncopy = ["~/.config"]')  # not a regular file, and contains config dir
        self.bad('[fs]\ncopy = ["~/.ssh/id_ed25519"]\ndeny = ["~/.ssh"]')

    def test_created_protected_paths_are_quarantined(self):
        self.write_profile("p", '[fs]\nrw = ["{project}"]\n'
                                'ro_in_project = [".git/hooks", ".claude/settings.json"]')
        plan = sb.build_plan(config.load_profile(self.paths, "p"), self.project, self.paths,
                             self.runtime, {})
        planted = os.path.join(self.project, ".claude", "settings.json")
        self.assertIn(planted, plan.watch)
        self.assertNotIn(os.path.join(self.project, ".git", "hooks"), plan.watch)  # existed
        self.assertEqual(sb.quarantine(plan, "s1"), [])  # nothing appeared: nothing moved
        os.makedirs(os.path.dirname(planted))
        open(planted, "w").close()
        self.assertEqual(sb.quarantine(plan, "s1"), [planted + ".pithos-quarantine-s1"])
        self.assertFalse(os.path.lexists(planted))
        self.assertTrue(os.path.isdir(os.path.join(self.project, ".git", "hooks")))

    def test_quarantine_never_follows_a_planted_link(self):
        outside = os.path.join(self.home, "outside")
        os.makedirs(outside)
        open(os.path.join(outside, "settings.json"), "w").close()
        self.write_profile("p", '[fs]\nrw = ["{project}"]\nro_in_project = [".claude/settings.json"]')
        plan = sb.build_plan(config.load_profile(self.paths, "p"), self.project, self.paths,
                             self.runtime, {})
        os.symlink(outside, os.path.join(self.project, ".claude"))
        self.assertEqual(sb.quarantine(plan, "s1"), [])
        self.assertTrue(os.path.exists(os.path.join(outside, "settings.json")))

    def make_gitdir(self, rel):
        path = os.path.join(self.project, rel)
        os.makedirs(os.path.join(path, "hooks"))
        os.makedirs(os.path.join(path, "refs", "heads"))
        for name in ("HEAD", "config", "refs/heads/config"):  # a branch named "config"
            open(os.path.join(path, name), "w").close()
        return path

    def test_submodule_git_dirs_are_protected(self):
        foo = self.make_gitdir(".git/modules/libs/foo")
        bar = self.make_gitdir(".git/modules/libs/foo/modules/bar")
        plan = self.plan()
        joined = " ".join(self.argv(plan))
        self.assertEqual(plan.gitdirs, [".git/modules/libs/foo", ".git/modules/libs/foo/modules/bar"])
        for gitdir in (foo, bar):
            self.assertIn(f"--ro-bind {gitdir}/config {gitdir}/config", joined)
            self.assertIn(f"--ro-bind {gitdir}/hooks {gitdir}/hooks", joined)
            self.assertIn(f"--bind {gitdir} {gitdir} ", joined)  # pinned, contents writable
            self.assertNotIn(f"{gitdir}/refs/heads/config", joined)
            self.assertIn(f"{gitdir}/commondir", plan.watch)
        self.assertIn(f"--bind {self.project}/.git/modules/libs {self.project}/.git/modules/libs ",
                      joined)

    def test_submodule_link_refused(self):
        os.makedirs(os.path.join(self.project, ".git", "modules"))
        os.symlink(self.home, os.path.join(self.project, ".git", "modules", "evil"))
        with self.assertRaises(config.ConfigError):
            self.plan()

    def test_new_submodule_git_dir_is_quarantined(self):
        old = self.make_gitdir(".git/modules/old")
        plan = self.plan()
        new = self.make_gitdir(".git/modules/new")
        os.symlink(self.home, os.path.join(self.project, ".git", "modules", "link"))
        moved = sb.quarantine(plan, "s1")
        for path in (f"{new}/config", f"{new}/hooks", f"{self.project}/.git/modules/link"):
            self.assertIn(f"{path}.pithos-quarantine-s1", moved)
            self.assertFalse(os.path.lexists(path))
        self.assertTrue(os.path.exists(f"{new}/HEAD"))  # only what host git would run moves
        self.assertTrue(os.path.exists(f"{old}/config"))
        self.assertTrue(os.path.isdir(self.home))

    def test_quarantine_goes_on_after_a_failed_move(self):
        self.write_profile("p", '[fs]\nrw = ["{project}"]\nro_in_project = [".envrc", ".mcp.json"]')
        plan = sb.build_plan(config.load_profile(self.paths, "p"), self.project, self.paths,
                             self.runtime, {})
        envrc, mcp = (os.path.join(self.project, name) for name in (".envrc", ".mcp.json"))
        for path in (envrc, mcp):
            open(path, "w").close()
        real = os.rename

        def rename(src, dst):
            if src == envrc:
                raise PermissionError(13, "Permission denied")
            real(src, dst)
        err = io.StringIO()
        with mock.patch.object(sb.os, "rename", rename), contextlib.redirect_stderr(err):
            self.assertEqual(sb.quarantine(plan, "s1"), [mcp + ".pithos-quarantine-s1"])
        self.assertIn(f"created {envrc} and it could not be moved aside", err.getvalue())
        self.assertFalse(os.path.lexists(mcp))

    def test_editor_and_direnv_files_are_protected(self):
        paths = config.Paths({"HOME": self.home, "PITHOS_CONFIG": os.path.join(ROOT, "profiles")})
        os.makedirs(os.path.join(self.project, ".vscode"))
        tasks = os.path.join(self.project, ".vscode", "tasks.json")
        open(tasks, "w").close()
        plan = sb.build_plan(config.load_profile(paths, "base"), self.project, paths, self.runtime, {})
        joined = " ".join(sb.bwrap_argv("bwrap", plan, self.project, ["x"]))
        self.assertIn(f"--ro-bind {tasks} {tasks}", joined)
        for rel in (".envrc", ".vscode/settings.json", ".vscode/launch.json"):
            self.assertIn(os.path.join(self.project, rel), plan.watch)

    SSH = {"ssh": {"key": "~/.ssh/id_ed25519"}}

    def fake_ssh(self, add_status=0):
        """subprocess.run for ssh-agent and ssh-add; the agent is a real process to kill."""
        agent = subprocess.Popen(["sleep", "60"])
        self.addCleanup(agent.wait)
        self.addCleanup(agent.kill)
        calls = []

        def run(argv, **_kw):
            calls.append(argv)
            if argv[0] == "ssh-agent":
                return subprocess.CompletedProcess(argv, 0, f"SSH_AGENT_PID={agent.pid}; export\n")
            return subprocess.CompletedProcess(argv, add_status)
        return agent, calls, run

    def start_agent(self, run, plan=None):
        with mock.patch.object(sb.subprocess, "run", run):
            return sb.start_ssh_agent(self.SSH, self.project, self.paths, self.runtime,
                                      plan or sb.Plan())

    def write_known_hosts(self):
        with open(os.path.join(self.home, ".ssh", "known_hosts"), "w") as f:
            f.write("github.com ssh-ed25519 AAAA\n")

    def test_ssh_agent_refuses_providers(self):
        self.write_known_hosts()
        agent, calls, run = self.fake_ssh()
        plan = sb.Plan()
        self.assertEqual(self.start_agent(run, plan), agent.pid)
        self.assertEqual(calls[0][:4], ["ssh-agent", "-s", "-P", "none"])
        self.assertIn("StrictHostKeyChecking=yes", plan.env["GIT_SSH_COMMAND"])
        self.assertIsNone(agent.poll())  # running: the launcher stops it at the end

    def test_missing_known_hosts_starts_no_agent(self):
        _, calls, run = self.fake_ssh()
        with self.assertRaisesRegex(config.ConfigError, "known_hosts"):
            self.start_agent(run)
        self.assertEqual(calls, [])

    def test_ssh_agent_never_outlives_a_failed_start(self):
        """Once ssh-add ran, the agent holds the key: any failure must stop it."""
        self.write_known_hosts()
        for failure in ("ssh-add", "copy"):
            with self.subTest(failure=failure):
                agent, _, run = self.fake_ssh(add_status=1 if failure == "ssh-add" else 0)
                copy = mock.patch.object(sb.shutil, "copyfile", side_effect=OSError(5, "EIO"))
                with copy if failure == "copy" else contextlib.nullcontext(), \
                        self.assertRaises(config.ConfigError):
                    self.start_agent(run)
                self.assertEqual(agent.wait(timeout=5), -15)

    def test_project_checks(self):
        for bad in [self.home, os.path.dirname(self.home), self.config, "/", "/tmp"]:
            with self.subTest(bad=bad), self.assertRaises(config.ConfigError):
                config.check_project(bad, self.paths)
        config.check_project(self.project, self.paths)


class ClaudeDir(Fixture):
    """The claude profile exposes only the login and this project's transcripts."""

    def setUp(self):
        super().setUp()
        self.claude = os.path.join(self.home, ".claude")
        self.slug = config.project_slug(self.project)
        for rel in ("history.jsonl", ".credentials.json", "settings.json",
                    "projects/-other-project/session.jsonl", "file-history/x/y"):
            path = os.path.join(self.claude, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            open(path, "w").close()
        open(os.path.join(self.home, ".claude.json"), "w").close()
        self.paths = config.Paths({"HOME": self.home, "PITHOS_CONFIG": os.path.join(ROOT, "profiles")})

    def test_slug(self):
        self.assertEqual(config.project_slug("/home/a/src/my.proj_1"), "-home-a-src-my-proj-1")
        self.assertEqual(config.project_slug("/p/é\U0001f600"), "-p----")  # UTF-16 code units, as in JS
        for hostile in ("/a/../../etc", "/a/\n\x1b/b", "/a/{project}"):
            with self.subTest(hostile=hostile):
                self.assertRegex(config.project_slug(hostile), r"^[A-Za-z0-9-]+$")
        with self.assertRaises(config.ConfigError):
            config.project_slug("/" + "x" * config.SLUG_MAX)

    def test_only_own_project_dir_is_mounted(self):
        plan = self.plan("claude")
        own = os.path.join(self.claude, "projects", self.slug)
        self.assertEqual(plan.mkdirs, [own])
        joined = " ".join(self.argv(plan))
        self.assertIn(f"--bind {own} {own}", joined)
        self.assertIn(f"--bind {self.claude}/.credentials.json ", joined)
        self.assertIn(f"--ro-bind {self.claude}/settings.json ", joined)
        self.assertNotIn(f"{self.claude} ", joined)
        for hidden in ("history.jsonl", "-other-project", "file-history"):
            self.assertNotIn(hidden, joined)
        self.assertFalse(os.path.exists(own))  # planning (and --dry-run) creates nothing
        sb.make_dirs(plan)
        self.assertEqual(os.stat(own).st_mode & 0o777, 0o700)

    def test_claude_json_is_a_discarded_copy(self):
        joined = " ".join(self.argv(self.plan("claude")))
        host = os.path.join(self.home, ".claude.json")
        self.assertIn(f"--bind {self.runtime}/copy-0 {host}", joined)
        self.assertNotIn(f"--bind {host} ", joined)

    def test_opencode_state_is_per_project(self):
        for rel in (".local/share/opencode", ".local/state/opencode", ".cache/opencode/bin"):
            os.makedirs(os.path.join(self.home, rel))
        plan = self.plan("opencode")
        joined = " ".join(self.argv(plan))
        for rel in (".local/share/opencode", ".local/state/opencode", ".cache/opencode"):
            self.assertNotIn(f"{self.home}/{rel}", joined)
        own = os.path.join(self.home, ".local/share/pithos-opencode", self.slug)
        self.assertEqual(plan.mkdirs, [own])
        for name, sub_ in (("XDG_DATA_HOME", "data"), ("XDG_STATE_HOME", "state"),
                           ("XDG_CACHE_HOME", "cache")):
            self.assertEqual(plan.env[name], f"{own}/{sub_}")

    def test_plain_opencode_never_sees_claude_login(self):
        joined = " ".join(self.argv(self.plan("opencode")))
        self.assertNotIn(self.claude, joined)

    def test_opencode_claude_mounts_only_this_project(self):
        plan = self.plan("opencode-claude")
        joined = " ".join(self.argv(plan))
        own = os.path.join(self.claude, "projects", self.slug)
        host = os.path.join(self.home, ".claude.json")
        self.assertIn(f"--bind {self.claude}/.credentials.json ", joined)
        self.assertIn(f"--ro-bind {self.claude}/settings.json ", joined)
        self.assertIn(f"--bind {own} {own}", joined)
        self.assertNotIn(f"--bind {host} ", joined)
        self.assertNotIn(f"{self.claude} ", joined)
        for hidden in ("history.jsonl", "-other-project", "file-history"):
            self.assertNotIn(hidden, joined)
        self.assertEqual(plan.env["XDG_STATE_HOME"].rsplit("/", 2)[0],
                         os.path.join(self.home, ".local/share/pithos-opencode"))

    def test_existing_project_dir_is_not_recreated(self):
        own = os.path.join(self.claude, "projects", self.slug)
        os.makedirs(own)
        plan = self.plan("claude")
        self.assertEqual(plan.mkdirs, [])
        self.assertIn(f"--bind {own} {own}", " ".join(self.argv(plan)))

    def test_project_dir_link_to_secret_refused(self):
        os.makedirs(os.path.join(self.claude, "projects"), exist_ok=True)
        os.symlink(os.path.join(self.home, ".ssh"), os.path.join(self.claude, "projects", self.slug))
        with self.assertRaises(config.ConfigError):
            self.plan("claude")

    def test_project_dir_that_is_a_file_refused(self):
        open(os.path.join(self.claude, "projects", self.slug), "w").close()
        with self.assertRaises(config.ConfigError):
            self.plan("claude")


class AgentNotice(Fixture):
    def notice_profile(self, target="~/.claude/CLAUDE.md"):
        self.write_profile("agent", f'''
            extends = "base"
            [fs]
            ro = ["~/.claude/CLAUDE.md"]
            [agent]
            notice_into = "{target}"
        ''')

    def binds(self, argv):
        return [argv[i:i + 3] for i, a in enumerate(argv) if a in ("--bind", "--ro-bind")]

    def test_blocked_list_is_a_single_read_only_file(self):
        argv = self.argv(self.plan())
        self.assertIn(["--ro-bind", f"{self.runtime}/blocked-hosts", config.SANDBOX_BLOCKED_HOSTS], self.binds(argv))
        mounted = [b[1] for b in self.binds(argv)]
        self.assertNotIn(self.runtime, mounted)
        self.assertFalse([b for b in self.binds(argv) if b[0] == "--bind" and "blocked-hosts" in b[1]])

    def test_profile_cannot_override_blocked_path(self):
        self.write_profile("sneaky", """
            extends = "base"
            [env]
            set = { PITHOS_BLOCKED_HOSTS = "/tmp/elsewhere" }
        """)
        self.assertEqual(self.plan("sneaky").env["PITHOS_BLOCKED_HOSTS"], config.SANDBOX_BLOCKED_HOSTS)

    def test_notice_is_added_to_the_users_file(self):
        os.makedirs(os.path.join(self.home, ".claude"))
        path = os.path.join(self.home, ".claude", "CLAUDE.md")
        with open(path, "w") as f:
            f.write("my own rules")
        self.notice_profile()
        plan = self.plan("agent")
        sb.make_dirs(plan)
        with open(os.path.join(self.runtime, "agent-notice.md")) as f:
            text = f.read()
        self.assertTrue(text.startswith("my own rules"))
        self.assertIn("pithos allow", text)
        with open(path) as f:
            self.assertEqual(f.read(), "my own rules")
        argv = self.argv(plan)
        generated = argv.index(os.path.join(self.runtime, "agent-notice.md"))
        original = argv.index(path)  # the plain bind comes first: the generated one wins
        self.assertLess(original, generated)
        self.assertEqual(argv[generated - 1], "--ro-bind")

    def test_notice_without_a_users_file(self):
        self.notice_profile()
        sb.make_dirs(self.plan("agent"))
        with open(os.path.join(self.runtime, "agent-notice.md")) as f:
            self.assertIn(config.SANDBOX_BLOCKED_HOSTS, f.read())

    def test_notice_cannot_target_a_denied_path(self):
        self.notice_profile("~/.ssh/config")
        with self.assertRaises(config.ConfigError):
            self.plan("agent")

    def test_notice_cannot_target_a_directory(self):
        os.makedirs(os.path.join(self.home, ".claude", "CLAUDE.md"))
        self.notice_profile()
        with self.assertRaises(config.ConfigError):
            self.plan("agent")

    def test_runtime_files_exist_for_every_bind(self):
        sb.write_runtime_files(self.runtime)
        for name in ("empty", "blocked-hosts", "notice.md", "opencode.json"):
            self.assertTrue(os.path.isfile(os.path.join(self.runtime, name)), name)
        with open(os.path.join(self.runtime, "opencode.json")) as f:
            self.assertEqual(json.load(f), {"instructions": [config.SANDBOX_NOTICE]})


class ProjectFile(Fixture):
    def test_untrusted_refused_then_trusted_then_changed(self):
        self.write_project_file('[net]\nallow = ["example.com"]\n')
        with self.assertRaises(config.ConfigError):
            self.plan()
        self.trust()
        plan = self.plan()
        self.assertIn(f"{self.project}/{config.PROJECT_FILE}", " ".join(self.argv(plan)))
        self.write_project_file('[fs]\nro = ["~/.ssh"]\n')
        with self.assertRaises(config.ConfigError):
            self.plan()

    def trust(self):
        with open(os.path.join(self.project, config.PROJECT_FILE), "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        os.makedirs(self.paths.state, exist_ok=True)
        with open(self.paths.trusted, "w") as f:
            json.dump({self.project: digest}, f)

    def test_extends_not_allowed(self):
        self.write_project_file('extends = "claude"\n')
        self.trust()
        with self.assertRaises(config.ConfigError):
            self.plan()

    def test_agent_section_not_allowed(self):
        self.write_project_file('[agent]\nnotice_into = "~/.bashrc"\n')
        self.trust()
        with self.assertRaises(config.ConfigError):
            self.plan()

    def test_symlinked_file_refused(self):
        os.symlink("/etc/hostname", os.path.join(self.project, config.PROJECT_FILE))
        with self.assertRaises(config.ConfigError):
            self.plan()

    def test_corrupt_trust_store_fails_closed(self):
        self.write_project_file('[net]\nallow = ["example.com"]\n')
        os.makedirs(self.paths.state, exist_ok=True)
        with open(self.paths.trusted, "w") as f:
            f.write('["not", "a", "dict"]')
        with self.assertRaises(config.ConfigError):
            self.plan()


class AllowCommand(Fixture):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("PITHOS", None)

    def session(self, name="s1", project=None, pid=None):
        os.makedirs(self.paths.sessions, exist_ok=True)
        with open(self.paths.session_file(name), "w") as f:
            json.dump({"pid": pid or os.getpid(), "project": project or self.project,
                       "allow": []}, f)

    def run_allow(self, *argv, answers=None):
        """Returns (exit code, stdout). With answers, stdin acts as a terminal."""
        _, args = sb.parse_args(["allow", "-C", self.project, *argv])
        out = io.StringIO()
        stdin = mock.Mock()
        stdin.isatty.return_value = answers is not None
        with mock.patch.object(sb.sys, "stdin", stdin), contextlib.redirect_stdout(out), \
                mock.patch("builtins.input", side_effect=answers or []) as prompts:
            code = sb.cmd_allow(args, self.paths)
        self.prompts = [call.args[0] for call in prompts.call_args_list]
        return code, out.getvalue()

    def session_allow(self, name="s1"):
        with open(self.paths.session_file(name)) as f:
            return json.load(f)["allow"]

    def saved(self):
        return config.read_json_table(self.paths.allowed).get(self.project, [])

    def write_log(self, events, name="s1"):
        os.makedirs(self.paths.logs, exist_ok=True)
        with open(os.path.join(self.paths.logs, name + ".jsonl"), "a") as f:
            for event in events:
                f.write((event if isinstance(event, str) else json.dumps(event)) + "\n")

    def denial(self, host, port=443, reason=sb.proxy.NOT_LISTED):
        return {"action": "deny", "host": host, "port": port, "reason": reason}

    def test_session_only_by_default(self):
        self.session()
        self.assertEqual(self.run_allow("Example.COM")[0], 0)
        self.assertEqual(self.session_allow(), ["example.com:443"])
        self.assertFalse(os.path.exists(self.paths.allowed))

    def test_save_writes_both_and_next_session_loads_it(self):
        self.session()
        self.run_allow("--save", "example.com:8080")
        self.assertEqual(self.session_allow(), ["example.com:8080"])
        self.assertEqual(self.saved(), ["example.com:8080"])
        self.assertEqual(os.stat(self.paths.allowed).st_mode & 0o777, 0o600)
        sb.register_session(self.paths, "s2", self.project)
        live = sb.proxy.LiveAllowlist(
            sb.proxy.Allowlist([]), [self.paths.allowed],
            lambda: sb.read_live_entries(self.paths, "s2", self.project))
        self.assertTrue(live.allows("name", "example.com", 8080))

    def test_no_session_writes_nothing(self):
        with self.assertRaisesRegex(config.ConfigError, "no running session"):
            self.run_allow("example.com")
        self.assertFalse(os.path.exists(self.paths.allowed))

    def test_save_works_without_a_session(self):
        self.assertEqual(self.run_allow("--save", "example.com")[0], 0)
        self.assertEqual(self.saved(), ["example.com:443"])

    def test_only_this_project_and_all_its_sessions(self):
        other = os.path.join(self.home, "src", "other")
        os.makedirs(other)
        self.session("s1")
        self.session("s2")
        self.session("s3", project=other)
        self.run_allow("example.com")
        self.assertEqual(self.session_allow("s1"), ["example.com:443"])
        self.assertEqual(self.session_allow("s2"), ["example.com:443"])
        self.assertEqual(self.session_allow("s3"), [])

    def test_stale_session_is_cleaned_up(self):
        child = subprocess.Popen(["true"])
        child.wait()
        self.session(pid=child.pid)
        with self.assertRaises(config.ConfigError):
            self.run_allow("example.com")
        self.assertFalse(os.path.exists(self.paths.session_file("s1")))

    def test_damaged_session_records_are_not_running(self):
        os.makedirs(self.paths.sessions)
        for name, text in [("a", "{broken"), ("b", "[]"), ("c", '{"pid": "1", "project": "x"}'),
                           ("d", '{"pid": true, "project": "x"}'), ("e", '{"pid": -1, "project": "x"}'),
                           ("f", json.dumps({"pid": os.getpid(), "project": 3}))]:
            with open(self.paths.session_file(name), "w") as f:
                f.write(text)
        self.assertEqual(sb.running_sessions(self.paths), {})

    def test_remove_clears_both(self):
        self.session()
        self.run_allow("--save", "example.com", "keep.example.com")
        code, out = self.run_allow("--remove", "EXAMPLE.com:443")
        self.assertEqual(code, 0)
        self.assertIn("stay open", out)
        self.assertEqual(self.session_allow(), ["keep.example.com:443"])
        self.assertEqual(self.saved(), ["keep.example.com:443"])

    def test_remove_unknown_host_is_an_error(self):
        self.session()
        with self.assertRaisesRegex(config.ConfigError, "not approved"):
            self.run_allow("--remove", "example.com")

    def test_refuses_what_a_sandbox_could_trick_you_into(self):
        self.session()
        for bad in ["127.0.0.1", "169.254.169.254:80", "[::1]", "*.com", "<img src=x onerror=alert(1)>"]:
            with self.subTest(bad=bad), self.assertRaises(config.ConfigError):
                self.run_allow(bad)
        self.assertEqual(self.session_allow(), [])

    def test_one_bad_host_refuses_the_whole_command(self):
        self.session()
        with self.assertRaises(config.ConfigError):
            self.run_allow("good.example.com", "127.0.0.1")
        self.assertEqual(self.session_allow(), [])

    def test_damaged_saved_list_is_not_overwritten(self):
        os.makedirs(self.paths.state, exist_ok=True)
        for text in ["{broken", '{"%s": "x"}' % self.project, '{"%s": [1]}' % self.project]:
            with self.subTest(text=text):
                with open(self.paths.allowed, "w") as f:
                    f.write(text)
                with self.assertRaisesRegex(config.ConfigError, "damaged"):
                    self.run_allow("--save", "example.com")
                with open(self.paths.allowed) as f:
                    self.assertEqual(f.read(), text)

    def test_flag_combinations(self):
        for argv in (["--save"], ["--remove"], ["--list", "x.com"], ["--save", "--remove", "x.com"]):
            with self.subTest(argv=argv), self.assertRaises(config.ConfigError):
                self.run_allow(*argv)

    def test_refused_inside_a_sandbox(self):
        self.session()
        os.environ["PITHOS"] = "1"
        with self.assertRaisesRegex(config.ConfigError, "outside the sandbox"):
            self.run_allow("example.com")

    def test_prompt_answers(self):
        self.session()
        self.write_log([self.denial("yes.example.com"), self.denial("yes.example.com"),
                        self.denial("save.example.com"), self.denial("enter.example.com"),
                        self.denial("no.example.com")])
        answers = {"yes.": "y", "save": "s", "enter": "", "no.": "n"}
        order = sb.pending_hosts(self.paths, sb.running_sessions(self.paths), self.project)
        self.assertEqual(order[0], ("yes.example.com:443", 2))
        replies = [next(v for k, v in answers.items() if entry.startswith(k)) for entry, _ in order]
        self.assertEqual(self.run_allow(answers=replies)[0], 0)
        self.assertEqual(sorted(self.session_allow()), ["save.example.com:443", "yes.example.com:443"])
        self.assertEqual(self.saved(), ["save.example.com:443"])
        self.assertIn("(2x)", self.prompts[0])
        self.assertEqual(len(self.run_allow(answers=["n", "n"])[1].splitlines()), 0)
        self.assertEqual(len(self.prompts), 2)  # approved hosts aren't asked about again

    def test_end_of_input_approves_nothing(self):
        self.session()
        self.write_log([self.denial("example.com")])
        self.assertEqual(self.run_allow(answers=[EOFError()])[0], 1)
        self.assertEqual(self.session_allow(), [])

    def test_no_terminal_approves_nothing(self):
        self.session()
        self.write_log([self.denial("example.com")])
        code, out = self.run_allow()
        self.assertEqual(code, 0)
        self.assertIn("example.com:443", out)
        self.assertIn("nothing approved", out)
        self.assertEqual(self.session_allow(), [])

    def test_hostile_log_lines_are_not_offered(self):
        self.session()
        self.write_log([
            self.denial("evil\x1b]52;c;x\x07.example.com"),
            self.denial("<img src=x onerror=alert(1)>"),
            self.denial("127.0.0.1"), self.denial("1.1.1.1"), self.denial("::1"),
            self.denial("UPPER.example.com"), self.denial("*.example.com"),
            self.denial("sni.example.com", reason="TLS SNI 'x' does not match"),
            self.denial("private.example.com", reason="non-public address 10.0.0.1"),
            self.denial("port.example.com", port="443"), self.denial("port.example.com", port=0),
            self.denial(["list"]), self.denial(None), self.denial({"a": 1}),
            "not json", "[1, 2]", '"text"', "null",
            {"action": "allow", "host": "allowed.example.com", "port": 443,
             "reason": sb.proxy.NOT_LISTED},
        ])
        code, out = self.run_allow()
        self.assertEqual((code, out), (0, "no denied hosts are waiting\n"))

    def test_prompt_list_is_capped(self):
        self.session()
        self.write_log([self.denial(f"h{n}.example.com") for n in range(sb.PENDING_SHOWN + 5)])
        _, out = self.run_allow()
        self.assertIn("and 5 more", out)
        self.assertEqual(out.count(":443"), sb.PENDING_SHOWN)

    def test_list(self):
        self.session()
        self.run_allow("--save", "example.com")
        _, out = self.run_allow("--list")
        self.assertIn('session s1: ["example.com:443"]', out)
        self.assertIn('saved for this project: ["example.com:443"]', out)

    def test_log_denied_prints_ipv6_that_parses_back(self):
        self.write_log([self.denial("2606:4700:4700::1111")])
        _, args = sb.parse_args(["log", "--denied"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            sb.cmd_log(args, self.paths)
        self.assertIn('"[2606:4700:4700::1111]:443"', out.getvalue())

    def run_log(self, *argv, paths=None):
        _, args = sb.parse_args(["log", *argv])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(sb.cmd_log(args, paths or self.paths), 0)
        return out.getvalue()

    def test_log_denied_without_denials_says_only_that(self):
        self.write_log([{"action": "allow", "host": "github.com", "port": 443}])
        self.assertEqual(self.run_log("--denied"), "nothing denied\n")

    def test_log_works_in_a_state_dir_with_glob_characters(self):
        state = os.path.join(self.root, "state[1]")
        paths = config.Paths({"HOME": self.home, "PITHOS_STATE": state})
        os.makedirs(paths.logs)
        with open(os.path.join(paths.logs, "s1.jsonl"), "w") as f:
            f.write(json.dumps({"action": "start", "profile": "base"}) + "\n")
        self.assertIn("profile=base", self.run_log(paths=paths))


class Report(Fixture):
    SID = "20260101-120000-abc123"
    EVIL = "<img src=x onerror=alert(1)>\x1b]52;c;evil\x07"

    def setUp(self):
        super().setUp()
        os.makedirs(self.paths.logs)

    def start(self, **extra):
        return {"ts": "2026-01-01T12:00:00+0000", "action": "start", "profile": "base",
                "project": self.project, "cmd": ["x"], **extra}

    def write(self, events, calls=None, sid=None):
        base = os.path.join(self.paths.logs, sid or self.SID)
        with open(base + ".jsonl", "w") as f:
            for event in events:
                f.write((event if isinstance(event, str) else json.dumps(event)) + "\n")
        if calls is not None:
            with open(base + ".trace", "w") as f:
                f.writelines(trace_lines(*calls))

    def report(self, *argv):
        _, args = sb.parse_args(["report", *argv])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = report.cmd_report(args, self.paths)
        self.assertEqual(code, 0)
        return out.getvalue()

    def section(self, text, title):
        return text.split(title, 1)[1].split("\n\n", 1)[0]

    def denial(self, host, reason=sb.proxy.NOT_LISTED, port=443):
        return {"action": "deny", "host": host, "port": port, "reason": reason}

    def missing(self, path):
        return f'openat(AT_FDCWD, "{path}", O_RDONLY) = -1 ENOENT (No such file or directory)'

    def test_no_sessions(self):
        self.assertEqual(self.report(), "no sessions logged yet\n")

    def test_no_limits_sessions_say_so(self):
        self.write([self.start(limits={"processes": 512, "memory": GB}, scoped=False)])
        self.assertIn("not enforced: --no-limits", self.report())
        self.write([self.start(limits={"processes": 512, "memory": GB})])
        self.assertNotIn("not enforced", self.report())

    def test_limits_and_kills(self):
        self.write([self.start(limits={"processes": 4500, "memory": GB, "total": "<evil>",
                                       "tmpfs": None, "cpu": 200}),
                    {"action": "limit", "limit": "memory", "count": 2},
                    {"action": "limit", "limit": "memory", "count": 1},
                    {"action": "limit", "limit": "processes", "count": 7},
                    {"action": "limit", "limit": "<evil>", "count": 9},
                    {"action": "limit", "limit": "memory", "count": "9"},
                    {"action": "limit", "limit": "memory", "count": -9}])
        out = self.report()
        self.assertIn("limits: processes 4500, memory per process 1G, memory in total unlimited, "
                      "tmpfs each unlimited, cpu 2 CPUs", out)
        self.assertIn("killed by the kernel at the memory limit: 3", out)
        self.assertIn("refused at the process limit: 7", out)
        self.assertNotIn("evil", out)

    def test_file_notice_events(self):
        os.makedirs(os.path.join(self.home, ".cache", "tool"))
        events = [self.start()] + [
            {"action": "file", "path": path, "reason": reason} for path, reason in (
                (os.path.join(self.home, ".ssh", "id_ed25519"), filetrace.HIDDEN),
                (os.path.join(self.home, ".cache", "tool"), filetrace.NOT_MOUNTED),
                (os.path.join(self.home, ".cache", "absent"), filetrace.NOT_MOUNTED),
                ("/opt/" + self.EVIL, filetrace.NOT_MOUNTED),
                (os.path.join(self.home, ".cache", "tool"), "made up"),
                ([1], filetrace.NOT_MOUNTED))]
        self.write(events)
        out = self.report()
        self.assertIn("id_ed25519", self.section(out, "Hidden paths the agent tried"))
        told = self.section(out, "agent was told about")
        self.assertIn(".cache/tool", told)
        self.assertNotIn("absent", told)
        self.assertNotIn("id_ed25519", told)
        self.assertNotIn("made up", out)
        self.assertNotIn("\x1b", out)

    def test_splits_violations_from_tuning(self):
        self.write([self.start(), self.denial("example.com"),
                    self.denial("evil.test", reason="TLS SNI 'x' does not match"),
                    {"action": "allow", "host": "github.com", "port": 443}], [])
        out = self.report()
        self.assertIn("evil.test", self.section(out, "policy violations"))
        self.assertNotIn("example.com", self.section(out, "policy violations"))
        self.assertIn("example.com:443", self.section(out, "tried and refused"))
        self.assertIn('"example.com:443",', self.section(out, "Hosts to consider"))
        self.assertNotIn("evil.test", self.section(out, "Hosts to consider"))
        self.assertNotIn("net.allow  github.com", out)

    def test_lists_hosts_contacted_with_counts(self):
        allow = {"action": "allow", "host": "api.example.com", "port": 443}
        self.write([self.start(), allow, allow,
                    {"action": "allow", "host": self.EVIL, "port": 443}], [])
        out = self.report()
        self.assertIn("2x api.example.com:443", self.section(out, "Hosts contacted"))
        self.assertNotIn("\x1b", out)

    def test_flags_probe_of_secret_even_through_dotdot(self):
        self.write([self.start()], [self.missing(f"{self.project}/../../.ssh/id_rsa")])
        self.assertIn("id_rsa", self.section(self.report(), "Sensitive paths"))

    def test_profile_deny_glob_is_sensitive(self):
        self.write([self.start()], [self.missing(f"{self.project}/a/b/secret.txt")])
        self.assertIn("secret.txt", self.section(self.report(), "Sensitive paths"))

    def test_protected_write_attempt(self):
        hook = f"{self.project}/.git/hooks/pre-commit"
        self.write([self.start()],
                   [f'openat(AT_FDCWD, "{hook}", O_WRONLY|O_CREAT, 0644) = -1 EROFS (Read-only file system)'])
        self.assertIn("pre-commit", self.section(self.report(), "Protected project"))

    def test_missing_host_path_offered_but_never_a_secret(self):
        wanted = os.path.join(self.home, "tool.conf")
        open(wanted, "w").close()
        self.write([self.start()], [self.missing(wanted), self.missing(self.home + "/.ssh/id_ed25519"),
                                    self.missing(self.home), self.missing("/proc/1/environ")])
        block = self.section(self.report(), "Looked for")
        self.assertIn("tool.conf", block)
        for bad in (".ssh", "environ"):
            self.assertNotIn(bad, block)
        self.assertNotIn(self.home + "\n", block + "\n")

    def test_unused_rules(self):
        self.write([self.start()], [f'openat(AT_FDCWD, "/usr/bin/x", O_RDONLY) = 3</usr/bin/x>'])
        block = self.section(self.report(), "Allowed but unused")
        self.assertIn("github.com", block)
        self.assertNotIn("/usr", block)

    def test_hostile_values_are_neutralised(self):
        self.write([self.start(cmd=[self.EVIL]), self.denial(self.EVIL), self.denial(self.EVIL, reason=self.EVIL),
                    {"action": "quarantine", "path": self.EVIL}, "not json", "[1]", 
                    self.denial(["x"]), self.denial("a.test", port="443")], [])
        out = self.report()
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)
        self.assertIn("unreadable log lines: 2", out)
        self.assertNotIn("onerror", self.section(out, "Hosts to consider"))
        self.assertNotIn("a.test", self.section(out, "Hosts to consider"))

    def test_session_id_is_validated(self):
        self.write([self.start()])
        for bad in ("../x", "20260101-120000-abc12", "x" * 10, "2026010١-120000-abc123"):
            _, args = sb.parse_args(["report", "--session", bad])
            with self.assertRaises(config.ConfigError):
                report.cmd_report(args, self.paths)
        self.assertIn(self.SID, self.report("--session", self.SID))

    def test_without_trace(self):
        self.write([self.start()])
        self.assertIn("re-run with --trace", self.report())

    def test_untrusted_project_config_is_not_applied(self):
        with open(os.path.join(self.project, ".pithos.toml"), "w") as f:
            f.write('[net]\nallow = ["planted.test"]\n')
        self.write([self.start()], [])
        out = self.report()
        self.assertIn("skipped", out)
        self.assertNotIn("planted.test", out)

    RULES = {"fs": {"ro": ["/opt/logged"], "rw": [], "rw_mkdir": [], "deny": ["~/.vault"],
                    "ro_in_project": []}, "net": {"allow": ["logged.test"]}}

    def test_logged_rules_win_over_the_current_profile(self):
        self.write([self.start(rules=self.RULES)], [self.missing(self.home + "/.vault/key")])
        out = self.report()
        self.assertIn("rules recorded when the session started", out)
        block = self.section(out, "Allowed but unused")
        self.assertIn("logged.test", block)
        self.assertNotIn("github.com", block)
        self.assertIn(".vault/key", self.section(out, "Sensitive paths"))

    def test_logged_rules_do_not_read_the_project_config(self):
        with open(os.path.join(self.project, ".pithos.toml"), "w") as f:
            f.write('[net]\nallow = ["planted.test"]\n')
        self.write([self.start(rules=self.RULES)], [])
        out = self.report()
        self.assertNotIn("planted.test", out)
        self.assertIn("logged.test", out)

    def test_damaged_logged_rules_are_skipped(self):
        for bad in (5, {"net": {"allow": "x"}}, {"nope": {}}, {"net": {"allow": ["bad host:x"]}}):
            with self.subTest(bad=bad):
                self.write([self.start(rules=bad)], [])
                self.assertIn("profile checks skipped", self.report())

    def test_snapshot_round_trips_through_validation(self):
        cfg = config.merge(config.load_profile(self.paths, "base"), {})
        snapshot = report.rule_snapshot(cfg)
        config.validate(json.loads(json.dumps(snapshot)), where="x")
        self.assertEqual(snapshot["net"]["allow"], ["github.com"])

    def test_same_profile_with_changed_rules_skips_checks(self):
        self.write([self.start(rules=self.RULES)], [])
        self.write([self.start()], [], sid="20260101-130000-abc123")
        self.assertIn("different profiles", self.report("--all"))

    def test_mixed_sessions_skip_profile_checks(self):
        self.write([self.start()], [])
        self.write([self.start(profile="other")], [], sid="20260101-130000-abc123")
        self.assertIn("different profiles", self.report("--all"))

    def test_removed_flags_are_refused(self):
        """report --explain and its run --no-base-net are gone, not silently ignored."""
        for argv in (["report", "--explain"], ["run", "--no-base-net", "--", "true"]):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit):
                sb.parse_args(argv)


class WindowTitle(unittest.TestCase):
    def stream(self, tty=True):
        out = io.StringIO()
        out.isatty = lambda: tty
        return out

    def test_names_window_in_tmux(self):
        out = self.stream()
        with mock.patch.dict(os.environ, {"TMUX": "/tmp/tmux-1000/default,1,0"}):
            sb.set_window_title("claude", out)
        self.assertEqual(out.getvalue(), "\033]2;claude\007")

    def test_does_nothing_outside_tmux(self):
        out = self.stream()
        with mock.patch.dict(os.environ, {"TMUX": ""}):
            sb.set_window_title("claude", out)
        self.assertEqual(out.getvalue(), "")

    def test_does_nothing_without_a_terminal(self):
        out = self.stream(tty=False)
        with mock.patch.dict(os.environ, {"TMUX": "x"}):
            sb.set_window_title("claude", out)
        self.assertEqual(out.getvalue(), "")

    def test_strips_control_characters(self):
        out = self.stream()
        with mock.patch.dict(os.environ, {"TMUX": "x"}):
            sb.set_window_title("\x1b]2;evil\x07claude", out)
        self.assertEqual(out.getvalue(), "\033]2;]2;evilclaude\007")


BWRAP_SETUP = 'mount("/home/setup", "/newroot/x", NULL, MS_BIND, NULL) = 0\n'
BRIDGE_START = 'execve("/usr/bin/python3", ["/usr/bin/python3", "-I"], 0x1 /* 9 vars */) = 0\n'


def trace_lines(*calls):
    return [f"7  {c}\n" for c in (BWRAP_SETUP.strip(), BRIDGE_START.strip(), *calls)]


class Trace(Fixture):
    def test_strace_argv_wraps_bwrap_unchanged(self):
        inner = ["/usr/bin/bwrap", "--args", "7", "--", "cmd"]
        for failed_only in (True, False):
            argv = filetrace.strace_argv("/usr/bin/strace", "/l/s.trace", inner, failed_only)
            self.assertEqual(argv[-len(inner):], inner)
            self.assertIn("-D", argv)
            self.assertIn("--seccomp-bpf", argv)
            self.assertNotIn("-v", argv)
            self.assertEqual("-Z" in argv, failed_only)

    def test_summary_starts_at_the_bridge_probe_and_skips_it(self):
        probe = f'stat("{config.TRACE_START}", 0x1) = -1 ENOENT (No such file or directory)'
        lines = [f"7  {c}\n" for c in (
            'openat(AT_FDCWD, "/setup", O_RDONLY) = -1 ENOENT (No such file or directory)',
            probe, 'openat(AT_FDCWD, "/after", O_RDONLY) = -1 ENOENT (x)')]
        self.assertEqual(filetrace.summarise_trace(lines)["missing"], {"/after": 1})

    def test_paths_are_unescaped_and_relative_ones_joined_to_the_cwd(self):
        groups = filetrace.summarise_trace(trace_lines(
            r'openat(AT_FDCWD</w>, "caf\303\251 \"q\" b\\s", O_RDONLY) = 3</w/x>',
            r'openat(AT_FDCWD, "/bad\377", O_RDONLY) = 3</x>'))
        self.assertEqual(set(groups["read"]), {'/w/café "q" b\\s', "/bad\\xff"})

    def test_flag_does_not_swallow_the_command(self):
        command, args = sb.parse_args(["--trace", "claude"])
        self.assertEqual((command, args.trace, args.cmd), ("run", True, ["claude"]))
        self.assertFalse(sb.parse_args(["claude"])[1].trace)

    def test_env_values_stay_off_the_traced_argv(self):
        plan = self.plan(environ={"TERM": "secret-term-value"})
        argv = filetrace.strace_argv("strace", "/l/s.trace",
                              sb.bwrap_argv("bwrap", plan, self.project, ["x"], env_fd=7))
        self.assertNotIn("secret-term-value", " ".join(argv))

    def test_missing_strace_is_an_error(self):
        _, args = sb.parse_args(["-C", self.project, "--trace", "claude"])
        with mock.patch.object(sb.shutil, "which", lambda n: None if n == "strace" else "/b/" + n), \
                mock.patch.object(sb, "check_bwrap", lambda bwrap: None):
            with self.assertRaisesRegex(config.ConfigError, "strace"):
                sb.cmd_run(args, self.paths)

    def test_log_is_private(self):
        path = os.path.join(self.root, "a.trace")
        filetrace.create_trace_log(path)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_log_refuses_existing_file_and_symlink(self):
        target = os.path.join(self.root, "target")
        link = os.path.join(self.root, "link.trace")
        os.symlink(target, link)
        with self.assertRaises(config.ConfigError):
            filetrace.create_trace_log(link)
        self.assertFalse(os.path.exists(target))
        open(target, "w").close()
        with self.assertRaises(config.ConfigError):
            filetrace.create_trace_log(target)

    def test_summary_groups(self):
        groups = filetrace.summarise_trace(trace_lines(
            'openat(AT_FDCWD, "/etc/hostname", O_RDONLY|O_CLOEXEC) = 3</etc/hostname>',
            'openat(AT_FDCWD, "/etc/hostname", O_RDONLY|O_CLOEXEC) = 3</etc/hostname>',
            'openat(AT_FDCWD, "/w/out", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</w/out>',
            'mkdir("/w/dir", 0777) = 0',
            'rename("/w/a", "/w/b") = 0',
            'symlink("/ignored/target", "/w/ln") = 0',
            'openat(4</w/sub>, "rel", O_RDONLY) = 5</w/sub/rel>',
            'statx(AT_FDCWD, "/opt/no", AT_STATX_SYNC_AS_STAT, STATX_ALL, 0x1) '
            '= -1 ENOENT (No such file or directory)',
            'openat(AT_FDCWD, "/usr/x", O_WRONLY) = -1 EROFS (Read-only file system)',
        ))
        self.assertEqual(groups["read"], {"/etc/hostname": 2, "/w/sub/rel": 1})
        self.assertEqual(set(groups["written"]), {"/w/out", "/w/dir", "/w/a", "/w/b", "/w/ln"})
        self.assertEqual(groups["missing"], {"/opt/no": 1})
        self.assertEqual(groups["refused"], {"/usr/x": 1})

    def test_summary_skips_setup_and_needs_the_bridge(self):
        groups = filetrace.summarise_trace(trace_lines())
        self.assertFalse(any(groups.values()))
        lines = ['7  openat(AT_FDCWD, "/before", O_RDONLY) = 3</before>\n']
        self.assertFalse(any(filetrace.summarise_trace(lines).values()))

    def test_summary_joins_split_lines(self):
        lines = trace_lines() + [
            '8  openat(AT_FDCWD, "/a", O_WRONLY <unfinished ...>\n',
            '9  stat("/b", {st_mode=S_IFREG}) = 0\n',
            '8  <... openat resumed>) = 3</a>\n',
        ]
        groups = filetrace.summarise_trace(lines)
        self.assertEqual(groups["written"], {"/a": 1})
        self.assertEqual(groups["read"], {"/b": 1})

    def test_summary_survives_hostile_lines(self):
        lines = trace_lines(
            'openat(AT_FDCWD, "/x O_WRONLY", O_RDONLY) = 3</x O_WRONLY>',
            'openat(AT_FDCWD, "/y) = -1 ENOENT (z)", O_RDONLY) = 3</y>',
        ) + ["garbage\n", "\n", "7  \n", '7  <... openat resumed>) = 3\n', '7  open("/cut\n',
             "7  openat(\n", "x" * 100000 + "\n"]
        groups = filetrace.summarise_trace(lines)
        self.assertEqual(set(groups["read"]), {"/x O_WRONLY", "/y) = -1 ENOENT (z)"})
        self.assertEqual(groups["missing"], {})

    def write_trace(self, name, *calls):
        os.makedirs(self.paths.logs, exist_ok=True)
        with open(os.path.join(self.paths.logs, name), "w") as f:
            f.writelines(trace_lines(*calls))

    def log_files(self, *extra):
        _, args = sb.parse_args(["log", "--files", *extra])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(sb.cmd_log(args, self.paths), 0)
        return out.getvalue()

    def test_log_files_strips_terminal_escapes(self):
        self.write_trace("1.trace", 'stat("/evil\x1b]52;c;x\x07", {}) = 0')
        output = self.log_files()
        self.assertIn("/evil", output)
        self.assertNotIn("\x1b", output)

    def test_log_files_uses_newest_unless_all(self):
        self.write_trace("1.trace", 'stat("/old", {}) = 0')
        self.write_trace("2.trace", 'stat("/new", {}) = 0')
        output = self.log_files()
        self.assertIn("/new", output)
        self.assertNotIn("/old", output)
        self.assertIn("/old", self.log_files("--all"))

    def test_log_files_without_a_trace(self):
        _, args = sb.parse_args(["log", "--files"])
        with self.assertRaisesRegex(config.ConfigError, "--trace"):
            sb.cmd_log(args, self.paths)


def failed(call, path, error="ENOENT", flags="O_RDONLY"):
    return f'{call}(AT_FDCWD, "{path}", {flags}) = -1 {error} (x)'


class FileNotice(Fixture):
    def setUp(self):
        super().setUp()
        self.view = filetrace.SandboxView(self.plan(), self.home)

    def reason(self, path, error="ENOENT", writes=False):
        return self.view.reason(path, error, writes)

    def test_reasons(self):
        h, p = self.home, self.project
        cases = {
            (f"{h}/.ssh/id_ed25519", "ENOENT"): filetrace.HIDDEN,  # plain deny, not even bound
            (f"{h}/.aws/credentials", "ENOENT"): filetrace.HIDDEN,  # sensitive, never suggested
            (f"{p}/sub/secret.key", "ENOENT"): filetrace.HIDDEN,  # deny glob
            ("/opt/tool/bin", "ENOENT"): filetrace.NOT_MOUNTED,
            (f"{h}/.npmrc", "ENOENT"): filetrace.NOT_MOUNTED,
            (f"{h}/node_modules", "ENOENT"): filetrace.NOT_MOUNTED,
            ("/usr/x", "EROFS"): filetrace.READ_ONLY,
            (f"{p}/.git/hooks/pre-commit", "EROFS"): filetrace.READ_ONLY,
            ("/usr/lib/missing.so", "ENOENT"): None,  # mounted: really missing
            (f"{p}/missing", "ENOENT"): None,
            ("/tmp/x", "ENOENT"): None,
            (f"{config.SANDBOX_RUN}/x", "EROFS"): None,
            ("/proc/1/environ", "EACCES"): None,
            (f"{h}/bin/git", "ENOENT"): None,  # PATH lookup
            (f"{os.path.dirname(p)}/node_modules", "ENOENT"): None,  # upward search
            ("/etc/ld.so.preload", "ENOENT"): None,
            ("/opt/x", "EINVAL"): None,
            ("relative/x", "ENOENT"): None,
            ("/opt/" + "a" * 5000, "ENOENT"): None,
        }
        for (path, error), expected in cases.items():
            with self.subTest(path=path[:60], error=error):
                self.assertEqual(self.reason(path, error), expected)

    def test_dot_dot_cannot_dodge_the_deny_list(self):
        self.assertEqual(self.reason(f"/opt/../{self.home}/.ssh/../.ssh/id_ed25519"), filetrace.HIDDEN)
        self.assertEqual(self.reason(f"//opt/x"), filetrace.NOT_MOUNTED)

    def test_bun_virtual_files_are_ignored(self):
        self.assertIsNone(self.reason("/$bunfs/root/chunk-qk6b3hm7.js"))

    def test_unmounted_path_is_shown_at_its_first_unmounted_level(self):
        """npm fills an empty ~/.npm in the home tmpfs: its hundreds of misses are one fact,
        that ~/.npm isn't mounted. Paths under a partly mounted dir keep their next level."""
        h = self.home
        cases = {
            f"{h}/.npm/_npx/9833/node_modules/x/package.json": f"{h}/.npm",
            f"{h}/.npmrc": f"{h}/.npmrc",
            "/opt/tool/bin/x": "/opt",
            f"{h}/.config/unmounted-tool/a/b": f"{h}/.config/unmounted-tool",
        }
        self.write_profile("cfg", """
            extends = "base"
            [fs]
            ro = ["~/.config/mounted-tool"]
        """)
        os.makedirs(os.path.join(h, ".config", "mounted-tool"))
        view = filetrace.SandboxView(self.plan("cfg"), h)
        for path, shown in cases.items():
            with self.subTest(path=path):
                self.assertEqual(view.reason(path, "ENOENT", False), filetrace.NOT_MOUNTED)
                self.assertEqual(view.shown_path(path), shown)

    def test_shown_path_never_widens_to_a_dir_holding_a_hidden_path(self):
        """Reporting ~/.aws-like parents as "not mounted" would invite mounting the secret."""
        view = self.view
        view.hidden.append(f"{self.home}/.dir/inner/secret")
        self.assertEqual(view.shown_path(f"{self.home}/.dir/other/x"), f"{self.home}/.dir/other")
        self.assertEqual(view.shown_path(f"{self.home}/.dir/inner/x"), f"{self.home}/.dir/inner/x")
        self.assertEqual(view.shown_path(f"{self.home}/.dir/inner/secret/x"),
                         f"{self.home}/.dir/inner/secret/x")

    def test_write_refused_on_read_only_bind(self):
        self.assertEqual(self.reason("/usr/x", "EACCES", writes=True), filetrace.READ_ONLY)
        self.assertIsNone(self.reason("/usr/x", "EACCES", writes=False))

    def denied(self):
        path = os.path.join(self.runtime, "blocked-files")
        open(path, "w").close()
        return path, filetrace.BlockedFiles(path)

    def test_list_lines_are_plain_text_and_appended_in_place(self):
        path, denied = self.denied()
        inode = os.stat(path).st_ino
        self.assertTrue(denied.add("/a\tb\nc\x1b]52;x\x07‮", filetrace.NOT_MOUNTED))
        self.assertFalse(denied.add("/a\tb\nc\x1b]52;x\x07‮", filetrace.NOT_MOUNTED))
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
        self.assertEqual(lines, ["/a\\x09b\\x0ac\\x1b]52;x\\x07\\x202e\tnot mounted"])
        self.assertEqual(os.stat(path).st_ino, inode)

    def test_list_is_capped(self):
        path, denied = self.denied()
        for n in range(filetrace.BLOCKED_FILES_LIMIT + 50):
            denied.add(f"/d{n % 50}/{n}", filetrace.NOT_MOUNTED)
        with open(path) as f:
            lines = f.read().splitlines()
        self.assertEqual(len(lines), filetrace.BLOCKED_FILES_LIMIT + 1)
        self.assertIn("truncated", lines[-1])

    def test_a_noisy_directory_cannot_push_out_later_paths(self):
        """Agents look up hundreds of files under ~/.npm at start; the path that failed for
        the user's task comes later and must still be listed."""
        path, denied = self.denied()
        denied.home = self.home
        for n in range(filetrace.BLOCKED_FILES_LIMIT * 2):
            denied.add(f"{self.home}/.npm/_npx/{n}", filetrace.NOT_MOUNTED)
        self.assertTrue(denied.add("/etc/hostname", filetrace.NOT_MOUNTED))
        with open(path) as f:
            lines = f.read().splitlines()
        self.assertEqual(len(lines), filetrace.BLOCKED_GROUP_LIMIT + 2)
        self.assertEqual(lines[-2], f"{self.home}/.npm/*\tmore paths here, not listed")
        self.assertEqual(lines[-1], "/etc/hostname\tnot mounted")

    def test_groups(self):
        h = self.home
        for path, group in ((f"{h}/.npm/a/b", f"{h}/.npm"), (f"{h}/x", f"{h}/x"),
                            ("/etc/a/b", "/etc"), ("/x", "/x"), (h, "/" + h.split("/")[1])):
            self.assertEqual(filetrace.file_group(path, h), group)

    def watch(self, lines, copy=False):
        fifo = os.path.join(self.runtime, "trace.fifo")
        os.mkfifo(fifo)
        path, denied = self.denied()
        events = []
        copy_path = os.path.join(self.root, "copy.trace") if copy else None
        watcher = filetrace.TraceWatcher(fifo, self.view, denied, lambda **e: events.append(e), copy_path)
        watcher.start()
        with open(fifo, "wb") as f:
            f.write("".join(lines).encode())
        watcher.finish()
        with open(path) as f:
            return f.read(), events, copy_path

    def test_watcher_lists_only_what_follows_the_start_probe(self):
        probe = f'7  stat("{config.TRACE_START}", 0x1) = -1 ENOENT (x)\n'
        long_line = "7  " + failed("openat", "/opt/" + "x" * filetrace.TRACE_LINE_MAX) + "\n"
        lines = ["7  " + failed("openat", "/opt/setup") + "\n", probe,
                 "8  " + failed("statx", "/opt/one") + "\n",
                 "8  " + failed("statx", "/opt/one") + "\n",
                 "9  " + failed("openat", "/usr/x", "EROFS", "O_WRONLY|O_CREAT") + "\n",
                 long_line, "garbage\n", '7  open("/cut\n']
        listed, events, copy_path = self.watch(lines, copy=True)
        self.assertEqual(listed, "/opt\tnot mounted\n/usr/x\tread-only\n")
        self.assertEqual([e["path"] for e in events], ["/opt", "/usr/x"])
        with open(copy_path) as f:
            self.assertEqual(f.read(), "".join(lines))

    def test_watcher_collapses_a_filling_tmpfs_dir(self):
        probe = f'7  stat("{config.TRACE_START}", 0x1) = -1 ENOENT (x)\n'
        lines = [probe] + [f"8  " + failed("statx", f"{self.home}/.npm/_cacache/tmp/{n}/x") + "\n"
                           for n in range(50)]
        listed, events, _ = self.watch(lines)
        self.assertEqual(listed, f"{self.home}/.npm\tnot mounted\n")
        self.assertEqual([e["path"] for e in events], [f"{self.home}/.npm"])

    def test_watcher_caps_logged_paths_per_group(self):
        """Hidden paths keep their full name, so a noisy one is capped like the agent's list."""
        probe = f'7  stat("{config.TRACE_START}", 0x1) = -1 ENOENT (x)\n'
        lines = [probe] + [f"8  " + failed("openat", f"{self.project}/t{n}/.env") + "\n"
                           for n in range(filetrace.BLOCKED_GROUP_LIMIT + 20)]
        lines.append("8  " + failed("openat", "/opt/later") + "\n")
        _, events, _ = self.watch(lines)
        files = [e for e in events if e["action"] == "file"]
        self.assertEqual(len(files), filetrace.BLOCKED_GROUP_LIMIT + 1)
        self.assertEqual(files[-1]["path"], "/opt")
        capped = [e for e in events if e["action"] == "files_capped"]
        self.assertEqual(len(capped), 1)
        self.assertEqual(capped[0]["group"], filetrace.file_group(self.project, self.home))

    def test_watcher_finishes_if_strace_never_opens_the_fifo(self):
        fifo = os.path.join(self.runtime, "trace.fifo")
        os.mkfifo(fifo)
        watcher = filetrace.TraceWatcher(fifo, self.view, filetrace.BlockedFiles(None))
        watcher.start()
        watcher.finish(timeout=0.2)
        self.assertIsNone(watcher.thread)

    def test_list_is_a_single_read_only_file_and_env_is_fixed(self):
        self.write_profile("sneaky", """
            extends = "base"
            [env]
            set = { PITHOS_BLOCKED_FILES = "/tmp/elsewhere" }
        """)
        plan = self.plan("sneaky")
        self.assertEqual(plan.env["PITHOS_BLOCKED_FILES"], config.SANDBOX_BLOCKED_FILES)
        argv = self.argv(plan)
        i = argv.index(config.SANDBOX_BLOCKED_FILES)
        self.assertEqual(argv[i - 2:i], ["--ro-bind", f"{self.runtime}/blocked-files"])

    def test_notice_mentions_the_list_only_when_enabled(self):
        self.assertNotIn(config.SANDBOX_BLOCKED_FILES, sb.AGENT_NOTICE)
        sb.write_runtime_files(self.runtime, sb.AGENT_NOTICE + sb.FILE_NOTICE)
        with open(os.path.join(self.runtime, "notice.md")) as f:
            self.assertIn(config.SANDBOX_BLOCKED_FILES, f.read())

    def test_setting_must_be_boolean_and_profile_only(self):
        self.write_profile("bad", '[agent]\nfile_notice = "no"\n')
        with self.assertRaises(config.ConfigError):
            config.load_profile(self.paths, "bad")
        with self.assertRaises(config.ConfigError):
            config.parse_project_file(self.project, b"[agent]\nfile_notice = false\n")

    def dry_run(self, *flags, strace=True, scope=False, systemd_run="/s/systemd-run"):
        flags = flags if scope else ("--no-limits", *flags)
        _, args = sb.parse_args(["--dry-run", *flags, "-C", self.project, "-p", "base", "true"])
        which = lambda n: None if n == "strace" and not strace else "/b/" + n
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sb.shutil, "which", which), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err), mock.patch.dict(os.environ, {"PITHOS_BWRAP": ""}), \
                mock.patch.object(sb, "find_systemd_run", lambda: systemd_run), \
                mock.patch.object(sb, "check_bwrap", lambda bwrap: None):
            self.assertEqual(sb.cmd_run(args, self.paths), 0)
        return out.getvalue(), err.getvalue()

    def test_on_by_default_and_opt_out(self):
        out, _ = self.dry_run()
        self.assertTrue(out.startswith("/b/strace ") and " -Z " in out)
        out, _ = self.dry_run("--trace")
        self.assertTrue(out.startswith("/b/strace ") and " -Z " not in out)
        self.assertTrue(self.dry_run("--no-file-notice")[0].startswith("/b/bwrap "))
        self.write_profile("base", "[agent]\nfile_notice = false\n[fs]\nrw = [\"{project}\"]\n")
        self.assertTrue(self.dry_run()[0].startswith("/b/bwrap "))

    def test_dry_run_changes_nothing_on_the_host(self):
        self.dry_run()
        self.assertFalse(os.path.exists(self.paths.state))

    def test_missing_strace_only_warns(self):
        out, err = self.dry_run(strace=False)
        self.assertTrue(out.startswith("/b/bwrap "))
        self.assertIn("strace not found", err)

    def test_restricted_ptrace_only_warns_without_trace(self):
        with mock.patch.object(sb, "ptrace_allowed", lambda: False):
            out, err = self.dry_run()
            self.assertTrue(out.startswith("/b/bwrap "))
            self.assertIn("ptrace", err)
            with self.assertRaisesRegex(config.ConfigError, "ptrace"):
                self.dry_run("--trace")


GB = 1 << 30


class Limits(Fixture):
    MACHINE = resources.Machine(ram=8 * GB, tasks=30000, cpus=8)

    def resolve(self, **given):
        return resources.resolve_limits({"limits": given}, self.MACHINE)

    def test_defaults_scale_with_the_machine(self):
        limits, warnings = self.resolve()
        self.assertEqual(limits, {"processes": 4500, "memory": 4 * GB, "total": 6 * GB,
                                  "tmpfs": 2 * GB, "cpu": None})  # 100% of the CPUs: no quota
        self.assertEqual(warnings, [])
        small, _ = resources.resolve_limits({}, resources.Machine(ram=GB, tasks=1000))
        self.assertEqual(small["processes"], 512)  # floor
        self.assertEqual(small["memory"], GB)  # floor, but never above the machine

    def test_values(self):
        cases = {("processes", 4096): 4096, ("processes", "4096"): 4096,
                 ("processes", "10%"): 3000, ("memory", "16G"): 6 * GB,  # the machine, then the default total
                 ("memory", "1536M"): 1536 << 20, ("memory", 3 * GB): 3 * GB,
                 ("total", "12.5%"): GB, ("tmpfs", "100M"): 100 << 20,
                 ("tmpfs", "1K"): 1 << 10, ("memory", "none"): None}
        for (key, value), expected in cases.items():
            with self.subTest(key=key, value=value):
                self.assertEqual(self.resolve(**{key: value})[0][key], expected)

    def test_per_process_limit_is_clamped_to_the_total(self):
        limits, warnings = self.resolve(memory="6G", total="1G")
        self.assertEqual(limits["memory"], GB)
        self.assertEqual(len(warnings), 1)
        self.assertIn("limits.memory", warnings[0])
        self.assertIn("the sandbox's total", warnings[0])
        # Not clamped when there is no total, or when the total is the larger one.
        self.assertEqual(self.resolve(memory="6G", total="none")[0]["memory"], 6 * GB)
        self.assertEqual(self.resolve(memory="1G", total="6G")[0]["memory"], GB)

    def test_floors_only_lift_the_percentage_defaults(self):
        self.assertEqual(self.resolve(tmpfs="1M")[0]["tmpfs"], 1 << 20)  # explicit: as given
        self.assertEqual(self.resolve(memory="1%")[0]["memory"], GB)   # computed: floored
        self.assertEqual(self.resolve(processes="1%")[0]["processes"], 512)

    def test_more_than_the_machine_is_lowered_with_a_warning(self):
        limits, warnings = self.resolve(memory="64G", processes=10 ** 6)
        self.assertEqual((limits["memory"], limits["processes"]), (6 * GB, 30000))
        self.assertEqual(len(warnings), 3)  # machine for memory, then total, then processes
        self.assertTrue(any("limits.memory" in w for w in warnings))

    def test_bad_values(self):
        for key, value in (("memory", "abc"), ("memory", "-1G"), ("memory", "0%"),
                           ("memory", "150%"), ("memory", "1.5G"), ("memory", "1e9"),
                           ("memory", ""), ("memory", "50 %"), ("memory", 0), ("memory", -5),
                           ("processes", "4096K"), ("processes", "1G"), ("tmpfs", "9" * 40),
                           ("total", "None"), ("memory", "١G"), ("memory", "٥٠%")):
            with self.subTest(key=key, value=value), self.assertRaisesRegex(config.ConfigError, key):
                self.resolve(**{key: value})

    def test_schema(self):
        for text in ('[limits]\nmemory = true', '[limits]\nmemory = ["1G"]',
                     '[limits]\nswap = "1G"', '[limits]\nmemory = 1.5'):
            with self.subTest(text=text):
                self.write_profile("bad", text)
                with self.assertRaises(config.ConfigError):
                    config.load_profile(self.paths, "bad")

    def test_project_file_cannot_set_limits(self):
        with self.assertRaisesRegex(config.ConfigError, "limits"):
            config.parse_project_file(self.project, b'[limits]\nmemory = "none"\n')

    def test_profile_values_override_defaults(self):
        self.write_profile("child", 'extends = "base"\n[limits]\ntotal = "none"\n')
        cfg = config.load_profile(self.paths, "child")
        self.assertIsNone(resources.resolve_limits(cfg, self.MACHINE)[0]["total"])

    def write(self, path, text):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)

    def test_machine_reads_meminfo_and_the_lowest_cgroup_limit(self):
        proc, sysfs = os.path.join(self.root, "proc"), os.path.join(self.root, "cg")
        self.write(f"{proc}/meminfo", "MemTotal:       8388608 kB\nMemFree: 1 kB\n")
        self.write(f"{proc}/self/cgroup", "0::/user.slice/app\n")
        self.write(f"{proc}/sys/kernel/threads-max", "1000\n")
        self.write(f"{sysfs}/memory.max", "max\n")
        self.write(f"{sysfs}/user.slice/memory.max", f"{2 * GB}\n")
        self.write(f"{sysfs}/user.slice/app/memory.max", f"{3 * GB}\n")
        machine = resources.read_machine(proc, sysfs)
        self.assertEqual(machine.ram, 2 * GB)
        self.assertLessEqual(machine.tasks, 1000)
        self.write(f"{proc}/self/cgroup", "garbage\n")
        self.assertEqual(resources.read_machine(proc, sysfs).ram, 8 * GB)
        os.unlink(f"{proc}/meminfo")
        with self.assertRaises(config.ConfigError):
            resources.read_machine(proc, sysfs)

    def limited_argv(self):
        limits, _ = self.resolve()
        plan = sb.build_plan(config.load_profile(self.paths, "base"), self.project, self.paths,
                             self.runtime, {}, limits=limits)
        return plan, self.argv(plan)

    def test_every_writable_tmpfs_is_sized(self):
        plan, argv = self.limited_argv()
        for dest in (self.home, "/tmp", "/var/tmp", "/dev/shm"):
            i = argv.index(dest)
            self.assertEqual(argv[i - 3:i], ["--size", str(2 * GB), "--tmpfs"], dest)
        i = argv.index("/run")
        self.assertEqual(argv[i - 3:i], ["--size", str(sb.RUN_TMPFS_SIZE), "--tmpfs"])
        self.assertEqual(set(plan.tmpfs), {self.home, "/tmp", "/var/tmp", "/dev/shm", "/run"})

    def test_root_and_dev_are_read_only_after_every_mount(self):
        _, argv = self.limited_argv()
        i = argv.index("--remount-ro")
        self.assertEqual(argv[i:i + 4], ["--remount-ro", "/dev", "--remount-ro", "/"])
        mounts = [n for n, a in enumerate(argv) if a in ("--bind", "--ro-bind", "--tmpfs", "--symlink")]
        self.assertLess(max(mounts), i)
        unlimited = self.argv(self.plan())  # / is read-only even without [limits]
        self.assertIn("--remount-ro", unlimited)

    def test_bridge_gets_the_rlimits(self):
        _, argv = self.limited_argv()
        self.assertIn(f"core=0,data={4 * GB}", argv)  # processes: the scope's TasksMax
        limits, _ = self.resolve()
        self.assertEqual(resources.bridge_limits(limits, scoped=False), f"core=0,nproc=4500,data={4 * GB}")
        self.assertEqual(resources.bridge_limits(None), "core=0")
        self.assertEqual(resources.bridge_limits({"processes": None, "memory": None}), "core=0")

    def test_old_bubblewrap_is_refused_clearly(self):
        fake = os.path.join(self.root, "bwrap")
        for text, ok in (("    --size BYTES  Set size\n    --ro-bind-fd FD DEST\n", True),
                         ("    --size BYTES  Set size\n", False), ("    --tmpfs DIR\n", False)):
            with open(fake, "w") as f:
                f.write(f"#!/bin/sh\ncat <<'EOF'\n{text}EOF\n")
            os.chmod(fake, 0o700)
            with self.subTest(ok=ok):
                if ok:
                    sb.check_bwrap(fake)
                else:
                    with self.assertRaisesRegex(config.ConfigError, "0.6"):
                        sb.check_bwrap(fake)
        with self.assertRaisesRegex(config.ConfigError, "cannot run"):
            sb.check_bwrap(os.path.join(self.root, "missing"))
        with self.assertRaisesRegex(config.ConfigError, "0.6"):
            sb.check_bwrap("/bin/true")  # runs, but prints no --size

    def test_notice(self):
        limits, _ = self.resolve()
        text = resources.limits_notice(limits, scoped=True)
        self.assertIn("processes 4500", text)
        self.assertIn("memory in total 6G", text)
        self.assertIn(config.SANDBOX_LIMIT_EVENTS, text)
        unscoped = resources.limits_notice(limits, scoped=False)
        self.assertNotIn("memory in total", unscoped)  # not enforced without a scope
        self.assertNotIn(config.SANDBOX_LIMIT_EVENTS, unscoped)
        only = resources.limits_notice({"processes": 100, "memory": None, "total": None,
                                 "tmpfs": None, "cpu": None}, scoped=True)
        self.assertIn("processes 100", only)
        self.assertNotIn("unlimited", only)
        self.assertEqual(resources.limits_notice(dict.fromkeys(config.LIMIT_KEYS), scoped=True), "")


class Scope(Fixture):
    MACHINE = Limits.MACHINE

    def test_cpu(self):
        cases = {"100%": None, "50%": 400, "2": 200, 2: 200, "12.5%": 100, "1%": 100,
                 "64": None, "none": None}
        for value, expected in cases.items():
            with self.subTest(value=value):
                limits, _ = resources.resolve_limits({"limits": {"cpu": value}}, self.MACHINE)
                self.assertEqual(limits["cpu"], expected)
        for bad in ("2G", "1.5", "-1", "0%", "x"):
            with self.subTest(bad=bad), self.assertRaisesRegex(config.ConfigError, "limits.cpu"):
                resources.resolve_limits({"limits": {"cpu": bad}}, self.MACHINE)

    def test_scope_argv(self):
        limits = {"processes": 4500, "memory": GB, "total": 6 * GB, "tmpfs": GB, "cpu": 200}
        argv = resources.scope_argv("/usr/bin/systemd-run", "pithos-x.scope", limits)
        self.assertEqual(argv, ["/usr/bin/systemd-run", "--user", "--scope", "--quiet",
                                "--collect", "--unit=pithos-x.scope", "-p", "OOMPolicy=continue",
                                "-p", f"MemoryMax={6 * GB}", "-p", "MemorySwapMax=0",
                                "-p", "TasksMax=4500", "-p", "CPUQuota=200%", "--"])
        bare = resources.scope_argv("/s", "u", dict.fromkeys(config.LIMIT_KEYS))
        self.assertEqual(bare[-1], "--")
        self.assertEqual(bare[bare.index("-p"):], ["-p", "OOMPolicy=continue", "--"])

    def test_systemd_run_only_from_system_dirs(self):
        with mock.patch.dict(os.environ, {"PATH": self.root}):
            found = resources.find_systemd_run()
        self.assertIn(found, (None, *resources.SYSTEMD_RUN_PATHS))

    def test_check_scope_reasons(self):
        self.assertIn("not installed", resources.check_scope(None))
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": ""}):
            self.assertIn("XDG_RUNTIME_DIR", resources.check_scope("/bin/true"))
        fake = os.path.join(self.root, "systemd-run")
        with open(fake, "w") as f:
            f.write("#!/bin/sh\necho 'Failed to connect to bus\x1b]52;c;x\x07' >&2\nexit 1\n")
        os.chmod(fake, 0o700)
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/run/user/1"}):
            why = resources.check_scope(fake)
        self.assertIn("Failed to connect to bus", why)
        self.assertNotIn("\x1b", why)

    def test_refuses_without_a_scope_unless_asked(self):
        dry = FileNotice.dry_run
        with self.assertRaisesRegex(config.ConfigError, "--no-limits"):
            dry(self, scope=True, systemd_run=None)
        out, err = dry(self, "--no-limits", scope=True, systemd_run=None)
        self.assertIn("--no-limits", err)
        self.assertNotIn("systemd-run", out)
        out, _ = dry(self, scope=True)
        self.assertTrue(out.startswith("/s/systemd-run --user --scope"))
        self.assertIn("TasksMax=", out)

    def test_no_limits_is_command_line_only(self):
        with self.assertRaises(config.ConfigError):
            config.parse_project_file(self.project, b"[limits]\ntotal = \"none\"\n")
        self.write_profile("bad", "[agent]\nno_limits = true\n")
        with self.assertRaises(config.ConfigError):
            config.load_profile(self.paths, "bad")


class LimitEventsTest(Fixture):
    LIMITS = {"processes": 4500, "memory": GB, "total": 6 * GB, "tmpfs": GB, "cpu": None}

    def events(self):
        path = os.path.join(self.runtime, "limit-events")
        open(path, "w").close()
        logged = []
        events = resources.LimitEvents(path, self.LIMITS, lambda **e: logged.append(e),
                                clock=lambda: "12:00:00")
        return path, events, logged

    def test_lines_are_fixed_text_appended_in_place(self):
        path, events, logged = self.events()
        inode = os.stat(path).st_ino
        events.add("memory", 1)
        events.add("processes", 3)
        with open(path) as f:
            self.assertEqual(f.read().splitlines(), [
                "12:00:00\tmemory\tthe kernel killed 1 process: the sandbox reached its memory "
                "limit (6G)",
                "12:00:00\tprocesses\t3 process or thread starts refused: the sandbox reached its "
                "limit of 4500 processes"])
        self.assertEqual(os.stat(path).st_ino, inode)
        self.assertEqual(logged, [{"action": "limit", "limit": "memory", "count": 1},
                                  {"action": "limit", "limit": "processes", "count": 3}])
        self.assertEqual(events.totals, {"memory": 1, "processes": 3})

    def test_without_a_total_limit_no_limit_is_claimed(self):
        path, events, _ = self.events()
        events.limits = {**self.LIMITS, "total": None}
        events.add("memory", 2)
        with open(path) as f:
            self.assertEqual(f.read(), "12:00:00\tmemory\tthe kernel killed 2 processes: the "
                                       "machine ran out of memory\n")

    def test_capped_but_still_counted(self):
        path, events, logged = self.events()
        for _ in range(resources.LIMIT_EVENTS_LIMIT + 50):
            events.add("processes", 1)
        with open(path) as f:
            lines = f.read().splitlines()
        self.assertEqual(len(lines), resources.LIMIT_EVENTS_LIMIT + 1)
        self.assertIn("truncated", lines[-1])
        self.assertEqual(events.totals["processes"], resources.LIMIT_EVENTS_LIMIT + 50)
        self.assertEqual(len(logged), resources.LIMIT_EVENTS_LIMIT + 50)

    def write(self, name, text):
        with open(os.path.join(self.cg, name), "w") as f:
            f.write(text)

    def test_monitor_reports_increases_only(self):
        self.cg = os.path.join(self.root, "scope")
        os.makedirs(self.cg)
        self.write("memory.events", "low 0\nhigh 0\nmax 5\noom 1\noom_kill 1\n")
        self.write("pids.events", "max 0\n")
        _, events, _ = self.events()
        monitor = resources.ScopeMonitor(self.cg, events)
        with mock.patch.object(resources, "EVENTS_INTERVAL", 0.01):
            monitor.start()
            self.write("memory.events", "max 9\noom_kill 3\n")
            self.write("pids.events", "max 4\n")
            for _ in range(200):
                if events.totals == {"memory": 2, "processes": 4}:
                    break
                time.sleep(0.01)
            self.write("pids.events", "max garbage\nmax 2\n")  # lower or bad: ignored
            monitor.stop()
        self.assertEqual(events.totals, {"memory": 2, "processes": 4})

    def test_monitor_without_event_files(self):
        _, events, _ = self.events()
        monitor = resources.ScopeMonitor(os.path.join(self.root, "missing"), events)
        monitor.start()
        monitor.stop()
        self.assertEqual(events.totals, {})

    def test_scope_cgroup(self):
        proc = os.path.join(self.root, "proc")
        os.makedirs(f"{proc}/7")
        with open(f"{proc}/7/cgroup", "w") as f:
            f.write("0::/user.slice/app.slice/pithos-s.scope\n")
        self.assertEqual(resources.scope_cgroup(7, "pithos-s.scope", proc, "/sys/fs/cgroup"),
                         "/sys/fs/cgroup/user.slice/app.slice/pithos-s.scope")
        with open(f"{proc}/7/cgroup", "w") as f:
            f.write("0::/x/../../etc/pithos-s.scope\n")
        self.assertIsNone(resources.scope_cgroup(7, "pithos-s.scope", proc, timeout=0.05))
        self.assertIsNone(resources.scope_cgroup(8, "pithos-s.scope", proc, timeout=0.05))

    def test_list_is_bound_read_only_and_env_fixed(self):
        self.write_profile("sneaky", 'extends = "base"\n[env]\nset = { PITHOS_LIMIT_EVENTS = "/tmp/x" }\n')
        plan = self.plan("sneaky")
        self.assertEqual(plan.env["PITHOS_LIMIT_EVENTS"], config.SANDBOX_LIMIT_EVENTS)
        argv = self.argv(plan)
        i = argv.index(config.SANDBOX_LIMIT_EVENTS)
        self.assertEqual(argv[i - 2:i], ["--ro-bind", f"{self.runtime}/limit-events"])


class Bridge(unittest.TestCase):
    def apply(self, spec):
        code = ("import sys, resource; sys.path.insert(0, sys.argv[1]); import bridge; "
                "bridge.apply_limits(sys.argv[2]); "
                "print([resource.getrlimit(r) for r in "
                "(resource.RLIMIT_CORE, resource.RLIMIT_NPROC, resource.RLIMIT_DATA)])")
        return subprocess.run([sys.executable, "-I", "-c", code, ROOT, spec],
                              capture_output=True, text=True)

    def test_sets_soft_and_hard_limits(self):
        done = self.apply(f"core=0,nproc=1000,data={4 * GB}")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.strip(), f"[(0, 0), (1000, 1000), ({4 * GB}, {4 * GB})]")

    def test_never_above_the_existing_hard_limit(self):
        hard = 900
        code = ("import sys, resource; sys.path.insert(0, sys.argv[1]); import bridge; "
                f"resource.setrlimit(resource.RLIMIT_NPROC, ({hard}, {hard})); "
                "bridge.apply_limits('nproc=5000'); print(resource.getrlimit(resource.RLIMIT_NPROC))")
        done = subprocess.run([sys.executable, "-I", "-c", code, ROOT], capture_output=True, text=True)
        self.assertEqual(done.stdout.strip(), f"({hard}, {hard})", done.stderr)

    def test_refuses_bad_specs(self):
        for spec in ("nproc=-1", "evil=1", "nproc=1;x", "nproc", "", "core=0,,data=1",
                     "nproc=0x10", "nproc=١٠"):
            with self.subTest(spec=spec):
                self.assertNotEqual(self.apply(spec).returncode, 0)


class ConnectClaudeAgent(Fixture):
    def connect_profile(self, value="true", env='XDG_DATA_HOME = "~/data"'):
        self.write_profile("oc", f"""
            extends = "base"
            [env]
            set = {{ {env} }}
            [agent]
            connect_claude_agent = {value}
        """)

    def fake_opencode(self, fail=False):
        path = os.path.join(self.project, "opencode")
        self.calls = os.path.join(self.project, "calls")
        status = 1 if fail else 0
        with open(path, "w") as f:
            f.write(f"""#!/bin/sh
for a in "$@"; do printf '[%s]' "$a" >> {self.calls}; done; echo >> {self.calls}
case "$*" in *"auth import"*) exit {status};; esac
exit 0
""")
        os.chmod(path, 0o700)
        return path

    def run_wrapped(self, *cmd):
        data = os.path.join(self.project, "data")
        os.makedirs(data, exist_ok=True)
        cfg = {"agent": {"connect_claude_agent": True}}
        wrapped = sb.agent_command(cfg, list(cmd))
        env = {"PATH": "/usr/bin:/bin", "XDG_DATA_HOME": data}
        result = subprocess.run(wrapped, env=env, capture_output=True, text=True)
        self.assertEqual((result.returncode, result.stderr), (0, ""))
        with open(self.calls) as f:
            return f.read().splitlines(), os.path.exists(
                os.path.join(data, "pithos-claude-agent-connected"))

    def test_credential_is_mounted_read_only_only_when_enabled(self):
        self.connect_profile()
        on = self.argv(self.plan("oc"))
        self.assertIn(config.SANDBOX_CLAUDE_AGENT, on)
        self.assertEqual(on[on.index(config.SANDBOX_CLAUDE_AGENT) - 2], "--ro-bind")
        self.assertNotIn(config.SANDBOX_CLAUDE_AGENT, self.argv(self.plan()))

    def test_credential_holds_no_secret(self):
        self.assertEqual(sb.CLAUDE_AGENT_CREDENTIAL[0]["value"],
                         {"type": "external", "methodID": "claude-login"})
        sb.write_runtime_files(self.runtime)
        with open(os.path.join(self.runtime, "claude-agent.json")) as f:
            self.assertEqual(json.load(f), sb.CLAUDE_AGENT_CREDENTIAL)

    def test_project_file_cannot_enable_it(self):
        with self.assertRaises(config.ConfigError):
            config.parse_project_file(self.project, b"[agent]\nconnect_claude_agent = true\n")

    def test_value_must_be_boolean(self):
        self.connect_profile(value='"true"')
        with self.assertRaises(config.ConfigError):
            self.plan("oc")

    def test_needs_per_project_data_dir(self):
        self.connect_profile(env='FOO = "bar"')
        with self.assertRaises(config.ConfigError):
            self.plan("oc")

    def test_only_wraps_opencode_and_only_when_enabled(self):
        on = {"agent": {"connect_claude_agent": True}}
        self.assertEqual(sb.agent_command(on, ["claude", "x"]), ["claude", "x"])
        self.assertEqual(sb.agent_command({"agent": {"connect_claude_agent": False}},
                                          ["opencode"]), ["opencode"])
        self.assertEqual(sb.agent_command({}, ["opencode"]), ["opencode"])
        self.assertEqual(sb.agent_command(on, ["opencode", "-x"])[-2:], ["opencode", "-x"])

    def test_shipped_profiles(self):
        for name, expected in (("opencode-claude", True), ("opencode", None)):
            with open(os.path.join(sb.HERE, "profiles", name + ".toml"), "rb") as f:
                self.assertEqual(tomllib.load(f).get("agent", {}).get("connect_claude_agent"), expected)

    def test_imports_once_then_skips(self):
        oc = self.fake_opencode()
        calls, marked = self.run_wrapped(oc, "--standalone")
        self.assertEqual(calls, [f"[--standalone][auth][import][{config.SANDBOX_CLAUDE_AGENT}]", "[--standalone]"])
        self.assertTrue(marked)
        calls, _ = self.run_wrapped(oc, "--standalone")
        self.assertEqual(len(calls), 3)  # only the launch was added

    def test_failed_import_still_starts_and_retries(self):
        oc = self.fake_opencode(fail=True)
        calls, marked = self.run_wrapped(oc)
        self.assertEqual(len(calls), 2)
        self.assertFalse(marked)
        calls, _ = self.run_wrapped(oc)
        self.assertEqual(len(calls), 4)

    def test_hostile_arguments_stay_arguments(self):
        oc = self.fake_opencode()
        evil = '$(touch pwned); `touch pwned` "\'; touch pwned'
        calls, _ = self.run_wrapped(oc, evil)
        self.assertEqual(calls[-1], f"[{evil}]")
        self.assertFalse(os.path.exists("pwned"))


class Surface(unittest.TestCase):
    def test_entry_points(self):
        """Fails when a subcommand is added: review it, then update this list."""
        self.assertEqual(sb.COMMANDS, ("run", "trust", "log", "allow", "report"))
        for cmd in sb.COMMANDS:
            self.assertEqual(sb.parse_args([cmd] if cmd != "run" else ["run", "true"])[0], cmd)
        self.assertEqual(sb.parse_args(["claude"])[0], "run")

    def test_clean_strips_escapes(self):
        self.assertNotIn("\x1b", config.clean("\x1b]52;c;evil\x07host"))
        self.assertEqual(config.clean("a\tb\nc"), "a\tb\nc")
        self.assertEqual(config.clean("a\tb\nc", keep=""), "a\\x09b\\x0ac")

    def test_bridge_agrees_with_the_launcher(self):
        """bridge.py runs alone in the sandbox, so it repeats these: they must not drift."""
        sys.path.insert(0, ROOT)
        import bridge
        self.assertEqual(bridge.TRACE_START, config.TRACE_START)
        self.assertEqual(bridge.PROXY_PORT, sb.PROXY_PORT)
        self.assertEqual(sb.PROXY_URL, f"http://127.0.0.1:{bridge.PROXY_PORT}")
        import publish
        self.assertEqual(bridge.PUBLISH_SOCK, sb.SANDBOX_PUBLISH_SOCK)
        self.assertEqual(bridge.TOKEN_LEN, publish.TOKEN_LEN)


class Publish(Fixture):
    def bridge_args(self, argv):
        i = len(argv) - 1 - argv[::-1].index(config.SANDBOX_RUN + "/bridge.py")
        return argv[i + 1:]

    def test_off_by_default(self):
        argv = self.argv(self.plan())
        self.assertNotIn(config.SANDBOX_RUN + "/publish.sock", argv)
        self.assertEqual(self.bridge_args(argv)[4:], ["-", "claude"])

    def test_socket_is_bound_read_only_and_bridge_gets_port_and_fd(self):
        plan = self.plan()
        sb.add_publish(plan, ("127.0.0.1", 4096))
        argv = sb.bwrap_argv("bwrap", plan, self.project, ["claude"], publish_fd=9)
        i = argv.index(config.SANDBOX_RUN + "/publish.sock")
        self.assertEqual(argv[i - 2:i], ["--ro-bind", f"{self.runtime}/publish.sock"])
        self.assertEqual(self.bridge_args(argv)[4:], ["4096:9", "claude"])

    def test_dry_run_shows_it(self):
        out, err = FileNotice.dry_run(self, "--publish", "4096")
        self.assertIn(config.SANDBOX_RUN + "/publish.sock", out)
        self.assertIn(" '4096:<fd>' true", out)
        self.assertNotIn("WARNING", err)

    def test_non_loopback_warns(self):
        _, err = FileNotice.dry_run(self, "--publish", "192.168.1.107:4096")
        self.assertIn("WARNING", err)
        self.assertIn("192.168.1.107:4096", err)

    def test_bad_values_stop_before_anything(self):
        for value in ("3128", "localhost:4096", "0.0.0.0:4096"):
            with self.subTest(value=value), self.assertRaises(config.ConfigError):
                FileNotice.dry_run(self, "--publish", value)

    def test_needs_a_value(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            sb.parse_args(["--publish", "--", "true"])

    def test_project_file_cannot_publish(self):
        with self.assertRaises(config.ConfigError):
            config.parse_project_file(self.project, b"[agent]\npublish = \"4096\"\n")


class EnvPipe(unittest.TestCase):
    def plan(self, value):
        plan = sb.Plan()
        plan.env = {"A": value}
        return plan

    def open_fds(self):
        return len(os.listdir("/proc/self/fd"))

    def test_holds_the_environment(self):
        fd = sb.env_pipe(self.plan("x y"))
        with os.fdopen(fd, "rb") as f:
            self.assertEqual(f.read(), b"--setenv\0A\0x y\0")

    def test_too_large_is_refused_without_leaking(self):
        before = self.open_fds()
        with self.assertRaisesRegex(config.ConfigError, "too large"):
            sb.env_pipe(self.plan("x" * sb.ENV_PIPE_MAX))
        self.assertEqual(self.open_fds(), before)


if __name__ == "__main__":
    unittest.main()
