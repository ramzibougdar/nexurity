"""Tests for scripts/guard.py (the read-only safeguard). Standard library only.

Run: python3 -m unittest discover -s plugins/nexurity/tests
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(HERE), "scripts")
sys.path.insert(0, SCRIPTS)

import engagement  # noqa: E402
import guard  # noqa: E402


class GuardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data = os.path.join(self.tmp.name, "data")
        self.project = os.path.join(self.tmp.name, "project")
        os.makedirs(self.project)
        self.session = "session-A"
        self._start(self.session, self.project)
        self.folder = self.engagement["folder"]

    def tearDown(self):
        self.tmp.cleanup()

    def _start(self, session, cwd, expect=0):
        out = self._run_script(["start", "--data", self.data, "--session", session, "--cwd", cwd,
                                "--kind", "audit", "--target", cwd])
        self.assertEqual(out.returncode, expect, out.stdout + out.stderr)
        if expect == 0:
            self.engagement = json.loads(out.stdout)
        return out

    def _run_script(self, args):
        return subprocess.run([sys.executable, os.path.join(SCRIPTS, "engagement.py")] + args,
                              capture_output=True, text=True)

    def decide(self, command=None, tool="Bash", session=None, path=None, cwd=None):
        payload = {"session_id": session or self.session, "cwd": cwd or self.project, "tool_name": tool,
                   "tool_input": {"command": command} if tool == "Bash" else {"file_path": path}}
        return guard.decide(payload, self.data)

    def assertAllowed(self, command, **kw):
        self.assertIsNone(self.decide(command, **kw), command)

    def assertRefused(self, command, **kw):
        self.assertIsNotNone(self.decide(command, **kw), command)

    # --- no engagement: nothing is blocked ---------------------------------
    def test_no_engagement_allows_everything(self):
        for command in ("rm -rf /tmp/x", "git push --force", "npm install"):
            self.assertAllowed(command, session="other-session")

    def test_other_session_is_not_constrained(self):
        self.assertAllowed("rm -rf build", session="session-B")
        self.assertIsNone(self.decide(tool="Write", path="/etc/hosts", session="session-B"))

    def test_no_sessions_folder_is_fast_path(self):
        empty = os.path.join(self.tmp.name, "empty-data")
        payload = {"session_id": "x", "cwd": "/", "tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}
        self.assertIsNone(guard.decide(payload, empty))

    # --- allowed read-only commands -----------------------------------------
    def test_read_only_commands_allowed(self):
        for command in (
            "cat /etc/nginx/nginx.conf",
            "grep -rn 'password' src | head -50",
            "rg --json -n eval .",
            "find . -name '*.php' -newer composer.json",
            "ls -la && stat composer.lock",
            "tail -n 200 /var/log/nginx/access.log 2>/dev/null",
            "journalctl -u nginx --since yesterday",
            "ss -tulpn",
            "crontab -l",
            "crontab -u www-data -l",
            "systemctl status nginx",
            "systemctl list-units --type=service",
            "dpkg -l",
            "apt list --upgradable",
            "nginx -T",
            "php -i",
            "docker ps -a",
            "docker inspect web",
            "curl -sI https://example.com",
            "curl -s -o /dev/null -w '%{http_code}' https://example.com/.env",
            "dig +short TXT example.com",
            "openssl s_client -connect example.com:443 -servername example.com < /dev/null",
            "git log --oneline -20",
            "git -C src diff HEAD~1",
            "semgrep --config auto --json .",
            "composer audit --format=json",
            "npm audit --json",
            "pip-audit -r requirements.txt",
            "cargo audit",
            "gitleaks detect --no-git --source .",
            "lynis audit system --quick",
            "sudo -n cat /etc/shadow",
            "timeout 10 curl -sI https://example.com",
        ):
            self.assertAllowed(command)

    def test_writes_into_engagement_folder_allowed(self):
        f = self.folder
        for command in (
            "semgrep --config auto --json -o %s/semgrep.json ." % f,
            "npm audit --json > %s/npm-audit.json" % f,
            "mkdir -p %s/evidence/logs" % f,
            "cp -a /var/log/nginx/access.log %s/evidence/" % f,
            "git clone --depth 1 https://github.com/x/y %s/src" % f,
            "cat /etc/passwd | tee %s/evidence/passwd" % f,
            "tar -czf %s/evidence/logs.tgz /var/log/nginx" % f,
            "python3 %s/render_report.py --ref X" % SCRIPTS,
            "cd %s && cat log.md" % f,
        ):
            self.assertAllowed(command)
        self.assertIsNone(self.decide(tool="Write", path=os.path.join(f, "findings.json")))

    def test_ssh_read_only_allowed(self):
        self.assertAllowed("ssh -p 2222 admin@web1 'cat /etc/ssh/sshd_config'")
        self.assertAllowed("ssh web1 'sudo -n nginx -T 2>/dev/null'")
        self.assertAllowed("ssh web1 'ls -la /var/www && grep -r eval /var/www/html | head'")
        self.assertAllowed("ssh web1 cat /etc/crontab > %s/evidence/crontab" % self.folder)

    # --- refused --------------------------------------------------------------
    def test_destructive_commands_refused(self):
        for command in (
            "rm -rf src", "mv a b", "chmod 777 x", "chown root x", "sed -i s/a/b/ f",
            "systemctl restart nginx", "kill 1234", "apt install curl", "apt-get remove x",
            "dnf install x", "nmap -sV 10.0.0.1", "nikto -h x", "sqlmap -u x", "hydra x",
            "curl -X POST https://example.com", "curl -d a=b https://example.com",
            "curl -o /tmp/out https://example.com", "wget https://example.com",
            "npm audit fix", "npm install", "pip-audit --fix", "cargo audit fix",
            "semgrep --autofix --config auto .", "git push", "git checkout main", "git -c core.pager=x log",
            "find . -name x -delete", "find . -exec rm {} ;", "rg --pre cat x",
            "docker run alpine", "docker exec web sh", "crontab -e", "php -r 'system(1);'",
            "python3 -c 'print(1)'", "python3 /tmp/x.py", "bash -c 'cat x'", "sh x.sh",
            "env cat x", "xargs rm", "awk '{system($0)}' f",
            "mysql -e 'DROP TABLE users'", "tee /etc/hosts", "mkdir /tmp/x", "cp x /tmp/y",
            "git clone https://github.com/x/y /tmp/y", "tar -xzf x.tgz -C /tmp",
            "sudo rm -rf /", "sudo -s", "timeout 5 rm x", "/bin/rm x", "./run.sh",
            "FOO=1 cat x", "$CMD", "echo x > /tmp/out", "echo x >> ~/.bashrc", "cat x 2> /tmp/err",
        ):
            self.assertRefused(command)

    def test_bypass_attempts_refused(self):
        for command in (
            "cat x; rm -rf /",
            "cat x && rm -rf /",
            "cat x || rm -rf /",
            "cat x | sh",
            "cat x & rm -rf /",
            "cat $(rm -rf /)",
            "cat `rm -rf /`",
            "cat <(rm x)",
            "bash -c 'rm -rf /'",
            "ssh web1 'rm -rf /var/www'",
            "ssh web1 'cat x; systemctl stop nginx'",
            "ssh web1 'cat x > /etc/passwd'",
            "ssh web1",
            "ssh -L 8080:localhost:80 web1 cat x",
            "ssh web1 'ssh web2 cat x'",
            "ssh web1 'mkdir /tmp/x'",
            "(rm -rf /)",
            "cat x\nrm -rf /",
            "cat <<EOF\nx\nEOF",
            "cd /tmp && echo x > out",
            "cd %s && cd .. && echo x > out" % self.folder,
            "echo x > %s/../escape" % self.folder,
        ):
            self.assertRefused(command)

    def test_nexurity_scripts_cannot_write_outside_folder(self):
        f, sc = self.folder, SCRIPTS
        for command in (
            'python3 %s/render_report.py --ref X' % sc,
            'python3 %s/render_report.py --folder %s' % (sc, f),
            'python3 %s/preserve_evidence.py --dest %s/evidence /var/log/nginx' % (sc, f),
            'python3 %s/engagement.py log --data /d --ref X --message ok' % sc,
            'python3 %s/engagement.py close --data /d --ref X' % sc,
            'python3 %s/triage_logs.py %s/evidence/access.log > %s/triage.json' % (sc, f, f),
            'python3 %s/cvss4.py --json "CVSS:4.0/AV:N"' % sc,
            'python3 %s/cms.py detect %s' % (sc, self.project),
            'python3 %s/cms.py scan %s --data /d --out %s/tools/cms' % (sc, self.project, f),
        ):
            self.assertAllowed(command)
        for command in (
            'python3 %s/render_report.py --folder %s' % (sc, self.project),
            'python3 %s/preserve_evidence.py --dest /tmp/x /etc' % sc,
            'python3 %s/preserve_evidence.py /etc' % sc,
            'python3 %s/engagement.py start --session other --cwd %s --kind audit --target x' % (sc, self.project),
            'python3 %s/../scripts/../tests/test_guard.py' % sc,
            'python3 %s/cms.py scan %s --data /d --out /tmp/cms' % (sc, self.project),
            'python3 %s/cms.py scan %s --data /d' % (sc, self.project),
            'python3 %s/cms.py scan %s --data /d --ou /tmp/cms' % (sc, self.project),
            'python3 %s/cms.py purge' % sc,
        ):
            self.assertRefused(command)

    def test_git_clone_with_dash_c_is_resolved(self):
        rel = os.path.relpath(self.folder, self.project)
        self.assertRefused("git -C /tmp clone https://github.com/x/y %s/src" % rel)
        self.assertAllowed("git -C %s clone https://github.com/x/y %s/src" % (self.project, rel))

    def test_write_tools_outside_folder_refused(self):
        for path in (os.path.join(self.project, "index.php"), "/etc/hosts", self.folder + "-other/x"):
            self.assertIsNotNone(self.decide(tool="Write", path=path), path)
            self.assertIsNotNone(self.decide(tool="Edit", path=path), path)

    def test_symlink_escape_refused(self):
        link = os.path.join(self.folder, "link")
        os.symlink(self.project, link)
        self.assertIsNotNone(self.decide(tool="Write", path=os.path.join(link, "x.php")))

    # --- engagements per session ------------------------------------------------
    def test_second_engagement_in_same_session_refused(self):
        out = self._start(self.session, self.project, expect=2)
        self.assertIn(self.engagement["ref"], out.stdout)

    def test_two_sessions_each_constrained_by_their_own_folder(self):
        other_project = os.path.join(self.tmp.name, "other")
        os.makedirs(other_project)
        first_folder = self.folder
        self._start("session-B", other_project)
        second_folder = self.engagement["folder"]
        self.assertNotEqual(first_folder, second_folder)
        self.assertIsNone(self.decide("echo x > %s/a" % first_folder, session=self.session))
        self.assertIsNotNone(self.decide("echo x > %s/a" % second_folder, session=self.session))
        self.assertIsNone(self.decide("echo x > %s/a" % second_folder, session="session-B", cwd=other_project))
        self.assertIsNotNone(self.decide("echo x > %s/a" % first_folder, session="session-B", cwd=other_project))

    def test_close_releases_the_session(self):
        out = self._run_script(["close", "--data", self.data, "--ref", self.engagement["ref"]])
        self.assertEqual(out.returncode, 0)
        self.assertAllowed("rm -rf build")

    def test_pending_engagement_claimed_by_session_in_same_folder(self):
        other_project = os.path.join(self.tmp.name, "pending")
        os.makedirs(other_project)
        self._start("${CLAUDE_SESSION_ID}", other_project)
        self.assertIsNotNone(self.decide("rm -rf x", session="session-C", cwd=other_project))
        self.assertIsNone(self.decide("rm -rf x", session="session-D", cwd=self.tmp.name))

    def test_hook_protocol(self):
        """The hook reads JSON on stdin, finds the data folder in CLAUDE_PLUGIN_DATA and exits 2 to refuse."""
        env = dict(os.environ, CLAUDE_PLUGIN_DATA=self.data)
        payload = {"session_id": self.session, "cwd": self.project, "tool_name": "Bash",
                   "tool_input": {"command": "rm -rf src"}}
        out = subprocess.run([sys.executable, os.path.join(SCRIPTS, "guard.py")], input=json.dumps(payload),
                             capture_output=True, text=True, env=env)
        self.assertEqual(out.returncode, 2)
        self.assertIn("Nexurity safeguard", out.stderr)
        payload["tool_input"]["command"] = "ls -la"
        out = subprocess.run([sys.executable, os.path.join(SCRIPTS, "guard.py")], input=json.dumps(payload),
                             capture_output=True, text=True, env=env)
        self.assertEqual(out.returncode, 0, out.stderr)
        out = subprocess.run([sys.executable, os.path.join(SCRIPTS, "guard.py")], input="not json",
                             capture_output=True, text=True, env=env)
        self.assertEqual(out.returncode, 0)

    def test_gitignore_created(self):
        with open(os.path.join(self.project, ".nexurity", ".gitignore")) as fh:
            self.assertIn("*", fh.read().split())


if __name__ == "__main__":
    unittest.main()
