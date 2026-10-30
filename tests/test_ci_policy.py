"""Regression tests for CI cost/safety boundaries and complete diff handling."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from ci_policy import changed_files, plan, release_metadata_changed


class Routing(unittest.TestCase):
    def test_docs_and_frontend_need_fast_only(self):
        self.assertEqual(plan(["README.ru.md", "panel/web/src/lib/Overview.svelte"])['profile'], "fast")

    def test_backend_and_client_checks_need_integration(self):
        for path in ("panel/server.go", "panel/helper.go", "tests/panel-ci.sh", "tests/features-ci.sh"):
            with self.subTest(path=path):
                self.assertEqual(plan([path])['profile'], "integration")

    def test_ci_edits_exercise_integration_without_running_full(self):
        paths = [".github/workflows/e2e.yml", ".github/workflows/fast.yml", ".github/workflows/integration.yml"]
        self.assertEqual(plan(paths)['profile'], "integration")

    def test_installer_probe_and_release_packaging_require_full(self):
        for path in ("veiltrium.sh", "tools/keenetic-vpn-probe.sh", ".github/workflows/panel-release.yml"):
            with self.subTest(path=path):
                self.assertEqual(plan(["README.md", path])['profile'], "full")

    def test_draft_defers_full_but_records_requirement(self):
        selected = plan(["veiltrium.sh"], draft=True)
        self.assertEqual(selected['profile'], "integration")
        self.assertTrue(selected['full_required'])
        self.assertEqual(plan(["veiltrium.sh"], draft=False)['profile'], "full")

    def test_unknown_code_is_conservative(self):
        self.assertEqual(plan(["tools/new-installer.sh"])['profile'], "full")

    def test_unit_tests_do_not_launch_system_suites(self):
        self.assertEqual(plan(["tests/unit-cli.sh", "tests/ci_policy.py", "tests/test_ci_policy.py"])['profile'], "fast")

    def test_empty_diff_needs_no_system_install(self):
        self.assertEqual(plan([])['profile'], "fast")

    def test_non_commit_input_is_rejected(self):
        with self.assertRaises(ValueError):
            changed_files("--help", "main")

    def test_manual_output_is_machine_readable(self):
        with tempfile.TemporaryDirectory() as tmp:
            out, summary = Path(tmp)/"output", Path(tmp)/"summary"
            env = dict(os.environ, GITHUB_OUTPUT=str(out), GITHUB_STEP_SUMMARY=str(summary))
            result = subprocess.check_output([sys.executable, str(Path(__file__).with_name("ci_policy.py")),
                                              "--manual", "integration"], env=env, text=True)
            self.assertEqual(json.loads(result)['profile'], "integration")
            self.assertIn("full_required=false\n", out.read_text())
            self.assertIn("INTEGRATION", summary.read_text())


class DiffHandling(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.previous = Path.cwd()
        self.addCleanup(self.tmp.cleanup)
        os.chdir(self.tmp.name)
        self.addCleanup(os.chdir, self.previous)
        self.git("init", "-q")
        Path("veiltrium.sh").write_text("#!/bin/bash\necho original\n")
        self.base = self.commit()

    def git(self, *args):
        return subprocess.check_output(["git", "-c", "user.name=CI test", "-c", "user.email=ci@example.invalid", *args], text=True).strip()

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "-qm", "fixture")
        return self.git("rev-parse", "HEAD")

    def test_rename_cannot_hide_an_installer_change(self):
        Path("docs").mkdir()
        Path("veiltrium.sh").rename("docs/retired.md")
        paths = changed_files(self.base, self.commit())
        self.assertIn("veiltrium.sh", paths)
        self.assertEqual(plan(paths)['profile'], "full")

    def test_deletion_requires_full(self):
        Path("veiltrium.sh").unlink()
        self.assertEqual(plan(changed_files(self.base, self.commit()))['profile'], "full")

    def test_entire_pr_not_only_last_commit(self):
        Path("veiltrium.sh").write_text("#!/bin/bash\necho changed\n")
        self.commit()
        Path("README.md").write_text("documentation")
        self.assertEqual(plan(changed_files(self.base, self.commit()))['profile'], "full")

    def release_fixture(self):
        self.fields = ('SCRIPT_VERSION="2026-10-30"\nPANEL_VERSION="panel-v0.1.8"\n'
                       'PANEL_SHA256_AMD64="aaa"\nPANEL_SHA256_ARM64="bbb"\n')
        Path("veiltrium.sh").write_text(self.fields)
        return self.commit()

    def test_release_cli_selects_published_panel_only_when_ready(self):
        base = self.release_fixture()
        Path("veiltrium.sh").write_text(self.fields.replace("2026-10-30", "2026-11-01"))
        head = self.commit()
        env = {k: v for k, v in os.environ.items() if k not in {"GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY"}}
        script = str(Path(__file__).resolve().with_name("ci_policy.py"))
        for draft, expected in (("true", False), ("false", True)):
            with self.subTest(draft=draft):
                raw = subprocess.check_output([sys.executable, script, "--base", base, "--head", head,
                                               "--draft", draft], text=True, env=env)
                self.assertEqual(json.loads(raw)["release_panel"], expected)

    def test_runtime_change_uses_source_panel(self):
        base = self.release_fixture()
        Path("veiltrium.sh").write_text(self.fields + "echo changed\n")
        self.assertFalse(release_metadata_changed(base, self.commit()))

    def test_final_version_switches_full_to_published_panel(self):
        base = self.release_fixture()
        Path("veiltrium.sh").write_text(self.fields.replace("2026-10-30", "2026-11-01"))
        self.assertTrue(release_metadata_changed(base, self.commit()))

    def test_changed_pin_switches_full_to_published_panel(self):
        base = self.release_fixture()
        Path("veiltrium.sh").write_text(self.fields.replace('AMD64="aaa"', 'AMD64="ccc"'))
        self.assertTrue(release_metadata_changed(base, self.commit()))

    def test_deleted_installer_does_not_claim_release_metadata(self):
        base = self.release_fixture()
        Path("veiltrium.sh").unlink()
        self.assertFalse(release_metadata_changed(base, self.commit()))

    @unittest.skipIf(os.name == "nt", "Windows file names cannot contain newlines")
    def test_nul_delimited_paths_preserve_newlines(self):
        name = "example\nnotes.md"
        Path(name).write_text("documentation")
        self.assertEqual(changed_files(self.base, self.commit()), [name])


if __name__ == "__main__":
    unittest.main()
