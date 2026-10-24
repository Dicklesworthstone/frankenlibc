#!/usr/bin/env python3
"""Exercise the actual workflow shell and unchanged guard using real Git repos.

Fixtures are deliberately retained: machine policy forbids automatic deletion.
Only main and its legacy mirror are created; no feature branches or mocks.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/ci.yml"


def preparation_script():
    text = WORKFLOW.read_text()
    marker = "      - name: Prepare main-only CI checkout\n        run: |\n"
    body = text.split(marker, 1)[1].split("\n      - name:", 1)[0]
    return "set -euo pipefail\n" + "\n".join(
        line[10:] for line in body.splitlines()
    )


class CheckoutPreparationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Path(tempfile.mkdtemp(prefix="frankenlibc-ci-checkout-"))
        self.remote = self.fixture / "origin.git"
        self.repo = self.fixture / "checkout"
        self.repo.mkdir()
        self.run_git(self.fixture, "init", "--bare", "--initial-branch=main", str(self.remote))
        self.run_git(self.repo, "init", "--initial-branch=main")
        self.run_git(self.repo, "config", "user.email", "ci-checkout-test@example.invalid")
        self.run_git(self.repo, "config", "user.name", "CI checkout regression")
        self.run_git(self.repo, "remote", "add", "origin", str(self.remote))
        # commit-tree creates objects without populating a local branch. This
        # matches a detached Actions PR checkout with no pre-existing main.
        (self.repo / "selected-source.txt").write_text("base source\n")
        self.run_git(self.repo, "add", "selected-source.txt")
        tree = self.git("write-tree")
        self.base = self.git("commit-tree", tree, input="base\n")
        self.run_git(self.repo, "push", str(self.remote), f"{self.base}:refs/heads/main")
        if not self.id().endswith("test_missing_remote_mirror_fails_without_attaching"):
            self.run_git(self.repo, "push", str(self.remote), f"{self.base}:refs/heads/master")
        (self.repo / "selected-source.txt").write_text("PR-only useful work\n")
        self.run_git(self.repo, "add", "selected-source.txt")
        tree = self.git("write-tree")
        self.selected = self.git("commit-tree", tree, "-p", self.base, input="PR source\n")
        # Attach to the selected object without a checkout/reset or file writes.
        self.run_git(self.repo, "update-ref", "--no-deref", "HEAD", self.selected)
        self.original_files = (self.repo / "selected-source.txt").read_bytes()
        scripts = self.repo / "scripts"
        scripts.mkdir()
        shutil.copy2(ROOT / "scripts/check_main_only_worktree_guard.sh", scripts)
        conformance = self.repo / "tests/conformance"
        conformance.mkdir(parents=True)
        shutil.copy2(ROOT / "tests/conformance/main_only_worktree_guard.v1.json", conformance)

    @staticmethod
    def run_git(repo, *args, input=None):
        return subprocess.run(["git", "-C", str(repo), *args], input=input,
                              text=True, capture_output=True, check=True, timeout=30).stdout.strip()

    def git(self, *args, input=None):
        return self.run_git(self.repo, *args, input=input)

    def prepare(self, expected=None):
        return subprocess.run(["bash", "-c", preparation_script()], cwd=self.repo,
                              env={**os.environ, "GITHUB_SHA": expected or self.selected},
                              text=True, capture_output=True, check=False, timeout=30)

    def assert_source_preserved(self):
        self.assertEqual(self.git("rev-parse", "HEAD"), self.selected)
        self.assertEqual((self.repo / "selected-source.txt").read_bytes(), self.original_files)

    def guard(self):
        result = subprocess.run(["bash", "scripts/check_main_only_worktree_guard.sh",
                                 "--validate-only"], cwd=self.repo,
                                text=True, capture_output=True, check=False, timeout=30)
        try:
            report = json.loads((self.repo / "target/conformance/main_only_worktree_guard.report.json").read_text())
        except json.JSONDecodeError as exc:
            self.fail(f"Guard emitted invalid JSON: {exc}")
        return result, report

    def test_detached_pr_preserves_source_and_passes_unchanged_guard(self):
        before, _ = self.guard()
        self.assertNotEqual(before.returncode, 0, "original Actions topology must fail")
        self.assertEqual(self.prepare().returncode, 0)
        self.assert_source_preserved()
        self.assertEqual(self.git("branch", "--show-current"), "main")
        self.assertEqual(self.git("for-each-ref", "--format=%(refname:short)", "refs/heads"), "main")
        self.assertEqual(self.git("rev-parse", "origin/main"), self.base)
        self.assertNotEqual(self.selected, self.base, "PR source must differ from main")
        result, report = self.guard()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(report["negative_controls"])
        self.assertTrue(all(c["status"] == "pass" for c in report["negative_controls"]))

    def test_attached_main_is_idempotent(self):
        self.git("branch", "main", self.selected)
        self.git("symbolic-ref", "HEAD", "refs/heads/main")
        self.assertEqual(self.prepare().returncode, 0)
        self.assertEqual(self.prepare().returncode, 0)
        self.assert_source_preserved()
        result, _ = self.guard()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_wrong_expected_sha_fails_without_creating_main(self):
        self.assertNotEqual(self.prepare(expected=self.base).returncode, 0)
        self.assert_source_preserved()
        self.assertEqual(self.git("branch", "--show-current"), "")
        self.assertEqual(self.git("for-each-ref", "--format=%(refname)", "refs/heads"), "")

    def test_existing_main_is_never_reset(self):
        self.git("branch", "main", self.base)
        self.assertNotEqual(self.prepare().returncode, 0)
        self.assert_source_preserved()
        self.assertEqual(self.git("rev-parse", "main"), self.base)
        self.assertEqual(self.git("branch", "--show-current"), "")

    def test_missing_remote_mirror_fails_without_attaching(self):
        self.assertNotEqual(self.prepare().returncode, 0)
        self.assert_source_preserved()
        self.assertEqual(self.git("branch", "--show-current"), "")
        self.assertEqual(self.git("for-each-ref", "--format=%(refname)", "refs/heads"), "")

    def test_stale_mirror_still_fails_guard(self):
        self.git("push", "origin", f"{self.selected}:refs/heads/master")
        self.assertEqual(self.prepare().returncode, 0)
        self.assert_source_preserved()
        result, report = self.guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("legacy_mirror_not_synced",
                      [e["failure_signature"] for e in report["errors"]])


if __name__ == "__main__":
    unittest.main(verbosity=2)
