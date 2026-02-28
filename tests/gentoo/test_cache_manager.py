#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def load_cache_manager(repo_root: Path):
    script_path = repo_root / "scripts/gentoo/cache_manager.py"
    spec = importlib.util.spec_from_file_location("cache_manager_module", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


class BinaryPackageCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.module = load_cache_manager(Path(__file__).resolve().parents[2])
        self.cache_dir = self.root / "binpkgs"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.root / "cache-events.jsonl"
        self.cache = self.module.BinaryPackageCache(
            cache_dir=self.cache_dir,
            max_age_days=7,
            metadata_file=self.cache_dir / "metadata.json",
            log_file=self.log_file,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _create_artifact(self, atom: str, version: str, body: bytes = b"payload") -> Path:
        category = atom.split("/", 1)[0]
        package = atom.split("/", 1)[1]
        dest = self.cache_dir / category
        dest.mkdir(parents=True, exist_ok=True)
        path = dest / f"{package}-{version}.tbz2"
        path.write_bytes(body)
        return path

    def test_put_and_lookup_cache_hit(self) -> None:
        atom = "sys-apps/coreutils"
        version = "9.4-r1"
        tbz2 = self._create_artifact(atom, version, b"coreutils")

        stored = self.cache.put(
            package=atom,
            version=version,
            tbz2_path=tbz2,
            frankenlibc_version="0.4.0",
            frankenlibc_mode="hardened",
            use_flags=["acl", "nls", "-selinux"],
            healing_actions_count=3,
        )
        hit, reason = self.cache.lookup(
            package=atom,
            version=version,
            expected_mode="hardened",
            expected_frankenlibc_version="0.4.0",
            expected_use_flags=["-selinux", "acl", "nls"],
        )

        self.assertEqual(reason, "ok")
        self.assertIsNotNone(hit)
        assert hit is not None
        self.assertEqual(hit.sha256, stored.sha256)
        self.assertEqual(hit.use_flags, ["-selinux", "acl", "nls"])

    def test_lookup_miss_on_checksum_corruption(self) -> None:
        atom = "sys-apps/grep"
        version = "3.11"
        tbz2 = self._create_artifact(atom, version, b"good")
        self.cache.put(
            package=atom,
            version=version,
            tbz2_path=tbz2,
            frankenlibc_version="0.4.0",
            frankenlibc_mode="hardened",
        )

        tbz2.write_bytes(b"tampered")
        hit, reason = self.cache.lookup(package=atom, version=version)
        self.assertIsNone(hit)
        self.assertEqual(reason, "checksum_mismatch")

    def test_lookup_miss_on_expired_entry(self) -> None:
        atom = "sys-devel/binutils"
        version = "2.43"
        tbz2 = self._create_artifact(atom, version, b"binutils")
        self.cache.put(
            package=atom,
            version=version,
            tbz2_path=tbz2,
            frankenlibc_version="0.4.0",
            frankenlibc_mode="hardened",
            built_at="2000-01-01T00:00:00Z",
        )

        hit, reason = self.cache.lookup(package=atom, version=version)
        self.assertIsNone(hit)
        self.assertEqual(reason, "stale_entry")

    def test_invalidate_specific_package(self) -> None:
        atom = "dev-db/redis"
        version = "7.2.3"
        other_atom = "dev-db/postgresql"
        other_version = "16.1"
        self.cache.put(
            package=atom,
            version=version,
            tbz2_path=self._create_artifact(atom, version),
            frankenlibc_version="0.4.0",
            frankenlibc_mode="hardened",
        )
        self.cache.put(
            package=other_atom,
            version=other_version,
            tbz2_path=self._create_artifact(other_atom, other_version),
            frankenlibc_version="0.4.0",
            frankenlibc_mode="hardened",
        )

        removed = self.cache.invalidate(package=atom)
        self.assertEqual(removed, 1)
        hit_removed, _ = self.cache.lookup(package=atom, version=version)
        hit_other, _ = self.cache.lookup(package=other_atom, version=other_version)
        self.assertIsNone(hit_removed)
        self.assertIsNotNone(hit_other)

    def test_validate_all_reports_invalid_entries(self) -> None:
        valid_atom = "net-misc/curl"
        valid_version = "8.8.0"
        invalid_atom = "dev-lang/python"
        invalid_version = "3.12.3"

        self.cache.put(
            package=valid_atom,
            version=valid_version,
            tbz2_path=self._create_artifact(valid_atom, valid_version, b"curl"),
            frankenlibc_version="0.4.0",
            frankenlibc_mode="hardened",
        )
        invalid_path = self._create_artifact(invalid_atom, invalid_version, b"python")
        self.cache.put(
            package=invalid_atom,
            version=invalid_version,
            tbz2_path=invalid_path,
            frankenlibc_version="0.4.0",
            frankenlibc_mode="hardened",
        )
        invalid_path.unlink()

        report = self.cache.validate_all(expected_mode="hardened", expected_frankenlibc_version="0.4.0")
        self.assertEqual(report["total_entries"], 2)
        self.assertEqual(report["valid_count"], 1)
        self.assertEqual(report["invalid_count"], 1)
        self.assertEqual(report["invalid"][0]["reason"], "missing_tbz2")

    def test_concurrent_lookup_access(self) -> None:
        atom = "sys-apps/findutils"
        version = "4.9.0"
        self.cache.put(
            package=atom,
            version=version,
            tbz2_path=self._create_artifact(atom, version, b"findutils"),
            frankenlibc_version="0.4.0",
            frankenlibc_mode="hardened",
        )

        def worker() -> str:
            entry, reason = self.cache.lookup(
                package=atom,
                version=version,
                expected_mode="hardened",
                expected_frankenlibc_version="0.4.0",
            )
            if entry is None:
                return reason
            return "ok"

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: worker(), range(64)))
        self.assertEqual(set(results), {"ok"})

        lines = self.log_file.read_text(encoding="utf-8").splitlines()
        self.assertGreaterEqual(len(lines), 64)
        first = json.loads(lines[0])
        self.assertIn("event", first)
        self.assertIn("hit_miss", first)
        self.assertIn("reason", first)


if __name__ == "__main__":
    unittest.main()
