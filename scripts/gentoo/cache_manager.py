#!/usr/bin/env python3
"""Binary package cache manager for Gentoo ecosystem validation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(raw: str) -> datetime:
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    return datetime.fromisoformat(raw).astimezone(timezone.utc)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def normalize_use_flags(flags: Iterable[str]) -> List[str]:
    return sorted({flag.strip() for flag in flags if flag and flag.strip()})


@dataclass
class CachedPackage:
    package: str
    version: str
    tbz2_path: str
    built_at: str
    frankenlibc_version: str
    frankenlibc_mode: str
    use_flags: List[str]
    sha256: str
    build_log_sha256: str
    healing_actions_count: int

    @property
    def key(self) -> str:
        return f"{self.package}-{self.version}"

    def to_record(self) -> Dict[str, object]:
        return asdict(self)

    @classmethod
    def from_record(cls, payload: Dict[str, object]) -> "CachedPackage":
        return cls(
            package=str(payload["package"]),
            version=str(payload["version"]),
            tbz2_path=str(payload["tbz2_path"]),
            built_at=str(payload["built_at"]),
            frankenlibc_version=str(payload["frankenlibc_version"]),
            frankenlibc_mode=str(payload["frankenlibc_mode"]),
            use_flags=[str(item) for item in payload.get("use_flags", [])],
            sha256=str(payload["sha256"]),
            build_log_sha256=str(payload.get("build_log_sha256", "")),
            healing_actions_count=int(payload.get("healing_actions_count", 0)),
        )


class BinaryPackageCache:
    """Cache manager that enforces provenance/integrity checks before reuse."""

    def __init__(
        self,
        cache_dir: Path,
        max_age_days: int = 7,
        max_entries: int = 4096,
        metadata_file: Optional[Path] = None,
        log_file: Optional[Path] = None,
    ) -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_age_days = max_age_days
        self.max_entries = max_entries
        self.metadata_file = metadata_file or (self.cache_dir / "metadata.json")
        env_log = os.environ.get("FLC_CACHE_LOG")
        self.log_file = log_file or (Path(env_log) if env_log else None)
        self._lock = threading.RLock()

    def _log_event(
        self,
        *,
        event: str,
        key: str,
        hit_miss: str,
        reason: str,
        checksum: str = "",
        age_days: Optional[int] = None,
    ) -> None:
        payload: Dict[str, object] = {
            "ts": utc_now(),
            "event": event,
            "key": key,
            "hit_miss": hit_miss,
            "reason": reason,
            "checksum": checksum,
        }
        if age_days is not None:
            payload["age_days"] = age_days
        if self.log_file is None:
            return
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        with self.log_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")

    def _load_metadata(self) -> Dict[str, Dict[str, object]]:
        if not self.metadata_file.exists():
            return {}
        payload = json.loads(self.metadata_file.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and "entries" in payload:
            entries = payload.get("entries", {})
            if isinstance(entries, dict):
                return {str(k): dict(v) for k, v in entries.items()}
        if isinstance(payload, dict):
            return {str(k): dict(v) for k, v in payload.items()}
        raise ValueError(f"Invalid metadata format in {self.metadata_file}")

    def _save_metadata(self, entries: Dict[str, Dict[str, object]]) -> None:
        body = {
            "schema_version": 1,
            "updated_at": utc_now(),
            "entries": entries,
        }
        tmp = self.metadata_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(self.metadata_file)

    def _validate_entry(
        self,
        entry: CachedPackage,
        *,
        expected_mode: Optional[str] = None,
        expected_frankenlibc_version: Optional[str] = None,
        expected_use_flags: Optional[Iterable[str]] = None,
        now: Optional[datetime] = None,
    ) -> Tuple[bool, str, int]:
        now = now or datetime.now(timezone.utc)
        try:
            built_at = parse_utc(entry.built_at)
        except ValueError:
            return False, "invalid_timestamp", -1
        age_days = (now - built_at).days
        if age_days > self.max_age_days:
            return False, "stale_entry", age_days

        tbz2_path = Path(entry.tbz2_path)
        if not tbz2_path.exists():
            return False, "missing_tbz2", age_days

        observed_checksum = sha256_file(tbz2_path)
        if observed_checksum != entry.sha256:
            return False, "checksum_mismatch", age_days

        if expected_mode and entry.frankenlibc_mode != expected_mode:
            return False, "mode_mismatch", age_days

        if expected_frankenlibc_version and entry.frankenlibc_version != expected_frankenlibc_version:
            return False, "version_mismatch", age_days

        if expected_use_flags is not None:
            want = normalize_use_flags(expected_use_flags)
            have = normalize_use_flags(entry.use_flags)
            if want != have:
                return False, "use_flag_mismatch", age_days

        return True, "ok", age_days

    def _prune_entries(self, entries: Dict[str, Dict[str, object]]) -> Dict[str, Dict[str, object]]:
        if len(entries) <= self.max_entries:
            return entries
        ranked = sorted(
            entries.items(),
            key=lambda item: parse_utc(str(item[1].get("built_at", "1970-01-01T00:00:00Z"))),
        )
        keep = ranked[-self.max_entries :]
        return {key: value for key, value in keep}

    def lookup(
        self,
        package: str,
        version: str,
        *,
        expected_mode: Optional[str] = None,
        expected_frankenlibc_version: Optional[str] = None,
        expected_use_flags: Optional[Iterable[str]] = None,
    ) -> Tuple[Optional[CachedPackage], str]:
        key = f"{package}-{version}"
        with self._lock:
            entries = self._load_metadata()
            record = entries.get(key)
            if record is None:
                self._log_event(event="cache_lookup", key=key, hit_miss="miss", reason="not_found")
                return None, "not_found"

            entry = CachedPackage.from_record(record)
            ok, reason, age_days = self._validate_entry(
                entry,
                expected_mode=expected_mode,
                expected_frankenlibc_version=expected_frankenlibc_version,
                expected_use_flags=expected_use_flags,
            )
            if not ok:
                self._log_event(
                    event="cache_lookup",
                    key=key,
                    hit_miss="miss",
                    reason=reason,
                    checksum=entry.sha256,
                    age_days=age_days if age_days >= 0 else None,
                )
                return None, reason

            self._log_event(
                event="cache_lookup",
                key=key,
                hit_miss="hit",
                reason="ok",
                checksum=entry.sha256,
                age_days=age_days,
            )
            return entry, "ok"

    def put(
        self,
        package: str,
        version: str,
        tbz2_path: Path,
        *,
        frankenlibc_version: str,
        frankenlibc_mode: str,
        use_flags: Optional[Iterable[str]] = None,
        build_log_path: Optional[Path] = None,
        healing_actions_count: int = 0,
        built_at: Optional[str] = None,
    ) -> CachedPackage:
        path = Path(tbz2_path)
        if not path.exists():
            raise FileNotFoundError(f"tbz2 not found: {path}")
        entry = CachedPackage(
            package=package,
            version=version,
            tbz2_path=str(path.resolve()),
            built_at=built_at or utc_now(),
            frankenlibc_version=frankenlibc_version,
            frankenlibc_mode=frankenlibc_mode,
            use_flags=normalize_use_flags(use_flags or []),
            sha256=sha256_file(path),
            build_log_sha256=sha256_file(build_log_path) if build_log_path and build_log_path.exists() else "",
            healing_actions_count=healing_actions_count,
        )
        key = entry.key
        with self._lock:
            entries = self._load_metadata()
            entries[key] = entry.to_record()
            entries = self._prune_entries(entries)
            self._save_metadata(entries)
            self._log_event(
                event="cache_put",
                key=key,
                hit_miss="write",
                reason="stored",
                checksum=entry.sha256,
            )
        return entry

    def invalidate(
        self,
        *,
        package: Optional[str] = None,
        version: Optional[str] = None,
        delete_files: bool = False,
    ) -> int:
        with self._lock:
            entries = self._load_metadata()
            keys = list(entries.keys())
            selected: List[str] = []
            for key in keys:
                record = CachedPackage.from_record(entries[key])
                if package and record.package != package:
                    continue
                if version and record.version != version:
                    continue
                selected.append(key)
            for key in selected:
                record = CachedPackage.from_record(entries[key])
                if delete_files:
                    path = Path(record.tbz2_path)
                    if path.exists():
                        path.unlink()
                entries.pop(key, None)
                self._log_event(event="cache_invalidate", key=key, hit_miss="write", reason="invalidated")
            self._save_metadata(entries)
            return len(selected)

    def list_entries(self) -> List[CachedPackage]:
        with self._lock:
            entries = self._load_metadata()
            return [CachedPackage.from_record(entries[key]) for key in sorted(entries.keys())]

    def validate_all(
        self,
        *,
        expected_mode: Optional[str] = None,
        expected_frankenlibc_version: Optional[str] = None,
    ) -> Dict[str, object]:
        with self._lock:
            entries = self._load_metadata()
        valid: List[Dict[str, object]] = []
        invalid: List[Dict[str, object]] = []
        for key in sorted(entries.keys()):
            entry = CachedPackage.from_record(entries[key])
            ok, reason, age_days = self._validate_entry(
                entry,
                expected_mode=expected_mode,
                expected_frankenlibc_version=expected_frankenlibc_version,
            )
            if ok:
                valid.append({"key": key, "age_days": age_days, "checksum": entry.sha256})
                self._log_event(
                    event="cache_validate",
                    key=key,
                    hit_miss="hit",
                    reason="ok",
                    checksum=entry.sha256,
                    age_days=age_days,
                )
            else:
                invalid.append(
                    {
                        "key": key,
                        "reason": reason,
                        "age_days": age_days,
                        "expected_mode": expected_mode,
                        "expected_frankenlibc_version": expected_frankenlibc_version,
                    }
                )
                self._log_event(
                    event="cache_validate",
                    key=key,
                    hit_miss="miss",
                    reason=reason,
                    checksum=entry.sha256,
                    age_days=age_days if age_days >= 0 else None,
                )
        return {
            "cache_dir": str(self.cache_dir),
            "metadata_file": str(self.metadata_file),
            "max_age_days": self.max_age_days,
            "total_entries": len(entries),
            "valid_count": len(valid),
            "invalid_count": len(invalid),
            "valid": valid,
            "invalid": invalid,
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage Gentoo binary package cache metadata.")
    parser.add_argument("--cache-dir", default="/var/cache/binpkgs", help="Binary package cache root")
    parser.add_argument("--metadata-file", default="", help="Optional metadata file override")
    parser.add_argument("--max-age-days", type=int, default=7, help="Entry TTL in days")
    parser.add_argument("--max-entries", type=int, default=4096, help="Maximum metadata entries")
    parser.add_argument("--log-file", default="", help="Structured cache-event log path (JSONL)")

    subparsers = parser.add_subparsers(dest="command", required=True)

    put_parser = subparsers.add_parser("put", help="Insert/update a cache entry")
    put_parser.add_argument("--package", required=True)
    put_parser.add_argument("--version", required=True)
    put_parser.add_argument("--tbz2", required=True)
    put_parser.add_argument("--franken-version", required=True)
    put_parser.add_argument("--mode", required=True)
    put_parser.add_argument("--use-flag", action="append", default=[])
    put_parser.add_argument("--build-log", default="")
    put_parser.add_argument("--healing-actions-count", type=int, default=0)
    put_parser.add_argument("--built-at", default="")

    get_parser = subparsers.add_parser("get", help="Lookup and validate a cache entry")
    get_parser.add_argument("--package", required=True)
    get_parser.add_argument("--version", required=True)
    get_parser.add_argument("--mode", default="")
    get_parser.add_argument("--franken-version", default="")
    get_parser.add_argument("--use-flag", action="append", default=[])

    invalidate_parser = subparsers.add_parser("invalidate", help="Remove cache metadata entries")
    invalidate_parser.add_argument("--package", default="")
    invalidate_parser.add_argument("--version", default="")
    invalidate_parser.add_argument("--delete-files", action="store_true")

    validate_parser = subparsers.add_parser("validate", help="Validate all metadata entries")
    validate_parser.add_argument("--mode", default="")
    validate_parser.add_argument("--franken-version", default="")
    validate_parser.add_argument("--strict", action="store_true", help="Exit nonzero if invalid entries exist")

    subparsers.add_parser("list", help="List all entries")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    metadata_file = Path(args.metadata_file) if args.metadata_file else None
    log_file = Path(args.log_file) if args.log_file else None
    cache = BinaryPackageCache(
        cache_dir=Path(args.cache_dir),
        max_age_days=args.max_age_days,
        max_entries=args.max_entries,
        metadata_file=metadata_file,
        log_file=log_file,
    )

    if args.command == "put":
        entry = cache.put(
            package=args.package,
            version=args.version,
            tbz2_path=Path(args.tbz2),
            frankenlibc_version=args.franken_version,
            frankenlibc_mode=args.mode,
            use_flags=args.use_flag,
            build_log_path=Path(args.build_log) if args.build_log else None,
            healing_actions_count=args.healing_actions_count,
            built_at=args.built_at or None,
        )
        print(json.dumps({"stored": True, "entry": entry.to_record()}, sort_keys=True))
        return 0

    if args.command == "get":
        entry, reason = cache.lookup(
            package=args.package,
            version=args.version,
            expected_mode=args.mode or None,
            expected_frankenlibc_version=args.franken_version or None,
            expected_use_flags=args.use_flag if args.use_flag else None,
        )
        if entry is None:
            print(json.dumps({"hit": False, "reason": reason, "key": f"{args.package}-{args.version}"}, sort_keys=True))
            return 1
        print(json.dumps({"hit": True, "reason": reason, "entry": entry.to_record()}, sort_keys=True))
        return 0

    if args.command == "invalidate":
        removed = cache.invalidate(
            package=args.package or None,
            version=args.version or None,
            delete_files=args.delete_files,
        )
        print(json.dumps({"invalidated": removed}, sort_keys=True))
        return 0

    if args.command == "validate":
        report = cache.validate_all(
            expected_mode=args.mode or None,
            expected_frankenlibc_version=args.franken_version or None,
        )
        print(json.dumps(report, indent=2, sort_keys=True))
        if args.strict and int(report["invalid_count"]) > 0:
            return 1
        return 0

    if args.command == "list":
        payload = [entry.to_record() for entry in cache.list_entries()]
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    raise RuntimeError(f"Unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
