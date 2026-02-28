# Gentoo Binary Package Cache Policy

This document defines the build-once/test-many cache flow for FrankenLibC Gentoo validation.

## Goals

1. Reuse validated `.tbz2` artifacts to avoid redundant rebuilds.
2. Enforce provenance and integrity before every cache hit.
3. Keep forensic traceability for each cache decision.

## Core Workflow

1. Build package with binary output:
```bash
emerge --buildpkg --verbose <atom>
```
2. Register artifact in cache metadata:
```bash
python3 scripts/gentoo/cache_manager.py \
  --cache-dir /var/cache/binpkgs \
  put \
  --package <atom> \
  --version <ver> \
  --tbz2 /var/cache/binpkgs/<category>/<pkg>-<ver>.tbz2 \
  --franken-version <frankenlibc-version> \
  --mode hardened
```
3. Reuse only after validation:
```bash
python3 scripts/gentoo/cache_manager.py \
  --cache-dir /var/cache/binpkgs \
  get \
  --package <atom> \
  --version <ver> \
  --mode hardened \
  --franken-version <frankenlibc-version>
```

## Validation Rules

Each cache lookup must pass all checks:

1. Entry exists in metadata.
2. Entry age is within `max_age_days`.
3. `.tbz2` file exists.
4. SHA-256 checksum matches metadata.
5. Mode compatibility (`strict` vs `hardened`) matches request.
6. FrankenLibC version compatibility matches request.
7. Optional USE-flag set matches request.

Any failure is treated as a cache miss.

## Metadata Schema

`/var/cache/binpkgs/metadata.json`:

```json
{
  "schema_version": 1,
  "updated_at": "2026-02-28T00:00:00Z",
  "entries": {
    "dev-db/redis-7.2.3": {
      "package": "dev-db/redis",
      "version": "7.2.3",
      "tbz2_path": "/var/cache/binpkgs/dev-db/redis-7.2.3.tbz2",
      "built_at": "2026-02-28T00:00:00Z",
      "frankenlibc_version": "0.4.0",
      "frankenlibc_mode": "hardened",
      "use_flags": ["jemalloc", "ssl", "-systemd"],
      "sha256": "<artifact-sha256>",
      "build_log_sha256": "<build-log-sha256>",
      "healing_actions_count": 47
    }
  }
}
```

## Operations

## Warm Cache

```bash
scripts/gentoo/warm_cache.sh \
  --packages configs/gentoo/top100-packages.txt \
  --cache-dir /var/cache/binpkgs \
  --mode hardened \
  --franken-version 0.4.0
```

## Validate Cache

```bash
python3 scripts/gentoo/validate_cache.py \
  --cache-dir /var/cache/binpkgs \
  --mode hardened \
  --franken-version 0.4.0 \
  --strict
```

## Invalidate Entries

```bash
# Invalidate a package across all versions (metadata only)
python3 scripts/gentoo/cache_manager.py --cache-dir /var/cache/binpkgs invalidate --package dev-db/redis

# Invalidate one exact version
python3 scripts/gentoo/cache_manager.py --cache-dir /var/cache/binpkgs invalidate --package dev-db/redis --version 7.2.3
```

## Structured Logging

Set `FLC_CACHE_LOG` to emit JSONL events:

```bash
export FLC_CACHE_LOG=/tmp/gentoo-cache-events.jsonl
```

Each event contains:

- `event` (`cache_lookup`, `cache_put`, `cache_validate`, `cache_invalidate`)
- `key`
- `hit_miss`
- `reason`
- `checksum`
- `age_days` (when available)

These logs are intended for regression triage and forensic replay.

## Policy Defaults

1. `max_age_days`: `7`
2. `max_entries`: `4096`
3. Default cache location: `/var/cache/binpkgs`
4. Cache metadata updates are atomic (`metadata.json.tmp` then rename)

## Recovery

If metadata is corrupted:

1. Move metadata aside:
```bash
mv /var/cache/binpkgs/metadata.json /var/cache/binpkgs/metadata.json.corrupt.$(date +%s)
```
2. Re-register artifacts using `warm_cache.sh` or `cache_manager.py put`.
3. Run `validate_cache.py --strict` before re-enabling cache reads.
