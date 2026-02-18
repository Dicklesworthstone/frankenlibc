#!/usr/bin/env python3
"""generate_iconv_table_pack.py — bd-13ya.

Deterministically generates the phase-1 iconv codec table pack and checksum
provenance artifacts used by reproducibility and drift gates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

BEAD_ID = "bd-13ya"
SCHEMA_VERSION = "v1"
GENERATOR_VERSION = "1.0.0"

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent

DEFAULT_LEDGER = REPO_ROOT / "tests/conformance/iconv_codec_scope_ledger.v1.json"
DEFAULT_PACK = REPO_ROOT / "tests/conformance/iconv_table_pack.v1.json"
DEFAULT_CHECKSUMS = REPO_ROOT / "tests/conformance/iconv_table_checksums.v1.json"


def normalize_codec_name(name: str) -> str:
    return "".join(ch for ch in name.upper() if ch not in "-_ \t")


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_json(payload: Any) -> str:
    return sha256_bytes(canonical_json(payload).encode("utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    path.write_text(serialized, encoding="utf-8")


def relpath(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        # Temporary validation outputs may live outside the repository.
        return "__external_output__"


def codec_template(normalized_name: str) -> dict[str, Any]:
    templates: dict[str, dict[str, Any]] = {
        "UTF8": {
            "family": "utf",
            "unit_kind": "variable-width",
            "max_units_per_scalar": 4,
            "endianness": "n/a",
            "deterministic_vectors": [
                {"input_hex": "41", "expected_scalar_sequence": ["U+0041"]},
                {"input_hex": "E282AC", "expected_scalar_sequence": ["U+20AC"]},
            ],
            "notes": "Phase-1 UTF-8 decoder/encoder path used by strict+hardened fixtures.",
        },
        "ISO88591": {
            "family": "single-byte",
            "unit_kind": "fixed-width",
            "max_units_per_scalar": 1,
            "endianness": "n/a",
            "deterministic_vectors": [
                {"input_hex": "41E9", "expected_scalar_sequence": ["U+0041", "U+00E9"]},
                {"input_hex": "FF", "expected_scalar_sequence": ["U+00FF"]},
            ],
            "notes": "Phase-1 Latin-1 baseline table for deterministic error semantics.",
        },
        "UTF16LE": {
            "family": "utf",
            "unit_kind": "fixed-width",
            "max_units_per_scalar": 2,
            "endianness": "little",
            "deterministic_vectors": [
                {"input_hex": "4100AC20", "expected_scalar_sequence": ["U+0041", "U+20AC"]},
                {"input_hex": "3DD800DE", "expected_scalar_sequence": ["U+10300"]},
            ],
            "notes": "Phase-1 UTF-16LE conversion table with surrogate-pair coverage.",
        },
        "UTF32": {
            "family": "utf",
            "unit_kind": "fixed-width",
            "max_units_per_scalar": 1,
            "endianness": "little",
            "emit_bom_on_open": True,
            "deterministic_vectors": [
                {"input_hex": "41000000", "expected_scalar_sequence": ["U+0041"]},
                {"input_hex": "AC200000", "expected_scalar_sequence": ["U+20AC"]},
            ],
            "notes": "Phase-1 UTF-32LE conversion table with deterministic BOM policy.",
        },
    }
    if normalized_name not in templates:
        raise ValueError(f"Unsupported phase-1 codec in ledger: {normalized_name}")
    return templates[normalized_name].copy()


def build_codec_tables(ledger: dict[str, Any]) -> list[dict[str, Any]]:
    tables: list[dict[str, Any]] = []
    included = ledger.get("included_codecs")
    if not isinstance(included, list):
        raise ValueError("included_codecs must be an array")

    for entry in included:
        canonical = str(entry["canonical"])
        normalized = normalize_codec_name(canonical)
        aliases = entry.get("aliases", [])
        if not isinstance(aliases, list):
            raise ValueError(f"aliases must be an array for codec {canonical}")

        template = codec_template(normalized)
        payload = {
            "canonical": canonical,
            "normalized": normalized,
            "aliases": aliases,
            "normalized_aliases": sorted(
                {normalize_codec_name(canonical), *(normalize_codec_name(alias) for alias in aliases)}
            ),
            "compatibility_intent": str(entry["compatibility_intent"]),
            "table": template,
        }
        payload["table_sha256"] = sha256_json(payload)
        tables.append(payload)

    tables.sort(key=lambda item: item["normalized"])
    return tables


def build_excluded_families(ledger: dict[str, Any]) -> list[dict[str, Any]]:
    families = ledger.get("excluded_codec_families")
    if not isinstance(families, list):
        raise ValueError("excluded_codec_families must be an array")

    normalized_families: list[dict[str, Any]] = []
    for entry in families:
        payload = {
            "canonical": str(entry["canonical"]),
            "normalized": normalize_codec_name(str(entry["canonical"])),
            "reason": str(entry["reason"]),
            "compatibility_intent": str(entry["compatibility_intent"]),
        }
        normalized_families.append(payload)
    normalized_families.sort(key=lambda item: item["normalized"])
    return normalized_families


def build_pack_payload(ledger_path: Path, ledger: dict[str, Any]) -> dict[str, Any]:
    ledger_sha256 = sha256_bytes(ledger_path.read_bytes())
    tables = build_codec_tables(ledger)
    excluded = build_excluded_families(ledger)

    table_pack = {
        "schema_version": SCHEMA_VERSION,
        "bead": BEAD_ID,
        "phase": ledger.get("phase", "phase1"),
        "generator": {
            "path": relpath(SCRIPT_PATH),
            "version": GENERATOR_VERSION,
        },
        "source_ledger": {
            "path": relpath(ledger_path),
            "bead": ledger.get("bead"),
            "sha256": ledger_sha256,
        },
        "included_codec_tables": tables,
        "excluded_codec_families": excluded,
        "support_matrix_mapping": ledger.get("support_matrix_mapping", {}),
    }

    table_pack["table_pack_sha256"] = sha256_json(table_pack)
    return table_pack


def build_checksums_payload(
    table_pack_path: Path,
    checksums_path: Path,
    table_pack: dict[str, Any],
) -> dict[str, Any]:
    codec_digests = {
        row["canonical"]: row["table_sha256"] for row in table_pack["included_codec_tables"]
    }
    excluded_digest = sha256_json(table_pack["excluded_codec_families"])

    checksums = {
        "schema_version": SCHEMA_VERSION,
        "bead": BEAD_ID,
        "generator": {
            "path": relpath(SCRIPT_PATH),
            "version": GENERATOR_VERSION,
        },
        "artifact_paths": {
            "table_pack": relpath(table_pack_path),
            "checksums": relpath(checksums_path),
        },
        "source_ledger_sha256": table_pack["source_ledger"]["sha256"],
        "codec_table_sha256": codec_digests,
        "excluded_codec_families_sha256": excluded_digest,
        "table_pack_sha256": table_pack["table_pack_sha256"],
    }
    checksums_for_digest = dict(checksums)
    checksums_for_digest.pop("artifact_paths", None)
    checksums["checksums_sha256"] = sha256_json(checksums_for_digest)
    return checksums


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate deterministic iconv phase-1 table pack + checksums"
    )
    parser.add_argument(
        "--ledger",
        type=Path,
        default=DEFAULT_LEDGER,
        help="Path to iconv scope ledger JSON",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_PACK,
        help="Output path for iconv table pack JSON",
    )
    parser.add_argument(
        "--checksums-output",
        type=Path,
        default=DEFAULT_CHECKSUMS,
        help="Output path for checksum manifest JSON",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ledger_path = args.ledger.resolve()
    output_path = args.output.resolve()
    checksums_path = args.checksums_output.resolve()

    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    table_pack = build_pack_payload(ledger_path, ledger)
    checksums = build_checksums_payload(output_path, checksums_path, table_pack)

    write_json(output_path, table_pack)
    write_json(checksums_path, checksums)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
