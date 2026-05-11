#!/usr/bin/env python3
"""Generate and validate Gentoo top-100 package list from tier metadata.

Source of truth:
  configs/gentoo/package-tiers.json

Generated artifact:
  configs/gentoo/top100-packages.txt
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def validate_and_collect_packages(data: dict[str, Any]) -> list[str]:
    if data.get("schema_version") != "v1":
        raise ValueError("schema_version must be 'v1'")

    constraints = data.get("constraints", {})
    target_total = int(constraints.get("target_total_packages", 100))
    target_tiers = int(constraints.get("target_tier_count", 5))
    target_per_tier = int(constraints.get("target_packages_per_tier", 20))

    tiers = data.get("tiers")
    if not isinstance(tiers, list):
        raise ValueError("tiers must be an array")
    if len(tiers) != target_tiers:
        raise ValueError(f"expected {target_tiers} tiers, found {len(tiers)}")

    all_packages: list[str] = []
    seen: set[str] = set()
    duplicates: set[str] = set()

    for tier in tiers:
        tier_id = tier.get("id", "<unknown-tier>")
        packages = tier.get("packages")
        if not isinstance(packages, list):
            raise ValueError(f"{tier_id}: packages must be an array")
        if len(packages) != target_per_tier:
            raise ValueError(
                f"{tier_id}: expected {target_per_tier} packages, found {len(packages)}"
            )
        for atom in packages:
            if not isinstance(atom, str) or "/" not in atom:
                raise ValueError(f"{tier_id}: invalid package atom {atom!r}")
            if atom in seen:
                duplicates.add(atom)
            seen.add(atom)
            all_packages.append(atom)

    if duplicates:
        dup_list = ", ".join(sorted(duplicates))
        raise ValueError(f"duplicate package atoms across tiers: {dup_list}")
    if len(all_packages) != target_total:
        raise ValueError(
            f"expected {target_total} total packages, found {len(all_packages)}"
        )

    return all_packages


def write_top100(path: Path, packages: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(packages) + "\n"
    path.write_text(content, encoding="utf-8")


def write_telemetry(
    path: Path,
    data: dict[str, Any],
    packages: list[str],
    input_path: Path,
    output_path: Path,
    check_only: bool,
) -> None:
    tiers = data.get("tiers", [])
    telemetry = {
        "schema_version": "gentoo_top100_package_selection_telemetry.v1",
        "bead": "bd-2icq.5",
        "event": "top100_package_selection_validated",
        "timestamp": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "status": "pass",
        "input_path": str(input_path),
        "output_path": str(output_path),
        "check_only": check_only,
        "package_count": len(packages),
        "tier_count": len(tiers) if isinstance(tiers, list) else 0,
        "first_package": packages[0] if packages else None,
        "last_package": packages[-1] if packages else None,
        "selection_criteria": data.get("selection_criteria", {}),
        "tier_package_counts": {
            tier.get("id", f"tier-{index + 1}"): len(tier.get("packages", []))
            for index, tier in enumerate(tiers)
            if isinstance(tier, dict)
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(telemetry, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    root = repo_root()
    default_input = root / "configs/gentoo/package-tiers.json"
    default_output = root / "configs/gentoo/top100-packages.txt"

    parser = argparse.ArgumentParser(
        description="Validate package tiers and (re)generate top100 package list."
    )
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=default_output)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate only; do not write output file.",
    )
    parser.add_argument(
        "--telemetry",
        type=Path,
        help="Optional path for structured package-selection telemetry JSON.",
    )
    args = parser.parse_args()

    data = load_json(args.input)
    packages = validate_and_collect_packages(data)
    if args.telemetry is not None:
        write_telemetry(
            args.telemetry,
            data,
            packages,
            args.input,
            args.output,
            args.check,
        )

    if args.check:
        print(
            f"OK: validated {len(packages)} package atoms across "
            f"{len(data['tiers'])} tiers from {args.input}"
        )
        return 0

    write_top100(args.output, packages)
    print(
        f"OK: wrote {len(packages)} package atoms to {args.output} "
        f"from {args.input}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
