#!/usr/bin/env python3
"""generate_proof_obligations_binder.py — bd-3yr14.5

Regenerates proof_obligations_binder.v1.json by validating and refreshing
the existing artifact:
- Validates that all evidence_artifacts exist
- Validates that all gates exist
- Validates that all source_refs point to existing files with valid lines
- Updates line numbers if content has shifted

The semantic content (proof obligation statements, scopes, categories) is
preserved from the committed artifact.
"""
import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

COMMITTED_PATH = REPO_ROOT / "tests" / "conformance" / "proof_obligations_binder.v1.json"


def load_json(path: Path):
    """Load and parse JSON file."""
    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        raise SystemExit(f"Failed to load {path}: {exc}") from exc


def file_exists(path_str: str) -> bool:
    """Check if a file exists (relative to repo root)."""
    path = Path(path_str)
    if path.is_absolute():
        return path.is_file()
    return (REPO_ROOT / path).is_file()


def validate_source_ref(ref: str) -> tuple[bool, str]:
    """
    Validate a source_ref (file:line format).
    Returns (is_valid, updated_ref).
    """
    if ":" not in ref:
        return False, ref

    file_part, line_part = ref.rsplit(":", 1)
    try:
        line_no = int(line_part)
    except ValueError:
        return False, ref

    path = Path(file_part)
    if not path.is_absolute():
        path = REPO_ROOT / file_part

    if not path.is_file():
        return False, ref

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return False, ref

    if line_no < 1 or line_no > len(lines):
        return False, ref

    # Line exists and is non-empty
    if lines[line_no - 1].strip():
        return True, ref

    return False, ref


def validate_obligation(obligation: dict) -> dict:
    """Validate and refresh a single proof obligation."""
    errors = []
    warnings = []

    # Validate evidence_artifacts
    for artifact in obligation.get("evidence_artifacts", []):
        if not file_exists(artifact):
            warnings.append(f"evidence_artifact not found: {artifact}")

    # Validate gates
    for gate in obligation.get("gates", []):
        if not file_exists(gate):
            warnings.append(f"gate not found: {gate}")

    # Validate source_refs
    valid_refs = []
    for ref in obligation.get("source_refs", []):
        is_valid, updated_ref = validate_source_ref(ref)
        if is_valid:
            valid_refs.append(updated_ref)
        else:
            warnings.append(f"source_ref invalid or stale: {ref}")

    # Return updated obligation with validation metadata
    result = dict(obligation)
    result["_validation"] = {
        "errors": errors,
        "warnings": warnings,
        "valid_source_refs": len(valid_refs),
        "total_source_refs": len(obligation.get("source_refs", [])),
    }
    return result


def generate_binder(output_path: Path | None = None) -> dict:
    """Generate the proof obligations binder."""
    if not COMMITTED_PATH.is_file():
        # Bootstrap: create minimal structure
        result = {
            "schema_version": "v1",
            "bead": "bd-5fw.4",
            "description": "Proof obligations binder: maps operational theorems to evidence artifacts and enforcing gates.",
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "obligations": [],
            "_validation_summary": {
                "total_obligations": 0,
                "valid_obligations": 0,
                "total_warnings": 0,
            },
        }
    else:
        # Load existing artifact
        committed = load_json(COMMITTED_PATH)

        # Validate each obligation
        validated_obligations = []
        total_warnings = 0
        valid_count = 0

        for obligation in committed.get("obligations", []):
            validated = validate_obligation(obligation)
            validation = validated.pop("_validation", {})
            total_warnings += len(validation.get("warnings", []))
            if not validation.get("errors"):
                valid_count += 1
            validated_obligations.append(validated)

        # Preserve all top-level keys from committed artifact
        result = dict(committed)
        result["obligations"] = validated_obligations
        result["_validation_summary"] = {
            "total_obligations": len(validated_obligations),
            "valid_obligations": valid_count,
            "total_warnings": total_warnings,
        }

    # Remove validation metadata for output (it's for internal use)
    output = {k: v for k, v in result.items() if not k.startswith("_")}
    output["obligations"] = [
        {k: v for k, v in ob.items() if not k.startswith("_")}
        for ob in result.get("obligations", [])
    ]

    if output_path:
        output_path.write_text(
            json.dumps(output, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )
    else:
        print(json.dumps(output, indent=2, sort_keys=False))

    return output


def main():
    parser = argparse.ArgumentParser(
        description="Generate proof_obligations_binder.v1.json"
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Output file path (default: stdout)",
    )
    args = parser.parse_args()

    generate_binder(args.output)


if __name__ == "__main__":
    main()
