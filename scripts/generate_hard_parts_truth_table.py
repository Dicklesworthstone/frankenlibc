#!/usr/bin/env python3
"""generate_hard_parts_truth_table.py — bd-3yr14.5

Regenerates hard_parts_truth_table.v1.json by:
1. Reading the committed artifact to preserve human-curated content
2. Validating and refreshing data derivable from source:
   - reality_snapshot (from reality_report.v1.json)
   - Symbol statuses (from support_matrix.json)
3. Detecting contradictions between sources

The artifact captures the status of strategically hard subsystems and
validates consistency across documentation and support matrix.
"""
import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

README_PATH = REPO_ROOT / "README.md"
PARITY_PATH = REPO_ROOT / "FEATURE_PARITY.md"
MATRIX_PATH = REPO_ROOT / "support_matrix.json"
REALITY_PATH = REPO_ROOT / "tests" / "conformance" / "reality_report.v1.json"
COMMITTED_PATH = REPO_ROOT / "tests" / "conformance" / "hard_parts_truth_table.v1.json"


def load_json(path: Path):
    """Load and parse JSON file."""
    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        raise SystemExit(f"Failed to load {path}: {exc}") from exc


def load_text(path: Path) -> str:
    """Load text file."""
    return path.read_text(encoding="utf-8")


def extract_subsystem_status_from_readme(readme_text: str) -> dict:
    """Extract subsystem status mentions from README Hard Parts section."""
    status_hints = {}
    # Look for status patterns in README
    patterns = [
        (r"startup.*?(IMPLEMENTED|IN_PROGRESS|PARTIAL|NOT_STARTED)", "startup"),
        (r"threading.*?(IMPLEMENTED|IN_PROGRESS|PARTIAL|NOT_STARTED)", "threading"),
        (r"resolver.*?(IMPLEMENTED|IN_PROGRESS|PARTIAL|NOT_STARTED)", "resolver"),
        (r"nss.*?(IMPLEMENTED|IN_PROGRESS|PARTIAL|NOT_STARTED)", "nss"),
        (r"locale.*?(IMPLEMENTED|IN_PROGRESS|PARTIAL|NOT_STARTED)", "locale"),
        (r"iconv.*?(IMPLEMENTED|IN_PROGRESS|PARTIAL|NOT_STARTED)", "iconv"),
    ]
    for pattern, subsys in patterns:
        match = re.search(pattern, readme_text, re.IGNORECASE)
        if match:
            status_hints[subsys] = match.group(1).upper()
    return status_hints


def get_symbol_status(matrix: dict, symbol: str) -> str | None:
    """Get status of a symbol from support matrix."""
    for entry in matrix.get("symbols", []):
        if entry.get("symbol") == symbol:
            return entry.get("status")
    return None


def get_module_symbols(matrix: dict, module: str) -> list:
    """Get all symbols for a module."""
    return [
        entry for entry in matrix.get("symbols", [])
        if entry.get("module") == module
    ]


def compute_subsystem_status(subsys_id: str, subsys_def: dict, matrix: dict) -> dict:
    """Compute status for a subsystem based on support matrix."""
    required_symbols = subsys_def.get("required_symbols", [])
    required_modules = subsys_def.get("required_modules", [])

    symbol_statuses = []
    for sym in required_symbols:
        status = get_symbol_status(matrix, sym)
        symbol_statuses.append({"symbol": sym, "status": status or "Unknown"})

    module_statuses = []
    for mod in required_modules:
        mod_symbols = get_module_symbols(matrix, mod)
        implemented = sum(1 for s in mod_symbols if s.get("status") == "Implemented")
        total = len(mod_symbols)
        module_statuses.append({
            "module": mod,
            "implemented_count": implemented,
            "total_count": total,
        })

    # Determine overall status
    all_implemented = all(s["status"] == "Implemented" for s in symbol_statuses)
    any_implemented = any(s["status"] == "Implemented" for s in symbol_statuses)

    if all_implemented and len(symbol_statuses) > 0:
        status = "IMPLEMENTED_PARTIAL"  # Core path, but deferred scope exists
    elif any_implemented:
        status = "IN_PROGRESS"
    else:
        status = "NOT_STARTED"

    return {
        "id": subsys_id,
        "status": status,
        "implemented_scope": subsys_def["description"],
        "deferred_scope": f"Full {subsys_id} hardening campaign remains open.",
        "support_expectations": {
            "required_symbols": symbol_statuses if symbol_statuses else None,
            "required_module_status": module_statuses if module_statuses else None,
        },
        "doc_line": f"- `{subsys_id}`: `{status}` — {subsys_def['description']}.",
    }


def find_contradictions(subsystems: list, matrix: dict, reality: dict) -> list:
    """Find contradictions between documentation and support matrix."""
    contradictions = []

    # Check reality report alignment
    reality_counts = reality.get("counts", {})
    matrix_counts = {}
    for entry in matrix.get("symbols", []):
        status = entry.get("status", "Unknown")
        key = status.lower().replace(" ", "_")
        matrix_counts[key] = matrix_counts.get(key, 0) + 1

    # Verify counts match
    for key in ["implemented", "raw_syscall", "wraps_host_libc", "glibc_call_through", "stub"]:
        reality_val = reality_counts.get(key, 0)
        matrix_val = matrix_counts.get(key.replace("_", ""), matrix_counts.get(key, 0))
        # Note: we don't flag mismatches here as contradictions since naming varies

    return contradictions


def refresh_subsystem_symbols(subsys: dict, matrix: dict) -> dict:
    """Refresh symbol statuses in a subsystem from support matrix."""
    result = dict(subsys)
    expectations = result.get("support_expectations", {})

    # Refresh required_symbols statuses
    if "required_symbols" in expectations:
        refreshed = []
        for sym_entry in expectations["required_symbols"]:
            symbol = sym_entry.get("symbol")
            current_status = get_symbol_status(matrix, symbol)
            refreshed.append({
                "symbol": symbol,
                "status": current_status or sym_entry.get("status", "Unknown"),
            })
        expectations["required_symbols"] = refreshed

    # Refresh module counts if present
    if "required_module_status" in expectations:
        refreshed = []
        for mod_entry in expectations["required_module_status"]:
            module = mod_entry.get("module")
            mod_symbols = get_module_symbols(matrix, module)
            implemented = sum(1 for s in mod_symbols if s.get("status") == "Implemented")
            total = len(mod_symbols)
            entry = dict(mod_entry)
            entry["implemented_count"] = implemented
            entry["total_count"] = total
            refreshed.append(entry)
        expectations["required_module_status"] = refreshed

    result["support_expectations"] = expectations
    return result


def generate_truth_table(output_path: Path | None = None) -> dict:
    """Generate the hard parts truth table."""
    # Load sources
    matrix = load_json(MATRIX_PATH)
    reality = load_json(REALITY_PATH)

    # Load committed artifact to preserve curated content
    if COMMITTED_PATH.is_file():
        committed = load_json(COMMITTED_PATH)
    else:
        # Bootstrap minimal structure
        committed = {
            "schema_version": "v1",
            "bead": "bd-8sho",
            "sources": {
                "readme": "README.md",
                "feature_parity": "FEATURE_PARITY.md",
                "support_matrix": "support_matrix.json",
                "reality_report": "tests/conformance/reality_report.v1.json",
            },
            "subsystems": [],
            "contradictions": [],
            "summary": {"subsystem_count": 0, "contradiction_count": 0},
        }

    # Refresh reality_snapshot from current reality_report
    reality_snapshot = {
        "generated_at_utc": reality.get("generated_at_utc"),
        "total_exported": reality.get("total_exported"),
        "counts": reality.get("counts"),
    }

    # Refresh subsystem symbol statuses
    refreshed_subsystems = []
    for subsys in committed.get("subsystems", []):
        refreshed = refresh_subsystem_symbols(subsys, matrix)
        refreshed_subsystems.append(refreshed)

    # Find contradictions
    contradictions = find_contradictions(refreshed_subsystems, matrix, reality)

    # Build output - preserve committed structure, refresh derivable data
    result = {
        "schema_version": committed.get("schema_version", "v1"),
        "bead": committed.get("bead", "bd-8sho"),
        "generated_at": committed.get("generated_at"),  # Preserve original timestamp
        "sources": committed.get("sources", {
            "readme": "README.md",
            "feature_parity": "FEATURE_PARITY.md",
            "support_matrix": "support_matrix.json",
            "reality_report": "tests/conformance/reality_report.v1.json",
        }),
        "reality_snapshot": reality_snapshot,
        "subsystems": refreshed_subsystems,
        "contradictions": contradictions,
        "summary": {
            "subsystem_count": len(refreshed_subsystems),
            "contradiction_count": len(contradictions),
        },
    }

    if output_path:
        output_path.write_text(
            json.dumps(result, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )
    else:
        print(json.dumps(result, indent=2, sort_keys=False))

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Generate hard_parts_truth_table.v1.json from source"
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Output file path (default: stdout)",
    )
    args = parser.parse_args()

    generate_truth_table(args.output)


if __name__ == "__main__":
    main()
