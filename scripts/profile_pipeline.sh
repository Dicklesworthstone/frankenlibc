#!/usr/bin/env bash
# profile_pipeline.sh — reproducible CPU/alloc/syscall profiling for critical benches.
#
# Produces timestamped artifacts under target/profiles/ so optimization rounds can be compared.
# Emits machine-readable artifacts per run:
#   - profile_report.v1.json (structured hotspot evidence)
#   - hotspot_opportunity_matrix.v1.json (deterministic ranked candidates)
# Default scope is strict-mode critical benches; use MODE=hardened for hardened.
#
# Usage:
#   scripts/profile_pipeline.sh
#   MODE=hardened PROFILE_TIME=2 scripts/profile_pipeline.sh
#   MODE=strict PROFILE_TARGETS="runtime_math_decide_strict membrane_validate_known_strict" scripts/profile_pipeline.sh
#
# Environment:
#   MODE             strict|hardened (default: strict)
#   PROFILE_TIME     Criterion profile time in seconds per benchmark (default: 1)
#   PROFILE_FREQ     perf sampling frequency for perf record (default: 199)
#   OUT_ROOT         Output root directory (default: target/profiles)
#   PROFILE_TARGETS  Space-delimited slugs to profile (default: all critical slugs)

set -euo pipefail

MODE="${MODE:-strict}"
PROFILE_TIME="${PROFILE_TIME:-1}"
PROFILE_FREQ="${PROFILE_FREQ:-199}"
OUT_ROOT="${OUT_ROOT:-target/profiles}"
RUN_TS="${RUN_TS:-$(date -u +%Y%m%dT%H%M%SZ)}"

if [[ "${MODE}" != "strict" && "${MODE}" != "hardened" ]]; then
    echo "ERROR: MODE must be strict or hardened (got: ${MODE})" >&2
    exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "ERROR: cargo not found in PATH" >&2
    exit 1
fi
if ! command -v perf >/dev/null 2>&1; then
    echo "ERROR: perf not found in PATH" >&2
    exit 1
fi
if ! command -v strace >/dev/null 2>&1; then
    echo "ERROR: strace not found in PATH" >&2
    exit 1
fi
if ! command -v cargo-flamegraph >/dev/null 2>&1; then
    echo "ERROR: cargo-flamegraph not found in PATH" >&2
    exit 1
fi
CARGO_BIN="$(command -v cargo)"
ORIG_PERF_PARANOID=""
PARANOID_ADJUSTED=0

if [[ -r /proc/sys/kernel/perf_event_paranoid ]]; then
    ORIG_PERF_PARANOID="$(cat /proc/sys/kernel/perf_event_paranoid)"
    if [[ "${ORIG_PERF_PARANOID}" -ge 2 ]]; then
        if ! sudo -n true >/dev/null 2>&1; then
            echo "ERROR: perf_event_paranoid=${ORIG_PERF_PARANOID} requires sudo -n to lower temporarily" >&2
            exit 1
        fi
        sudo -n sysctl -w kernel.perf_event_paranoid=1 >/dev/null
        PARANOID_ADJUSTED=1
    fi
fi

restore_perf_paranoid() {
    if [[ "${PARANOID_ADJUSTED}" -eq 1 && -n "${ORIG_PERF_PARANOID}" ]]; then
        sudo -n sysctl -w "kernel.perf_event_paranoid=${ORIG_PERF_PARANOID}" >/dev/null || true
    fi
}
trap restore_perf_paranoid EXIT

RUN_DIR="${OUT_ROOT}/${RUN_TS}/${MODE}"
CPU_DIR="${RUN_DIR}/cpu"
ALLOC_DIR="${RUN_DIR}/alloc"
SYSCALL_DIR="${RUN_DIR}/syscall"
mkdir -p "${CPU_DIR}" "${ALLOC_DIR}" "${SYSCALL_DIR}"

COMMAND_LOG="${RUN_DIR}/commands.log"
SUMMARY_LOG="${RUN_DIR}/summary.log"
MANIFEST="${RUN_DIR}/manifest.txt"
PROFILE_REPORT="${RUN_DIR}/profile_report.v1.json"
HOTSPOT_MATRIX="${RUN_DIR}/hotspot_opportunity_matrix.v1.json"
TARGET_INDEX_TSV="${RUN_DIR}/targets.tsv"

: >"${TARGET_INDEX_TSV}"

declare -a TARGET_MATRIX=(
    "runtime_math_bench|runtime_math/decide/${MODE}|runtime_math_decide_${MODE}"
    "runtime_math_bench|runtime_math/observe_fast/${MODE}|runtime_math_observe_fast_${MODE}"
    "runtime_math_bench|runtime_math/decide_observe/${MODE}|runtime_math_decide_observe_${MODE}"
    "membrane_bench|validate_known|membrane_validate_known_${MODE}"
)

if [[ -n "${PROFILE_TARGETS:-}" ]]; then
    declare -a FILTERED=()
    for row in "${TARGET_MATRIX[@]}"; do
        slug="${row##*|}"
        for wanted in ${PROFILE_TARGETS}; do
            if [[ "${slug}" == "${wanted}" ]]; then
                FILTERED+=("${row}")
            fi
        done
    done
    TARGET_MATRIX=("${FILTERED[@]}")
fi

if [[ "${#TARGET_MATRIX[@]}" -eq 0 ]]; then
    echo "ERROR: no targets selected; check PROFILE_TARGETS" >&2
    exit 1
fi

append_cmd() {
    printf '%s\n' "$*" >>"${COMMAND_LOG}"
}

extract_cpu_top5() {
    local perf_data="$1"
    local out_file="$2"
    perf report -i "${perf_data}" --stdio --no-children --sort=symbol \
        | awk '/^ *[0-9]+\.[0-9]+%/ {print; c++; if (c==5) exit}' >"${out_file}"
}

extract_alloc_top5() {
    local perf_data="$1"
    local out_file="$2"
    local raw_file="${out_file%.top5.txt}.report.txt"
    perf report -i "${perf_data}" --stdio --no-children --sort=symbol >"${raw_file}"

    grep -Ei 'alloc|malloc|calloc|realloc|free|__rdl|jemalloc|mmap|munmap|brk' "${raw_file}" \
        | head -n 5 >"${out_file}" || true

    if [[ ! -s "${out_file}" ]]; then
        awk '/^ *[0-9]+\.[0-9]+%/ {print; c++; if (c==5) exit}' "${raw_file}" >"${out_file}"
    fi
}

extract_syscall_top5() {
    local strace_file="$1"
    local out_file="$2"
    awk '/^ *[0-9]+\.[0-9]+/ {print; c++; if (c==5) exit}' "${strace_file}" >"${out_file}"
}

profile_target() {
    local bench="$1"
    local bench_id="$2"
    local slug="$3"

    echo "== Profiling ${slug} ==" | tee -a "${SUMMARY_LOG}"

    local cpu_svg="${CPU_DIR}/${slug}.svg"
    local cpu_data="${CPU_DIR}/${slug}.perf.data"
    local cpu_top5="${CPU_DIR}/${slug}.top5.txt"

    append_cmd "FRANKENLIBC_MODE=${MODE} CARGO_PROFILE_BENCH_DEBUG=true cargo flamegraph -F ${PROFILE_FREQ} -p frankenlibc-bench --bench ${bench} --deterministic -o ${cpu_svg} -- --bench --profile-time ${PROFILE_TIME} --exact ${bench_id}"
    FRANKENLIBC_MODE="${MODE}" CARGO_PROFILE_BENCH_DEBUG=true \
        cargo flamegraph -F "${PROFILE_FREQ}" -p frankenlibc-bench --bench "${bench}" --deterministic \
        -o "${cpu_svg}" -- \
        --bench --profile-time "${PROFILE_TIME}" --exact "${bench_id}"

    if [[ -f perf.data ]]; then
        mv perf.data "${cpu_data}"
        extract_cpu_top5 "${cpu_data}" "${cpu_top5}"
    else
        echo "WARN: perf.data missing after flamegraph for ${slug}" | tee -a "${SUMMARY_LOG}"
    fi

    local alloc_data="${ALLOC_DIR}/${slug}.perf.data"
    local alloc_top5="${ALLOC_DIR}/${slug}.top5.txt"
    append_cmd "perf record -F ${PROFILE_FREQ} -g -o ${alloc_data} -- env FRANKENLIBC_MODE=${MODE} ${CARGO_BIN} bench -p frankenlibc-bench --bench ${bench} -- --profile-time ${PROFILE_TIME} --exact ${bench_id}"
    perf record -F "${PROFILE_FREQ}" -g -o "${alloc_data}" -- \
        env FRANKENLIBC_MODE="${MODE}" "${CARGO_BIN}" bench -p frankenlibc-bench --bench "${bench}" -- \
            --profile-time "${PROFILE_TIME}" --exact "${bench_id}" >/dev/null
    extract_alloc_top5 "${alloc_data}" "${alloc_top5}"

    local syscall_raw="${SYSCALL_DIR}/${slug}.strace.txt"
    local syscall_top5="${SYSCALL_DIR}/${slug}.top5.txt"
    append_cmd "strace -f -qq -c -o ${syscall_raw} env FRANKENLIBC_MODE=${MODE} ${CARGO_BIN} bench -p frankenlibc-bench --bench ${bench} -- --profile-time ${PROFILE_TIME} --exact ${bench_id}"
    strace -f -qq -c -o "${syscall_raw}" \
        env FRANKENLIBC_MODE="${MODE}" "${CARGO_BIN}" bench -p frankenlibc-bench --bench "${bench}" -- \
            --profile-time "${PROFILE_TIME}" --exact "${bench_id}" >/dev/null 2>&1
    extract_syscall_top5 "${syscall_raw}" "${syscall_top5}"

    echo "  CPU top-5: ${cpu_top5}" | tee -a "${SUMMARY_LOG}"
    echo "  Alloc top-5: ${alloc_top5}" | tee -a "${SUMMARY_LOG}"
    echo "  Syscall top-5: ${syscall_top5}" | tee -a "${SUMMARY_LOG}"
    echo "" | tee -a "${SUMMARY_LOG}"

    printf "%s\t%s\t%s\t%s\t%s\t%s\n" \
        "${bench}" "${bench_id}" "${slug}" "${cpu_top5}" "${alloc_top5}" "${syscall_top5}" >>"${TARGET_INDEX_TSV}"
}

emit_structured_reports() {
    python3 - "${RUN_TS}" "${MODE}" "${PROFILE_TIME}" "${PROFILE_FREQ}" "${RUN_DIR}" "${TARGET_INDEX_TSV}" "${PROFILE_REPORT}" "${HOTSPOT_MATRIX}" <<'PY'
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

run_ts, mode, profile_time, profile_freq, run_dir, index_tsv, profile_report, hotspot_matrix = sys.argv[1:]
run_dir_path = Path(run_dir)
index_path = Path(index_tsv)
profile_report_path = Path(profile_report)
hotspot_matrix_path = Path(hotspot_matrix)

if not index_path.exists():
    raise SystemExit(f"missing target index: {index_path}")


def parse_top5(path: str) -> list[dict]:
    p = Path(path)
    rows: list[dict] = []
    if not p.exists():
        return rows

    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue

        perf_match = re.match(r"^\s*([0-9]+(?:\.[0-9]+)?)%\s+\[[^\]]+\]\s+(.*)$", line)
        if perf_match:
            pct = float(perf_match.group(1))
            symbol = perf_match.group(2).strip()
            symbol = symbol.split("  -", 1)[0].strip() or symbol
            rows.append({"pct": pct, "symbol": symbol, "raw": line.strip()})
            continue

        parts = line.split()
        if parts and re.match(r"^[0-9]+(?:\.[0-9]+)?$", parts[0]):
            pct = float(parts[0])
            symbol = parts[-1]
            rows.append({"pct": pct, "symbol": symbol, "raw": line.strip()})

    for i, row in enumerate(rows, 1):
        row["rank"] = i
    return rows


def effort_heuristic(symbol: str) -> float:
    s = symbol.lower()
    if "glibc_rs_membrane" in s or "frankenlibc" in s:
        return 3.5
    if s.startswith("__") or s.startswith("[k]") or "llvm::" in s:
        return 1.5
    return 2.5


targets: list[dict] = []
aggregates: dict[str, dict] = {}
with index_path.open("r", encoding="utf-8") as f:
    for raw in f:
        line = raw.rstrip("\n")
        if not line:
            continue
        bench, bench_id, slug, cpu_path, alloc_path, syscall_path = line.split("\t")
        cpu_top5 = parse_top5(cpu_path)
        alloc_top5 = parse_top5(alloc_path)
        syscall_top5 = parse_top5(syscall_path)

        target = {
            "bench": bench,
            "bench_id": bench_id,
            "slug": slug,
            "artifacts": {
                "cpu_top5_path": cpu_path,
                "alloc_top5_path": alloc_path,
                "syscall_top5_path": syscall_path,
            },
            "cpu_top5": cpu_top5,
            "alloc_top5": alloc_top5,
            "syscall_top5": syscall_top5,
        }
        targets.append(target)

        def ingest(kind: str, rows: list[dict]) -> None:
            for row in rows:
                symbol = row["symbol"]
                slot = aggregates.setdefault(
                    symbol,
                    {
                        "symbol": symbol,
                        "cpu_pct": 0.0,
                        "alloc_pct": 0.0,
                        "syscall_pct": 0.0,
                        "cpu_hits": 0,
                        "alloc_hits": 0,
                        "syscall_hits": 0,
                        "targets": set(),
                    },
                )
                pct = float(row["pct"])
                if kind == "cpu":
                    slot["cpu_pct"] += pct
                    slot["cpu_hits"] += 1
                elif kind == "alloc":
                    slot["alloc_pct"] += pct
                    slot["alloc_hits"] += 1
                else:
                    slot["syscall_pct"] += pct
                    slot["syscall_hits"] += 1
                slot["targets"].add(slug)

        ingest("cpu", cpu_top5)
        ingest("alloc", alloc_top5)
        ingest("syscall", syscall_top5)

generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

profile_report_doc = {
    "schema_version": 1,
    "generated_at_utc": generated_at,
    "run": {
        "run_ts": run_ts,
        "mode": mode,
        "profile_time_s": int(profile_time),
        "profile_freq_hz": int(profile_freq),
        "run_dir": str(run_dir_path),
    },
    "targets": targets,
    "summary": {
        "target_count": len(targets),
        "unique_hotspot_symbols": len(aggregates),
        "artifact_files": {
            "manifest": str(run_dir_path / "manifest.txt"),
            "commands_log": str(run_dir_path / "commands.log"),
            "summary_log": str(run_dir_path / "summary.log"),
            "target_index_tsv": str(index_path),
        },
    },
}

max_impact_raw = 0.0
for slot in aggregates.values():
    impact_raw = (slot["cpu_pct"] * 0.6) + (slot["alloc_pct"] * 0.3) + (slot["syscall_pct"] * 0.1)
    if impact_raw > max_impact_raw:
        max_impact_raw = impact_raw

entries: list[dict] = []
target_denominator = max(len(targets), 1)
for symbol, slot in aggregates.items():
    impact_raw = (slot["cpu_pct"] * 0.6) + (slot["alloc_pct"] * 0.3) + (slot["syscall_pct"] * 0.1)
    impact = 0.0 if max_impact_raw == 0 else round((impact_raw / max_impact_raw) * 5.0, 2)
    confidence = round((len(slot["targets"]) / target_denominator) * 5.0, 2)
    effort = round(effort_heuristic(symbol), 2)
    score = round((impact * 0.5) + (confidence * 0.3) + (effort * 0.2), 2)
    status = "eligible" if score >= 2.0 else "deferred"

    entries.append(
        {
            "id": f"hotspot-{len(entries) + 1:03d}",
            "symbol": symbol,
            "impact": impact,
            "confidence": confidence,
            "effort": effort,
            "score": score,
            "status": status,
            "target_hits": len(slot["targets"]),
            "target_slugs": sorted(slot["targets"]),
            "evidence": {
                "cpu_pct_sum": round(slot["cpu_pct"], 2),
                "alloc_pct_sum": round(slot["alloc_pct"], 2),
                "syscall_pct_sum": round(slot["syscall_pct"], 2),
                "cpu_hits": slot["cpu_hits"],
                "alloc_hits": slot["alloc_hits"],
                "syscall_hits": slot["syscall_hits"],
                "impact_raw": round(impact_raw, 4),
                "impact_raw_max": round(max_impact_raw, 4),
            },
        }
    )

entries.sort(key=lambda row: (-row["score"], -row["impact"], -row["confidence"], row["symbol"]))
for idx, row in enumerate(entries, 1):
    row["rank"] = idx

eligible_count = sum(1 for row in entries if row["status"] == "eligible")
deferred_count = len(entries) - eligible_count

hotspot_matrix_doc = {
    "schema_version": 1,
    "generated_at_utc": generated_at,
    "source_run": {
        "run_ts": run_ts,
        "mode": mode,
        "run_dir": str(run_dir_path),
        "profile_report": str(profile_report_path),
    },
    "scoring": {
        "formula": "score = impact*0.5 + confidence*0.3 + effort*0.2",
        "impact_basis": "normalized weighted hotspot share (cpu=0.6, alloc=0.3, syscall=0.1)",
        "confidence_basis": "target coverage ratio across profiled slugs",
        "effort_basis": "symbol-ownership heuristic (owned/runtime symbols favored)",
        "threshold": 2.0,
    },
    "entries": entries,
    "summary": {
        "total_entries": len(entries),
        "eligible_entries": eligible_count,
        "deferred_entries": deferred_count,
        "top_candidates": entries[:10],
    },
}

profile_report_path.write_text(json.dumps(profile_report_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
hotspot_matrix_path.write_text(json.dumps(hotspot_matrix_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

{
    echo "run_ts=${RUN_TS}"
    echo "mode=${MODE}"
    echo "profile_time=${PROFILE_TIME}"
    echo "profile_freq=${PROFILE_FREQ}"
    echo "run_dir=${RUN_DIR}"
    echo "profile_report=${PROFILE_REPORT}"
    echo "hotspot_opportunity_matrix=${HOTSPOT_MATRIX}"
} >"${MANIFEST}"

for row in "${TARGET_MATRIX[@]}"; do
    IFS='|' read -r bench bench_id slug <<<"${row}"
    profile_target "${bench}" "${bench_id}" "${slug}"
done

emit_structured_reports

echo "Profiling complete."
echo "Artifacts: ${RUN_DIR}"
echo "Command log: ${COMMAND_LOG}"
echo "Summary: ${SUMMARY_LOG}"
echo "Profile report: ${PROFILE_REPORT}"
echo "Hotspot matrix: ${HOTSPOT_MATRIX}"
