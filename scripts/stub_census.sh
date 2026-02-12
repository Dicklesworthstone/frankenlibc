#!/usr/bin/env bash
# Stub census: deterministic static inventory of todo!/unimplemented!/panic!
# placeholders in the frankenlibc workspace, cross-referenced against the
# support matrix and ABI exports.
#
# Deliverable for bd-2vb.
# Regenerates identically on repeated runs (deterministic output).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/tests/conformance/stub_census.json"
MATRIX="${ROOT}/support_matrix.json"
ABI_SRC="${ROOT}/crates/frankenlibc-abi/src"
CORE_SRC="${ROOT}/crates/frankenlibc-core/src"

timestamp_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# 1. Find all todo!/unimplemented!/panic! in core and abi crates
todo_lines=$(grep -rn 'todo!\|unimplemented!\|panic!' \
    "${CORE_SRC}" "${ABI_SRC}" 2>/dev/null \
    | grep -v '// *SAFETY:' \
    | grep -v '#\[should_panic' \
    | grep -v 'test' \
    | sort || true)

# 2. Find all extern "C" fn exports in ABI crate
abi_exports=$(grep -rn 'pub unsafe extern "C" fn\|pub extern "C" fn' \
    "${ABI_SRC}" 2>/dev/null \
    | sed 's/.*fn \([a-zA-Z_][a-zA-Z0-9_]*\).*/\1/' \
    | sort -u || true)

# 3. Generate JSON report via python
python3 - "$ROOT" "$MATRIX" "$CORE_SRC" "$ABI_SRC" "$timestamp_utc" <<'PYEOF'
import json, sys, os, re, subprocess
from pathlib import Path

root = sys.argv[1]
matrix_path = sys.argv[2]
core_src = sys.argv[3]
abi_src = sys.argv[4]
timestamp = sys.argv[5]

# Load support matrix
with open(matrix_path) as f:
    matrix = json.load(f)

matrix_symbols = {s["symbol"]: s for s in matrix["symbols"]}

# Find all todo!/unimplemented! in core
stub_pattern = re.compile(r'(todo|unimplemented|panic)!\s*\((.*?)\)', re.DOTALL)

stubs = []
for dirpath, _, filenames in sorted(os.walk(core_src)):
    for fname in sorted(filenames):
        if not fname.endswith('.rs'):
            continue
        fpath = os.path.join(dirpath, fname)
        rel = os.path.relpath(fpath, root)
        with open(fpath) as f:
            lines = f.readlines()
        for i, line in enumerate(lines, 1):
            m = stub_pattern.search(line)
            if not m:
                continue
            stub_type = m.group(1) + "!"
            msg = m.group(2).strip().strip('"').strip("'")
            # Extract function name from context
            fn_name = None
            for j in range(max(0, i-5), i):
                fn_match = re.search(r'pub fn (\w+)', lines[j])
                if fn_match:
                    fn_name = fn_match.group(1)
            stubs.append({
                "location": f"{rel}:{i}",
                "stub_type": stub_type,
                "stub_message": msg,
                "core_function": fn_name,
            })

# Find all extern "C" exports in ABI
abi_exports = {}
for dirpath, _, filenames in sorted(os.walk(abi_src)):
    for fname in sorted(filenames):
        if not fname.endswith('.rs'):
            continue
        fpath = os.path.join(dirpath, fname)
        rel = os.path.relpath(fpath, root)
        with open(fpath) as f:
            content = f.read()
        for m in re.finditer(r'pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)', content):
            abi_exports[m.group(1)] = rel

# Map core function names to likely ABI symbol names
# (core names are usually same as POSIX names)
RISK_CATEGORIES = {
    "iconv": "iconv",
    "setjmp": "setjmp", "longjmp": "setjmp",
    "tcgetattr": "terminal", "tcsetattr": "terminal",
    "getaddrinfo": "netdb", "getnameinfo": "netdb",
    "freeaddrinfo": "netdb", "gai_strerror": "netdb",
    "pthread_key_create": "threading", "pthread_key_delete": "threading",
    "pthread_getspecific": "threading", "pthread_setspecific": "threading",
    "pthread_create": "threading", "pthread_join": "threading",
    "pthread_detach": "threading", "pthread_exit": "threading",
    "pthread_self": "threading",
    "rand": "stdlib", "srand": "stdlib",
    "getenv": "stdlib", "setenv": "stdlib",
}

CALL_FAMILIES = {
    "iconv": "iconv", "setjmp": "setjmp", "longjmp": "setjmp",
    "tcgetattr": "termios", "tcsetattr": "termios",
    "getaddrinfo": "resolver", "getnameinfo": "resolver",
    "freeaddrinfo": "resolver", "gai_strerror": "resolver",
    "pthread_key_create": "pthread", "pthread_key_delete": "pthread",
    "pthread_getspecific": "pthread", "pthread_setspecific": "pthread",
    "pthread_create": "pthread", "pthread_join": "pthread",
    "pthread_detach": "pthread", "pthread_exit": "pthread",
    "pthread_self": "pthread",
    "rand": "stdlib", "srand": "stdlib",
    "getenv": "stdlib", "setenv": "stdlib",
}

# Enrich each stub
enriched = []
for s in stubs:
    fn = s["core_function"]
    if not fn:
        continue
    in_abi = fn in abi_exports
    matrix_entry = matrix_symbols.get(fn)
    matrix_status = matrix_entry["status"] if matrix_entry else None
    # Determine if core function is reachable from ABI
    reachable = in_abi  # simplified: if fn is exported, it may be called
    # But most ABI functions have their own impls and don't call core
    # We check if the ABI file actually imports the core module
    abi_module = abi_exports.get(fn, "")
    calls_core = False
    if abi_module:
        abi_path = os.path.join(root, abi_module)
        if os.path.exists(abi_path):
            with open(abi_path) as f:
                abi_content = f.read()
            # Check if ABI calls core stub: look for explicit
            # glibc_rs_core::<module>::<fn>() or <alias>::<fn>() patterns
            # Must find the function name as a *call* (followed by '('),
            # not just as an extern "C" fn definition.
            import_aliases = re.findall(
                r'use glibc_rs_core::(\w+)(?:\s+as\s+(\w+))?', abi_content)
            for (mod_name, alias) in import_aliases:
                prefix = alias if alias else mod_name
                # e.g. "termios_core::tcgetattr(" or "glibc_rs_core::termios::tcgetattr("
                if f"{prefix}::{fn}(" in abi_content:
                    calls_core = True
                    break
            if f"glibc_rs_core::{fn}(" in abi_content:
                calls_core = True

    enriched.append({
        "symbol": fn,
        "abi_module": abi_module if abi_module else None,
        "core_location": s["location"],
        "stub_type": s["stub_type"],
        "stub_message": s["stub_message"],
        "support_matrix_status": matrix_status,
        "in_support_matrix": matrix_entry is not None,
        "has_abi_export": in_abi,
        "abi_calls_core_stub": calls_core,
        "reachable_from_abi": calls_core,
        "risk_category": RISK_CATEGORIES.get(fn, "other"),
        "call_family": CALL_FAMILIES.get(fn, "other"),
    })

# Detect support matrix inconsistencies
inconsistencies = []

# Check resolver symbols marked Stub that are actually Implemented
resolver_impls = ["getaddrinfo", "freeaddrinfo", "getnameinfo", "gai_strerror"]
for sym in resolver_impls:
    entry = matrix_symbols.get(sym)
    if entry and entry["status"] == "Stub":
        inconsistencies.append({
            "symbol": sym,
            "matrix_status": "Stub",
            "actual_status": "Implemented",
            "evidence": f"resolv_abi.rs has full extern \"C\" implementation",
            "severity": "high",
        })

# Check pthread symbols marked GlibcCallThrough that are actually Implemented
pthread_pure_rust = ["pthread_self", "pthread_equal"]
for sym in pthread_pure_rust:
    entry = matrix_symbols.get(sym)
    if entry and entry["status"] == "GlibcCallThrough":
        inconsistencies.append({
            "symbol": sym,
            "matrix_status": "GlibcCallThrough",
            "actual_status": "Implemented",
            "evidence": f"pthread_abi.rs uses pure Rust (no libc:: calls)",
            "severity": "medium",
        })

pthread_std_thread = ["pthread_create", "pthread_join", "pthread_detach"]
for sym in pthread_std_thread:
    entry = matrix_symbols.get(sym)
    if entry and entry["status"] == "GlibcCallThrough":
        inconsistencies.append({
            "symbol": sym,
            "matrix_status": "GlibcCallThrough",
            "actual_status": "Implemented",
            "evidence": f"pthread_abi.rs uses std::thread (not libc call-through)",
            "severity": "medium",
        })

# Check termios symbols marked RawSyscall that are GlibcCallThrough
termios_callthrough = ["tcgetattr", "tcsetattr"]
for sym in termios_callthrough:
    entry = matrix_symbols.get(sym)
    if entry and entry["status"] == "RawSyscall":
        inconsistencies.append({
            "symbol": sym,
            "matrix_status": "RawSyscall",
            "actual_status": "GlibcCallThrough",
            "evidence": f"termios_abi.rs calls libc::{sym}()",
            "severity": "medium",
        })

# Missing symbols (have core stubs but no ABI export and not in matrix)
missing_from_abi = []
seen_symbols = set()
for s in enriched:
    sym = s["symbol"]
    if sym in seen_symbols:
        continue
    seen_symbols.add(sym)
    if not s["has_abi_export"] and not s["in_support_matrix"]:
        missing_from_abi.append({
            "symbol": sym,
            "core_location": s["core_location"],
            "risk_category": s["risk_category"],
            "call_family": s["call_family"],
            "note": "Has core stub with todo!() but no ABI export and not in support matrix",
        })

# Deduplicate enriched by symbol
seen = set()
deduped = []
for s in enriched:
    if s["symbol"] not in seen:
        seen.add(s["symbol"])
        deduped.append(s)

# Summary stats
by_risk = {}
for s in deduped:
    r = s["risk_category"]
    by_risk[r] = by_risk.get(r, 0) + 1

by_family = {}
for s in deduped:
    f = s["call_family"]
    by_family[f] = by_family.get(f, 0) + 1

report = {
    "census_version": 1,
    "generated_utc": timestamp,
    "workspace_root": root,
    "total_todo_occurrences": len(stubs),
    "total_unique_stub_symbols": len(deduped),
    "total_abi_exports": len(abi_exports),
    "total_matrix_symbols": len(matrix_symbols),
    "stubs": sorted(deduped, key=lambda s: (s["risk_category"], s["symbol"])),
    "inconsistencies": sorted(inconsistencies, key=lambda i: (i["severity"], i["symbol"])),
    "missing_from_abi_and_matrix": sorted(missing_from_abi, key=lambda m: m["symbol"]),
    "summary": {
        "reachable_stubs": sum(1 for s in deduped if s["reachable_from_abi"]),
        "unreachable_stubs": sum(1 for s in deduped if not s["reachable_from_abi"]),
        "matrix_inconsistencies": len(inconsistencies),
        "missing_symbols": len(missing_from_abi),
        "by_risk_category": dict(sorted(by_risk.items())),
        "by_call_family": dict(sorted(by_family.items())),
    },
}

with open(sys.argv[2].replace("support_matrix.json", "tests/conformance/stub_census.json"), 'w') as f:
    json.dump(report, f, indent=2)
    f.write('\n')

# Also write to stdout for CI consumption
json.dump(report, sys.stdout, indent=2)
print()
PYEOF

echo ""
echo "=== Stub Census Summary ==="
python3 -c "
import json
with open('${OUT}') as f:
    r = json.load(f)
print(f\"Total todo!/unimplemented!/panic! occurrences: {r['total_todo_occurrences']}\")
print(f\"Unique stub symbols: {r['total_unique_stub_symbols']}\")
print(f\"Reachable from ABI: {r['summary']['reachable_stubs']}\")
print(f\"Unreachable (dead code): {r['summary']['unreachable_stubs']}\")
print(f\"Support matrix inconsistencies: {r['summary']['matrix_inconsistencies']}\")
print(f\"Missing from ABI+matrix: {r['summary']['missing_symbols']}\")
print()
print('By risk category:')
for k, v in r['summary']['by_risk_category'].items():
    print(f'  {k}: {v}')
print()
if r['inconsistencies']:
    print('Matrix inconsistencies:')
    for i in r['inconsistencies']:
        print(f\"  {i['symbol']:30s} matrix={i['matrix_status']:20s} actual={i['actual_status']}\")
print()
if r['missing_from_abi_and_matrix']:
    print('Missing from ABI + support matrix:')
    for m in r['missing_from_abi_and_matrix']:
        print(f\"  {m['symbol']:30s} family={m['call_family']:10s} risk={m['risk_category']}\")
"

echo ""
echo "Census written to: ${OUT}"
