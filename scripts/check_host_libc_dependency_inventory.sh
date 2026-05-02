#!/usr/bin/env bash
# check_host_libc_dependency_inventory.sh - host libc dependency inventory gate.
#
# Generates:
#   target/conformance/host_libc_dependency_inventory.report.json
#   target/conformance/host_libc_dependency_inventory.log.jsonl
#
# By default the release artifact is optional so source-level CI can run without
# forcing a release build. Set FRANKENLIBC_REQUIRE_RELEASE_ARTIFACT=1 to require
# target/release/libfrankenlibc_abi.so and include readelf/ldd/objdump/nm
# evidence. Strict artifact mode also rejects stale release artifacts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
CONTRACT="${ROOT}/tests/conformance/host_libc_dependency_inventory.v1.json"
REPORT_PATH="${FRANKENLIBC_HOST_DEP_REPORT:-${OUT_DIR}/host_libc_dependency_inventory.report.json}"
LOG_PATH="${FRANKENLIBC_HOST_DEP_LOG:-${OUT_DIR}/host_libc_dependency_inventory.log.jsonl}"
RELEASE_ARTIFACT="${FRANKENLIBC_RELEASE_ARTIFACT:-${ROOT}/target/release/libfrankenlibc_abi.so}"
REQUIRE_RELEASE_ARTIFACT="${FRANKENLIBC_REQUIRE_RELEASE_ARTIFACT:-0}"
ENFORCE_RELEASE_STALENESS="${FRANKENLIBC_ENFORCE_RELEASE_STALENESS:-auto}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT_PATH}")" "$(dirname "${LOG_PATH}")"

export ROOT CONTRACT REPORT_PATH LOG_PATH RELEASE_ARTIFACT REQUIRE_RELEASE_ARTIFACT ENFORCE_RELEASE_STALENESS

python3 - <<'PY'
import json
import os
import re
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

root = Path(os.environ["ROOT"])
contract_path = Path(os.environ["CONTRACT"])
report_path = Path(os.environ["REPORT_PATH"])
log_path = Path(os.environ["LOG_PATH"])
release_artifact = Path(os.environ["RELEASE_ARTIFACT"])
require_release = os.environ.get("REQUIRE_RELEASE_ARTIFACT") == "1"
staleness_mode = os.environ.get("ENFORCE_RELEASE_STALENESS", "auto")
if not report_path.is_absolute():
    report_path = root / report_path
if not log_path.is_absolute():
    log_path = root / log_path
if not release_artifact.is_absolute():
    release_artifact = root / release_artifact

contract = json.loads(contract_path.read_text(encoding="utf-8"))
abi_src = root / contract["inputs"]["abi_source_dir"]
abi_cargo_toml = root / "crates/frankenlibc-abi/Cargo.toml"
replacement_profile = json.loads(
    (root / contract["inputs"]["replacement_profile"]).read_text(encoding="utf-8")
)
replacement_levels = json.loads(
    (root / contract["inputs"]["replacement_levels"]).read_text(encoding="utf-8")
)

source_commit = subprocess.run(
    ["git", "rev-parse", "HEAD"],
    cwd=root,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    check=False,
).stdout.strip()
target_dir = os.environ.get("CARGO_TARGET_DIR", str(root / "target"))
timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

function_re = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
direct_libc_re = re.compile(r"\blibc::([a-z_][a-z0-9_]*)\s*\(")
resolve_call_re = re.compile(r"resolve_host_symbol_(raw|cached)\s*\(([^)]*)\)")
resolve_literal_re = re.compile(r'resolve_host_symbol_raw\s*\(\s*"([^"]+)"\s*\)')
host_pthread_def_re = re.compile(r"\bhost_pthread_([a-z0-9_]+)_raw\s*\(")
host_pthread_call_re = re.compile(r"\bhost_pthread_([a-z0-9_]+)\s*\(")
dlvsym_next_re = re.compile(r"\bdlvsym_next\s*\(")
crate_type_re = re.compile(r"crate-type\s*=\s*\[([^\]]*)\]")
source_surface_re = re.compile(
    r"host[- ](?:glibc|libc)|WrapsHostLibc|GlibcCallThrough|"
    r"resolve_host_symbol_(?:raw|cached)|__libc_start_main|__cxa_thread_atexit_impl|"
    r"\b(?:dlopen|dlsym|dlvsym|dlclose|dlinfo)\b|LD_PRELOAD|"
    r"readelf|ldd|objdump|nm -D|BootstrapHostSymbols|HostStdio|HostLibio|"
    r"ThreadSymbolsReady|AllocatorSymbolsReady",
    re.IGNORECASE,
)

allowlist_modules = set(replacement_profile.get("interpose_allowlist", {}).get("modules", []))
allowlist_sentinels = set(
    contract.get("profile_allowlist_policy", {}).get("explicit_sentinels", [])
)
allowlist_real_modules = allowlist_modules - allowlist_sentinels
required_categories = set(contract["required_inventory_categories"])
required_anchor_symbols = set(contract["required_anchor_symbols"])
declared_abi_modules = {path.stem for path in abi_src.rglob("*.rs")}
implicit_allowlist_modules = {"host_resolve"}
source_surfaces = contract.get("source_surfaces", {})
surface_build_scripts = source_surfaces.get("build_scripts", [])
surface_test_roots = source_surfaces.get("test_roots", [])
surface_generated_docs = source_surfaces.get("generated_docs", [])
suppressed_surface_paths = set(
    contract.get("false_positive_suppression", {}).get("self_reference_paths", [])
)
stale_reference_inputs = contract.get("stale_artifact_policy", {}).get(
    "reference_inputs",
    [
        contract["inputs"]["abi_source_dir"],
        "crates/frankenlibc-abi/Cargo.toml",
        "support_matrix.json",
        contract["inputs"]["replacement_profile"],
        contract["inputs"]["replacement_levels"],
    ],
)


def rel(path: Path) -> str:
    return str(path.relative_to(root))


def rel_or_abs(path: Path) -> str:
    return rel(path) if path.is_relative_to(root) else str(path)


def count_braces(line: str) -> int:
    return line.count("{") - line.count("}")


def extract_arg_expr(resolver_kind: str, raw_args: str) -> str:
    parts = [part.strip() for part in raw_args.split(",") if part.strip()]
    if resolver_kind == "cached" and len(parts) >= 2:
        return parts[-1]
    if parts:
        return parts[0]
    return "<unknown>"


def module_name(path: Path) -> str:
    return path.stem


def default_library_for(category: str, symbol: str) -> str:
    if category == "release_dynamic_dependency":
        return symbol if ".so" in symbol else "dynamic-loader"
    if category == "direct_libc_call":
        return "libc"
    if category == "host_pthread_resolver":
        return "libpthread/libc"
    if category == "loader_boundary":
        return "ld-linux/libdl"
    if category == "crt_startup":
        return "host-libc-crt"
    if category == "host_symbol_resolution":
        return "host-libc-symbol-table"
    if category == "static_artifact_configuration":
        return "staticlib-artifact"
    if category == "build_script_host_dependency":
        return "build-script-contract"
    if category == "test_host_oracle_reference":
        return "test-oracle-host-libc"
    if category == "generated_doc_host_dependency":
        return "generated-docs"
    return "unknown"


def profile_for(category: str, module: str, symbol: str) -> tuple[list[str], list[str], str]:
    if category == "release_dynamic_dependency":
        return (["L0", "L1"], ["L2", "L3"], "dynamic_runtime_dependency")
    if category == "static_artifact_configuration":
        return (["L0", "L1"], ["L2", "L3"], "standalone_static_archive_gap")
    if category in {"loader_boundary", "crt_startup", "host_symbol_resolution", "host_pthread_resolver"}:
        return (["L0", "L1"], ["L2", "L3"], "interpose_host_resolution_only")
    if category == "direct_libc_call":
        if module in allowlist_modules or module in implicit_allowlist_modules:
            return (["L0", "L1"], ["L2", "L3"], "interpose_allowlist")
        return ([], ["L0", "L1", "L2", "L3"], "unapproved_source_callthrough")
    if category == "build_script_host_dependency":
        return (["L0", "L1", "L2", "L3"], [], "build_time_contract_reference")
    if category == "test_host_oracle_reference":
        return (["L0", "L1", "L2", "L3"], [], "test_oracle_only")
    if category == "generated_doc_host_dependency":
        return (["L0", "L1", "L2", "L3"], [], "documentation_inventory")
    return (["L0", "L1"], ["L2", "L3"], "inventory_default")


def classify_resolved_symbol(path: Path, symbol: str) -> str:
    if path.name == "startup_abi.rs" or symbol in {"__libc_start_main", "__cxa_thread_atexit_impl"}:
        return "crt_startup"
    if path.name in {"dlfcn_abi.rs", "host_resolve.rs"} or symbol.startswith("dl") or symbol == "_IO_list_all":
        return "loader_boundary"
    return "host_symbol_resolution"


events: list[dict] = []


def add_event(
    *,
    category: str,
    path: Path,
    line: int,
    symbol: str,
    context: str,
    oracle_kind: str,
    expected: str,
    actual: str,
    failure_signature: str = "",
    library: str | None = None,
    extra: dict | None = None,
) -> None:
    module = module_name(path) if path != release_artifact else "release_artifact"
    allowed_levels, blocked_levels, policy = profile_for(category, module, symbol)
    replacement_level = ",".join(allowed_levels + blocked_levels) if (allowed_levels or blocked_levels) else "unclassified"
    artifact_path = rel_or_abs(path)
    row = {
        "trace_id": f"host-dep:{category}:{module}:{line}:{symbol}",
        "bead_id": "bd-bp8fl.6.1",
        "scenario_id": f"{category}:{module}:{symbol}:{line}",
        "runtime_mode": "strict,hardened",
        "replacement_level": replacement_level,
        "api_family": module,
        "symbol": symbol,
        "artifact_path": artifact_path,
        "dependency_kind": category,
        "library": library or default_library_for(category, symbol),
        "oracle_kind": oracle_kind,
        "expected": expected,
        "actual": actual,
        "errno": None,
        "decision_path": "contract>source_scan>profile_policy>inventory",
        "healing_action": None,
        "latency_ns": 0,
        "artifact_refs": [artifact_path, rel(report_path), rel(log_path)],
        "source_commit": source_commit,
        "target_dir": target_dir,
        "failure_signature": failure_signature,
        "timestamp": timestamp,
        "category": category,
        "module": module,
        "path": artifact_path,
        "line": line,
        "context": context,
        "allowed_replacement_levels": allowed_levels,
        "blocked_replacement_levels": blocked_levels,
        "profile_policy": policy,
    }
    if extra:
        row.update(extra)
    events.append(row)


def iter_surface_files(entries: list[str], suffixes: tuple[str, ...]) -> list[Path]:
    files: list[Path] = []
    for entry in entries:
        path = root / entry
        if not path.exists():
            continue
        if path.is_file():
            files.append(path)
            continue
        for child in sorted(path.rglob("*")):
            if child.is_file() and child.suffix in suffixes:
                files.append(child)
    return sorted(set(files))


def should_skip_surface(path: Path) -> bool:
    relpath = rel_or_abs(path)
    return relpath in suppressed_surface_paths


def extract_surface_symbol(text: str) -> str:
    libc_match = direct_libc_re.search(text)
    if libc_match:
        return "libc::" + libc_match.group(1)
    resolver_match = resolve_literal_re.search(text)
    if resolver_match:
        return resolver_match.group(1)
    match = source_surface_re.search(text)
    if match:
        return match.group(0)
    return "host-libc-reference"


def scan_source_surface(paths: list[Path], category: str, oracle_kind: str, expected: str, actual: str) -> None:
    for path in paths:
        if should_skip_surface(path):
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            if category == "test_host_oracle_reference":
                if not direct_libc_re.search(stripped) and not source_surface_re.search(stripped):
                    continue
            elif not source_surface_re.search(stripped):
                continue
            add_event(
                category=category,
                path=path,
                line=lineno,
                symbol=extract_surface_symbol(stripped),
                context=stripped[:160],
                oracle_kind=oracle_kind,
                expected=expected,
                actual=actual,
            )


def newest_reference_input_mtime() -> float:
    newest = 0.0
    suffixes = {".rs", ".toml", ".json", ".map", ".sh", ".md"}
    for entry in stale_reference_inputs:
        path = root / entry
        if not path.exists():
            continue
        if path.is_file():
            newest = max(newest, path.stat().st_mtime)
            continue
        for child in path.rglob("*"):
            if child.is_file() and child.suffix in suffixes:
                newest = max(newest, child.stat().st_mtime)
    return newest


def should_enforce_staleness() -> bool:
    if staleness_mode == "1":
        return True
    if staleness_mode == "0":
        return False
    return require_release and release_artifact.is_relative_to(root / "target")


def check_release_staleness() -> bool:
    if not release_artifact.exists() or not should_enforce_staleness():
        return False
    newest_input = newest_reference_input_mtime()
    if newest_input and release_artifact.stat().st_mtime + 1 < newest_input:
        add_event(
            category="release_dynamic_dependency",
            path=release_artifact,
            line=0,
            symbol=release_artifact.name,
            context="release artifact older than configured source inputs",
            oracle_kind="release_artifact_staleness",
            expected="release artifact mtime is newer than ABI/support inventory inputs",
            actual="stale",
            failure_signature="stale_release_artifact",
            extra={
                "release_artifact_status": "present",
                "release_artifact_mtime": release_artifact.stat().st_mtime,
                "newest_reference_input_mtime": newest_input,
            },
        )
        return True
    return False


def scan_artifact_configuration() -> None:
    if not abi_cargo_toml.exists():
        return
    text = abi_cargo_toml.read_text(encoding="utf-8")
    crate_types: list[str] = []
    match = crate_type_re.search(text)
    if match:
        crate_types = [
            part.strip().strip('"').strip("'")
            for part in match.group(1).split(",")
            if part.strip()
        ]
    for crate_type in crate_types:
        add_event(
            category="static_artifact_configuration",
            path=abi_cargo_toml,
            line=0,
            symbol=f"crate-type:{crate_type}",
            context=f"frankenlibc-abi crate-type includes {crate_type}",
            oracle_kind="cargo_crate_type_scan",
            expected="cdylib present and staticlib gap explicit",
            actual="configured",
        )
    if "staticlib" not in crate_types:
        add_event(
            category="static_artifact_configuration",
            path=abi_cargo_toml,
            line=0,
            symbol="crate-type:staticlib",
            context="frankenlibc-abi does not currently emit a staticlib release artifact",
            oracle_kind="cargo_crate_type_scan",
            expected="staticlib output is either configured or explicitly blocked for standalone promotion",
            actual="not_configured",
            failure_signature="staticlib_not_configured_for_standalone",
        )


scan_artifact_configuration()

for path in sorted(abi_src.rglob("*.rs")):
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    brace_depth = 0
    pending_fn = None
    current_fn = None
    current_fn_base_depth = 0
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped.startswith("//"):
            fn_match = function_re.search(line)
            if fn_match:
                pending_fn = fn_match.group(1)
        new_depth = brace_depth if stripped.startswith("//") else brace_depth + count_braces(line)
        if current_fn is None and pending_fn is not None and new_depth > brace_depth:
            current_fn = pending_fn
            current_fn_base_depth = brace_depth
            pending_fn = None

        if not stripped.startswith("//"):
            for match in resolve_literal_re.finditer(line):
                symbol = match.group(1)
                category = classify_resolved_symbol(path, symbol)
                add_event(
                    category=category,
                    path=path,
                    line=lineno,
                    symbol=symbol,
                    context=stripped[:160],
                    oracle_kind="source_literal_resolver_scan",
                    expected="dependency documented and blocked for L2/L3 unless later allowlisted",
                    actual="host resolver literal reachable",
                    extra={"current_function": current_fn},
                )

            if "resolve_host_symbol_" in line and "fn resolve_host_symbol_" not in stripped:
                literal_seen = bool(resolve_literal_re.search(line))
                call_match = resolve_call_re.search(line)
                if call_match and not literal_seen:
                    resolver_kind = call_match.group(1)
                    symbol_expr = extract_arg_expr(resolver_kind, call_match.group(2))
                    symbol = f"<dynamic:{symbol_expr}>"
                    add_event(
                        category="host_symbol_resolution",
                        path=path,
                        line=lineno,
                        symbol=symbol,
                        context=stripped[:160],
                        oracle_kind=f"source_dynamic_resolver_scan:{resolver_kind}",
                        expected="dynamic host resolver dependency documented",
                        actual="dynamic host resolver reachable",
                        extra={"current_function": current_fn, "resolver_kind": resolver_kind},
                    )

            for match in direct_libc_re.finditer(line):
                symbol = match.group(1)
                if symbol == "syscall":
                    continue
                add_event(
                    category="direct_libc_call",
                    path=path,
                    line=lineno,
                    symbol=symbol,
                    context=stripped[:160],
                    oracle_kind="source_direct_libc_call_scan",
                    expected="direct host libc call documented and classified by replacement profile",
                    actual="direct libc call expression reachable",
                    extra={"current_function": current_fn},
                )

            for match in host_pthread_def_re.finditer(line):
                pthread_name = match.group(1)
                symbol = "pthread_" + pthread_name
                add_event(
                    category="host_pthread_resolver",
                    path=path,
                    line=lineno,
                    symbol=symbol,
                    context=stripped[:160],
                    oracle_kind="source_host_pthread_resolver_scan",
                    expected="host pthread resolver documented as interpose-only",
                    actual="host pthread raw resolver defined",
                    extra={"current_function": current_fn},
                )

            if "fn host_pthread_" not in stripped:
                for match in host_pthread_call_re.finditer(line):
                    pthread_name = match.group(1)
                    if pthread_name.endswith("_sym"):
                        continue
                    symbol = "pthread_" + pthread_name
                    add_event(
                        category="host_pthread_resolver",
                        path=path,
                        line=lineno,
                        symbol=symbol,
                        context=stripped[:160],
                        oracle_kind="source_host_pthread_call_scan",
                        expected="host pthread call documented as interpose-only",
                        actual="host pthread wrapper call reachable",
                        extra={"current_function": current_fn},
                    )

            if dlvsym_next_re.search(line):
                add_event(
                    category="loader_boundary",
                    path=path,
                    line=lineno,
                    symbol="dlvsym_next",
                    context=stripped[:160],
                    oracle_kind="source_loader_boundary_scan",
                    expected="loader boundary dependency documented and blocked for standalone levels",
                    actual="dlvsym_next loader resolver reachable",
                    extra={"current_function": current_fn},
                )

        if current_fn is not None and new_depth <= current_fn_base_depth:
            current_fn = None
        brace_depth = new_depth

scan_source_surface(
    iter_surface_files(surface_build_scripts, (".rs",)),
    "build_script_host_dependency",
    "build_script_surface_scan",
    "build scripts document host dependency assumptions without introducing runtime call-through claims",
    "host dependency contract reference present",
)
scan_source_surface(
    iter_surface_files(surface_test_roots, (".rs", ".c", ".sh", ".json", ".md")),
    "test_host_oracle_reference",
    "test_oracle_surface_scan",
    "tests may reference host libc only as oracle or fixture setup, not as release-artifact support",
    "test host-libc oracle/reference present",
)
scan_source_surface(
    iter_surface_files(surface_generated_docs, (".md", ".json")),
    "generated_doc_host_dependency",
    "generated_doc_surface_scan",
    "generated docs and checked-in planning artifacts state host dependency limits explicitly",
    "documentation host dependency reference present",
)


def add_release_missing() -> None:
    add_event(
        category="release_dynamic_dependency",
        path=release_artifact,
        line=0,
        symbol="libfrankenlibc_abi.so",
        context="release artifact not present during source-only inventory run",
        oracle_kind="release_artifact_presence",
        expected="target/release/libfrankenlibc_abi.so exists when FRANKENLIBC_REQUIRE_RELEASE_ARTIFACT=1",
        actual="missing",
        failure_signature="release_artifact_missing" if require_release else "",
        extra={"release_artifact_status": "missing"},
    )


release_status = "missing"
release_stale = False
if release_artifact.exists():
    release_status = "present"
    release_stale = check_release_staleness()
    readelf = subprocess.run(
        ["readelf", "-d", str(release_artifact)],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if readelf.returncode == 0:
        for idx, line in enumerate(readelf.stdout.splitlines(), start=1):
            needed = re.search(r"\(NEEDED\).*Shared library: \[([^\]]+)\]", line)
            if needed:
                add_event(
                    category="release_dynamic_dependency",
                    path=release_artifact,
                    line=idx,
                    symbol=needed.group(1),
                    context=line.strip(),
                    oracle_kind="readelf_dynamic_needed",
                    expected="dynamic dependency documented",
                    actual="needed",
                    library=needed.group(1),
                    extra={"release_artifact_status": "present", "tool": "readelf -d"},
                )
    else:
        add_event(
            category="release_dynamic_dependency",
            path=release_artifact,
            line=0,
            symbol="readelf",
            context=readelf.stderr.strip()[:160],
            oracle_kind="readelf_dynamic_needed",
            expected="readelf succeeds",
            actual="readelf_failed",
            failure_signature="readelf_failed",
            extra={"release_artifact_status": "present"},
        )

    objdump = subprocess.run(
        ["objdump", "-p", str(release_artifact)],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if objdump.returncode == 0:
        for idx, line in enumerate(objdump.stdout.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("NEEDED "):
                library = stripped.split(None, 1)[1].strip()
                add_event(
                    category="release_dynamic_dependency",
                    path=release_artifact,
                    line=idx,
                    symbol=library,
                    context=stripped,
                    oracle_kind="objdump_dynamic_needed",
                    expected="dynamic dependency documented",
                    actual="needed",
                    library=library,
                    extra={"release_artifact_status": "present", "tool": "objdump -p"},
                )
    else:
        add_event(
            category="release_dynamic_dependency",
            path=release_artifact,
            line=0,
            symbol="objdump",
            context=objdump.stderr.strip()[:160],
            oracle_kind="objdump_dynamic_needed",
            expected="objdump succeeds",
            actual="objdump_failed",
            failure_signature="objdump_failed",
            extra={"release_artifact_status": "present"},
        )

    ldd = subprocess.run(
        ["ldd", str(release_artifact)],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if ldd.returncode == 0:
        for idx, line in enumerate(ldd.stdout.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            if "=>" in stripped:
                library = stripped.split("=>", 1)[0].strip()
            else:
                library = stripped.split(None, 1)[0].strip()
            if not library or library.startswith("statically"):
                continue
            add_event(
                category="release_dynamic_dependency",
                path=release_artifact,
                line=idx,
                symbol=library,
                context=stripped[:160],
                oracle_kind="ldd_runtime_dependency",
                expected="runtime loader dependency documented",
                actual="needed",
                library=library,
                extra={"release_artifact_status": "present", "tool": "ldd"},
            )
    else:
        add_event(
            category="release_dynamic_dependency",
            path=release_artifact,
            line=0,
            symbol="ldd",
            context=ldd.stderr.strip()[:160],
            oracle_kind="ldd_runtime_dependency",
            expected="ldd succeeds",
            actual="ldd_failed",
            failure_signature="ldd_failed",
            extra={"release_artifact_status": "present"},
        )

    nm = subprocess.run(
        ["nm", "-D", "--undefined-only", str(release_artifact)],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if nm.returncode == 0:
        for idx, line in enumerate(nm.stdout.splitlines(), start=1):
            parts = line.strip().split()
            if not parts:
                continue
            symbol = parts[-1]
            if symbol:
                add_event(
                    category="release_dynamic_dependency",
                    path=release_artifact,
                    line=idx,
                    symbol=symbol,
                    context=line.strip()[:160],
                    oracle_kind="nm_dynamic_undefined",
                    expected="undefined dynamic symbol documented",
                    actual="undefined",
                    library="dynamic-loader",
                    extra={"release_artifact_status": "present", "tool": "nm -D --undefined-only"},
                )
    else:
        add_event(
            category="release_dynamic_dependency",
            path=release_artifact,
            line=0,
            symbol="nm",
            context=nm.stderr.strip()[:160],
            oracle_kind="nm_dynamic_undefined",
            expected="nm succeeds",
            actual="nm_failed",
            failure_signature="nm_failed",
            extra={"release_artifact_status": "present"},
        )
else:
    add_release_missing()

events.sort(key=lambda row: (row["category"], row["path"], row["line"], row["symbol"]))

categories_seen = {row["category"] for row in events}
symbols_seen = {row["symbol"] for row in events}
direct_call_modules_seen = {
    row["module"] for row in events if row["category"] == "direct_libc_call"
}
unapproved_callthroughs = [
    row for row in events if row["profile_policy"] == "unapproved_source_callthrough"
]
unresolved_allowlist_modules = sorted(allowlist_real_modules - declared_abi_modules)
errors: list[str] = []
missing_categories = sorted(required_categories - categories_seen)
missing_anchor_symbols = sorted(required_anchor_symbols - symbols_seen)
if missing_categories:
    errors.append(f"missing inventory categories: {missing_categories}")
if missing_anchor_symbols:
    errors.append(f"missing required anchor symbols: {missing_anchor_symbols}")
if unresolved_allowlist_modules:
    errors.append(f"interpose allowlist names missing ABI modules: {unresolved_allowlist_modules}")
if unapproved_callthroughs:
    sample = [
        f"{row['path']}:{row['line']}:{row['symbol']}"
        for row in unapproved_callthroughs[:10]
    ]
    errors.append(f"unapproved source callthroughs: {sample}")
if require_release and not release_artifact.exists():
    errors.append("release artifact missing while FRANKENLIBC_REQUIRE_RELEASE_ARTIFACT=1")
if release_stale and should_enforce_staleness():
    errors.append("release artifact stale relative to configured source inputs")

required_log_fields = set(contract["required_log_fields"])
for idx, row in enumerate(events[:20]):
    missing = sorted(required_log_fields - set(row))
    if missing:
        errors.append(f"log row {idx} missing required fields: {missing}")
        break

category_counts = Counter(row["category"] for row in events)
policy_counts = Counter(row["profile_policy"] for row in events)
module_counts = Counter(row["module"] for row in events)
oracle_counts = Counter(row["oracle_kind"] for row in events)
library_counts = Counter(row["library"] for row in events)
dynamic_audit_tools_seen = sorted(
    {
        row.get("tool")
        for row in events
        if row["category"] == "release_dynamic_dependency" and row.get("tool")
    }
)
surface_category_counts = {
    category: category_counts.get(category, 0)
    for category in [
        "build_script_host_dependency",
        "test_host_oracle_reference",
        "generated_doc_host_dependency",
    ]
}
l2_l3_blockers = [
    row
    for row in events
    if "L2" in row.get("blocked_replacement_levels", [])
    or "L3" in row.get("blocked_replacement_levels", [])
]
negative_claim_results: list[dict] = []


def add_negative_claim_result(
    claim_id: str,
    *,
    blocked: bool,
    evidence_count: int,
    guard_status: str,
    failure_signature: str = "",
) -> None:
    negative_claim_results.append(
        {
            "id": claim_id,
            "status": "blocked_by_inventory" if blocked else guard_status,
            "evidence_count": evidence_count,
            "failure_signature": failure_signature,
        }
    )


host_resolution_blockers = [
    row
    for row in l2_l3_blockers
    if row["category"] in {"host_symbol_resolution", "loader_boundary", "host_pthread_resolver"}
]
startup_blockers = [row for row in l2_l3_blockers if row["category"] == "crt_startup"]
release_dependency_rows = [
    row for row in events if row["category"] == "release_dynamic_dependency"
]
add_negative_claim_result(
    "neg-l2-host-symbol-resolution",
    blocked=bool(host_resolution_blockers),
    evidence_count=len(host_resolution_blockers),
    guard_status="claim_not_blocked",
)
add_negative_claim_result(
    "neg-l3-dynamic-glibc-needed",
    blocked=bool(release_dependency_rows),
    evidence_count=len(release_dependency_rows),
    guard_status="claim_not_blocked",
    failure_signature="release_artifact_missing" if release_status == "missing" else "",
)
add_negative_claim_result(
    "neg-startup-host-delegation",
    blocked=bool(startup_blockers),
    evidence_count=len(startup_blockers),
    guard_status="claim_not_blocked",
)
add_negative_claim_result(
    "neg-unapproved-interpose-callthrough",
    blocked=bool(unapproved_callthroughs),
    evidence_count=len(unapproved_callthroughs),
    guard_status="guard_clean",
    failure_signature="unapproved_source_callthrough" if unapproved_callthroughs else "",
)

claim_not_blocked = [
    row["id"] for row in negative_claim_results if row["status"] == "claim_not_blocked"
]
if claim_not_blocked:
    errors.append(f"negative claim guard did not block: {claim_not_blocked}")

by_symbol = defaultdict(int)
for row in events:
    by_symbol[(row["category"], row["symbol"])] += 1

log_path.write_text(
    "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in events),
    encoding="utf-8",
)

report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.6.1",
    "status": "pass" if not errors else "fail",
    "source_commit": source_commit,
    "generated_at": timestamp,
    "inputs": contract["inputs"],
    "artifact_refs": [
        rel(contract_path),
        rel(report_path),
        rel(log_path),
        rel(release_artifact) if release_artifact.is_relative_to(root) else str(release_artifact),
    ],
    "release_artifact": {
        "path": rel(release_artifact) if release_artifact.is_relative_to(root) else str(release_artifact),
        "status": release_status,
        "required": require_release,
        "staleness_enforced": should_enforce_staleness(),
        "stale": release_stale,
    },
    "summary": {
        "inventory_event_count": len(events),
        "category_counts": dict(sorted(category_counts.items())),
        "dependency_counts_by_category": dict(sorted(category_counts.items())),
        "module_counts": dict(sorted(module_counts.items())),
        "policy_counts": dict(sorted(policy_counts.items())),
        "oracle_counts": dict(sorted(oracle_counts.items())),
        "library_counts": dict(sorted(library_counts.items())),
        "source_surface_counts": surface_category_counts,
        "dynamic_audit_tools_seen": dynamic_audit_tools_seen,
        "l2_l3_blocker_count": len(l2_l3_blockers),
        "unapproved_direct_libc_call_count": len(unapproved_callthroughs),
        "required_categories_seen": sorted(required_categories & categories_seen),
        "required_anchor_symbols_seen": sorted(required_anchor_symbols & symbols_seen),
        "direct_call_modules_seen": sorted(direct_call_modules_seen),
        "allowlist_modules_seen": sorted(direct_call_modules_seen & allowlist_modules),
        "implicit_allowlist_modules_seen": sorted(direct_call_modules_seen & implicit_allowlist_modules),
        "unused_interpose_allowlist_modules": sorted(allowlist_real_modules - direct_call_modules_seen),
        "unresolved_allowlist_modules": unresolved_allowlist_modules,
    },
    "negative_claim_results": negative_claim_results,
    "top_blockers": [
        {
            "category": row["category"],
            "module": row["module"],
            "symbol": row["symbol"],
            "path": row["path"],
            "line": row["line"],
            "blocked_replacement_levels": row["blocked_replacement_levels"],
            "profile_policy": row["profile_policy"],
        }
        for row in l2_l3_blockers[:40]
    ],
    "l2_l3_blockers": [
        {
            "category": row["category"],
            "module": row["module"],
            "symbol": row["symbol"],
            "library": row["library"],
            "artifact_path": row["artifact_path"],
            "line": row["line"],
            "blocked_replacement_levels": row["blocked_replacement_levels"],
            "profile_policy": row["profile_policy"],
            "failure_signature": row["failure_signature"],
        }
        for row in l2_l3_blockers[:200]
    ],
    "symbol_counts": [
        {
            "category": category,
            "symbol": symbol,
            "count": count,
        }
        for (category, symbol), count in sorted(by_symbol.items(), key=lambda item: (-item[1], item[0][0], item[0][1]))[:80]
    ],
    "replacement_level_contract": contract["replacement_levels"],
    "replacement_profile_summary": {
        "interpose_allowlist_modules": sorted(allowlist_modules),
        "interpose_allowlist_sentinels": sorted(allowlist_sentinels),
        "implicit_allowlist_modules": sorted(implicit_allowlist_modules),
        "replacement_level_count": len(replacement_levels.get("levels", replacement_levels)),
    },
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

print(json.dumps(report, indent=2, sort_keys=True))
if errors:
    raise SystemExit(1)
PY
