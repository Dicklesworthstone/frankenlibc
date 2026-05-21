#!/usr/bin/env python3
"""Generate the bd-smp21.1 host-delegation census artifact.

The census is source-derived and deterministic: it scans ABI Rust sources for
host resolver/delegate primitives, then propagates those through local helper
calls to exported ABI entrypoints.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "host_delegation_census.v1"
BEAD_ID = "bd-smp21.1"
DETECTOR_VERSION = 2

REQUIRED_ANCHORS = [
    "__libc_start_main",
    "dladdr",
    "dlclose",
    "dl_iterate_phdr",
    "dlopen",
    "dlsym",
    "pthread_create",
    "pthread_detach",
    "pthread_join",
]

THREAD_RAW_SYMBOLS = {
    "cancel": "pthread_cancel",
    "clockjoin_np": "pthread_clockjoin_np",
    "condattr_getclock": "pthread_condattr_getclock",
    "create": "pthread_create",
    "detach": "pthread_detach",
    "equal": "pthread_equal",
    "exit": "pthread_exit",
    "join": "pthread_join",
    "self": "pthread_self",
    "setcancelstate": "pthread_setcancelstate",
    "setcanceltype": "pthread_setcanceltype",
    "testcancel": "pthread_testcancel",
    "timedjoin_np": "pthread_timedjoin_np",
    "tryjoin_np": "pthread_tryjoin_np",
}

FUNCTION_RE = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
CALL_RE = re.compile(r"(?<![\w.])([A-Za-z_][A-Za-z0-9_]*)\s*\(")
RAW_LITERAL_RE = re.compile(r'resolve_host_symbol_raw\s*\(\s*"([^"]+)"')
RAW_DYNAMIC_RE = re.compile(r"resolve_host_symbol_raw\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)")
CACHED_LITERAL_RE = re.compile(r'resolve_host_symbol_cached\s*\([^,]+,\s*"([^"]+)"')
RESOLVED_THREAD_RE = re.compile(r"\bresolved_thread_([A-Za-z0-9_]+)_raw\s*\(")
BROADER_REFERENCE_RE = re.compile(
    r"resolve_host_symbol_|delegate_to_host_|resolved_thread_|host_pthread_|"
    r"host_dlsym|host_dlvsym|dlvsym_next|host_dl_iterate_phdr_cached|"
    r"host_dladdr_cached|FallbackHost|HostDelegateUnavailable"
)


@dataclass(frozen=True)
class HostCall:
    path: str
    line: int
    function: str
    delegation_kind: str
    host_symbol: str
    expression: str
    evidence: str


@dataclass
class FunctionInfo:
    name: str
    path: Path
    start_line: int
    body_start_line: int
    signature: str
    attr_text: str
    lines: list[tuple[int, str]] = field(default_factory=list)

    @property
    def module(self) -> str:
        return self.path.stem

    @property
    def is_exported_abi(self) -> bool:
        signature = self.signature
        attrs = self.attr_text
        return (
            'extern "C"' in signature
            and ("no_mangle" in attrs or signature.lstrip().startswith("pub "))
        )


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_tree_sha256(files: list[Path], root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(rel(root, path).encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def parse_functions(path: Path) -> list[FunctionInfo]:
    text = path.read_text(encoding="utf-8")
    rows = text.splitlines()
    functions: list[FunctionInfo] = []
    idx = 0
    while idx < len(rows):
        line = rows[idx]
        match = FUNCTION_RE.search(line)
        if not match:
            idx += 1
            continue

        attr_start = idx
        while attr_start > 0:
            prev = rows[attr_start - 1].strip()
            if prev.startswith("#[") or prev.startswith("///") or prev == "":
                attr_start -= 1
                continue
            break
        attrs = "\n".join(rows[attr_start:idx])
        signature_lines: list[str] = []
        brace_balance = 0
        end_idx = idx
        seen_open = False
        body_start_line = idx + 1
        while end_idx < len(rows):
            current = rows[end_idx]
            signature_lines.append(current)
            if "{" in current and not seen_open:
                seen_open = True
                body_start_line = end_idx + 1
            brace_balance += current.count("{") - current.count("}")
            if seen_open:
                break
            end_idx += 1

        function = FunctionInfo(
            name=match.group(1),
            path=path,
            start_line=idx + 1,
            body_start_line=body_start_line,
            signature="\n".join(signature_lines),
            attr_text=attrs,
        )
        while end_idx < len(rows):
            current = rows[end_idx]
            if end_idx != body_start_line - 1:
                brace_balance += current.count("{") - current.count("}")
            function.lines.append((end_idx + 1, current))
            if seen_open and brace_balance <= 0:
                break
            end_idx += 1

        functions.append(function)
        idx = max(end_idx + 1, idx + 1)
    return functions


def strip_comments(line: str) -> str:
    return line.split("//", 1)[0]


def detect_host_calls(function: FunctionInfo, root: Path) -> list[HostCall]:
    calls: list[HostCall] = []
    path = rel(root, function.path)
    for line_no, raw_line in function.lines:
        if line_no < function.body_start_line:
            continue
        line = strip_comments(raw_line)
        if not line.strip():
            continue
        for symbol in RAW_LITERAL_RE.findall(line):
            calls.append(
                HostCall(
                    path=path,
                    line=line_no,
                    function=function.name,
                    delegation_kind="resolve_host_symbol_raw_literal",
                    host_symbol=symbol,
                    expression=line.strip(),
                    evidence=f"{path}:{line_no}",
                )
            )
        for symbol in CACHED_LITERAL_RE.findall(line):
            calls.append(
                HostCall(
                    path=path,
                    line=line_no,
                    function=function.name,
                    delegation_kind="resolve_host_symbol_cached_literal",
                    host_symbol=symbol,
                    expression=line.strip(),
                    evidence=f"{path}:{line_no}",
                )
            )
        if RAW_DYNAMIC_RE.search(line):
            calls.append(
                HostCall(
                    path=path,
                    line=line_no,
                    function=function.name,
                    delegation_kind="resolve_host_symbol_raw_dynamic",
                    host_symbol="<dynamic>",
                    expression=line.strip(),
                    evidence=f"{path}:{line_no}",
                )
            )
        for thread_key in RESOLVED_THREAD_RE.findall(line):
            calls.append(
                HostCall(
                    path=path,
                    line=line_no,
                    function=function.name,
                    delegation_kind="resolved_thread_raw_accessor",
                    host_symbol=THREAD_RAW_SYMBOLS.get(thread_key, f"pthread_{thread_key}"),
                    expression=line.strip(),
                    evidence=f"{path}:{line_no}",
                )
            )
        static_needles = [
            ("delegate_to_host_libc_start_main", "__libc_start_main", "startup_host_delegate"),
            ("host_dlsym(", "dlsym", "host_dlsym_helper"),
            ("host_dlvsym(", "dlvsym", "host_dlvsym_helper"),
            ("dlvsym_next(", "dlvsym", "rtld_next_host_dlvsym"),
            ("host_dl_iterate_phdr_cached(", "dl_iterate_phdr", "cached_host_loader_symbol"),
            ("host_dladdr_cached(", "dladdr", "cached_host_loader_symbol"),
            ("host_malloc_raw(", "malloc", "cached_host_allocator_symbol"),
            ("host_calloc_raw(", "calloc", "cached_host_allocator_symbol"),
            ("host_realloc_raw(", "realloc", "cached_host_allocator_symbol"),
            ("host_free_raw(", "free", "cached_host_allocator_symbol"),
            ("host_errno_location_raw(", "__errno_location", "cached_host_errno_symbol"),
        ]
        for needle, host_symbol, kind in static_needles:
            if needle in line:
                calls.append(
                    HostCall(
                        path=path,
                        line=line_no,
                        function=function.name,
                        delegation_kind=kind,
                        host_symbol=host_symbol,
                        expression=line.strip(),
                        evidence=f"{path}:{line_no}",
                    )
                )
    return calls


def direct_function_calls(function: FunctionInfo, known_functions: set[str]) -> set[str]:
    called = set()
    for _line_no, raw_line in function.lines:
        for candidate in CALL_RE.findall(strip_comments(raw_line)):
            if candidate in known_functions and candidate != function.name:
                called.add(candidate)
    return called


def alias_callsites(function: FunctionInfo, targets: set[str], root: Path) -> list[HostCall]:
    calls: list[HostCall] = []
    path = rel(root, function.path)
    for line_no, raw_line in function.lines:
        if line_no < function.body_start_line:
            continue
        line = strip_comments(raw_line)
        for target in sorted(targets):
            if re.search(rf"(?<![\w.]){re.escape(target)}\s*\(", line):
                calls.append(
                    HostCall(
                        path=path,
                        line=line_no,
                        function=function.name,
                        delegation_kind="alias_to_host_delegating_symbol",
                        host_symbol=target,
                        expression=line.strip(),
                        evidence=f"{path}:{line_no}",
                    )
                )
    return calls


def host_reaching_functions(
    direct_host_calls: dict[str, list[HostCall]],
    call_graph: dict[str, set[str]],
) -> set[str]:
    reaching = {name for name, calls in direct_host_calls.items() if calls}
    changed = True
    while changed:
        changed = False
        for name, callees in call_graph.items():
            if name in reaching:
                continue
            if callees & reaching:
                reaching.add(name)
                changed = True
    return reaching


def reachable_host_helpers(
    start: str,
    call_graph: dict[str, set[str]],
    host_reaching: set[str],
) -> set[str]:
    reachable: set[str] = set()
    stack = list(call_graph.get(start, set()) & host_reaching)
    while stack:
        name = stack.pop()
        if name in reachable or name == start:
            continue
        reachable.add(name)
        stack.extend(call_graph.get(name, set()) & host_reaching)
    return reachable


def broader_references(source_files: list[Path], root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in source_files:
        for line_no, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            text = raw_line.strip()
            if not text or not BROADER_REFERENCE_RE.search(text):
                continue
            rows.append(
                {
                    "path": rel(root, path),
                    "line": line_no,
                    "module": path.stem,
                    "evidence": f"{rel(root, path)}:{line_no}",
                    "text": text,
                }
            )
    return rows


def build_payload(root: Path, abi_source_dir: Path) -> dict[str, Any]:
    source_files = sorted(abi_source_dir.glob("*.rs"))
    functions: list[FunctionInfo] = []
    for path in source_files:
        functions.extend(parse_functions(path))

    function_by_name = {function.name: function for function in functions}
    known_functions = set(function_by_name)
    direct_host_calls = {
        function.name: detect_host_calls(function, root) for function in functions
    }
    call_graph = {
        function.name: direct_function_calls(function, known_functions) for function in functions
    }

    symbol_rows: list[dict[str, Any]] = []
    all_calls: list[dict[str, Any]] = []
    exported_functions = [function for function in functions if function.is_exported_abi]
    host_reaching = host_reaching_functions(direct_host_calls, call_graph)
    expanded_calls: dict[str, list[HostCall]] = {}
    for function in exported_functions:
        calls = list(direct_host_calls[function.name])
        helper_names = reachable_host_helpers(function.name, call_graph, host_reaching)
        caller_names = {function.name, *helper_names}
        for caller_name in sorted(
            caller_names,
            key=lambda name: (
                rel(root, function_by_name[name].path),
                function_by_name[name].start_line,
                name,
            ),
        ):
            caller = function_by_name[caller_name]
            alias_targets = call_graph.get(caller_name, set()) & host_reaching
            if caller_name == function.name:
                alias_targets.discard(function.name)
            calls.extend(alias_callsites(caller, alias_targets, root))
        for target in sorted(
            helper_names,
            key=lambda name: (
                rel(root, function_by_name[name].path),
                function_by_name[name].start_line,
                name,
            ),
        ):
            calls.extend(direct_host_calls[target])
        if calls:
            expanded_calls[function.name] = calls

    for function in sorted(exported_functions, key=lambda item: (rel(root, item.path), item.start_line)):
        calls = expanded_calls.get(function.name, [])
        if not calls:
            continue
        host_symbols = sorted({call.host_symbol for call in calls})
        kinds = sorted({call.delegation_kind for call in calls})
        callsite_ids = []
        for idx, call in enumerate(calls, 1):
            callsite_id = f"{function.module}:{function.name}:{function.start_line}:{idx:03d}"
            callsite_ids.append(callsite_id)
            all_calls.append(
                {
                    "id": callsite_id,
                    "exported_symbol": function.name,
                    "module": function.module,
                    "path": call.path,
                    "line": call.line,
                    "helper_function": call.function,
                    "delegation_kind": call.delegation_kind,
                    "host_symbol": call.host_symbol,
                    "expression": call.expression,
                    "evidence": call.evidence,
                }
            )
        symbol_rows.append(
            {
                "symbol": function.name,
                "module": function.module,
                "source": f"{rel(root, function.path)}:{function.start_line}",
                "host_symbols": host_symbols,
                "delegation_kinds": kinds,
                "callsite_count": len(calls),
                "callsite_ids": callsite_ids,
            }
        )

    symbol_rows.sort(key=lambda row: (row["module"], row["symbol"]))
    all_calls.sort(key=lambda row: (row["module"], row["exported_symbol"], row["id"]))
    module_counts: dict[str, int] = {}
    for row in symbol_rows:
        module_counts[row["module"]] = module_counts.get(row["module"], 0) + 1
    required_anchor_rows = [
        {
            "symbol": symbol,
            "present": any(row["symbol"] == symbol for row in symbol_rows),
        }
        for symbol in REQUIRED_ANCHORS
    ]
    source_refs = broader_references(source_files, root)

    return {
        "schema_version": SCHEMA_VERSION,
        "bead": BEAD_ID,
        "description": "Source-derived census of exported ABI symbols whose default path reaches host libc/dynamic-loader resolver or delegate primitives.",
        "detector": {
            "version": DETECTOR_VERSION,
            "abi_source_dir": rel(root, abi_source_dir),
            "source_file_count": len(source_files),
            "source_tree_sha256": source_tree_sha256(source_files, root),
        },
        "policy": {
            "required_anchor_symbols": REQUIRED_ANCHORS,
            "host_delegation_needles": [
                "resolve_host_symbol_raw",
                "resolve_host_symbol_cached",
                "resolved_thread_*_raw",
                "delegate_to_host_libc_start_main",
                "host_dlsym",
                "host_dlvsym",
                "host_dl_iterate_phdr_cached",
                "host_dladdr_cached",
            ],
        },
        "summary": {
            "exported_symbol_count": sum(1 for function in functions if function.is_exported_abi),
            "host_delegating_symbol_count": len(symbol_rows),
            "host_delegation_callsite_count": len(all_calls),
            "broader_source_reference_count": len(source_refs),
            "module_count": len(module_counts),
            "required_anchor_count": len(REQUIRED_ANCHORS),
            "required_anchor_present_count": sum(1 for row in required_anchor_rows if row["present"]),
        },
        "module_census": [
            {"module": module, "host_delegating_symbol_count": count}
            for module, count in sorted(module_counts.items())
        ],
        "required_anchor_symbols": required_anchor_rows,
        "symbol_census": symbol_rows,
        "callsite_census": all_calls,
        "broader_source_references": source_refs,
        "source_file_hashes": [
            {"path": rel(root, path), "sha256": file_sha256(path)} for path in source_files
        ],
    }


def canonical(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def main() -> int:
    root = repo_root()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--abi-source-dir",
        type=Path,
        default=root / "crates/frankenlibc-abi/src",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=root / "tests/conformance/host_delegation_census.v1.json",
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    abi_source_dir = args.abi_source_dir
    if not abi_source_dir.is_absolute():
        abi_source_dir = root / abi_source_dir
    output = args.output
    if not output.is_absolute():
        output = root / output

    payload = build_payload(root, abi_source_dir)
    if args.check:
        if not output.exists():
            print(f"FAIL: missing artifact {output}")
            return 1
        existing = json.loads(output.read_text(encoding="utf-8"))
        if canonical(existing) != canonical(payload):
            print(f"FAIL: {output} is stale; regenerate with:")
            print(f"  scripts/generate_host_delegation_census.py --output {output.relative_to(root)}")
            return 1
        print(
            "PASS: host delegation census current "
            f"(symbols={payload['summary']['host_delegating_symbol_count']}, "
            f"callsites={payload['summary']['host_delegation_callsite_count']})"
        )
        return 0

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"Wrote {output.relative_to(root)} "
        f"(symbols={payload['summary']['host_delegating_symbol_count']}, "
        f"callsites={payload['summary']['host_delegation_callsite_count']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
