#!/usr/bin/env python3
"""generate_support_matrix_maintenance.py — bd-3g4p

Automated support matrix maintenance: validates that the implementation
status of each symbol in support_matrix.json matches code reality and
links symbols to conformance fixture coverage.

Three validation passes:
  1. STATUS VALIDATION: Code patterns match declared status.
  2. CONFORMANCE LINKAGE: Symbols linked to fixture test cases.
  3. COVERAGE REPORT: Per-module and per-status coverage statistics.

Outputs a JSON maintenance report to stdout (or --output file).
"""
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
MATRIX_PATH = REPO_ROOT / "support_matrix.json"
ABI_SRC = REPO_ROOT / "crates" / "frankenlibc-abi" / "src"
FIXTURE_DIR = REPO_ROOT / "tests" / "conformance" / "fixtures"
CONFORMANCE_MATRIX_PATH = REPO_ROOT / "tests" / "conformance" / "conformance_matrix.v1.json"
HOST_DELEGATION_CENSUS_PATH = (
    REPO_ROOT / "tests" / "conformance" / "host_delegation_census.v1.json"
)
PROMOTION_PROOF_MANIFEST_PATHS = (
    REPO_ROOT / "tests" / "conformance" / "math_abi_promotion_tranche.v1.json",
    REPO_ROOT / "tests" / "conformance" / "err_abi_promotion_tranche.v1.json",
    REPO_ROOT / "tests" / "conformance" / "locale_abi_promotion_tranche.v1.json",
    REPO_ROOT / "tests" / "conformance" / "iconv_locale_bootstrap_promotion_tranche.v1.json",
    REPO_ROOT / "tests" / "conformance" / "search_abi_promotion_tranche.v1.json",
    REPO_ROOT / "tests" / "conformance" / "resolv_abi_promotion_tranche.v1.json",
    REPO_ROOT / "tests" / "conformance" / "dirent_abi_promotion_tranche.v1.json",
    REPO_ROOT / "tests" / "conformance" / "grp_abi_promotion_tranche.v1.json",
    REPO_ROOT / "tests" / "conformance" / "pwd_abi_promotion_tranche.v1.json",
    REPO_ROOT / "tests" / "conformance" / "pwd_gshadow_abi_promotion_tranche.v1.json",
    REPO_ROOT / "tests" / "conformance" / "inet_abi_promotion_tranche.v1.json",
    REPO_ROOT / "tests" / "conformance" / "setjmp_abi_promotion_tranche.v1.json",
    REPO_ROOT / "tests" / "conformance" / "pthread_mutex_abi_promotion_tranche.v1.json",
    REPO_ROOT / "tests" / "conformance" / "c11threads_abi_promotion_tranche.v1.json",
    REPO_ROOT / "tests" / "conformance" / "stdio_abi_promotion_tranche.v1.json",
    REPO_ROOT / "tests" / "conformance" / "wchar_abi_promotion_tranche.v1.json",
    REPO_ROOT / "tests" / "conformance" / "string_abi_promotion_tranche.v1.json",
    REPO_ROOT / "tests" / "conformance" / "fortify_abi_promotion_tranche.v1.json",
    REPO_ROOT / "tests" / "conformance" / "unistd_abi_promotion_tranche.v1.json",
    REPO_ROOT / "tests" / "conformance" / "rpc_abi_promotion_tranche.v1.json",
    REPO_ROOT / "tests" / "conformance" / "glibc_internal_abi_promotion_tranche.v1.json",
)
HIGH_IMPACT_RATCHET_MODULES = (
    "math_abi",
    "glibc_internal_abi",
    "unistd_abi",
    "rpc_abi",
    "stdlib_abi",
    "wchar_abi",
    "fortify_abi",
    "stdio_abi",
)
ACCEPTED_PROMOTION_PROOF_CLASSIFICATIONS = {
    "native-libm-with-errno-bridge",
    "native-err-formatting-with-runtime-io-bridge",
    "native-locale-catalog-with-errno-bridge",
    "native-iconv-locale-bootstrap-with-errno-bridge",
    "native-search-hash-table-with-errno-bridge",
    "native-protocol-database-with-errno-bridge",
    "native-dirent64-alias-with-errno-bridge",
    "native-group-files-with-errno-bridge",
    "native-passwd-files-with-errno-bridge",
    "native-gshadow-files-with-sys-read-errno-bridge",
    "native-interface-index-ioctl-with-errno-bridge",
    "native-setjmp-phase1-with-errno-bridges",
    "native-pthread-mutex-futex-core-with-errno-bridge",
    "native-c11threads-pthread-abi-bridge",
    "native-stdio-scanf-libio-registry-with-errno-bridge",
    "native-wchar-isoc-libio-codec-allocator-bridge",
    "native-string-conversion-argz-envz-glob-regex-allocator-errno-bridge",
    "native-fortify-wrapper-libio-allocator-errno-bridge",
    "native-unistd-stackfail-lfs-wchar-stream-locale-sem-syslog-process-getopt-errno-bridge",
    "native-rpc-xdr-netname-allocator-errno-bridge",
    "native-glibc-internal-clone-errno-bridge",
}

# Patterns indicating actual host libc call expressions.
# Type/constant references like `libc::timex` or `libc::EINVAL` are not calls.
LIBC_CALL_PATTERN = re.compile(r'\blibc::(\w+)\s*\(')
# Patterns indicating explicit host delegation inside ABI bodies.
WRAPS_HOST_LIBC_PATTERN = re.compile(
    r'(host_\w+_fn\s*\(|(?:crate::host_resolve::|host_resolve::)?resolve_host_symbol\w*\s*\()'
)
# Patterns indicating stdio/malloc libc delegation (explicit list per bd-9chy.2).
WRAPS_LIBC_CALL_PATTERN = re.compile(
    r'\blibc::(?:fopen|fclose|fread|fwrite|fseek|ftell|fflush|setvbuf|ungetc|'
    r'feof|ferror|clearerr|fileno|getline|getdelim|printf|malloc|free|realloc)\s*\('
)
# Patterns indicating raw syscall usage
SYSCALL_PATTERN = re.compile(
    r'(?:crate::syscall::|super::syscall::|syscall!|syscall_raw|'
    r'libc::syscall\b|libc::SYS_|__NR_)'
)
NEXT_FN_PATTERN = re.compile(
    r'\n\s*(?:(?:#\[[^\n]*\]|//[/!][^\n]*)\n\s*)*'
    r'(?:pub\s+)?(?:unsafe\s+)?(?:extern\s+"C"\s+)?fn\s+\w+\s*\('
)
# Patterns indicating stub/unimplemented (explicit Rust stub macros only;
# `return -1` is a normal POSIX error return, not a stub indicator).
STUB_PATTERNS = [
    re.compile(r'\btodo!\b'),
    re.compile(r'\bunimplemented!\b'),
]
# Data symbols (statics, not functions)
DATA_SYMBOLS = {"stdin", "stdout", "stderr"}
STATUS_PROMOTION_RANK = {
    "Stub": 0,
    "GlibcCallThrough": 1,
    "WrapsHostLibc": 2,
    "Implemented": 3,
    "RawSyscall": 4,
}
ALTERNATE_PATTERN_MODULES = {"glibc_internal_abi", "rpc_abi"}
CROSS_MODULE_SOURCE_LOCATORS = {
    ("math_abi", "fedisableexcept"): "fenv_abi",
    ("math_abi", "feenableexcept"): "fenv_abi",
    ("math_abi", "fegetexcept"): "fenv_abi",
    ("math_abi", "fegetmode"): "fenv_abi",
    ("math_abi", "fesetexcept"): "fenv_abi",
    ("math_abi", "fesetmode"): "fenv_abi",
    ("math_abi", "fetestexceptflag"): "fenv_abi",
}
PROMOTION_PROOF_WARNING = "host delegation census covered by promotion proof manifest"
FN_NAME_PATTERN = re.compile(r'\bfn\s+([A-Za-z_]\w*)\s*\(')
HOST_RESOLVE_BLOCK_USE_PATTERN = re.compile(
    r'use\s+crate::host_resolve::\{(?P<body>.*?)\};',
    re.S,
)
HOST_RESOLVE_SINGLE_USE_PATTERN = re.compile(
    r'use\s+crate::host_resolve::(?P<name>[A-Za-z_]\w*)(?:\s+as\s+(?P<alias>[A-Za-z_]\w*))?\s*;'
)


def validate_matrix_rollups(matrix):
    """Reject contradictory ownership counts; this does not prove ABI parity."""
    status_fields = {
        "Implemented": "implemented",
        "RawSyscall": "raw_syscall",
        "WrapsHostLibc": "wraps_host_libc",
        "GlibcCallThrough": "glibc_call_through",
        "Stub": "stub",
    }
    if not isinstance(matrix, dict):
        raise ValueError("support matrix must be an object")
    symbols = matrix.get("symbols")
    if not isinstance(symbols, list) or not symbols:
        raise ValueError("support matrix symbols must be a nonempty array")
    counts = dict.fromkeys(status_fields.values(), 0)
    seen = set()
    for index, row in enumerate(symbols):
        if not isinstance(row, dict):
            raise ValueError(f"symbols[{index}] must be an object")
        name = row.get("symbol")
        if not isinstance(name, str) or not name.strip() or name in seen:
            raise ValueError(f"symbols[{index}] has an empty or duplicate symbol: {name!r}")
        seen.add(name)
        status = row.get("status")
        if not isinstance(status, str) or status not in status_fields:
            raise ValueError(f"symbols[{index}] has invalid status: {status!r}")
        counts[status_fields[status]] += 1

    def check_count(section, key, expected, prefix):
        actual = section.get(key)
        if type(actual) is not int or actual != expected:
            raise ValueError(f"{prefix}{key}: declared {actual!r}, rows require {expected}")

    total = len(symbols)
    check_count(matrix, "total_exported", total, "")
    for section_name in (None, "counts", "summary"):
        section = matrix if section_name is None else matrix.get(section_name)
        prefix = "" if section_name is None else f"{section_name}."
        if not isinstance(section, dict):
            raise ValueError(f"{section_name} must be an object")
        for key, count in counts.items():
            check_count(section, key, count, prefix)
        if section_name == "summary":
            check_count(section, "total", total, prefix)
        # Existing matrices need not store a percentage. If supplied, it must
        # use the same one-decimal convention as the generated dashboard.
        if "native_coverage_pct" in section:
            expected = round((counts["implemented"] + counts["raw_syscall"]) / total * 100, 1)
            actual = section["native_coverage_pct"]
            if type(actual) not in (int, float) or actual != expected:
                raise ValueError(
                    f"{prefix}native_coverage_pct: declared {actual!r}, rows require {expected}"
                )


def load_matrix():
    with open(MATRIX_PATH, encoding="utf-8") as f:
        matrix = json.load(f)
    validate_matrix_rollups(matrix)
    return matrix


def validate_matrix_provenance(matrix):
    """Require the matrix snapshot to include every committed ABI source change."""
    source_commit = matrix.get("source_commit")
    if not isinstance(source_commit, str) or re.fullmatch(
        r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source_commit
    ) is None:
        raise ValueError(
            "support_matrix.json source_commit must be a full lowercase Git object ID"
        )

    generated_at_utc = matrix.get("generated_at_utc")
    if not isinstance(generated_at_utc, str):
        raise ValueError("support_matrix.json generated_at_utc must be an RFC 3339 timestamp")
    try:
        generated_at = datetime.fromisoformat(generated_at_utc.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(
            "support_matrix.json generated_at_utc must be an RFC 3339 timestamp"
        ) from error
    if generated_at.tzinfo is None:
        raise ValueError("support_matrix.json generated_at_utc must include a timezone")

    try:
        subprocess.run(
            ["git", "rev-parse", "--verify", f"{source_commit}^{{commit}}"],
            cwd=REPO_ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        newest_raw = subprocess.check_output(
            [
                "git",
                "log",
                "-1",
                "--format=%H%x00%cI",
                "--",
                str(ABI_SRC.relative_to(REPO_ROOT)),
            ],
            cwd=REPO_ROOT,
            text=True,
        ).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError("unable to resolve support-matrix Git provenance") from error

    try:
        newest_commit, newest_timestamp = newest_raw.split("\0", 1)
        newest_time = datetime.fromisoformat(newest_timestamp)
    except ValueError as error:
        raise ValueError("unable to parse newest ABI source commit provenance") from error

    contains_newest = subprocess.run(
        ["git", "merge-base", "--is-ancestor", newest_commit, source_commit],
        cwd=REPO_ROOT,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if contains_newest.returncode != 0:
        raise ValueError(
            "support_matrix.json source_commit predates the newest ABI source commit "
            f"{newest_commit}"
        )
    if generated_at < newest_time:
        raise ValueError(
            "support_matrix.json generated_at_utc predates the newest ABI source commit "
            f"timestamp {newest_timestamp}"
        )

    return {
        "source_commit": source_commit,
        "source_generated_at_utc": generated_at_utc,
        "newest_abi_commit": newest_commit,
        "newest_abi_commit_time": newest_timestamp,
    }


def load_fixtures():
    """Scan fixture directory, returning a map of function_name → fixture info."""
    fixture_map = {}  # function_name -> list of {file, case_name, mode}
    if not FIXTURE_DIR.is_dir():
        return fixture_map

    for fpath in sorted(FIXTURE_DIR.glob("*.json")):
        try:
            with fpath.open(encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        for case in data.get("cases", []):
            func = case.get("function", "")
            name = case.get("name", "")
            mode = case.get("mode", "unknown")
            if func:
                # Normalize: strip class prefix (e.g., "PressureSensor::observe" → "observe")
                bare_func = func.split("::")[-1] if "::" in func else func
                entry = {"file": fpath.name, "case": name, "mode": mode}
                fixture_map.setdefault(bare_func, []).append(entry)
                if bare_func != func:
                    fixture_map.setdefault(func, []).append(entry)

    return fixture_map


def load_previous_report(path: Path):
    """Best-effort load of previous report for trend/comparison checks."""
    if not path.is_file():
        return None
    try:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return None
        return data
    except (OSError, json.JSONDecodeError):
        return None


def load_conformance_matrix(path: Path):
    """Load symbol/mode conformance status map from conformance matrix artifact."""
    if not path.is_file():
        return {}
    try:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}

    out = {}
    for row in data.get("symbol_matrix", []):
        symbol = str(row.get("symbol", ""))
        mode = str(row.get("mode", ""))
        if not symbol or not mode:
            continue
        out.setdefault(symbol, {})[mode] = {
            "total": int(row.get("total", 0)),
            "passed": int(row.get("passed", 0)),
            "failed": int(row.get("failed", 0)),
            "errors": int(row.get("errors", 0)),
            "pass_rate_percent": float(row.get("pass_rate_percent", 0.0)),
        }
    return out


def load_host_delegation_census(path: Path):
    """Load symbol-level host delegation evidence from the canonical census."""
    if not path.is_file():
        return {}
    try:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}

    out = {}
    rows = data.get("symbol_census", [])
    if not isinstance(rows, list):
        return out
    for row in rows:
        if not isinstance(row, dict):
            continue
        symbol = str(row.get("symbol", ""))
        if symbol:
            out[symbol] = row
    return out


def sha256_file(path: Path):
    """Return a lowercase SHA-256 digest without normalizing file contents."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def strip_rust_noncode(text):
    """Blank comments and string/character literals while preserving offsets.

    Stub evidence must be an executable macro invocation.  In particular, a
    doc comment, diagnostic string, or test fixture that merely spells
    ``abi_stub_contract!(...)`` is not evidence about an exported symbol.
    """
    out = list(text)
    i = 0
    n = len(text)
    raw_literal_pattern = re.compile(r'(?:br|r)(?P<hashes>#{0,255})"')
    lifetime_pattern = re.compile(r"'[A-Za-z_]\w*")

    def blank(start, end):
        for index in range(start, min(end, n)):
            if out[index] != "\n":
                out[index] = " "

    while i < n:
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            blank(i, end)
            i = end
            continue
        if text.startswith("/*", i):
            start = i
            depth = 1
            i += 2
            while i < n and depth:
                if text.startswith("/*", i):
                    depth += 1
                    i += 2
                elif text.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            blank(start, i)
            continue

        # Raw strings and raw byte strings: r"...", r#"..."#, br"...".
        raw = raw_literal_pattern.match(text, i)
        if raw:
            start = i
            hashes = raw.group("hashes")
            i = raw.end()
            terminator = '"' + hashes
            end = text.find(terminator, i)
            i = n if end < 0 else end + len(terminator)
            blank(start, i)
            continue

        prefix_len = 0
        quote = None
        if text.startswith('b"', i):
            prefix_len, quote = 1, '"'
        elif text.startswith("b'", i):
            prefix_len, quote = 1, "'"
        elif text[i] in ('"', "'"):
            quote = text[i]
        if quote is not None:
            # A leading apostrophe in a lifetime is not a character literal.
            if quote == "'" and prefix_len == 0 and lifetime_pattern.match(text, i):
                i += 1
                continue
            start = i
            i += prefix_len + 1
            escaped = False
            while i < n:
                ch = text[i]
                i += 1
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    break
            blank(start, i)
            continue
        i += 1
    return "".join(out)


def balanced_brace_end(source, open_brace):
    """Return the exclusive end of a balanced brace block, or ``None``."""
    depth = 0
    for index in range(open_brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    return None


def scan_stub_contract_annotations(abi_source_dir: Path):
    """Resolve direct and macro-generated concrete stub-contract markers."""
    annotations = {}
    errors = []
    sources = {}
    for path in sorted(abi_source_dir.glob("*.rs")):
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as error:
            errors.append(f"stub annotation source unreadable: {path}: {error}")
            continue
        sources[path] = (raw, strip_rust_noncode(raw))

    direct_pattern = re.compile(
        r"\babi_stub_contract!\s*\(\s*([A-Za-z_]\w*)\s*\)\s*;"
    )
    generic_pattern = re.compile(
        r"\babi_stub_contract!\s*\(\s*\$([A-Za-z_]\w*)\s*\)\s*;"
    )
    token_pattern = re.compile(r"\babi_stub_contract!\s*\(")
    macro_pattern = re.compile(r"\bmacro_rules!\s+([A-Za-z_]\w*)\s*\{")
    generator_macros = set()

    for path, (raw, code) in sources.items():
        accepted_starts = {
            match.start() for match in direct_pattern.finditer(code)
        } | {
            match.start() for match in generic_pattern.finditer(code)
        }
        for match in token_pattern.finditer(code):
            if match.start() not in accepted_starts:
                line = code.count("\n", 0, match.start()) + 1
                errors.append(
                    f"malformed abi_stub_contract! annotation at {path}:{line}"
                )

        for match in direct_pattern.finditer(code):
            symbol = match.group(1)
            line = code.count("\n", 0, match.start()) + 1
            following_export = re.compile(
                rf"(?:(?:\s+)|(?://[/!]?[^\n]*(?:\n|$)))*"
                rf"(?:#\[[^\]]*\]\s*)*"
                rf"(?:pub\s+)?(?:unsafe\s+)?extern\s+\"C(?:-unwind)?\"\s+"
                rf"fn\s+{re.escape(symbol)}\s*\("
            )
            if following_export.match(raw, match.end()) is None:
                errors.append(
                    f"abi_stub_contract for {symbol} is not immediately followed by "
                    f"its exported function at {path}:{line}"
                )
            annotations.setdefault(symbol, []).append(
                {
                    "kind": "direct",
                    "source": str(path),
                    "line": line,
                }
            )

        for match in macro_pattern.finditer(code):
            end = balanced_brace_end(code, match.end() - 1)
            if end is None:
                errors.append(
                    f"unbalanced macro_rules! {match.group(1)} at {path}:"
                    f"{code.count(chr(10), 0, match.start()) + 1}"
                )
                continue
            body = code[match.start():end]
            if generic_pattern.search(body):
                macro_name = match.group(1)
                if re.search(r"\bfn\s+\$[A-Za-z_]\w*\s*\(", body) is None:
                    errors.append(
                        f"stub generator {macro_name} marks a symbol but emits no function "
                        f"at {path}:{code.count(chr(10), 0, match.start()) + 1}"
                    )
                else:
                    generator_macros.add(macro_name)

    for macro_name in sorted(generator_macros):
        invocation_pattern = re.compile(
            rf"\b{re.escape(macro_name)}!\s*\(\s*([A-Za-z_]\w*)"
        )
        invocation_token = re.compile(rf"\b{re.escape(macro_name)}!\s*\(")
        for path, (_raw, code) in sources.items():
            accepted_starts = {
                match.start() for match in invocation_pattern.finditer(code)
            }
            for match in invocation_token.finditer(code):
                if match.start() not in accepted_starts:
                    line = code.count("\n", 0, match.start()) + 1
                    errors.append(
                        f"malformed {macro_name}! stub generator invocation at {path}:{line}"
                    )
            for match in invocation_pattern.finditer(code):
                symbol = match.group(1)
                line = code.count("\n", 0, match.start()) + 1
                annotations.setdefault(symbol, []).append(
                    {
                        "kind": "generated",
                        "generator_macro": macro_name,
                        "source": str(path),
                        "line": line,
                    }
                )

    for symbol, provenance in sorted(annotations.items()):
        if len(provenance) > 1:
            locations = ", ".join(
                f"{row['source']}:{row['line']}" for row in provenance
            )
            errors.append(f"duplicate stub annotation for {symbol}: {locations}")

    return {
        "annotations": annotations,
        "generator_macros": sorted(generator_macros),
        "errors": errors,
        "source_file_count": len(sources),
    }


def validate_host_delegation_census(path: Path, repo_root: Path, abi_source_dir: Path):
    """Load positive host evidence, failing closed on stale/ambiguous input."""
    result = {
        "usable": False,
        "rows": {},
        "unknown_symbols": set(),
        "errors": [],
        "ambiguities": [],
        "provenance": {
            "path": str(path),
            "artifact_sha256": None,
            "schema_version": None,
            "detector_version": None,
            "source_tree_sha256": None,
        },
    }
    if not path.is_file():
        result["errors"].append(f"host delegation census missing: {path}")
        return result
    try:
        result["provenance"]["artifact_sha256"] = sha256_file(path)
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        result["errors"].append(f"host delegation census unreadable: {path}: {error}")
        return result
    if not isinstance(data, dict):
        result["errors"].append("host delegation census root must be an object")
        return result

    result["provenance"]["schema_version"] = data.get("schema_version")
    if data.get("schema_version") != "host_delegation_census.v1":
        result["errors"].append(
            "host delegation census schema_version must be host_delegation_census.v1"
        )
    detector = data.get("detector")
    if not isinstance(detector, dict):
        result["errors"].append("host delegation census detector must be an object")
        detector = {}
    result["provenance"]["detector_version"] = detector.get("version")
    result["provenance"]["source_tree_sha256"] = detector.get("source_tree_sha256")
    if type(detector.get("version")) is not int or detector.get("version") < 4:
        result["errors"].append("host delegation census detector version is invalid")
    if not isinstance(detector.get("source_tree_sha256"), str) or not re.fullmatch(
        r"[0-9a-f]{64}", detector.get("source_tree_sha256", "")
    ):
        result["errors"].append("host delegation census source_tree_sha256 is invalid")

    hashes = data.get("source_file_hashes")
    seen_paths = set()
    if not isinstance(hashes, list) or not hashes:
        result["errors"].append("host delegation census source_file_hashes is missing or empty")
        hashes = []
    for index, row in enumerate(hashes):
        if not isinstance(row, dict):
            result["errors"].append(f"source_file_hashes[{index}] must be an object")
            continue
        rel = row.get("path")
        expected = row.get("sha256")
        if not isinstance(rel, str) or not rel or rel in seen_paths:
            result["errors"].append(
                f"source_file_hashes[{index}] has an empty or duplicate path: {rel!r}"
            )
            continue
        seen_paths.add(rel)
        source_path = repo_root / rel
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            result["errors"].append(f"invalid source hash for {rel}")
        elif not source_path.is_file():
            result["errors"].append(f"census source file missing: {rel}")
        elif sha256_file(source_path) != expected:
            result["errors"].append(f"stale census source hash: {rel}")

    expected_paths = {
        str(path.relative_to(repo_root))
        for path in abi_source_dir.glob("*.rs")
        if path.is_file()
    }
    if seen_paths != expected_paths:
        missing = sorted(expected_paths - seen_paths)
        extra = sorted(seen_paths - expected_paths)
        result["errors"].append(
            "census source file set mismatch: "
            f"missing={missing[:10]!r} extra={extra[:10]!r}"
        )
    declared_count = detector.get("source_file_count")
    if type(declared_count) is not int or declared_count != len(hashes):
        result["errors"].append(
            "census detector source_file_count does not match source_file_hashes"
        )

    callsites = data.get("callsite_census")
    callsites_by_id = {}
    if not isinstance(callsites, list):
        result["errors"].append("host delegation census callsite_census must be an array")
        callsites = []
    for index, row in enumerate(callsites):
        if not isinstance(row, dict):
            result["errors"].append(f"callsite_census[{index}] must be an object")
            continue
        callsite_id = row.get("id")
        exported_symbol = row.get("exported_symbol")
        exported_function_id = row.get("exported_function_id")
        module = row.get("module")
        source_path = row.get("path")
        source_line = row.get("line")
        helper_function = row.get("helper_function")
        helper_function_id = row.get("helper_function_id")
        host_symbol = row.get("host_symbol")
        evidence = row.get("evidence")
        expression = row.get("expression")
        path = row.get("reachability_path")
        hops = row.get("reachability_hops")
        helper_identity = (
            re.fullmatch(
                r"([A-Za-z_][A-Za-z0-9_]*)::([A-Za-z_][A-Za-z0-9_]*)@(\d+)",
                helper_function_id,
            )
            if isinstance(helper_function_id, str)
            else None
        )
        source_line_matches = False
        if isinstance(source_path, str) and type(source_line) is int and source_line > 0:
            try:
                source_lines = (repo_root / source_path).read_text(
                    encoding="utf-8"
                ).splitlines()
                source_line_matches = (
                    source_line <= len(source_lines)
                    and isinstance(expression, str)
                    and bool(expression)
                    and expression in source_lines[source_line - 1]
                )
            except OSError:
                source_line_matches = False
        valid = (
            isinstance(callsite_id, str) and bool(callsite_id)
            and isinstance(exported_symbol, str) and bool(exported_symbol)
            and isinstance(exported_function_id, str) and bool(exported_function_id)
            and isinstance(module, str) and bool(module)
            and isinstance(source_path, str) and source_path in seen_paths
            and type(source_line) is int and source_line > 0
            and isinstance(helper_function, str) and bool(helper_function)
            and isinstance(helper_function_id, str) and bool(helper_function_id)
            and helper_identity is not None
            and helper_identity.group(1) == Path(source_path).stem
            and helper_identity.group(2) == helper_function
            and host_symbol == exported_symbol
            and evidence == f"{source_path}:{source_line}"
            and source_line_matches
            and isinstance(path, list) and bool(path)
            and all(isinstance(value, str) and value for value in path)
            and path[0] == exported_function_id
            and path[-1] == helper_function_id
            and type(hops) is int
            and hops == len(path) - 1
        )
        if not valid:
            result["errors"].append(
                f"malformed host census callsite at callsite_census[{index}]"
            )
            continue
        if callsite_id in callsites_by_id:
            result["errors"].append(f"duplicate host census callsite id: {callsite_id}")
            continue
        callsites_by_id[callsite_id] = row

    rows = data.get("symbol_census")
    if not isinstance(rows, list):
        result["errors"].append("host delegation census symbol_census must be an array")
        rows = []
    referenced_callsite_ids = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            result["errors"].append(f"symbol_census[{index}] must be an object")
            continue
        symbol = row.get("symbol")
        module = row.get("module")
        source = row.get("source")
        function_id = row.get("function_id")
        host_symbols = row.get("host_symbols")
        kinds = row.get("delegation_kinds")
        callsite_ids = row.get("callsite_ids")
        callsite_count = row.get("callsite_count")
        source_match = (
            re.fullmatch(r"(.+):(\d+)", source)
            if isinstance(source, str)
            else None
        )
        source_path = source_match.group(1) if source_match else None
        source_line = int(source_match.group(2)) if source_match else None
        function_identity = (
            re.fullmatch(
                r"([A-Za-z_][A-Za-z0-9_]*)::([A-Za-z_][A-Za-z0-9_]*)@(\d+)",
                function_id,
            )
            if isinstance(function_id, str)
            else None
        )
        source_declares_function = False
        if (
            isinstance(source_path, str)
            and source_line is not None
            and source_line > 0
            and function_identity is not None
        ):
            try:
                source_lines = (repo_root / source_path).read_text(
                    encoding="utf-8"
                ).splitlines()
                source_declares_function = (
                    source_line <= len(source_lines)
                    and re.search(
                        rf"\bfn\s+{re.escape(function_identity.group(2))}\s*\(",
                        source_lines[source_line - 1],
                    )
                    is not None
                )
            except OSError:
                source_declares_function = False
        valid = (
            isinstance(symbol, str) and bool(symbol)
            and isinstance(module, str) and bool(module)
            and isinstance(source, str) and bool(source)
            and isinstance(function_id, str) and bool(function_id)
            and source_match is not None
            and source_path in seen_paths
            and source_line is not None and source_line > 0
            and Path(source_path).stem == module
            and function_identity is not None
            and function_identity.group(1) == module
            and int(function_identity.group(3)) == source_line
            and source_declares_function
            and isinstance(host_symbols, list) and bool(host_symbols)
            and all(isinstance(value, str) and value for value in host_symbols)
            and host_symbols == [symbol]
            and isinstance(kinds, list) and bool(kinds)
            and all(isinstance(value, str) and value for value in kinds)
            and isinstance(callsite_ids, list) and bool(callsite_ids)
            and all(isinstance(value, str) and value for value in callsite_ids)
            and type(callsite_count) is int
            and callsite_count == len(callsite_ids)
            and len(callsite_ids) == len(set(callsite_ids))
        )
        if not valid:
            result["errors"].append(f"malformed host census row at symbol_census[{index}]")
            continue
        referenced_callsites = [callsites_by_id.get(value) for value in callsite_ids]
        if any(value is None for value in referenced_callsites) or any(
            value.get("exported_symbol") != symbol
            or value.get("module") != module
            or value.get("exported_function_id") != function_id
            for value in referenced_callsites
            if isinstance(value, dict)
        ):
            result["errors"].append(
                f"host census row for {symbol} has missing or cross-symbol callsite ids"
            )
            continue
        if symbol in result["rows"]:
            result["errors"].append(f"duplicate host census row for {symbol}")
            result["rows"].pop(symbol, None)
            result["unknown_symbols"].add(symbol)
            continue
        if symbol not in result["unknown_symbols"]:
            result["rows"][symbol] = row
            referenced_callsite_ids.update(callsite_ids)

    if referenced_callsite_ids != set(callsites_by_id):
        result["errors"].append(
            "host delegation census callsite ids are not an exact symbol-row partition"
        )

    unknown_edges = data.get("unknown_call_edges")
    if not isinstance(unknown_edges, list):
        result["errors"].append("host delegation census unknown_call_edges must be an array")
        unknown_edges = []
    summary = data.get("summary")
    if not isinstance(summary, dict):
        result["errors"].append("host delegation census summary must be an object")
        summary = {}
    declared_unknown = summary.get("unknown_call_edge_count")
    if type(declared_unknown) is not int or declared_unknown != len(unknown_edges):
        result["errors"].append(
            "host delegation census unknown_call_edge_count is missing or inconsistent"
        )
    declared_callsites = summary.get("host_delegation_callsite_count")
    if type(declared_callsites) is not int or declared_callsites != len(callsites):
        result["errors"].append(
            "host delegation census host_delegation_callsite_count is missing or inconsistent"
        )
    for index, row in enumerate(unknown_edges):
        if not isinstance(row, dict):
            result["errors"].append(f"unknown_call_edges[{index}] must be an object")
            continue
        candidates = []
        for key in (
            "reachable_exports",
            "reachable_export_symbols",
            "reachable_from_exported_symbols",
            "exported_symbols",
            "symbols",
        ):
            value = row.get(key)
            if isinstance(value, list):
                candidates.extend(value)
        for key in (
            "symbol",
            "exported_symbol",
            "caller_export",
            "caller_exported_symbol",
        ):
            value = row.get(key)
            if isinstance(value, str):
                candidates.append(value)
        result["unknown_symbols"].update(
            value for value in candidates if isinstance(value, str) and value
        )
        result["ambiguities"].append(
            f"ambiguous census call edge at unknown_call_edges[{index}]"
        )

    result["usable"] = not result["errors"]
    return result


def build_downgrade_derivation(matrix_symbols, annotations, census):
    """Derive only evidence-backed downgrades; never infer a promotion."""
    matrix_by_symbol = {row["symbol"]: row for row in matrix_symbols}
    errors = (
        list(annotations.get("errors", []))
        + list(census.get("errors", []))
        + list(census.get("ambiguities", []))
    )
    for symbol in sorted(annotations.get("annotations", {})):
        if symbol not in matrix_by_symbol:
            errors.append(f"stub annotation names symbol absent from support matrix: {symbol}")
    for symbol in sorted(census.get("rows", {})):
        if symbol not in matrix_by_symbol:
            errors.append(f"host census names symbol absent from support matrix: {symbol}")

    rows = []
    mismatches = []
    for entry in sorted(matrix_symbols, key=lambda row: row["symbol"]):
        symbol = entry["symbol"]
        current = entry["status"]
        module = entry.get("module", "unknown")
        marker_rows = annotations.get("annotations", {}).get(symbol, [])
        census_row = census.get("rows", {}).get(symbol)
        derived = None
        evidence_state = "none"
        provenance = {}

        if marker_rows:
            derived = "Stub"
            evidence_state = "explicit_stub_contract"
            provenance["stub_contract"] = marker_rows
        elif symbol in census.get("unknown_symbols", set()):
            evidence_state = "ambiguous_census"
        elif census.get("usable", False) and census_row is not None:
            if census_row.get("module") != module:
                evidence_state = "ambiguous_census"
                errors.append(
                    f"host census module mismatch for {symbol}: "
                    f"matrix={module!r} census={census_row.get('module')!r}"
                )
            else:
                derived = "WrapsHostLibc"
                evidence_state = "observed_host_dependency"
                provenance["host_census"] = {
                    "source": census_row.get("source"),
                    "host_symbols": census_row.get("host_symbols"),
                    "delegation_kinds": census_row.get("delegation_kinds"),
                    "callsite_count": census_row.get("callsite_count"),
                    "callsite_ids": census_row.get("callsite_ids"),
                }
        elif not census.get("usable", False):
            evidence_state = "unknown_census"

        recommended = current
        promotion_suppressed = False
        mismatch = False
        if derived is not None:
            current_rank = STATUS_PROMOTION_RANK[current]
            derived_rank = STATUS_PROMOTION_RANK[derived]
            if derived_rank < current_rank:
                recommended = derived
                mismatch = True
            elif derived_rank > current_rank:
                promotion_suppressed = True
        row = {
            "symbol": symbol,
            "module": module,
            "current_status": current,
            "evidence_state": evidence_state,
            "derived_status": derived,
            "recommended_status": recommended,
            "promotion_suppressed": promotion_suppressed,
            "downgrade_mismatch": mismatch,
            "provenance": provenance,
        }
        rows.append(row)
        if mismatch:
            mismatches.append(row)

    status = "pass" if not errors and not mismatches else "fail"
    return {
        "schema_version": "support_matrix_downgrade_derivation.v1",
        "policy": {
            "explicit_stub_contract_derives": "Stub",
            "observed_host_dependency_derives": "WrapsHostLibc",
            "absence_or_unknown_evidence": "retain-current-and-fail-closed",
            "promotions_allowed": False,
        },
        "provenance": {
            "abi_source_dir": str(ABI_SRC),
            "stub_source_file_count": annotations.get("source_file_count", 0),
            "stub_generator_macros": annotations.get("generator_macros", []),
            "host_census": census.get("provenance", {}),
        },
        "summary": {
            "status": status,
            "symbol_count": len(rows),
            "stub_annotation_count": len(annotations.get("annotations", {})),
            "host_evidence_count": len(census.get("rows", {})),
            "downgrade_mismatch_count": len(mismatches),
            "promotion_suppressed_count": sum(
                1 for row in rows if row["promotion_suppressed"]
            ),
            "evidence_error_count": len(errors),
        },
        "errors": errors,
        "mismatches": mismatches,
        "symbols": rows,
    }


def conformance_mode_passed(mode_entry):
    """True when a conformance-mode row has non-zero coverage and zero failures/errors."""
    if not isinstance(mode_entry, dict):
        return False
    return (
        int(mode_entry.get("total", 0)) > 0
        and int(mode_entry.get("failed", 0)) == 0
        and int(mode_entry.get("errors", 0)) == 0
    )


def parse_promotion_proof_manifest_paths(raw: str):
    """Parse one or more promotion proof manifest paths from an argument string."""
    paths = []
    for chunk in re.split(r"[,{}]".format(re.escape(os.pathsep)), raw):
        chunk = chunk.strip()
        if chunk:
            paths.append(Path(chunk))
    return paths


def load_promotion_proof_manifest(path: Path):
    """Load one bounded promotion proof manifest."""
    if not path.is_file():
        return {}
    try:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}

    policy = data.get("policy", {})
    if not isinstance(policy, dict):
        policy = {}
    required_modes = tuple(policy.get("required_modes", ["strict", "hardened"]))
    accepted_host_symbols = set(policy.get("accepted_host_symbols", []))
    accepted_delegation_kinds = set(policy.get("accepted_delegation_kinds", []))
    classification = str(policy.get("classification", ""))
    support_matrix_status = str(policy.get("support_matrix_status", "Implemented"))

    proofs = {}
    for row in data.get("symbols", []):
        if not isinstance(row, dict):
            continue
        symbol = str(row.get("symbol", ""))
        if not symbol:
            continue
        if row.get("decision") != "proven":
            continue
        modes_ok = True
        for mode in required_modes:
            modes_ok = modes_ok and conformance_mode_passed(row.get(f"{mode}_conformance"))
        if not modes_ok:
            continue
        proofs[symbol] = {
            "module": str(row.get("module", "")),
            "classification": classification,
            "support_matrix_status": support_matrix_status,
            "accepted_host_symbols": accepted_host_symbols,
            "accepted_delegation_kinds": accepted_delegation_kinds,
            "required_modes": required_modes,
        }
    return proofs


def load_promotion_proofs(paths):
    """Load bounded promotion proofs that classify census hits as non-delegating."""
    proofs = {}
    for path in paths:
        proofs.update(load_promotion_proof_manifest(path))
    return proofs


def promotion_proof_covers_census(symbol, status, module, host_delegation_entry, proof):
    """Return true when a proof manifest explains all census hits for a symbol."""
    if not isinstance(host_delegation_entry, dict) or not isinstance(proof, dict):
        return False
    if status != proof.get("support_matrix_status", "Implemented"):
        return False
    if module != proof.get("module"):
        return False
    if proof.get("classification") not in ACCEPTED_PROMOTION_PROOF_CLASSIFICATIONS:
        return False

    host_symbols = set(host_delegation_entry.get("host_symbols", []))
    delegation_kinds = set(host_delegation_entry.get("delegation_kinds", []))
    accepted_host_symbols = proof.get("accepted_host_symbols", set())
    accepted_delegation_kinds = proof.get("accepted_delegation_kinds", set())
    if not host_symbols or not delegation_kinds:
        return False
    return host_symbols <= accepted_host_symbols and delegation_kinds <= accepted_delegation_kinds


def classify_status_validation_issue(status, module, findings, warnings):
    """Attach a stable machine class to maintenance findings without waiving them."""
    finding_set = set(findings or [])
    warning_set = set(warnings or [])

    if PROMOTION_PROOF_WARNING in warning_set:
        return {
            "issue_class": "promotion_proof_accepted",
            "scanner_bucket": "native_proven_errno_bridge",
            "actionable_next_step": "keep proof manifest strict+hardened mode rows current",
        }
    if "Implemented but host delegation detected" in finding_set:
        return {
            "issue_class": "true_host_delegation",
            "scanner_bucket": "source_level_host_call",
            "actionable_next_step": "downgrade status or remove host delegation from the implementation",
        }
    if "Implemented but host delegation census detected" in finding_set:
        return {
            "issue_class": "host_census_unverified",
            "scanner_bucket": "census_only_host_reachability",
            "actionable_next_step": "prove bounded non-core bridge use or downgrade status",
        }
    if any(finding.startswith("function body not found") for finding in finding_set):
        if module in ALTERNATE_PATTERN_MODULES:
            return {
                "issue_class": "alternate_pattern_unresolved",
                "scanner_bucket": "generated_or_alias_pattern",
                "actionable_next_step": "teach scanner the local macro/alias pattern or classify as scanner-unknown",
            }
        return {
            "issue_class": "missing_body",
            "scanner_bucket": "scanner_unknown",
            "actionable_next_step": "add a source locator pattern or update the support-matrix row",
        }
    if "module source not found" in finding_set:
        return {
            "issue_class": "module_source_missing",
            "scanner_bucket": "scanner_unknown",
            "actionable_next_step": "add module source or correct support-matrix module name",
        }
    if any("no host delegation detected" in finding for finding in finding_set):
        return {
            "issue_class": "taxonomy_overstates_host_dependency",
            "scanner_bucket": "status_source_mismatch",
            "actionable_next_step": "promote status only after strict+hardened evidence is present",
        }
    return {
        "issue_class": "status_pattern_mismatch",
        "scanner_bucket": "scanner_unknown",
        "actionable_next_step": "inspect findings and add a specific classifier",
    }


def count_statuses_from_map(status_map):
    counts = {}
    for status in status_map.values():
        counts[status] = counts.get(status, 0) + 1
    return counts


def classify_stub_transitions(
    current_status_map,
    previous_status_map,
    baseline_symbol_map_loaded,
    stub_annotations,
):
    """Allow a new Stub label only when exact source provenance requires it."""
    if not baseline_symbol_map_loaded:
        return {
            "new_stub_symbols": [],
            "annotated_new_stub_symbols": [],
            "unannotated_new_stub_symbols": [],
            "status": "pass",
        }
    concrete_annotations = {
        symbol
        for symbol, provenance in stub_annotations.get("annotations", {}).items()
        if len(provenance) == 1
    }
    new_stub_symbols = sorted(
        symbol
        for symbol, status in current_status_map.items()
        if status == "Stub" and previous_status_map.get(symbol) != "Stub"
    )
    annotated = sorted(set(new_stub_symbols) & concrete_annotations)
    unannotated = sorted(set(new_stub_symbols) - concrete_annotations)
    return {
        "new_stub_symbols": new_stub_symbols,
        "annotated_new_stub_symbols": annotated,
        "unannotated_new_stub_symbols": unannotated,
        "status": "pass" if not unannotated else "fail",
    }


def load_promotion_triage(path: Path | None):
    """Load optional promotion-triage rows keyed by symbol."""
    if path is None or not path.is_file():
        return {}, False
    try:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}, False

    rows = {}
    for row in data.get("promotions", []):
        if not isinstance(row, dict):
            continue
        symbol = str(row.get("symbol", ""))
        if symbol:
            rows[symbol] = row
    return rows, True


def ratchet_proof_class(row, triage_row, proof):
    """Classify why a promoted symbol is, or is not, acceptable to the fixture ratchet."""
    strict_pass = conformance_mode_passed(row.get("strict_conformance"))
    hardened_pass = conformance_mode_passed(row.get("hardened_conformance"))
    if strict_pass and hardened_pass:
        return "strict_hardened_conformance_proof"
    if isinstance(proof, dict):
        if (
            row.get("current_status") == proof.get("support_matrix_status", "Implemented")
            and row.get("module") == proof.get("module")
        ):
            return "strict_hardened_conformance_proof"

    category = str((triage_row or {}).get("category", "untriaged"))
    if category == "downgrade-now":
        return "documented_downgrade_required"
    if category == "scanner-false-positive":
        return "documented_no_fixture_rationale"

    missing = set(row.get("missing_evidence", []))
    if missing & {"missing_strict_fixture", "missing_hardened_fixture"}:
        return "missing_fixture_evidence"

    return "fixture_rows_without_passing_conformance"


def build_fixture_coverage_ratchet(
    reclassified_symbols,
    promotion_triage_by_symbol,
    promotion_triage_loaded,
    promotion_proofs,
    by_module,
):
    """Summarize promotion evidence pressure by module, proof class, and mode."""
    accepted_classes = {
        "strict_hardened_conformance_proof",
        "documented_downgrade_required",
        "documented_no_fixture_rationale",
    }
    module_deltas = {
        module: {
            "implemented_promotion_delta": 0,
            "proof_class_counts": {},
            "mode_deltas": {
                "strict": {
                    "fixture_rows": 0,
                    "passing_conformance_promotions": 0,
                    "missing_fixture_promotions": 0,
                    "missing_passing_conformance_promotions": 0,
                },
                "hardened": {
                    "fixture_rows": 0,
                    "passing_conformance_promotions": 0,
                    "missing_fixture_promotions": 0,
                    "missing_passing_conformance_promotions": 0,
                },
            },
            "triage_category_counts": {},
            "violating_symbols": [],
        }
        for module in HIGH_IMPACT_RATCHET_MODULES
    }

    violations = []
    for row in reclassified_symbols:
        if not row.get("promotion_requires_evidence"):
            continue
        if row.get("current_status") != "Implemented":
            continue

        symbol = str(row.get("symbol", ""))
        triage_row = promotion_triage_by_symbol.get(symbol, {})
        module = str(triage_row.get("module") or row.get("module") or "unknown")
        info = module_deltas.setdefault(
            module,
            {
                "implemented_promotion_delta": 0,
                "proof_class_counts": {},
                "mode_deltas": {
                    "strict": {
                        "fixture_rows": 0,
                        "passing_conformance_promotions": 0,
                        "missing_fixture_promotions": 0,
                        "missing_passing_conformance_promotions": 0,
                    },
                    "hardened": {
                        "fixture_rows": 0,
                        "passing_conformance_promotions": 0,
                        "missing_fixture_promotions": 0,
                        "missing_passing_conformance_promotions": 0,
                    },
                },
                "triage_category_counts": {},
                "violating_symbols": [],
            },
        )

        proof = promotion_proofs.get(symbol)
        proof_class = ratchet_proof_class(row, triage_row, proof)
        triage_category = str(triage_row.get("category", "untriaged"))
        info["implemented_promotion_delta"] += 1
        info["proof_class_counts"][proof_class] = (
            info["proof_class_counts"].get(proof_class, 0) + 1
        )
        info["triage_category_counts"][triage_category] = (
            info["triage_category_counts"].get(triage_category, 0) + 1
        )

        for mode in ("strict", "hardened"):
            fixture_count = int(row.get(f"{mode}_fixture_count", 0))
            mode_info = info["mode_deltas"][mode]
            mode_info["fixture_rows"] += fixture_count
            if fixture_count == 0:
                mode_info["missing_fixture_promotions"] += 1
            proof_required_modes = (
                set(proof.get("required_modes", ())) if isinstance(proof, dict) else set()
            )
            if conformance_mode_passed(row.get(f"{mode}_conformance")) or (
                proof_class == "strict_hardened_conformance_proof"
                and mode in proof_required_modes
            ):
                mode_info["passing_conformance_promotions"] += 1
            else:
                mode_info["missing_passing_conformance_promotions"] += 1

        if proof_class not in accepted_classes:
            violation = {
                "symbol": symbol,
                "module": module,
                "proof_class": proof_class,
                "triage_category": triage_category,
                "missing_evidence": list(row.get("missing_evidence", [])),
                "strict_fixture_count": int(row.get("strict_fixture_count", 0)),
                "hardened_fixture_count": int(row.get("hardened_fixture_count", 0)),
            }
            violations.append(violation)
            if len(info["violating_symbols"]) < 50:
                info["violating_symbols"].append(symbol)

    proof_manifest_by_module = {}
    for symbol, proof in sorted(promotion_proofs.items()):
        module = str(proof.get("module", "unknown"))
        info = proof_manifest_by_module.setdefault(
            module,
            {
                "strict_hardened_symbol_count": 0,
                "required_modes": list(proof.get("required_modes", ("strict", "hardened"))),
                "symbols": [],
            },
        )
        info["strict_hardened_symbol_count"] += 1
        if len(info["symbols"]) < 50:
            info["symbols"].append(symbol)

    for module, info in module_deltas.items():
        info["proof_class_counts"] = dict(sorted(info["proof_class_counts"].items()))
        info["triage_category_counts"] = dict(sorted(info["triage_category_counts"].items()))
        if module in by_module:
            info["current_module_coverage"] = {
                "total": int(by_module[module]["total"]),
                "linked": int(by_module[module]["linked"]),
                "coverage_pct": round(
                    by_module[module]["linked"] / by_module[module]["total"] * 100,
                    1,
                )
                if by_module[module]["total"]
                else 0.0,
            }

    return {
        "schema_version": "fixture_coverage_ratchet.v1",
        "bead": "bd-8t1chf",
        "promotion_triage_manifest_loaded": promotion_triage_loaded,
        "policy": {
            "high_impact_modules": list(HIGH_IMPACT_RATCHET_MODULES),
            "accepted_proof_classes": sorted(accepted_classes),
            "mode_requirement": "Implemented promotions require strict and hardened passing conformance, or an explicit triage rationale for downgrade/scanner handling",
        },
        "summary": {
            "implemented_promotion_delta": sum(
                info["implemented_promotion_delta"] for info in module_deltas.values()
            ),
            "module_count": len(
                [
                    info
                    for info in module_deltas.values()
                    if info["implemented_promotion_delta"] > 0
                ]
            ),
            "violation_count": len(violations),
            "status": "pass" if not violations else "fail",
        },
        "module_deltas": dict(sorted(module_deltas.items())),
        "proof_manifest_by_module": dict(sorted(proof_manifest_by_module.items())),
        "violations": violations,
    }




def read_module_source(module_name):
    """Read ABI module source file content."""
    src_path = ABI_SRC / f"{module_name}.rs"
    if not src_path.is_file():
        return None
    return src_path.read_text(encoding="utf-8")


def source_module_for_symbol(module_name, symbol):
    """Return the ABI source module that owns a cataloged symbol body."""
    return CROSS_MODULE_SOURCE_LOCATORS.get((module_name, symbol), module_name)


def extract_host_resolve_aliases(source):
    """Return locally visible names imported from crate::host_resolve."""
    aliases = set()

    for match in HOST_RESOLVE_BLOCK_USE_PATTERN.finditer(source):
        body = match.group("body")
        for raw_item in body.split(","):
            item = raw_item.strip()
            if not item:
                continue
            item = item.split("//", 1)[0].strip()
            if not item:
                continue
            if " as " in item:
                _orig, alias = item.split(" as ", 1)
                aliases.add(alias.strip())
            else:
                aliases.add(item.strip())

    for match in HOST_RESOLVE_SINGLE_USE_PATTERN.finditer(source):
        alias = match.group("alias") or match.group("name")
        aliases.add(alias.strip())

    return aliases


def strip_rust_comments(text):
    """Blank out `//`-style and `/* */` comments, preserving offsets and lines.

    Host-delegation detection is a *call* analysis, but every pattern it uses is
    a plain regex over raw source, so prose inside a doc comment counts as a
    call. That is not hypothetical: a lock-ordering doc comment in `stream_cell`
    reading ``for { c=fgetc(in); fputc(c,out); }`` made `stream_cell` a host
    helper, which transitively made `scanf_core_impl`, `scanf_core` and finally
    `sscanf` "Implemented but host delegation detected" — a gate failure caused
    by a comment (bd-4habm0).

    Replacement is space-for-character (newlines kept) so any offset- or
    line-based reasoning over the result stays aligned with the original.
    """
    out = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '/' and i + 1 < n and text[i + 1] == '/':
            while i < n and text[i] != '\n':
                out.append(' ')
                i += 1
        elif ch == '/' and i + 1 < n and text[i + 1] == '*':
            # Rust block comments nest.
            depth = 0
            while i < n:
                if text.startswith('/*', i):
                    depth += 1
                    out.append('  ')
                    i += 2
                elif text.startswith('*/', i):
                    depth -= 1
                    out.append('  ')
                    i += 2
                    if depth == 0:
                        break
                else:
                    out.append('\n' if text[i] == '\n' else ' ')
                    i += 1
        else:
            out.append(ch)
            i += 1
    return ''.join(out)


def body_calls_any(body, names):
    """True when body contains a function-style call to any name."""
    for name in names:
        if re.search(rf'\b{re.escape(name)}\s*\(', body):
            return True
    return False


def analyze_module_source(source):
    """Collect per-module helper metadata used by status classification."""
    host_resolve_aliases = extract_host_resolve_aliases(source)
    function_names = []
    for match in FN_NAME_PATTERN.finditer(source):
        name = match.group(1)
        if name not in function_names:
            function_names.append(name)

    function_bodies = {}
    for name in function_names:
        body = extract_function_body(source, name)
        if body is not None:
            # Comment-blind: host delegation is a property of code, not prose.
            function_bodies[name] = strip_rust_comments(body)

    host_helper_functions = set()
    changed = True
    while changed:
        changed = False
        for name, body in function_bodies.items():
            if name in host_helper_functions:
                continue
            if (
                WRAPS_HOST_LIBC_PATTERN.search(body)
                or WRAPS_LIBC_CALL_PATTERN.search(body)
                or body_calls_any(body, host_resolve_aliases)
                or body_calls_any(body, host_helper_functions)
            ):
                host_helper_functions.add(name)
                changed = True

    return {
        "host_resolve_aliases": host_resolve_aliases,
        "host_helper_functions": host_helper_functions,
    }


def extract_function_body(source, fn_name):
    """Extract approximate function body for a given fn name.

    Returns the text from 'fn name(' to the next function definition or EOF.
    This is approximate but sufficient for pattern matching.
    """
    pattern = re.compile(rf'\bfn\s+{re.escape(fn_name)}\s*\(')
    for match in pattern.finditer(source):
        signature_tail = source[match.end():]
        open_brace = signature_tail.find("{")
        statement_end = signature_tail.find(";")

        # Skip forward declarations inside extern blocks; we only want actual
        # function definitions with bodies.
        if open_brace < 0:
            continue
        if statement_end >= 0 and statement_end < open_brace:
            continue

        start = match.start()
        end = balanced_brace_end(source, match.end() + open_brace)
        if end is None:
            next_fn = NEXT_FN_PATTERN.search(signature_tail)
            if next_fn:
                end = match.end() + next_fn.start()
            else:
                end = len(source)
        return source[start:end]

    return None


def is_type_or_constant(name):
    """Heuristic: libc:: references that are types or constants, not function calls.

    Types: end in _t, start with lowercase c_ prefix, are ALL_CAPS, or match
    known struct/enum patterns.
    Constants: ALL_CAPS or start with uppercase (e.g., EINVAL, AF_INET, SIG_DFL).
    Functions: lowercase names like 'malloc', 'write', 'pthread_create'.
    """
    if name.endswith("_t"):
        return True
    if name.startswith("c_"):
        return True
    # ALL_CAPS or starts with uppercase = constant or type
    if name[0].isupper():
        return True
    # _SC_*, _PC_*, _CS_* are sysconf/pathconf/confstr constants
    if re.match(r'^_(?:SC|PC|CS|POSIX)_', name):
        return True
    # Known struct names that are lowercase
    lowercase_types = {
        "stat", "dirent", "dirent64", "passwd", "group", "spwd",
        "termios", "winsize", "addrinfo", "hostent", "servent",
        "protoent", "linger", "timezone", "tm", "iovec", "msghdr",
        "epoll_event", "pollfd", "glob_t", "if_nameindex", "sigval",
    }
    return name in lowercase_types


def validate_status(
    symbol,
    status,
    module,
    source,
    module_analysis,
    host_delegation_entry,
    promotion_proof,
    stub_contract_provenance=None,
):
    """Validate that a symbol's code matches its declared status.

    Returns (is_valid, findings: list of str, warnings: list of str).
    """
    if symbol in DATA_SYMBOLS:
        return True, [], []

    proof_available = (
        isinstance(promotion_proof, dict)
        and status == promotion_proof.get("support_matrix_status", "Implemented")
        and module == promotion_proof.get("module")
        and promotion_proof.get("classification") in ACCEPTED_PROMOTION_PROOF_CLASSIFICATIONS
    )
    explicit_stub_contract = (
        isinstance(stub_contract_provenance, list)
        and len(stub_contract_provenance) == 1
    )
    body = extract_function_body(source, symbol)
    if body is None:
        if status == "Stub":
            if explicit_stub_contract:
                return True, [], []
            return False, ["Stub body not found and no explicit stub contract"], []
        warnings = [PROMOTION_PROOF_WARNING] if proof_available else []
        return True, [f"function body not found (may use alternate pattern)"], warnings

    findings = []
    warnings = []
    proof_covers_census = promotion_proof_covers_census(
        symbol,
        status,
        module,
        host_delegation_entry,
        promotion_proof,
    )
    census_detected_host_delegation = (
        isinstance(host_delegation_entry, dict) and not proof_covers_census
    )
    if proof_covers_census or proof_available:
        warnings.append(PROMOTION_PROOF_WARNING)
    host_resolve_aliases = module_analysis.get("host_resolve_aliases", set())
    host_helper_functions = module_analysis.get("host_helper_functions", set())
    # Comment-blind, matching analyze_module_source: a doc comment that quotes a
    # call is prose, not delegation (bd-4habm0).
    code_body = strip_rust_comments(body)
    wraps_host_libc = bool(
        WRAPS_HOST_LIBC_PATTERN.search(code_body)
        or WRAPS_LIBC_CALL_PATTERN.search(code_body)
        or body_calls_any(code_body, host_resolve_aliases)
        or body_calls_any(code_body, host_helper_functions)
    )

    if status == "Implemented":
        if census_detected_host_delegation:
            findings.append("Implemented but host delegation census detected")
        if wraps_host_libc:
            findings.append("Implemented but host delegation detected")
        # Should NOT have libc:: host calls (except libc type references
        # and common utility functions).
        libc_calls = LIBC_CALL_PATTERN.findall(body)
        # Filter out type-only references (common pattern: libc::c_int etc.)
        type_refs = {"c_int", "c_uint", "c_long", "c_ulong", "c_char",
                     "c_void", "c_double", "c_float", "size_t", "ssize_t",
                     "off_t", "pid_t", "uid_t", "gid_t", "mode_t",
                     "socklen_t", "sockaddr", "sigset_t", "timespec",
                     "timeval", "stat", "dirent", "DIR", "FILE",
                     "pthread_t", "pthread_attr_t", "pthread_mutex_t",
                     "pthread_mutexattr_t", "pthread_cond_t",
                     "pthread_condattr_t", "pthread_rwlock_t",
                     "pthread_key_t", "pthread_once_t",
                     "PTHREAD_MUTEX_INITIALIZER", "PTHREAD_COND_INITIALIZER",
                     "PTHREAD_RWLOCK_INITIALIZER", "CLOCK_REALTIME",
                     "CLOCK_MONOTONIC", "EINVAL", "ENOMEM", "ENOSYS",
                     "EAGAIN", "EDEADLK", "EBUSY", "EPERM", "ESRCH",
                     "ENOENT", "ERANGE", "EACCES", "EEXIST", "EINTR",
                     "EBADF", "EFAULT", "EMFILE", "ENFILE", "E2BIG",
                     "EISDIR", "ENOTDIR", "ENOTEMPTY", "EXDEV", "ELOOP",
                     "ENAMETOOLONG", "EOF",
                     "AF_INET", "AF_INET6", "AF_UNIX", "SOCK_STREAM",
                     "SOCK_DGRAM", "SOL_SOCKET", "SO_REUSEADDR",
                     "O_RDONLY", "O_WRONLY", "O_RDWR", "O_CREAT",
                     "O_TRUNC", "O_APPEND", "O_NONBLOCK", "O_CLOEXEC",
                     "SEEK_SET", "SEEK_CUR", "SEEK_END",
                     "F_GETFL", "F_SETFL", "F_DUPFD", "F_GETFD", "F_SETFD",
                     "STDIN_FILENO", "STDOUT_FILENO", "STDERR_FILENO",
                     "EXIT_SUCCESS", "EXIT_FAILURE", "NULL",
                     "RLIMIT_NOFILE", "RLIM_INFINITY",
                     # Network struct/type references
                     "addrinfo", "sockaddr_in", "sockaddr_in6",
                     "sockaddr_un", "sockaddr_storage", "in_addr",
                     "in6_addr", "hostent", "servent", "protoent",
                     "linger", "ip_mreq",
                     # Passwd/group struct references
                     "passwd", "group", "spwd",
                     # Terminal struct references
                     "termios", "winsize",
                     # Locale/iconv references
                     "locale_t", "nl_item",
                     # Misc struct/type references
                     "rlimit", "rusage", "utsname", "sysinfo",
                     "epoll_event", "pollfd", "fd_set",
                     "Dl_info", "dl_phdr_info",
                     "glob_t", "regex_t", "regmatch_t",
                     "sem_t", "key_t", "shmid_ds", "semid_ds", "msqid_ds",
                     "sigaction", "stack_t", "siginfo_t", "sigval",
                     "itimerval", "itimerspec",
                     "statvfs", "statfs",
                     "tm", "timezone",
                     "DIR",
                     # Scheduler/process struct references
                     "sched_param",
                     # utmpx struct
                     "utmpx",
                     # getopt struct
                     "option",
                     # Network/IPC struct references
                     "sigevent", "cmsghdr",
                     }
        # Utility functions that Implemented symbols may legitimately call.
        # These are infrastructure/helper calls, NOT delegation of core logic.
        # The key GCT indicator is dlsym/dlvsym, not use of libc utilities.
        utility_fns = {
            # Errno access
            "__errno_location",
            # Raw syscall mechanism (not a glibc function call)
            "syscall",
            # Memory allocation (using system allocator is normal)
            "malloc", "calloc", "realloc", "free",
            # Basic memory/string operations (low-level utilities)
            "memcpy", "memmove", "memset", "strlen", "strcmp", "strncpy",
            "strcat", "strncat", "strcpy", "strncmp", "strerror",
            # Process control
            "abort", "_exit", "raise", "signal",
            # I/O primitives used as building blocks
            "write", "read", "open", "close", "fflush", "fwrite", "fgets",
            "lseek", "fstat", "lstat",
            # Directory operations
            "opendir", "closedir", "fdopendir", "readdir64_r",
            # Terminal/device operations
            "cfsetispeed", "cfsetospeed", "cfgetispeed", "cfgetospeed",
            "cfmakeraw",
            # Network primitives
            "bind", "setsockopt", "getsockopt",
            # Process/user info
            "getpid", "getuid", "geteuid", "getegid", "getpgid",
            "getgroups", "getpwuid", "getrlimit", "setitimer",
            "getauxval", "sbrk", "getcwd",
            # Signal handling
            "sigprocmask", "sigsuspend", "sigaddset", "sigdelset",
            "sigemptyset",
            # Dynamic linking (used for fallback resolution, not core delegation)
            "dlsym",
            # Thread primitives (our own implementations via pthread_abi)
            "pthread_self", "pthread_equal", "pthread_create",
            "pthread_join", "pthread_detach", "pthread_exit",
            "pthread_once", "pthread_key_create", "pthread_key_delete",
            "pthread_getspecific", "pthread_setspecific",
            "pthread_mutex_init", "pthread_mutex_destroy",
            "pthread_mutex_lock", "pthread_mutex_unlock",
            "pthread_mutex_trylock", "pthread_mutex_timedlock",
            "pthread_cond_init", "pthread_cond_destroy",
            "pthread_cond_signal", "pthread_cond_broadcast",
            "pthread_cond_wait", "pthread_cond_timedwait",
            "pthread_condattr_getclock",
            "pthread_attr_init", "pthread_attr_destroy",
            "pthread_condattr_init", "pthread_condattr_destroy",
            "pthread_condattr_setclock",
            "pthread_setschedparam", "pthread_getschedparam",
            # Spawn
            "posix_spawn", "posix_spawnp",
            # Time
            "clock_gettime", "clock_settime", "nanosleep", "mktime",
            # Misc POSIX utilities
            "sched_yield", "confstr", "fork", "sysctl",
            "openat", "mknodat", "mkstemp", "mkostemp", "mkostemps",
            "mkstemps", "pread", "pread64", "ppoll", "poll",
            "recv", "recvfrom", "readlink", "readlinkat",
            "realpath", "ptsname_r", "ttyname_r",
            "gethostname", "getdomainname",
            "sethostid", "settimeofday", "adjtime",
            "utime", "utimes", "futimes", "lutimes",
            "freeaddrinfo", "getaddrinfo",
            "endmntent", "mq_open",
            "backtrace", "backtrace_symbols", "backtrace_symbols_fd",
            "fcntl", "ioctl",
            "sched_rr_get_interval",
            # Additional libc utilities used as building blocks
            "sysconf", "getenv", "gmtime_r", "strtoll", "strtoull",
            "socket", "readdir", "fileno", "setrlimit",
            "sched_get_priority_max", "sched_get_priority_min",
            "sched_setparam", "sched_getparam", "sched_setscheduler",
            "sched_getscheduler",
            "pthread_mutexattr_init", "pthread_mutexattr_destroy",
            "pthread_mutexattr_settype",
            "flock",
        }
        fn_calls = [c for c in libc_calls
                    if c not in type_refs
                    and c not in utility_fns
                    and not is_type_or_constant(c)]
        if fn_calls:
            unique_calls = sorted(set(fn_calls))
            calls_str = ", ".join(unique_calls[:5])
            findings.append("Implemented but calls libc::{" + calls_str + "}")

        # Should NOT have stub patterns
        for pat in STUB_PATTERNS:
            if pat.search(body):
                findings.append(f"Implemented but contains stub pattern: {pat.pattern}")

    elif status == "RawSyscall":
        if wraps_host_libc:
            findings.append("RawSyscall but host delegation detected")
        # RawSyscall functions use libc::syscall() and libc::SYS_* constants
        # which IS the raw syscall path (not glibc function calls).
        # We check that they don't call actual glibc library functions.
        libc_calls = LIBC_CALL_PATTERN.findall(body)
        # libc::syscall and libc::SYS_* are the raw syscall mechanism
        syscall_ok = re.compile(r'^(?:syscall|SYS_\w+)$')
        type_refs = {"c_int", "c_uint", "c_long", "c_ulong", "c_char",
                     "c_void", "c_double", "c_float", "size_t", "ssize_t",
                     "off_t", "pid_t", "uid_t", "gid_t", "mode_t",
                     "socklen_t", "sockaddr", "timespec", "timeval",
                     "stat", "dirent", "iovec", "msghdr", "loff_t",
                     "EINVAL", "ENOMEM", "ENOSYS", "EAGAIN", "EBADF",
                     "EFAULT", "EINTR", "EACCES", "ENOENT", "EPERM",
                     "EEXIST", "EISDIR", "ENOTDIR", "ENOTEMPTY",
                     "EBUSY", "ENFILE", "EMFILE", "ERANGE", "E2BIG",
                     "ELOOP", "ENAMETOOLONG", "EXDEV", "ESPIPE",
                     "O_RDONLY", "O_WRONLY", "O_RDWR", "O_CREAT",
                     "O_TRUNC", "O_APPEND", "O_NONBLOCK", "O_CLOEXEC",
                     "O_DIRECTORY", "O_NOFOLLOW", "O_EXCL",
                     "AT_FDCWD", "AT_REMOVEDIR", "AT_SYMLINK_NOFOLLOW",
                     "SEEK_SET", "SEEK_CUR", "SEEK_END",
                     "AF_INET", "AF_INET6", "AF_UNIX", "SOCK_STREAM",
                     "SOCK_DGRAM", "SOCK_CLOEXEC", "SOCK_NONBLOCK",
                     "SOL_SOCKET", "SO_REUSEADDR", "SO_ERROR",
                     "MSG_DONTWAIT", "MSG_NOSIGNAL", "SHUT_RDWR",
                     "SHUT_RD", "SHUT_WR",
                     "F_GETFL", "F_SETFL", "F_DUPFD", "F_GETFD", "F_SETFD",
                     "FD_CLOEXEC", "FIONBIO",
                     "CLOCK_REALTIME", "CLOCK_MONOTONIC",
                     "SIGCHLD", "SIG_DFL", "SIG_IGN",
                     "WNOHANG", "WUNTRACED",
                     "PROT_READ", "PROT_WRITE", "PROT_EXEC", "PROT_NONE",
                     "MAP_PRIVATE", "MAP_ANONYMOUS", "MAP_SHARED", "MAP_FIXED",
                     "MAP_FAILED", "MREMAP_MAYMOVE",
                     "RLIMIT_NOFILE", "RLIM_INFINITY",
                     "GRND_NONBLOCK", "GRND_RANDOM",
                     "R_OK", "W_OK", "X_OK", "F_OK",
                     "DT_DIR", "DT_REG", "DT_LNK", "DT_UNKNOWN",
                     "STDIN_FILENO", "STDOUT_FILENO", "STDERR_FILENO",
                     "EXIT_SUCCESS", "EXIT_FAILURE",
                     "POLLIN", "POLLOUT", "POLLERR", "POLLHUP",
                     "EPOLL_CTL_ADD", "EPOLL_CTL_DEL", "EPOLL_CTL_MOD",
                     "EPOLLIN", "EPOLLOUT", "EPOLLERR", "EPOLLHUP",
                     "RUSAGE_SELF", "RUSAGE_CHILDREN",
                     "TIOCGWINSZ", "TCSANOW", "TCSADRAIN", "TCSAFLUSH",
                     "c_ushort",
                     # Struct/type references used in syscall wrappers
                     "termios", "winsize", "rlimit", "rusage",
                     "utsname", "sysinfo", "statvfs", "statfs",
                     "epoll_event", "pollfd", "fd_set",
                     "sigaction", "stack_t", "siginfo_t", "sigset_t",
                     "itimerval", "itimerspec", "tm", "timezone",
                     "sockaddr_in", "sockaddr_in6", "sockaddr_un",
                     "sockaddr_storage", "in_addr", "in6_addr",
                     "linger", "ip_mreq", "addrinfo",
                     "DIR", "dirent64",
                     "sigevent", "flock",
                     }
        # Utility functions that RawSyscall wrappers may legitimately use
        # (e.g., errno setting, signal mask setup, lock/flock wrappers)
        raw_utility_fns = {
            "__errno_location",
            "sigemptyset", "sigaddset", "sigdelset", "sigprocmask",
            "ioctl", "clock_gettime", "flock",
        }
        glibc_calls = [c for c in libc_calls
                       if c not in type_refs
                       and c not in raw_utility_fns
                       and not syscall_ok.match(c)
                       and not is_type_or_constant(c)]
        if glibc_calls:
            unique_calls = sorted(set(glibc_calls))
            calls_str = ", ".join(unique_calls[:5])
            findings.append("RawSyscall but calls glibc::{" + calls_str + "}")

    elif status == "WrapsHostLibc":
        if not wraps_host_libc and not census_detected_host_delegation:
            findings.append("WrapsHostLibc but no host delegation detected")

    elif status == "GlibcCallThrough":
        # Should have libc:: references or macro-based delegation patterns.
        # Many GCT symbols delegate via macros (io_resolve!, rpc_delegate!,
        # host_delegate!, dlsym_passthrough!) that don't contain raw libc::.
        libc_calls = LIBC_CALL_PATTERN.findall(body)
        has_delegation_macro = bool(re.search(
            r'\b(?:io_resolve|rpc_delegate|host_delegate|dlsym_passthrough|'
            r'dlvsym_next|crate::dlfcn_abi|host_dlsym|host_dlopen|'
            r'host_dlclose|host_dladdr|host_dl_iterate_phdr)', body))
        # Also check the line containing the fn definition for macro invocations
        # (dlsym_passthrough! appears before `fn name(` on the same line)
        if not has_delegation_macro:
            fn_pat = re.compile(rf'\bfn\s+{re.escape(symbol)}\s*\(')
            fn_match = fn_pat.search(source)
            if fn_match:
                line_start = source.rfind('\n', 0, fn_match.start()) + 1
                line = source[line_start:fn_match.start()]
                has_delegation_macro = bool(re.search(
                    r'\b(?:dlsym_passthrough|io_resolve|rpc_delegate|'
                    r'host_delegate)\s*!', line))
        if not libc_calls and not has_delegation_macro:
            findings.append("GlibcCallThrough but no libc:: references found")

    elif status == "Stub":
        # Source contracts are authoritative for deterministic ABI fallbacks;
        # todo!/unimplemented! are retained only for legacy rows awaiting an
        # explicit contract annotation.
        has_stub = explicit_stub_contract or any(pat.search(body) for pat in STUB_PATTERNS)
        if not has_stub:
            findings.append("Stub but no explicit stub contract or stub pattern found")

    is_valid = len(findings) == 0
    return is_valid, findings, warnings


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Support matrix maintenance validator")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    parser.add_argument(
        "--previous-report",
        default=str(REPO_ROOT / "tests" / "conformance" / "support_matrix_maintenance_report.v1.json"),
        help="Path to previous maintenance report used for trend/reclassification checks",
    )
    parser.add_argument(
        "--conformance-matrix",
        default=str(CONFORMANCE_MATRIX_PATH),
        help="Path to conformance_matrix artifact used for reclassification evidence checks",
    )
    parser.add_argument(
        "--host-delegation-census",
        default=str(HOST_DELEGATION_CENSUS_PATH),
        help="Path to canonical host delegation census used for taxonomy validation",
    )
    parser.add_argument(
        "--promotion-proof-manifest",
        default=os.pathsep.join(str(path) for path in PROMOTION_PROOF_MANIFEST_PATHS),
        help="Path list to bounded promotion proof manifests used to classify non-core host bridge census hits",
    )
    parser.add_argument(
        "--promotion-triage-report",
        default="",
        help="Optional promotion triage manifest used to classify fixture-ratchet deltas",
    )
    parser.add_argument("--self-test", action="store_true", help="Run self-test")
    parser.add_argument(
        "--self-test-downgrade-only",
        action="store_true",
        help="Run focused downgrade-evidence self-test without loading repository artifacts",
    )
    args = parser.parse_args()

    if args.self_test_downgrade_only:
        test_downgrade_only_evidence()
        return
    if args.self_test:
        run_self_test()
        return

    previous_report = load_previous_report(Path(args.previous_report))
    conformance_by_symbol = load_conformance_matrix(Path(args.conformance_matrix))
    host_census_path = Path(args.host_delegation_census)
    host_delegation_by_symbol = load_host_delegation_census(host_census_path)
    validated_host_census = validate_host_delegation_census(
        host_census_path,
        REPO_ROOT,
        ABI_SRC,
    )
    stub_annotations = scan_stub_contract_annotations(ABI_SRC)
    promotion_proof_paths = parse_promotion_proof_manifest_paths(args.promotion_proof_manifest)
    promotion_proofs = load_promotion_proofs(promotion_proof_paths)
    promotion_triage_path = Path(args.promotion_triage_report) if args.promotion_triage_report else None
    promotion_triage_by_symbol, promotion_triage_loaded = load_promotion_triage(
        promotion_triage_path
    )

    matrix = load_matrix()
    provenance = validate_matrix_provenance(matrix)
    source_commit = provenance["source_commit"]
    symbols = matrix.get("symbols", [])
    downgrade_derivation = build_downgrade_derivation(
        symbols,
        stub_annotations,
        validated_host_census,
    )
    fixture_map = load_fixtures()

    # Cache module sources
    module_cache = {}
    module_analysis_cache = {}

    status_results = []
    linkage_results = []
    warnings = 0

    # --- Pass 1: Status Validation ---
    status_valid = 0
    status_invalid = 0
    status_skipped = 0

    for entry in symbols:
        sym = entry["symbol"]
        st = entry.get("status", "unknown")
        module = entry.get("module", "unknown")
        source_module = source_module_for_symbol(module, sym)

        if source_module not in module_cache:
            module_cache[source_module] = read_module_source(source_module)
            module_analysis_cache[source_module] = (
                analyze_module_source(module_cache[source_module])
                if module_cache[source_module] is not None
                else {}
            )

        source = module_cache[source_module]
        if source is None:
            status_skipped += 1
            findings = ["module source not found"]
            status_results.append({
                "symbol": sym,
                "status": st,
                "module": module,
                "valid": None,
                "findings": findings,
                "warnings": [],
                **classify_status_validation_issue(st, module, findings, []),
            })
            continue

        is_valid, findings, warn_list = validate_status(
            sym,
            st,
            module,
            source,
            module_analysis_cache.get(source_module, {}),
            host_delegation_by_symbol.get(sym),
            promotion_proofs.get(sym),
            stub_annotations.get("annotations", {}).get(sym),
        )
        warnings += len(warn_list)
        if is_valid:
            status_valid += 1
        else:
            status_invalid += 1

        status_results.append({
            "symbol": sym,
            "status": st,
            "module": module,
            "valid": is_valid,
            "findings": findings,
            "warnings": warn_list,
            **classify_status_validation_issue(st, module, findings, warn_list),
        })

    # --- Pass 2: Conformance Linkage ---
    linked = 0
    unlinked = 0

    for entry in symbols:
        sym = entry["symbol"]
        cases = fixture_map.get(sym, [])
        has_fixture = len(cases) > 0
        strict_cases = sum(1 for c in cases if c["mode"] in ("strict", "both"))
        hardened_cases = sum(1 for c in cases if c["mode"] in ("hardened", "both"))

        if has_fixture:
            linked += 1
        else:
            unlinked += 1

        linkage_results.append({
            "symbol": sym,
            "has_fixture": has_fixture,
            "fixture_count": len(cases),
            "strict_count": strict_cases,
            "hardened_count": hardened_cases,
            "fixtures": [c["file"] for c in cases[:5]],
        })

    # --- Pass 3: Coverage Statistics ---
    by_status = {}
    by_module = {}
    by_status_linked = {}
    symbol_status_map = {}
    symbol_module_map = {}
    linkage_by_symbol = {}

    for i, entry in enumerate(symbols):
        sym = str(entry.get("symbol", ""))
        st = str(entry.get("status", "unknown"))
        module = entry.get("module", "unknown")
        has_fix = linkage_results[i]["has_fixture"]

        symbol_status_map[sym] = st
        symbol_module_map[sym] = str(module)
        linkage_by_symbol[sym] = linkage_results[i]

        by_status[st] = by_status.get(st, 0) + 1
        by_module.setdefault(module, {"total": 0, "linked": 0})
        by_module[module]["total"] += 1
        if has_fix:
            by_module[module]["linked"] += 1
            by_status_linked[st] = by_status_linked.get(st, 0) + 1

    total_symbols = len(symbols)
    coverage_pct = (linked / total_symbols * 100) if total_symbols else 0.0
    status_valid_pct = (status_valid / total_symbols * 100) if total_symbols else 0.0

    implemented_count = by_status.get("Implemented", 0)
    raw_syscall_count = by_status.get("RawSyscall", 0)
    wraps_host_libc_count = by_status.get("WrapsHostLibc", 0)
    callthrough_count = by_status.get("GlibcCallThrough", 0)
    stub_count = by_status.get("Stub", 0)
    native_count = implemented_count + raw_syscall_count
    native_coverage_pct = (native_count / total_symbols * 100.0) if total_symbols else 0.0

    previous_symbol_status_map = {}
    previous_status_counts = {}
    previous_native_coverage_pct = None
    previous_stub_count = stub_count
    baseline_loaded = False
    baseline_symbol_map_loaded = False

    if isinstance(previous_report, dict):
        baseline_loaded = True
        previous_symbol_status_map = previous_report.get("symbol_status_map", {})
        if not isinstance(previous_symbol_status_map, dict):
            previous_symbol_status_map = {}
        baseline_symbol_map_loaded = bool(previous_symbol_status_map)

        previous_status_counts = previous_report.get("coverage_dashboard", {}).get("status_counts", {})
        if not isinstance(previous_status_counts, dict):
            previous_status_counts = {}
        if not previous_status_counts:
            previous_status_distribution = previous_report.get("status_distribution", {})
            if isinstance(previous_status_distribution, dict):
                for status_name, info in previous_status_distribution.items():
                    if isinstance(info, dict):
                        previous_status_counts[status_name] = int(info.get("count", 0))
        if not previous_status_counts and previous_symbol_status_map:
            previous_status_counts = count_statuses_from_map(previous_symbol_status_map)

        prev_native = previous_report.get("coverage_dashboard", {}).get("native_coverage_pct")
        try:
            previous_native_coverage_pct = float(prev_native) if prev_native is not None else None
        except (TypeError, ValueError):
            previous_native_coverage_pct = None

        try:
            previous_stub_count = int(previous_status_counts.get("Stub", previous_stub_count))
        except (TypeError, ValueError):
            previous_stub_count = stub_count

    # Symbol reclassification analysis
    reclassified_symbols = []
    if baseline_symbol_map_loaded:
        for symbol in sorted(set(previous_symbol_status_map.keys()) & set(symbol_status_map.keys())):
            previous_status = previous_symbol_status_map.get(symbol)
            current_status = symbol_status_map.get(symbol)
            if previous_status == current_status:
                continue

            previous_rank = STATUS_PROMOTION_RANK.get(str(previous_status), -1)
            current_rank = STATUS_PROMOTION_RANK.get(str(current_status), -1)
            promotion_requires_evidence = current_rank > previous_rank

            linkage = linkage_by_symbol.get(symbol, {})
            strict_fixture = int(linkage.get("strict_count", 0)) > 0
            hardened_fixture = int(linkage.get("hardened_count", 0)) > 0

            mode_rows = conformance_by_symbol.get(symbol, {})
            strict_row = mode_rows.get("strict")
            hardened_row = mode_rows.get("hardened")
            strict_pass = conformance_mode_passed(strict_row)
            hardened_pass = conformance_mode_passed(hardened_row)

            missing_evidence = []
            if promotion_requires_evidence:
                if not strict_fixture:
                    missing_evidence.append("missing_strict_fixture")
                if not hardened_fixture:
                    missing_evidence.append("missing_hardened_fixture")
                if not strict_pass:
                    missing_evidence.append("strict_conformance_not_passing")
                if not hardened_pass:
                    missing_evidence.append("hardened_conformance_not_passing")

            reclassified_symbols.append({
                "symbol": symbol,
                "module": symbol_module_map.get(symbol, "unknown"),
                "previous_status": previous_status,
                "current_status": current_status,
                "promotion_requires_evidence": promotion_requires_evidence,
                "strict_fixture_count": int(linkage.get("strict_count", 0)),
                "hardened_fixture_count": int(linkage.get("hardened_count", 0)),
                "strict_conformance": strict_row,
                "hardened_conformance": hardened_row,
                "conformance_evidence_passed": (not promotion_requires_evidence)
                or len(missing_evidence) == 0,
                "missing_evidence": missing_evidence,
            })

    reclassification_violations = [
        row for row in reclassified_symbols if not row["conformance_evidence_passed"]
    ]
    fixture_coverage_ratchet = build_fixture_coverage_ratchet(
        reclassified_symbols,
        promotion_triage_by_symbol,
        promotion_triage_loaded,
        promotion_proofs,
        by_module,
    )

    status_count_delta = {}
    for status_name in sorted(set(by_status.keys()) | set(previous_status_counts.keys())):
        status_count_delta[status_name] = int(by_status.get(status_name, 0)) - int(
            previous_status_counts.get(status_name, 0)
        )

    if baseline_symbol_map_loaded:
        new_symbols = sorted(set(symbol_status_map.keys()) - set(previous_symbol_status_map.keys()))
        removed_symbols = sorted(set(previous_symbol_status_map.keys()) - set(symbol_status_map.keys()))
    else:
        new_symbols = []
        removed_symbols = []

    stub_transition_policy = classify_stub_transitions(
        symbol_status_map,
        previous_symbol_status_map,
        baseline_symbol_map_loaded,
        stub_annotations,
    )
    native_delta = None
    if previous_native_coverage_pct is not None:
        native_delta = round(native_coverage_pct - previous_native_coverage_pct, 2)

    # Build report
    report = {
        "schema_version": "v1",
        "bead": "bd-3g4p",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_commit": source_commit,
        "source_generated_at_utc": provenance["source_generated_at_utc"],
        "newest_abi_commit": provenance["newest_abi_commit"],
        "newest_abi_commit_time": provenance["newest_abi_commit_time"],
        "summary": {
            "total_symbols": total_symbols,
            "status_validated": status_valid,
            "status_invalid": status_invalid,
            "status_skipped": status_skipped,
            "status_valid_pct": round(status_valid_pct, 1),
            "fixture_linked": linked,
            "fixture_unlinked": unlinked,
            "fixture_coverage_pct": round(coverage_pct, 1),
            "total_warnings": warnings,
        },
        "coverage_dashboard": {
            "total_symbols": total_symbols,
            "status_counts": {
                "Implemented": implemented_count,
                "RawSyscall": raw_syscall_count,
                "WrapsHostLibc": wraps_host_libc_count,
                "GlibcCallThrough": callthrough_count,
                "Stub": stub_count,
            },
            "status_share_pct": {
                "Implemented": round((implemented_count / total_symbols * 100.0), 1) if total_symbols else 0.0,
                "RawSyscall": round((raw_syscall_count / total_symbols * 100.0), 1) if total_symbols else 0.0,
                "WrapsHostLibc": round((wraps_host_libc_count / total_symbols * 100.0), 1)
                if total_symbols
                else 0.0,
                "GlibcCallThrough": round((callthrough_count / total_symbols * 100.0), 1) if total_symbols else 0.0,
                "Stub": round((stub_count / total_symbols * 100.0), 1) if total_symbols else 0.0,
            },
            "native_coverage_pct": round(native_coverage_pct, 1),
        },
        "trend": {
            "baseline_report_path": str(Path(args.previous_report)),
            "baseline_loaded": baseline_loaded,
            "baseline_symbol_map_loaded": baseline_symbol_map_loaded,
            "promotion_proof_manifest_path": args.promotion_proof_manifest,
            "promotion_proof_manifest_paths": [str(path) for path in promotion_proof_paths],
            "promotion_proof_symbol_count": len(promotion_proofs),
            "promotion_triage_manifest_path": str(promotion_triage_path)
            if promotion_triage_path is not None
            else None,
            "promotion_triage_manifest_loaded": promotion_triage_loaded,
            "status_count_delta": status_count_delta,
            "native_coverage_pct_delta": native_delta,
            "reclassified_symbol_count": len(reclassified_symbols),
            "new_symbol_count": len(new_symbols),
            "removed_symbol_count": len(removed_symbols),
            "new_symbols": new_symbols,
            "removed_symbols": removed_symbols,
        },
        "policy_checks": {
            "no_new_stub_symbols": {
                "status": stub_transition_policy["status"],
                "previous_stub_count": previous_stub_count,
                "current_stub_count": stub_count,
                "delta": stub_count - previous_stub_count,
                "rule": "new Stub rows require one concrete abi_stub_contract! provenance record",
                "new_stub_symbols": stub_transition_policy["new_stub_symbols"],
                "annotated_new_stub_symbols": stub_transition_policy[
                    "annotated_new_stub_symbols"
                ],
                "unannotated_new_stub_symbols": stub_transition_policy[
                    "unannotated_new_stub_symbols"
                ],
            },
            "reclassification_requires_conformance": {
                "status": "pass" if not reclassification_violations else "fail",
                "baseline_symbol_map_loaded": baseline_symbol_map_loaded,
                "total_reclassified": len(reclassified_symbols),
                "violations": reclassification_violations,
            },
            "fixture_coverage_ratchet": {
                "status": fixture_coverage_ratchet["summary"]["status"],
                "implemented_promotion_delta": fixture_coverage_ratchet["summary"][
                    "implemented_promotion_delta"
                ],
                "violation_count": fixture_coverage_ratchet["summary"]["violation_count"],
                "promotion_triage_manifest_loaded": promotion_triage_loaded,
            },
            "downgrade_only_evidence": {
                "status": downgrade_derivation["summary"]["status"],
                "stub_annotation_count": downgrade_derivation["summary"][
                    "stub_annotation_count"
                ],
                "host_evidence_count": downgrade_derivation["summary"][
                    "host_evidence_count"
                ],
                "downgrade_mismatch_count": downgrade_derivation["summary"][
                    "downgrade_mismatch_count"
                ],
                "promotion_suppressed_count": downgrade_derivation["summary"][
                    "promotion_suppressed_count"
                ],
                "evidence_error_count": downgrade_derivation["summary"][
                    "evidence_error_count"
                ],
            },
        },
        "downgrade_derivation": downgrade_derivation,
        "fixture_coverage_ratchet": fixture_coverage_ratchet,
        "status_distribution": {
            st: {
                "count": by_status.get(st, 0),
                "fixture_linked": by_status_linked.get(st, 0),
            }
            for st in sorted(by_status.keys())
        },
        "module_coverage": {
            mod_name: {
                "total": info["total"],
                "linked": info["linked"],
                "coverage_pct": round(info["linked"] / info["total"] * 100, 1)
                if info["total"] > 0
                else 0,
            }
            for mod_name, info in sorted(by_module.items())
        },
        "symbol_status_map": dict(sorted(symbol_status_map.items())),
        "reclassified_symbols": reclassified_symbols,
        "status_validation_issues": [
            r for r in status_results if r.get("findings") or r.get("warnings")
        ],
        "unlinked_symbols": [
            r["symbol"] for r in linkage_results if not r["has_fixture"]
        ],
    }

    output = json.dumps(report, indent=2) + "\n"

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        # Print summary to stderr
        print(f"Total symbols: {total_symbols}", file=sys.stderr)
        print(f"Status valid: {status_valid}/{total_symbols} ({status_valid_pct:.1f}%)",
              file=sys.stderr)
        print(f"Fixture linked: {linked}/{total_symbols} ({coverage_pct:.1f}%)",
              file=sys.stderr)
        print(
            f"Stub guard: previous={previous_stub_count} current={stub_count} "
            f"({report['policy_checks']['no_new_stub_symbols']['status']})",
            file=sys.stderr,
        )
        print(
            f"Reclassification evidence: {len(reclassified_symbols)} changed, "
            f"violations={len(reclassification_violations)}",
            file=sys.stderr,
        )
        print(
            "Downgrade-only evidence: "
            f"{downgrade_derivation['summary']['status']} "
            f"mismatches={downgrade_derivation['summary']['downgrade_mismatch_count']} "
            f"errors={downgrade_derivation['summary']['evidence_error_count']}",
            file=sys.stderr,
        )
        print(f"Warnings: {warnings}", file=sys.stderr)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(output)

    # Report generation always succeeds. Findings are informational
    # and consumed by the CI gate for threshold-based decisions.
    sys.exit(0)


def test_matrix_rollups():
    """Hand-counted positive inputs and single-defect negative controls."""
    from copy import deepcopy

    counts = {
        "implemented": 1, "raw_syscall": 1, "wraps_host_libc": 1,
        "glibc_call_through": 0, "stub": 0,
    }
    valid = {
        "symbols": [
            {"symbol": "native", "status": "Implemented"},
            {"symbol": "syscall", "status": "RawSyscall"},
            {"symbol": "host", "status": "WrapsHostLibc"},
        ],
        "total_exported": 3,
        **counts,
        "counts": dict(counts),
        "summary": {"total": 3, **counts},
    }
    passed = 0

    def reject(candidate, diagnostic):
        nonlocal passed
        try:
            validate_matrix_rollups(candidate)
        except ValueError as error:
            if diagnostic not in str(error):
                raise AssertionError(f"wrong rejection: {error}") from error
        else:
            raise AssertionError(f"invalid matrix accepted: {diagnostic}")
        passed += 1

    validate_matrix_rollups(valid)
    passed += 1
    for section_name in (None, "counts", "summary"):
        prefix = "" if section_name is None else f"{section_name}."
        for field in counts:
            candidate = deepcopy(valid)
            section = candidate if section_name is None else candidate[section_name]
            section[field] += 1
            reject(candidate, f"{prefix}{field}:")
        candidate = deepcopy(valid)
        section = candidate if section_name is None else candidate[section_name]
        section["native_coverage_pct"] = 66.7
        validate_matrix_rollups(candidate)
        passed += 1
        section["native_coverage_pct"] = 66.6
        reject(candidate, f"{prefix}native_coverage_pct:")

    for value in (None, True, 3.0, "3", 4):
        candidate = deepcopy(valid)
        candidate["total_exported"] = value
        reject(candidate, "total_exported:")
    candidate = deepcopy(valid)
    candidate["summary"]["total"] = 4
    reject(candidate, "summary.total:")
    for field in ("counts", "summary"):
        candidate = deepcopy(valid)
        candidate[field] = []
        reject(candidate, f"{field} must be an object")
    reject([], "must be an object")
    for rows in (None, [], {}):
        candidate = deepcopy(valid)
        candidate["symbols"] = rows
        reject(candidate, "symbols must be a nonempty array")
    for row in (None, {}, {"symbol": " "}, {"symbol": "native", "status": "Stub"}):
        candidate = deepcopy(valid)
        candidate["symbols"][1] = row
        reject(candidate, "symbols[1]")
    for status in (None, "", "Native", [], True):
        candidate = deepcopy(valid)
        candidate["symbols"][0]["status"] = status
        reject(candidate, "invalid status")
    candidate = deepcopy(valid)
    candidate["symbols"][0]["status"] = "WrapsHostLibc"
    reject(candidate, "implemented:")
    print(f"Self-test: matrix rollups: {passed} cases passed")


def test_downgrade_only_evidence():
    """Focused negative controls for source annotations and census evidence."""
    import tempfile

    passed = 0
    with tempfile.TemporaryDirectory(prefix="frankenlibc-maintenance-selftest-") as raw_tmp:
        tmp = Path(raw_tmp)

        prose_dir = tmp / "prose"
        prose_dir.mkdir()
        (prose_dir / "demo.rs").write_text(
            "// abi_stub_contract!(comment_only);\n"
            "const PROSE: &str = \"abi_stub_contract!(string_only);\";\n"
            "abi_stub_contract!(real_stub);\n"
            "#[unsafe(no_mangle)]\n"
            "pub unsafe extern \"C\" fn real_stub() -> i32 { -1 }\n",
            encoding="utf-8",
        )
        prose = scan_stub_contract_annotations(prose_dir)
        if set(prose["annotations"]) != {"real_stub"} or prose["errors"]:
            raise AssertionError(f"false prose annotation accepted: {prose}")
        passed += 1

        malformed_dir = tmp / "malformed"
        malformed_dir.mkdir()
        (malformed_dir / "demo.rs").write_text(
            'abi_stub_contract!("not_an_identifier");\n',
            encoding="utf-8",
        )
        malformed = scan_stub_contract_annotations(malformed_dir)
        if not any("malformed abi_stub_contract" in error for error in malformed["errors"]):
            raise AssertionError(f"malformed annotation was not rejected: {malformed}")
        passed += 1

        duplicate_dir = tmp / "duplicate"
        duplicate_dir.mkdir()
        (duplicate_dir / "demo.rs").write_text(
            "abi_stub_contract!(twice);\nabi_stub_contract!(twice);\n",
            encoding="utf-8",
        )
        duplicate = scan_stub_contract_annotations(duplicate_dir)
        if not any("duplicate stub annotation for twice" in error for error in duplicate["errors"]):
            raise AssertionError(f"duplicate annotation was not rejected: {duplicate}")
        passed += 1

        generated_dir = tmp / "generated"
        generated_dir.mkdir()
        (generated_dir / "demo.rs").write_text(
            "macro_rules! generated_stub {\n"
            "    ($name:ident) => {\n"
            "        abi_stub_contract!($name);\n"
            "        #[unsafe(no_mangle)]\n"
            "        pub unsafe extern \"C\" fn $name() {}\n"
            "    };\n"
            "}\n"
            "generated_stub!(first);\ngenerated_stub!(second);\n",
            encoding="utf-8",
        )
        generated = scan_stub_contract_annotations(generated_dir)
        if set(generated["annotations"]) != {"first", "second"} or generated["errors"]:
            raise AssertionError(f"generated annotations were not resolved: {generated}")
        passed += 1

        source_dir = tmp / "repo" / "crates" / "frankenlibc-abi" / "src"
        source_dir.mkdir(parents=True)
        source_file = source_dir / "demo.rs"
        source_file.write_text(
            'pub fn hosted() { resolve_host_symbol_raw("hosted"); }\n',
            encoding="utf-8",
        )
        relative_source = "crates/frankenlibc-abi/src/demo.rs"
        valid_row = {
            "symbol": "hosted",
            "module": "demo",
            "source": f"{relative_source}:1",
            "function_id": "demo::hosted@1",
            "host_symbols": ["hosted"],
            "delegation_kinds": ["resolve_host_symbol_raw_dynamic"],
            "callsite_count": 1,
            "callsite_ids": ["demo:hosted:1:001"],
        }

        def write_census(name, *, digest, rows, include_unknown=True):
            census_path = tmp / name
            callsites = [
                {
                    "id": callsite_id,
                    "exported_symbol": row["symbol"],
                    "exported_function_id": "demo::hosted@1",
                    "module": "demo",
                    "path": relative_source,
                    "line": 1,
                    "helper_function": "hosted",
                    "helper_function_id": "demo::hosted@1",
                    "host_symbol": row["symbol"],
                    "evidence": f"{relative_source}:1",
                    "expression": 'resolve_host_symbol_raw("hosted")',
                    "reachability_path": ["demo::hosted@1"],
                    "reachability_hops": 0,
                }
                for row in rows[:1]
                for callsite_id in row.get("callsite_ids", [])
            ]
            body = {
                "schema_version": "host_delegation_census.v1",
                "detector": {
                    "version": 4,
                    "source_file_count": 1,
                    "source_tree_sha256": "0" * 64,
                },
                "source_file_hashes": [
                    {"path": relative_source, "sha256": digest}
                ],
                "symbol_census": rows,
                "callsite_census": callsites,
                "summary": {
                    "host_delegation_callsite_count": len(callsites),
                    "unknown_call_edge_count": 0,
                },
            }
            if include_unknown:
                body["unknown_call_edges"] = []
            census_path.write_text(json.dumps(body), encoding="utf-8")
            return census_path

        stale_path = write_census(
            "stale.json",
            digest="f" * 64,
            rows=[valid_row],
        )
        stale = validate_host_delegation_census(stale_path, tmp / "repo", source_dir)
        if stale["usable"] or not any("stale census source hash" in error for error in stale["errors"]):
            raise AssertionError(f"stale census was not rejected: {stale}")
        passed += 1

        missing_body_path = write_census(
            "missing-body.json",
            digest=sha256_file(source_file),
            rows=[valid_row],
            include_unknown=False,
        )
        missing_body = validate_host_delegation_census(
            missing_body_path, tmp / "repo", source_dir
        )
        if missing_body["usable"] or not any(
            "unknown_call_edges must be an array" in error
            for error in missing_body["errors"]
        ):
            raise AssertionError(f"missing census body was not rejected: {missing_body}")
        passed += 1

        duplicate_census_path = write_census(
            "duplicate-census.json",
            digest=sha256_file(source_file),
            rows=[valid_row, dict(valid_row)],
        )
        duplicate_census = validate_host_delegation_census(
            duplicate_census_path, tmp / "repo", source_dir
        )
        if duplicate_census["usable"] or not any(
            "duplicate host census row for hosted" in error
            for error in duplicate_census["errors"]
        ):
            raise AssertionError(f"ambiguous census body was not rejected: {duplicate_census}")
        passed += 1

    absent = build_downgrade_derivation(
        [{"symbol": "native", "module": "demo", "status": "Implemented"}],
        {"annotations": {}, "errors": [], "source_file_count": 1},
        {"usable": True, "rows": {}, "unknown_symbols": set(), "errors": [], "provenance": {}},
    )
    absent_row = absent["symbols"][0]
    if absent_row["derived_status"] is not None or absent_row["recommended_status"] != "Implemented":
        raise AssertionError(f"absence promoted or changed status: {absent_row}")
    passed += 1

    non_promotion = build_downgrade_derivation(
        [{"symbol": "hosted", "module": "demo", "status": "Stub"}],
        {"annotations": {}, "errors": [], "source_file_count": 1},
        {
            "usable": True,
            "rows": {"hosted": valid_row},
            "unknown_symbols": set(),
            "errors": [],
            "provenance": {},
        },
    )
    non_promotion_row = non_promotion["symbols"][0]
    if (
        non_promotion_row["recommended_status"] != "Stub"
        or not non_promotion_row["promotion_suppressed"]
    ):
        raise AssertionError(f"host evidence promoted Stub: {non_promotion_row}")
    passed += 1

    observed_amid_ambiguity = build_downgrade_derivation(
        [{"symbol": "hosted", "module": "demo", "status": "Implemented"}],
        {"annotations": {}, "errors": [], "source_file_count": 1},
        {
            "usable": True,
            "rows": {"hosted": valid_row},
            "unknown_symbols": {"other"},
            "errors": [],
            "ambiguities": ["unresolved edge for other"],
            "provenance": {},
        },
    )
    observed_row = observed_amid_ambiguity["symbols"][0]
    if (
        observed_row["derived_status"] != "WrapsHostLibc"
        or observed_row["recommended_status"] != "WrapsHostLibc"
        or observed_amid_ambiguity["summary"]["status"] != "fail"
    ):
        raise AssertionError(
            "positive host evidence was lost behind unrelated ambiguity: "
            f"{observed_amid_ambiguity}"
        )
    passed += 1

    ambiguous_target = build_downgrade_derivation(
        [{"symbol": "hosted", "module": "demo", "status": "Implemented"}],
        {"annotations": {}, "errors": [], "source_file_count": 1},
        {
            "usable": True,
            "rows": {"hosted": valid_row},
            "unknown_symbols": {"hosted"},
            "errors": [],
            "ambiguities": ["unresolved edge for hosted"],
            "provenance": {},
        },
    )
    ambiguous_row = ambiguous_target["symbols"][0]
    if (
        ambiguous_row["derived_status"] is not None
        or ambiguous_row["evidence_state"] != "ambiguous_census"
        or ambiguous_target["summary"]["status"] != "fail"
    ):
        raise AssertionError(
            f"symbol-local ambiguity did not suppress host derivation: {ambiguous_target}"
        )
    passed += 1

    downgrade = build_downgrade_derivation(
        [{"symbol": "annotated", "module": "demo", "status": "Implemented"}],
        {
            "annotations": {
                "annotated": [{"kind": "direct", "source": "demo.rs", "line": 1}]
            },
            "errors": [],
            "source_file_count": 1,
        },
        {"usable": False, "rows": {}, "unknown_symbols": set(), "errors": [], "provenance": {}},
    )
    if (
        downgrade["summary"]["status"] != "fail"
        or downgrade["summary"]["downgrade_mismatch_count"] != 1
        or downgrade["symbols"][0]["recommended_status"] != "Stub"
    ):
        raise AssertionError(f"derived downgrade mismatch was not rejected: {downgrade}")
    passed += 1

    transition_annotations = {
        "annotations": {
            "truthful_stub": [
                {"kind": "direct", "source": "demo.rs", "line": 1}
            ]
        }
    }
    truthful_transition = classify_stub_transitions(
        {"truthful_stub": "Stub"},
        {"truthful_stub": "Implemented"},
        True,
        transition_annotations,
    )
    unproven_transition = classify_stub_transitions(
        {"unproven_stub": "Stub"},
        {"unproven_stub": "Implemented"},
        True,
        transition_annotations,
    )
    if (
        truthful_transition["status"] != "pass"
        or truthful_transition["annotated_new_stub_symbols"] != ["truthful_stub"]
        or unproven_transition["status"] != "fail"
        or unproven_transition["unannotated_new_stub_symbols"] != ["unproven_stub"]
    ):
        raise AssertionError(
            "new Stub provenance policy accepted the wrong transition: "
            f"{truthful_transition}, {unproven_transition}"
        )
    passed += 1

    stub_source = "pub extern \"C\" fn truthful_stub() -> i32 { -1 }\n"
    accepted_stub = validate_status(
        "truthful_stub",
        "Stub",
        "demo",
        stub_source,
        analyze_module_source(stub_source),
        None,
        None,
        transition_annotations["annotations"]["truthful_stub"],
    )
    rejected_stub = validate_status(
        "truthful_stub",
        "Stub",
        "demo",
        stub_source,
        analyze_module_source(stub_source),
        None,
        None,
        None,
    )
    missing_stub = validate_status(
        "missing_stub",
        "Stub",
        "demo",
        stub_source,
        analyze_module_source(stub_source),
        None,
        None,
        None,
    )
    if accepted_stub[0] is not True or rejected_stub[0] is not False or missing_stub[0] is not False:
        raise AssertionError(
            "Stub validation did not require exact annotation provenance: "
            f"accepted={accepted_stub}, rejected={rejected_stub}, missing={missing_stub}"
        )
    passed += 1

    missing_census = validate_host_delegation_census(
        Path("/definitely/missing/host-delegation-census.json"),
        REPO_ROOT,
        ABI_SRC,
    )
    if missing_census["usable"] or not missing_census["errors"]:
        raise AssertionError(f"missing census was not rejected: {missing_census}")
    passed += 1

    current = scan_stub_contract_annotations(ABI_SRC)
    generated_current = [
        symbol
        for symbol, rows in current["annotations"].items()
        if any(row.get("generator_macro") == "rpc_stub" for row in rows)
    ]
    required_direct = {
        "register_printf_function",
        "register_printf_modifier",
        "register_printf_specifier",
        "register_printf_type",
    }
    if len(generated_current) != 32 or not required_direct <= set(current["annotations"]):
        raise AssertionError(
            "current source annotations did not resolve all 32 rpc_stub invocations "
            f"and four direct contracts: {current}"
        )
    passed += 1
    print(f"Self-test: downgrade-only evidence: {passed} cases passed")


def run_self_test():
    """Exercise the loader and the taxonomy checks that protect native claims."""
    test_matrix_rollups()
    test_downgrade_only_evidence()
    print("Self-test: loading matrix...")
    matrix = load_matrix()
    symbols = matrix.get("symbols", [])
    print(f"  {len(symbols)} symbols loaded")

    print("Self-test: validating matrix provenance...")
    provenance = validate_matrix_provenance(matrix)
    if provenance["source_commit"] != matrix["source_commit"]:
        raise AssertionError("validated source commit did not match the matrix")
    from copy import deepcopy

    stale = deepcopy(matrix)
    stale["generated_at_utc"] = "1970-01-01T00:00:00Z"
    try:
        validate_matrix_provenance(stale)
    except ValueError as error:
        if "predates the newest ABI source commit" not in str(error):
            raise AssertionError(f"wrong stale-timestamp rejection: {error}") from error
    else:
        raise AssertionError("stale matrix timestamp was accepted")
    symbolic = deepcopy(matrix)
    symbolic["source_commit"] = "current"
    try:
        validate_matrix_provenance(symbolic)
    except ValueError as error:
        if "full lowercase Git object ID" not in str(error):
            raise AssertionError(f"wrong symbolic-commit rejection: {error}") from error
    else:
        raise AssertionError("symbolic matrix source commit was accepted")
    print("  pass: current provenance accepted; stale and symbolic controls rejected")

    print("Self-test: loading fixtures...")
    fixtures = load_fixtures()
    print(f"  {len(fixtures)} fixture functions indexed")

    print("Self-test: status validation on first 3 symbols...")
    module_cache = {}
    for entry in symbols[:3]:
        sym = entry["symbol"]
        module = entry.get("module", "unknown")
        if module not in module_cache:
            module_cache[module] = read_module_source(module)
        source = module_cache[module]
        if source:
            module_analysis = analyze_module_source(source)
            is_valid, findings, warnings = validate_status(
                sym,
                entry["status"],
                module,
                source,
                module_analysis,
                None,
                None,
            )
            details = [*findings, *warnings] or ["ok"]
            mark = "pass" if is_valid else "fail"
            print(f"  {mark} {sym} ({entry['status']}): {details}")
        else:
            print(f"  ? {sym}: source not found")

    # A partial-native crypt implementation is still host-wrapping when an
    # unsupported setting reaches libxcrypt.  This is deliberately tested by
    # asking the validator to evaluate the wrong taxonomy: a future edit that
    # calls the host fallback but labels any of these entrypoints Implemented
    # must make this control fail rather than quietly inflate native coverage.
    print("Self-test: crypt host-delegation negative control...")
    crypt_symbols = (
        "crypt",
        "crypt_r",
        "crypt_ra",
        "crypt_rn",
        "fcrypt",
        "xcrypt",
        "xcrypt_r",
    )
    rows_by_symbol = {
        symbol: [row for row in symbols if row.get("symbol") == symbol]
        for symbol in crypt_symbols
    }
    crypt_source = read_module_source("unistd_abi")
    if not crypt_source:
        raise RuntimeError("crypt host-delegation self-test could not load unistd_abi")
    crypt_analysis = analyze_module_source(crypt_source)
    for symbol, rows in rows_by_symbol.items():
        if len(rows) != 1:
            raise RuntimeError(
                f"crypt host-delegation self-test expected one {symbol} row, got {len(rows)}"
            )
        row = rows[0]
        if row.get("status") != "WrapsHostLibc":
            raise RuntimeError(
                f"crypt host-delegation self-test requires {symbol} to be WrapsHostLibc"
            )
        is_valid, findings, _warnings = validate_status(
            symbol,
            "WrapsHostLibc",
            "unistd_abi",
            crypt_source,
            crypt_analysis,
            None,
            None,
        )
        if not is_valid:
            raise RuntimeError(
                f"crypt host-delegation self-test rejected current {symbol}: {findings}"
            )
        _is_valid, wrong_findings, _warnings = validate_status(
            symbol,
            "Implemented",
            "unistd_abi",
            crypt_source,
            crypt_analysis,
            None,
            None,
        )
        if "Implemented but host delegation detected" not in wrong_findings:
            raise RuntimeError(
                f"crypt host-delegation negative control did not reject {symbol}: "
                f"{wrong_findings}"
            )
    print(f"  pass: {len(crypt_symbols)} partial-native entrypoints reject Implemented")

    print("Self-test: PASS")


if __name__ == "__main__":
    main()
