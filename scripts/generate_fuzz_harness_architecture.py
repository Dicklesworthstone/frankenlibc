#!/usr/bin/env python3
"""generate_fuzz_harness_architecture.py — bd-1oz.5

Fuzz harness architecture spec and deterministic corpus seeding strategy:
  1. Target inventory — scan and classify all fuzz targets by domain.
  2. Harness conventions — validate harness patterns (no_main, size guards, cleanup).
  3. Corpus seeding — generate deterministic seed corpora per target.
  4. Dictionary generation — create dictionaries for high-signal mutation.
  5. Quality checklist — assess target maturity (impl status, coverage depth).

Generates a JSON report to stdout (or --output).
"""
import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


def find_repo_root():
    p = Path(__file__).resolve().parent.parent
    if (p / "Cargo.toml").exists():
        return p
    return Path.cwd()


# Domain classification for fuzz targets
TARGET_DOMAINS = {
    "fuzz_string": {
        "domain": "abi-entrypoint",
        "category": "string-ops",
        "description": "String function fuzzing (strlen, strcmp, strcpy, strstr)",
        "cwe_coverage": ["CWE-120", "CWE-125", "CWE-787"],
        "priority": "high",
    },
    "fuzz_malloc": {
        "domain": "allocator",
        "category": "heap-ops",
        "description": "Malloc/free/realloc sequence fuzzing via ValidationPipeline",
        "cwe_coverage": ["CWE-415", "CWE-416", "CWE-122", "CWE-131"],
        "priority": "critical",
    },
    "fuzz_membrane": {
        "domain": "membrane",
        "category": "ptr-validation",
        "description": "Pointer validation pipeline with arbitrary addresses",
        "cwe_coverage": ["CWE-476", "CWE-824", "CWE-825"],
        "priority": "critical",
    },
    "fuzz_printf": {
        "domain": "abi-entrypoint",
        "category": "format-string",
        "description": "Printf format string parsing and safety",
        "cwe_coverage": ["CWE-134", "CWE-787"],
        "priority": "high",
    },
    "fuzz_locale": {
        "domain": "locale",
        "category": "locale-api",
        "description": "Locale category/name parsing and C-locale ABI semantics fuzzing",
        "cwe_coverage": ["CWE-20", "CWE-170", "CWE-476"],
        "priority": "high",
    },
    "fuzz_runtime_math": {
        "domain": "runtime-kernel",
        "category": "controller-transitions",
        "description": "Runtime math decision and observation transition fuzzing",
        "cwe_coverage": ["CWE-670", "CWE-682", "CWE-835"],
        "priority": "high",
    },
    "fuzz_elf_loader": {
        "domain": "loader",
        "category": "elf-parser-relocations",
        "description": "ELF header/table parsing and relocation application fuzzing",
        "cwe_coverage": ["CWE-20", "CWE-125", "CWE-190", "CWE-787"],
        "priority": "high",
    },
}

# Harness convention checks
HARNESS_CHECKS = [
    ("no_main_attr", r"#!\[no_main\]", "Must use #![no_main] attribute"),
    ("fuzz_target_macro", r"fuzz_target!", "Must use fuzz_target! macro"),
    ("input_size_guard", r"", "Should have bounded input handling or an explicit size guard"),
    ("no_unwrap", r"\.unwrap\(\)", "Should avoid unwrap (use safe alternatives)"),
    ("no_panic", r"panic!", "Should avoid explicit panics"),
]


def compute_seed_hash(target_name, seed_index, content):
    """Deterministic seed identifier."""
    canonical = f"{target_name}:{seed_index}:{content.hex()}"
    return hashlib.sha256(canonical.encode()).hexdigest()[:12]


def generate_string_seeds():
    """Deterministic seed corpus for string operations."""
    seeds = []
    # Empty string
    seeds.append(b"\x00")
    # Single char
    seeds.append(b"A\x00")
    # Typical string
    seeds.append(b"hello world\x00")
    # Max-boundary (255 chars)
    seeds.append(b"A" * 255 + b"\x00")
    # Embedded nulls
    seeds.append(b"foo\x00bar\x00baz\x00")
    # All-0xFF (non-ASCII)
    seeds.append(b"\xff" * 16 + b"\x00")
    # UTF-8 multibyte
    seeds.append("héllo wörld\x00".encode("utf-8"))
    # Two strings for strcmp-like functions
    seeds.append(b"abc\x00def\x00")
    return seeds


def generate_malloc_seeds():
    """Deterministic seed corpus for allocator operations."""
    seeds = []
    # Simple alloc (op=0, size=64)
    seeds.append(bytes([0, 64, 0, 0]))
    # Alloc then free
    seeds.append(bytes([0, 64, 0, 0, 1, 0, 0, 0]))
    # Multiple allocs
    seeds.append(bytes([0, 32, 0, 0, 0, 64, 0, 0, 0, 128, 0, 0]))
    # Alloc-free-alloc cycle
    seeds.append(bytes([0, 16, 0, 0, 1, 0, 0, 0, 0, 16, 0, 0]))
    # Large allocation
    seeds.append(bytes([0, 0xFF, 0xFF, 0]))
    # Rapid free (double-free attempt)
    seeds.append(bytes([0, 32, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0]))
    # Validate operation
    seeds.append(bytes([0, 64, 0, 0, 2, 0, 0, 0]))
    return seeds


def generate_membrane_seeds():
    """Deterministic seed corpus for pointer validation."""
    seeds = []
    # Null pointer
    seeds.append(b"\x00" * 8)
    # Low address (likely unmapped)
    seeds.append(bytes([0x01, 0, 0, 0, 0, 0, 0, 0]))
    # Typical heap address
    seeds.append(bytes([0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]))
    # Stack-like address
    seeds.append(bytes([0x00, 0xF0, 0xFF, 0x7F, 0x00, 0x00, 0x00, 0x00]))
    # Kernel-space address
    seeds.append(bytes([0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]))
    # Max address
    seeds.append(b"\xFF" * 8)
    # Multiple addresses
    seeds.append(b"\x00" * 8 + b"\xFF" * 8)
    return seeds


def generate_printf_seeds():
    """Deterministic seed corpus for format string parsing."""
    seeds = []
    # Simple string
    seeds.append(b"hello")
    # Basic format specifiers
    seeds.append(b"%d %s %f")
    # Width/precision
    seeds.append(b"%10.5f %*d")
    # Positional
    seeds.append(b"%1$d %2$s")
    # Long format chain
    seeds.append(b"%d" * 50)
    # Dangerous %n
    seeds.append(b"%n%n%n%n")
    # Mixed specifiers
    seeds.append(b"val=%d str=%s ptr=%p hex=%x")
    return seeds


def generate_locale_seeds():
    """Deterministic seed corpus for locale parsing and ABI state transitions."""
    seeds = []
    seeds.append(b"C")
    seeds.append(b"POSIX")
    seeds.append(b"")
    seeds.append(b"en_US.UTF-8")
    seeds.append(b"messages")
    seeds.append(b"/usr/share/locale")
    seeds.append(b"C:messages:/usr/share/locale")
    return seeds


def generate_runtime_math_seeds():
    """Deterministic seed corpus for runtime math transitions."""
    seeds = []
    seeds.append(bytes([0, 0, 0, 0, 0, 0, 1, 0]))
    seeds.append(bytes([1, 1, 0x10, 0, 0x20, 0, 0x40, 0]))
    seeds.append(bytes([2, 1, 0xFF, 0, 0x80, 0, 0xAA, 0x55]))
    seeds.append(bytes([5, 2, 0x34, 0x12, 0x10, 0x27, 0x0F, 0xF0]))
    return seeds


SEED_GENERATORS = {
    "fuzz_string": generate_string_seeds,
    "fuzz_malloc": generate_malloc_seeds,
    "fuzz_membrane": generate_membrane_seeds,
    "fuzz_printf": generate_printf_seeds,
    "fuzz_locale": generate_locale_seeds,
    "fuzz_runtime_math": generate_runtime_math_seeds,
}

# Dictionary entries per domain
DICTIONARIES = {
    "fuzz_string": [
        '""', '"\\x00"', '"AAAA"', '"\\xff\\xff"',
        '"hello"', '"\\n"', '"\\t"', '"\\r\\n"',
    ],
    "fuzz_malloc": [
        '"\\x00\\x01\\x00\\x00"',  # alloc 256
        '"\\x00\\x00\\x01\\x00"',  # alloc 65536
        '"\\x01\\x00\\x00\\x00"',  # free
        '"\\x02\\x00\\x00\\x00"',  # validate
    ],
    "fuzz_membrane": [
        '"\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"',  # null
        '"\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff"',  # max
    ],
    "fuzz_printf": [
        '"%d"', '"%s"', '"%f"', '"%p"', '"%x"', '"%n"',
        '"%10d"', '"%.5f"', '"%*d"', '"%1$d"', '"%%"',
    ],
    "fuzz_locale": [
        '"C"',
        '"POSIX"',
        '"en_US.UTF-8"',
        '"messages"',
        '"/usr/share/locale"',
        '"CODESET"',
        '"RADIXCHAR"',
        '"LC_ALL"',
    ],
    "fuzz_runtime_math": [
        '"strict"', '"hardened"', '"off"',
        '"allocator"', '"resolver"', '"locale"', '"runtime-math"',
    ],
    "fuzz_elf_loader": [
        '"ELF"',
        '"PT_LOAD"',
        '"PT_DYNAMIC"',
        '".dynsym"',
        '".dynstr"',
        '".rela.dyn"',
        '"R_X86_64_RELATIVE"',
        '"R_X86_64_JUMP_SLOT"',
        '"malloc"',
        '"GLIBC_2.2.5"',
    ],
}

GENERIC_DICTIONARY = [
    '"\\x00"',
    '"\\xff"',
    '"A"',
    '"0"',
    '" "',
    '"\\n"',
]


def has_structured_input_guard(content):
    """Detect explicit size bounding in structured-input fuzz targets."""
    guard_patterns = [
        r"\b\w+(?:\.\w+)*\.len\(\)\s*(?:==|!=|<=|>=|<|>)",
        r"\b\w+(?:\.\w+)*\.is_empty\(\)",
        r"\.min\(\s*\d+\s*\)",
        r"\.max\(\s*\d+\s*\)",
        r"\.clamp\(\s*[^,]+,\s*[^)]+\)",
    ]
    return any(re.search(pattern, content) for pattern in guard_patterns)


def dictionary_for_target(target_name, analysis):
    """Return dictionary entries for a target, using domain fallbacks."""
    if target_name in DICTIONARIES:
        return DICTIONARIES[target_name]

    category = analysis.get("category", "")
    domain = analysis.get("domain", "")
    if "string" in category or target_name in {"fuzz_ctype", "fuzz_iconv", "fuzz_scanf"}:
        return GENERIC_DICTIONARY + ['"%s"', '"%d"', '"UTF-8"', '"ASCII"']
    if "math" in category or domain == "runtime-kernel" or target_name in {"fuzz_math", "fuzz_time"}:
        return GENERIC_DICTIONARY + ['"nan"', '"inf"', '"-inf"', '"0.0"', '"1.0"']
    if "resolver" in category or target_name in {"fuzz_inet", "fuzz_resolv", "fuzz_resolver", "fuzz_pwd_grp", "fuzz_dirent"}:
        return GENERIC_DICTIONARY + ['"localhost"', '"127.0.0.1"', '"::1"', '"/etc/passwd"']
    return GENERIC_DICTIONARY


def analyze_target(target_name, source_path):
    """Analyze a fuzz target source file."""
    try:
        content = source_path.read_text()
    except OSError:
        return {"error": f"Cannot read {source_path}"}

    checks = []
    for check_name, pattern, description in HARNESS_CHECKS:
        if check_name == "input_size_guard":
            passed = has_structured_input_guard(content)
        else:
            found = bool(re.search(pattern, content))
            # no_unwrap and no_panic are negative checks (want NOT found)
            if check_name in ("no_unwrap", "no_panic"):
                passed = not found
            else:
                passed = found
        if check_name in ("no_unwrap", "no_panic"):
            found = bool(re.search(pattern, content))
            passed = not found
        checks.append({
            "check": check_name,
            "passed": passed,
            "description": description,
        })

    # Detect TODO markers
    todos = re.findall(r"//\s*TODO:?\s*(.*)", content)

    # Implementation maturity
    has_real_logic = ("arena" in content.lower()
                      or "pipeline" in content.lower()
                      or "validate" in content.lower()
                      or "frankenlibc" in content)
    is_stub = len(todos) > 0 and not has_real_logic

    domain_info = TARGET_DOMAINS.get(target_name, {})

    return {
        "target": target_name,
        "source": str(source_path.relative_to(source_path.parent.parent.parent.parent)),
        "domain": domain_info.get("domain", "unknown"),
        "category": domain_info.get("category", "unknown"),
        "description": domain_info.get("description", ""),
        "priority": domain_info.get("priority", "normal"),
        "cwe_coverage": domain_info.get("cwe_coverage", []),
        "checks": checks,
        "checks_passed": sum(1 for c in checks if c["passed"]),
        "checks_total": len(checks),
        "todos": todos,
        "implementation_status": "stub" if is_stub else "functional",
        "lines": len(content.splitlines()),
    }


def build_corpus_manifest(target_name):
    """Build deterministic corpus manifest for a target."""
    root = find_repo_root()
    corpus_dir = root / "crates" / "frankenlibc-fuzz" / "corpus" / target_name
    seeds_data = []
    if corpus_dir.exists():
        for seed_path in sorted(p for p in corpus_dir.iterdir() if p.is_file()):
            seeds_data.append(seed_path.read_bytes())
    else:
        gen = SEED_GENERATORS.get(target_name)
        if gen:
            seeds_data = gen()
        else:
            seeds_data = [target_name.encode("utf-8"), b"\x00", b"\xff\x00"]

    seeds = []
    for i, content in enumerate(seeds_data):
        seed_hash = compute_seed_hash(target_name, i, content)
        seeds.append({
            "index": i,
            "seed_id": f"seed-{seed_hash}",
            "size_bytes": len(content),
            "sha256_prefix": seed_hash,
        })

    return {
        "target": target_name,
        "seeds": seeds,
        "count": len(seeds),
        "strategy": "deterministic",
        "reproducible": True,
    }


def build_dictionary_manifest(target_name):
    """Build dictionary manifest for a target."""
    root = find_repo_root()
    dict_path = root / "crates" / "frankenlibc-fuzz" / "dictionaries" / f"{target_name}.dict"
    if dict_path.exists():
        entries = [
            line.strip()
            for line in dict_path.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    else:
        analysis = analyze_target(
            target_name, root / "crates" / "frankenlibc-fuzz" / "fuzz_targets" / f"{target_name}.rs"
        )
        entries = dictionary_for_target(target_name, analysis)
    return {
        "target": target_name,
        "entries": entries,
        "count": len(entries),
        "format": "libfuzzer",
    }


def main():
    parser = argparse.ArgumentParser(
        description="Fuzz harness architecture spec generator")
    parser.add_argument("-o", "--output", help="Output file path")
    args = parser.parse_args()

    root = find_repo_root()
    fuzz_dir = root / "crates" / "frankenlibc-fuzz"
    targets_dir = fuzz_dir / "fuzz_targets"

    if not targets_dir.exists():
        print("ERROR: fuzz_targets/ not found", file=sys.stderr)
        sys.exit(1)

    # Parse Cargo.toml for target list
    cargo_toml = fuzz_dir / "Cargo.toml"
    target_names = []
    if cargo_toml.exists():
        content = cargo_toml.read_text()
        for m in re.finditer(r'name\s*=\s*"(fuzz_\w+)"', content):
            target_names.append(m.group(1))

    # Analyze each target
    target_analyses = []
    for name in sorted(target_names):
        source = targets_dir / f"{name}.rs"
        if source.exists():
            analysis = analyze_target(name, source)
            target_analyses.append(analysis)

    # Build corpus manifests
    corpus_manifests = []
    for name in sorted(target_names):
        manifest = build_corpus_manifest(name)
        corpus_manifests.append(manifest)

    # Build dictionary manifests
    dict_manifests = []
    for name in sorted(target_names):
        manifest = build_dictionary_manifest(name)
        dict_manifests.append(manifest)

    # Quality checklist summary
    total_checks = sum(t["checks_total"] for t in target_analyses)
    passed_checks = sum(t["checks_passed"] for t in target_analyses)
    functional_targets = sum(
        1 for t in target_analyses if t["implementation_status"] == "functional")
    stub_targets = sum(
        1 for t in target_analyses if t["implementation_status"] == "stub")
    total_seeds = sum(c["count"] for c in corpus_manifests)
    total_dict_entries = sum(d["count"] for d in dict_manifests)

    # Covered CWEs
    all_cwes = set()
    for t in target_analyses:
        all_cwes.update(t.get("cwe_coverage", []))

    # Harness conventions spec
    harness_conventions = {
        "required_attributes": ["#![no_main]"],
        "required_macros": ["fuzz_target!"],
        "input_handling": {
            "size_guard": "All targets must check data.len() before parsing",
            "null_termination": "String targets must ensure null-terminated input",
            "chunk_parsing": "Multi-op targets parse data in fixed-size chunks",
        },
        "safety_rules": [
            "No unwrap() — use safe alternatives or early return",
            "No explicit panic! — let libfuzzer handle assertion failures",
            "All allocations must be cleaned up on all paths",
            "Fuzzer must not depend on external state (filesystem, network)",
        ],
        "artifact_layout": {
            "corpus": "crates/frankenlibc-fuzz/corpus/<target_name>/",
            "dictionary": "crates/frankenlibc-fuzz/dictionaries/<target_name>.dict",
            "crashes": "crates/frankenlibc-fuzz/artifacts/<target_name>/",
        },
        "domains": {
            "abi-entrypoint": "Fuzz exported C ABI symbols (string, printf, stdlib)",
            "allocator": "Fuzz malloc/free/realloc sequences and edge cases",
            "loader": "Fuzz ELF object parsing, symbol lookup, and relocation machinery",
            "locale": "Fuzz locale categories, langinfo selectors, and C-locale stateful APIs",
            "membrane": "Fuzz TSM validation pipeline with arbitrary inputs",
            "runtime-math": "Fuzz math library functions (future)",
        },
    }

    report = {
        "schema_version": "v1",
        "bead": "bd-1oz.5",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "total_targets": len(target_analyses),
            "functional_targets": functional_targets,
            "stub_targets": stub_targets,
            "checks_passed": passed_checks,
            "checks_total": total_checks,
            "quality_score_pct": round(passed_checks / total_checks * 100, 1)
            if total_checks > 0 else 0,
            "total_seed_corpus": total_seeds,
            "total_dict_entries": total_dict_entries,
            "cwe_coverage": sorted(all_cwes),
            "unique_cwes": len(all_cwes),
            "domains_covered": sorted(set(
                t["domain"] for t in target_analyses if t["domain"] != "unknown")),
        },
        "harness_conventions": harness_conventions,
        "target_analyses": target_analyses,
        "corpus_strategy": {
            "approach": "deterministic",
            "description": "Each target gets hand-crafted seed inputs covering "
                           "boundary conditions, typical usage, and attack patterns. "
                           "Seeds are content-addressed for reproducibility.",
            "manifests": corpus_manifests,
        },
        "dictionary_strategy": {
            "format": "libfuzzer",
            "description": "Per-target dictionaries with domain-specific tokens "
                           "to guide mutation toward high-signal inputs.",
            "manifests": dict_manifests,
        },
        "quality_checklist": {
            "convention_compliance": f"{passed_checks}/{total_checks} checks passed",
            "implementation_coverage": f"{functional_targets}/{len(target_analyses)} targets functional",
            "corpus_seeded": f"{sum(1 for c in corpus_manifests if c['count'] > 0)}/{len(target_analyses)} targets with seeds",
            "dictionary_created": f"{sum(1 for d in dict_manifests if d['count'] > 0)}/{len(target_analyses)} targets with dictionaries",
            "cwe_mapping": f"{len(all_cwes)} CWEs covered across targets",
        },
    }

    output = json.dumps(report, indent=2) + "\n"
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
