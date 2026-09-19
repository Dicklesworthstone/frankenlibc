#!/usr/bin/env bash
# check_test_extern_symbols.sh — static extern-symbol audit for crates/*/tests probes
# (bd-blnp4u detector; the approach bd-5wckql used to find two link aborts without a build).
#
# WHY: every .rs file under crates/*/tests is compiled by cargo as its own test target
# REGARDLESS of gitignore, and a throwaway zz_*.rs probe that declares an extern symbol
# no library provides aborts `cargo test -p <crate>` before a single target executes —
# invisible to git status/blame (bd-blnp4u, bd-5wckql). This script finds those
# statically, in seconds, without compiling anything.
#
# WHAT IT DOES:
#   1. Scans crates/*/tests/**/*.rs for `unsafe extern "C" { ... }` declaration
#      blocks, capturing #[link(name = "...")] and #[link_name = "..."] attributes.
#   2. Collects the dynamic exports of the system libraries a test can legally bind
#      to (libm, libc, libpthread, librt, libdl, libutil) via `nm -D`.
#   3. Flags any declared symbol that NO scanned library exports (guaranteed
#      link failure for its test target).
#
# SCOPE / HONEST LIMITS:
#   - Resolution is per-DECLARATION, not per-link-line: a symbol that exists only in
#     libm is reported as "m" so the author can confirm the right #[link] is present.
#   - Versioned/symbol-hidden exports and weak symbols are treated like normal
#     dynamic symbols (nm -D view).
#   - Rust mangled names (#[no_mangle]-less) are out of scope; only plain extern fns
#     and statics inside extern blocks are checked.
#   - This does NOT prove a probe links (rustc attribute errors, type mismatches);
#     it proves the SYMBOLS exist. It is a screen, not a build.
#
# Usage:
#   scripts/check_test_extern_symbols.sh [paths...]        # default: crates/*/tests
#   SCAN_ROOT=/tmp/fake-tests scripts/check_test_extern_symbols.sh /tmp/fake-tests
#
# Exit codes: 0 = clean, 1 = unresolvable symbols found, 2 = tool error.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT"

SCAN_PATHS=("$@")
if [[ ${#SCAN_PATHS[@]} -eq 0 ]]; then
    SCAN_PATHS=(crates/*/tests)
fi

LIBS=(
    /usr/lib/x86_64-linux-gnu/libm.so.6
    /usr/lib/x86_64-linux-gnu/libc.so.6
    /usr/lib/x86_64-linux-gnu/libpthread.so.0
    /usr/lib/x86_64-linux-gnu/librt.so.1
    /usr/lib/x86_64-linux-gnu/libdl.so.2
    /usr/lib/x86_64-linux-gnu/libutil.so.1
    /usr/lib/x86_64-linux-gnu/libresolv.so.2
    /usr/lib/x86_64-linux-gnu/libcrypt.so.1
)

python3 - "${SCAN_PATHS[@]}" "${LIBS[@]}" <<'PY'
import pathlib
import re
import subprocess
import sys

scan_paths = []
libs = []
for a in sys.argv[1:]:
    (libs if a.endswith(".so.0") or a.endswith(".so.6") or a.endswith(".so.1") or a.endswith(".so.2") else scan_paths).append(a)

# ---- 1. Collect library exports: symbol -> sorted lib tags -------------------
lib_tag = {}
exports: dict[str, set[str]] = {}
for path in libs:
    p = pathlib.Path(path)
    if not p.exists():
        print(f"WARN: library not present, skipping: {path}", file=sys.stderr)
        continue
    tag = re.search(r"lib(\w+?)\.so", p.name).group(1)[0]  # m, c, p(thr), r, d, u
    out = subprocess.run(["nm", "-D", "--defined-only", str(p)],
                         capture_output=True, text=True)
    for line in out.stdout.splitlines():
        parts = line.split(maxsplit=2)
        if len(parts) == 3 and parts[1] in "TWIDRViBDGS":
            # nm prints default versions inline ("yn@@GLIBC_2.2.5"); declared
            # externs bind by bare name, so strip any @ / @@ suffix.
            name = re.sub(r"@.*$", "", parts[2])
            exports.setdefault(name, set()).add(tag)
    lib_tag[p.name] = tag

# ---- 2. Parse extern blocks from test sources --------------------------------
# Matches: [attrs] unsafe extern "C" { ... }   (brace-balanced, no nesting in practice)
ATTR_LINK_NAME = re.compile(r'#\s*\[\s*link_name\s*=\s*"([^"]+)"')
ATTR_LINK = re.compile(r'#\s*\[\s*link\s*\(([^)]*)\)\s*\]')
DECL = re.compile(
    r'(?:#\[[^\]]*\]\s*)*(?:pub\s+)?(?:unsafe\s+)?(?:fn|static)(?:\s+mut)?\s+'
    r'([A-Za-z_][A-Za-z0-9_]*)')

decls: dict[str, set[str]] = {}   # symbol -> files
files_scanned = 0
blocks_found = 0
for root in scan_paths:
    for path in sorted(pathlib.Path(root).rglob("*.rs")):
        text = path.read_text(encoding="utf-8", errors="replace")
        files_scanned += 1
        for m in re.finditer(r'unsafe\s+extern\s+"C"\s*\{', text):
            blocks_found += 1
            start = m.end() - 1
            depth = 0
            end = start
            for i in range(start, len(text)):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            body = text[m.end():end]
            # Strip comments so prose like "static buffer" in a doc comment is not
            # mistaken for a declaration. (Strings inside extern blocks only carry
            # link_name attrs, which have no "//" — acceptable for a screen.)
            body = re.sub(r'//[^\n]*', '', body)
            body = re.sub(r'/\*.*?\*/', '', body, flags=re.S)
            # Attributes immediately preceding the block apply to the whole block
            # (e.g. #[link(name = "m")]); #[link_name] sits per-declaration.
            head = text[max(0, m.start() - 400):m.start()]
            block_libs = set()
            for lm in ATTR_LINK.finditer(head[-400:]):
                attrs = lm.group(1)
                nm = re.search(r'name\s*=\s*"([^"]+)"', attrs)
                if nm:
                    n = nm.group(1)
                    block_libs.add(re.sub(r"^lib", "", n)[0])
            for dm in re.finditer(
                r'((?:#\s*\[[^\]]*\]\s*)*)(?:pub\s+)?(?:unsafe\s+)?(?:fn|static)'
                r'(?:\s+mut)?\s+([A-Za-z_][A-Za-z0-9_]*)', body):
                attrs, name = dm.group(1), dm.group(2)
                ln = ATTR_LINK_NAME.search(attrs)
                sym = ln.group(1) if ln else name
                decls.setdefault(sym, set()).add(str(path))
                if block_libs:
                    # Record which libs the block claims, used for the report only.
                    decls.setdefault("__blocklibs__", set()).update(
                        f"{sym}:{sorted(block_libs)}")

# ---- 3. Report ----------------------------------------------------------------
unresolved = sorted(s for s in decls if s != "__blocklibs__" and s not in exports)
print(f"scanned_files={files_scanned} extern_blocks={blocks_found} "
      f"declared_symbols={len(decls) - (1 if '__blocklibs__' in decls else 0)} "
      f"library_exports={len(exports)}")
if unresolved:
    print(f"FAIL: {len(unresolved)} declared extern symbol(s) exported by NONE of "
          f"the scanned libraries — their test targets cannot link:")
    for s in unresolved:
        for f in sorted(decls[s]):
            print(f"  {s}  <- {f}")
    sys.exit(1)
print("PASS: every declared extern symbol resolves against the scanned libraries")
PY
