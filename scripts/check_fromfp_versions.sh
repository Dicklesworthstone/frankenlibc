#!/usr/bin/env bash
# bd-dzsk9d: test the deployed ELF, not the rlib's Rust signatures.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="${1:-${FRANKENLIBC_SMOKE_LIB_PATH:-$ROOT/target/release/libfrankenlibc_abi.so}}"
LIB="$(realpath -- "$LIB")"
[[ -f "$LIB" ]] || { echo "Missing release library: $LIB" >&2; exit 2; }
OUT="$(mktemp -d)"
trap 'rm -rf -- "$OUT"' EXIT
readelf --dyn-syms --wide "$LIB" > "$OUT/symbols"
python3 - "$OUT/symbols" <<'PY'
import pathlib
import sys
names = {line.split()[-1] for line in pathlib.Path(sys.argv[1]).read_text().splitlines() if line.split()}
errors = []
for suffix, old in [("", "2.25"), ("f", "2.25"), ("l", "2.25"),
                    ("f32", "2.27"), ("f64", "2.27"), ("f32x", "2.27"),
                    ("f64x", "2.27"), ("f128", "2.26")]:
    for family in ["fromfp", "ufromfp", "fromfpx", "ufromfpx"]:
        name = family + suffix
        for required in [f"{name}@GLIBC_{old}", f"{name}@@GLIBC_2.43"]:
            if required not in names:
                errors.append("missing " + required)
        if name in names:
            errors.append("unsafe unversioned export " + name)
if errors:
    raise SystemExit("\n".join(errors))
print("fromfp ELF versions: 64 exports checked")
PY
"${CC:-cc}" -std=gnu11 -O2 -Wall -Wextra -Werror \
    "$ROOT/tests/integration/fixture_fromfp_versions.c" -ldl -o "$OUT/probe"
for mode in strict hardened; do
    echo "fromfp mode=$mode"
    timeout 30s env FRANKENLIBC_MODE="$mode" LD_PRELOAD="$LIB" "$OUT/probe" "$LIB"
done
