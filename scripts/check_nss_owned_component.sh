#!/usr/bin/env bash
# Execute exact NSS source against a real native loader, without changing the
# product's standalone admission checks. Build the core rlib normally first:
#   cargo build --release -p frankenlibc-core --lib
# Arguments identify the matching core/libc rlibs and their dependency tree;
# no source is copied, rewritten, or substituted for the production NSS module.
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: $0 CANDIDATE_DSO CORE_RLIB LIBC_RLIB DEPENDENCY_TREE OUTPUT_DIRECTORY" >&2
  exit 2
fi
root="$(cd "$(dirname "$0")/.." && pwd)"
candidate="$(realpath "$1")"
core_rlib="$(realpath "$2")"
libc_rlib="$(realpath "$3")"
dependency_tree="$(realpath "$4")"
output="$5"
mkdir -p "$output"
output="$(realpath "$output")"

for file in "$candidate" "$core_rlib" "$libc_rlib"; do
  [[ -s "$file" ]] || { echo "missing input: $file" >&2; exit 1; }
done
compiler="${CC:-cc}"
for service in flowned flownedlegacy flownedtuple; do
  extra=()
  case "$service" in
    flownedlegacy) extra=(-DNO_HOST3 -DNO_HOST2 -DNO_HOSTADDR2 -DNO_INITGROUPS) ;;
    flownedtuple) extra=(-DWITH_HOST4 -DNO_HOST1 -DNO_HOST2 -DNO_HOST3) ;;
  esac
  "$compiler" -std=c11 -D_GNU_SOURCE -O2 -Wall -Wextra -Werror \
    -shared -fPIC -nostdlib -fno-stack-protector -DFLTEST_NATIVE_MODULE \
    "-DSERVICE=$service" "${extra[@]}" \
    "-Wl,-soname,libnss_$service.so.2" -Wl,--hash-style=both \
    "$root/tests/integration/fixture_nss_module_lib.c" \
    -o "$output/libnss_$service.so.2"
  readelf -dW "$output/libnss_$service.so.2" > "$output/$service.dynamic"
  if grep -q '(NEEDED)' "$output/$service.dynamic"; then
    echo "fixture must not import a host runtime DSO: $service" >&2
    exit 1
  fi
done

dependencies=()
externs=(--extern "frankenlibc_core=$core_rlib" --extern "libc=$libc_rlib")
# Newer Cargo artifact layouts keep metadata beside the archive. Pass both
# when present so rustc can read the matching crate metadata and link its code.
if [[ -s "${core_rlib%.rlib}.rmeta" ]]; then
  externs+=(--extern "frankenlibc_core=${core_rlib%.rlib}.rmeta")
fi
if [[ -s "${libc_rlib%.rlib}.rmeta" ]]; then
  externs+=(--extern "libc=${libc_rlib%.rlib}.rmeta")
fi
while IFS= read -r directory; do
  dependencies+=(-L "dependency=$directory")
done < <(rg --files "$dependency_tree" | python3 -c '
import pathlib, sys
suffixes = (".rlib", ".rmeta", ".so", ".dylib", ".dll")
print("\n".join(sorted({str(pathlib.Path(p.strip()).parent) for p in sys.stdin if p.rstrip().endswith(suffixes)})))
')
"${RUSTC:-rustc}" --edition=2024 --test -D warnings -C debuginfo=0 -Zthreads=1 \
  --cfg 'feature="standalone"' \
  "${externs[@]}" \
  "${dependencies[@]}" "$root/tests/integration/nss_owned_component.rs" \
  -o "$output/nss-owned-component"

export FRANKENLIBC_NSS_COMPONENT_CANDIDATE="$candidate"
export FRANKENLIBC_NSS_COMPONENT_FIXTURES="$output"
# The provider's initial-exec TLS exceeds GNU's default dlopen surplus once
# deep binding selects its own TLS symbols. Reserve space at process startup;
# this changes the component host's resources, not provider selection or code.
export GLIBC_TUNABLES=glibc.rtld.optional_static_tls=32768
unset LD_PRELOAD LD_AUDIT FRANKENLIBC_NSS_COMPONENT_CHILD
"$output/nss-owned-component" --nocapture --test-threads=1 2>&1 | tee "$output/component.log"
grep -F 'test result: ok. 1 passed; 0 failed;' "$output/component.log"
echo 'PASS: exact-source owned NSS component; full standalone admission remains separate'
