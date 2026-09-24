#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 ]]; then echo "usage: $0 OUTPUT_DIRECTORY" >&2; exit 2; fi
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
mkdir -p -- "$1"
output=$(cd -- "$1" && pwd)
cc=${CC:-cc}
"$cc" -std=c11 -O2 -Wall -Wextra -Werror "$source_dir/host_probe.c" -ldl -pthread -o "$output/host_probe"
"$cc" -std=c11 -O2 -Wall -Wextra -Werror "$source_dir/contract_probe.c" -ldl -o "$output/contract_probe"
for hash in gnu sysv both; do
    full="$output/$hash/full"
    stripped="$output/$hash/sectionless"
    mkdir -p -- "$full" "$stripped"
    options=(-std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared -nostdlib "-Wl,--hash-style=$hash")
    "$cc" "${options[@]}" "$source_dir/provider.c" \
        -Wl,-soname,libversions.so "-Wl,--version-script=$source_dir/provider.map" -o "$full/libversions.so"
    "$cc" "${options[@]}" "$source_dir/consumer.c" -L"$full" -lversions \
        '-Wl,-rpath,$ORIGIN' -o "$full/consumer.so"
    "$cc" "${options[@]}" "$source_dir/legacy.c" -o "$full/legacy.so"
    "$cc" "${options[@]}" "$source_dir/unversioned.c" -o "$full/unversioned.so"
    "$cc" "${options[@]}" "$source_dir/plain_provider.c" -Wl,-soname,libversions.so -o "$full/plain_provider.so"
    python3 - "$full" "$stripped" <<'PY'
import pathlib, struct, sys
source, destination = map(pathlib.Path, sys.argv[1:])
for name in ('libversions.so', 'consumer.so', 'legacy.so', 'unversioned.so'):
    data = bytearray((source / name).read_bytes())
    if data[:6] != b'\x7fELF\x02\x01':
        raise SystemExit('fixtures require little-endian ELF64')
    struct.pack_into('<Q', data, 40, 0)  # e_shoff
    struct.pack_into('<HHH', data, 58, 0, 0, 0)
    (destination / name).write_bytes(data)
PY
    python3 "$source_dir/contracts.py" "$output/$hash"
done
