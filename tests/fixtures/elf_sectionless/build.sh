#!/usr/bin/env bash
# Build real linker-produced, self-contained DSOs, then remove ONLY their
# section-header tables/non-loadable tail. Runtime metadata is not synthesized.
set -euo pipefail
if [[ $# != 3 || ! $2 =~ ^(gnu|sysv|both)$ || ! $3 =~ ^(plain|relr)$ ]]; then
    echo "usage: $0 OUTPUT_DIRECTORY {gnu|sysv|both} {plain|relr}" >&2
    exit 2
fi
out=$1
style=$2
packing=$3
src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
mkdir -p -- "$out"
for name in libsectionless_dep.unstripped.so libsectionless_root.unstripped.so libsectionless_dep.so libsectionless_root.so host_probe; do
    if [[ -e $out/$name ]]; then
        echo "refusing to overwrite fixture: $out/$name" >&2
        exit 2
    fi
done
cc=${CC:-cc}
flags=(-shared -nostdlib -fPIC -O2 -fno-stack-protector "-Wl,--hash-style=$style")
if [[ $packing == relr ]]; then flags+=(-Wl,-z,pack-relative-relocs); fi
"$cc" "${flags[@]}" -Wl,-soname,libsectionless_dep.so \
    "-Wl,--version-script=$src/dependency.map" "$src/dependency.c" -o "$out/libsectionless_dep.unstripped.so"
# The link name is also the dependency's final runtime name. Preserve the
# original separately for the sectionful/sectionless metadata comparison.
cp -- "$out/libsectionless_dep.unstripped.so" "$out/libsectionless_dep.so"
"$cc" "${flags[@]}" -Wl,-soname,libsectionless_root.so \
    "-Wl,--version-script=$src/root.map" '-Wl,-rpath,$ORIGIN' \
    "$src/root.c" "-L$out" -lsectionless_dep -o "$out/libsectionless_root.unstripped.so"
python3 - "$out" <<'PY'
from pathlib import Path
import struct
import sys
out = Path(sys.argv[1])
for name in ("dep", "root"):
    data = bytearray((out / f"libsectionless_{name}.unstripped.so").read_bytes())
    if data[:6] != b"\x7fELF\x02\x01":
        raise SystemExit("fixture compiler must emit little-endian ELF64")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    if phentsize != 56 or phnum == 0:
        raise SystemExit("unexpected ELF program header layout")
    end = phoff + phentsize * phnum
    for index in range(phnum):
        kind, flags, offset, vaddr, paddr, filesz, memsz, align = struct.unpack_from("<IIQQQQQQ", data, phoff + index * phentsize)
        if filesz:
            end = max(end, offset + filesz)
    if end > len(data):
        raise SystemExit("fixture program headers are out of bounds")
    struct.pack_into("<Q", data, 40, 0)
    struct.pack_into("<HHH", data, 58, 0, 0, 0)
    (out / f"libsectionless_{name}.so").write_bytes(data[:end])
PY
"$cc" -O2 -Wall -Wextra -Werror "$src/host_probe.c" -ldl -pthread -o "$out/host_probe"
