# EXISTING_GLIBC_STRUCTURE.md

> Spec extraction baseline from `legacy_glibc_code/glibc` for clean-room Rust implementation.

## 1. Repository Scale Snapshot

Extracted from the local legacy source tree in this repository:

- Total files: `20767`
- Code files (`.c/.S/.s/.cc`): `13510`
- Header files (`.h`): `3495`

Large top-level components by file count include:

- `sysdeps`: `11209`
- `localedata`: `913`
- `elf`: `890`
- `iconvdata`: `681`
- `stdio-common`: `658`
- `math`: `592`
- `nptl`: `357`
- `benchtests`: `358`

## 2. ABI Surface Baseline (Host libc Snapshot)

Host baseline (`/usr/lib/x86_64-linux-gnu/libc.so.6`) exported symbol count:

- Defined dynamic symbols: `3160`

Initial milestone symbol/version seed (string/memory slice):

- `memchr@@GLIBC_2.2.5`
- `memcmp@@GLIBC_2.2.5`
- `memcpy@@GLIBC_2.14`
- `memcpy@GLIBC_2.2.5`
- `memmove@@GLIBC_2.2.5`
- `memrchr@@GLIBC_2.2.5`
- `memset@@GLIBC_2.2.5`
- `rawmemchr@@GLIBC_2.2.5`
- `stpcpy@@GLIBC_2.2.5`
- `stpncpy@@GLIBC_2.2.5`
- `strcat@@GLIBC_2.2.5`
- `strchr@@GLIBC_2.2.5`
- `strcmp@@GLIBC_2.2.5`
- `strcpy@@GLIBC_2.2.5`
- `strlen@@GLIBC_2.2.5`
- `strncat@@GLIBC_2.2.5`
- `strncmp@@GLIBC_2.2.5`
- `strncpy@@GLIBC_2.2.5`
- `strnlen@@GLIBC_2.2.5`
- `strrchr@@GLIBC_2.2.5`
- `strstr@@GLIBC_2.2.5`
- `strtok@@GLIBC_2.2.5`

## 3. String Subsystem Baseline

Legacy source reference:
- `legacy_glibc_code/glibc/string/`
- `legacy_glibc_code/glibc/string/Versions`

`string/Versions` exports include (non-exhaustive by version band):

- `GLIBC_2.0`: `memcpy`, `memmove`, `memset`, `memcmp`, `memchr`, `str*` core set
- `GLIBC_2.1`: `mempcpy`, `rawmemchr`, `strcasestr`, `strverscmp`
- `GLIBC_2.2`: `memrchr`
- `GLIBC_2.25`: `explicit_bzero`
- `GLIBC_2.38`: `strlcat`, `strlcpy`
- `GLIBC_2.43`: `memset_explicit`

## 4. Wide String / Multibyte Baseline

Legacy source reference:
- `legacy_glibc_code/glibc/wcsmbs/`
- `legacy_glibc_code/glibc/wcsmbs/Versions`

Key export groups include:

- Wide string core: `wcscpy`, `wcslen`, `wcscmp`, `wcsncmp`, `wcsxfrm`, etc.
- Wide memory: `wmemcpy`, `wmemmove`, `wmemcmp`, etc.
- Conversion APIs: `mbrtowc`, `wcrtomb`, `c16rtomb`, `c32rtomb`, `mbrtoc16`, `mbrtoc32`, `c8rtomb`, `mbrtoc8`.

## 5. Behavior Extraction Policy

Implementation may only use this extracted spec and subsequent updates to this document.

Rules:

1. Add exact behavior notes before implementing a new API slice.
2. Record edge cases as explicit fixture ids.
3. Record symbol/version requirements per function family.

## 6. Priority Bring-Up Order

1. String/memory primitives (hot path + broad dependency fan-out)
2. `stdio-common` minimal correctness surface
3. `stdlib` and `time`
4. `pthread`/sync and dynamic linker-adjacent surfaces
5. Remaining long-tail APIs and architecture-specific optimization passes

