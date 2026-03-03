# LLVM libc Overlay + Allocator Study (bd-2icq.1)

Date: 2026-03-03  
Scope: partial overlay mechanism, malloc design, TLS/errno/global-state handling, ABI strategy, test strategy, GPU allocator evolution.

## Primary Sources

- Overlay mode docs: <https://libc.llvm.org/overlay_mode.html>
- Build/test modes: <https://libc.llvm.org/build_and_test.html>
- Configure options: <https://libc.llvm.org/configure.html>
- Developer code style and header policy: <https://libc.llvm.org/dev/code_style.html>
- GPU docs: <https://libc.llvm.org/gpu/index.html>, <https://libc.llvm.org/gpu/using.html>, <https://libc.llvm.org/gpu/testing.html>
- LLVM libc source tree: <https://github.com/llvm/llvm-project/tree/main/libc>
- Allocator sources:
  - `libc/src/__support/freelist_heap.h`
  - `libc/src/__support/block.h`
  - `libc/src/__support/GPU/allocator.cpp`
  - `libc/src/stdlib/baremetal/malloc.cpp`
  - `libc/src/stdlib/gpu/malloc.cpp`
- Errno/TLS sources:
  - `libc/src/__support/libc_errno.h`
  - `libc/src/errno/libc_errno.cpp`
  - `libc/src/stdlib/exit.cpp`
- Archive construction source:
  - `libc/lib/CMakeLists.txt`
- GPU allocator commit history (path-filtered GitHub API):
  - `libc/src/__support/GPU/allocator.cpp`
  - `libc/src/stdlib/gpu/malloc.cpp`

## Direct Answers to the 7 Research Questions

### 1) How does LLVM libc handle symbol interposition with partial overlay?

- LLVM libc overlay mode is static-archive-first linking: symbols found in `libllvmlibc.a` are taken from LLVM libc; unresolved symbols fall through to system libc based on normal link order.
- Overlay explicitly keeps system headers in user code and avoids implementation-ABI-sensitive functions in the archive.
- In source build logic, non-full-build installs `llvmlibc` archive target (output name `libllvmlibc.a`) from `TARGET_LLVMLIBC_ENTRYPOINTS`.

Evidence:
- <https://libc.llvm.org/overlay_mode.html>
- <https://raw.githubusercontent.com/llvm/llvm-project/main/libc/lib/CMakeLists.txt>

### 2) What is LLVM libc's strategy for TLS and thread-local allocator state?

- `errno` is mode-selectable:
  - full-build default: thread-local errno (`LIBC_ERRNO_MODE_THREAD_LOCAL`),
  - public-packaging/overlay default: inline system errno (`LIBC_ERRNO_MODE_SYSTEM_INLINE`).
- Runtime implementations use `libc_errno` (not raw `errno`) and mode-specific backing in `libc_errno.cpp`.
- Overlay-mode limitation is documented in code for `exit`: TLS destructor finalization in overlay is currently caveated (`TODO`, linked issue).
- Allocator-wise, the examined baremetal allocator path uses a global `freelist_heap` singleton, not thread-local allocator state.

Evidence:
- <https://raw.githubusercontent.com/llvm/llvm-project/main/libc/src/__support/libc_errno.h>
- <https://raw.githubusercontent.com/llvm/llvm-project/main/libc/src/errno/libc_errno.cpp>
- <https://raw.githubusercontent.com/llvm/llvm-project/main/libc/src/stdlib/exit.cpp>
- <https://raw.githubusercontent.com/llvm/llvm-project/main/libc/src/__support/freelist_heap.cpp>

### 3) How do they handle errno and other global state?

- Errno is abstracted behind `libc_errno` and can be:
  - undefined,
  - thread-local,
  - shared global,
  - external callback-backed,
  - system-inline macro (`errno`) for overlay/public packaging.
- This decouples libc internals from one fixed errno storage model and enables overlay-safe operation.

Evidence:
- <https://raw.githubusercontent.com/llvm/llvm-project/main/libc/src/__support/libc_errno.h>
- <https://raw.githubusercontent.com/llvm/llvm-project/main/libc/src/errno/libc_errno.cpp>
- <https://libc.llvm.org/dev/code_style.html>

### 4) What's their ABI compatibility strategy with glibc?

- Overlay mode keeps user code on system headers and only includes archive functions that are ABI-safe without libc-private structs.
- Example from docs: `strlen`/`round` are suitable; `fopen` and `FILE`-dependent APIs are excluded.
- Internal source inclusion policy enforces header proxies under `hdr/` that branch on `LLVM_LIBC_FULL_BUILD` to avoid accidental ABI drift between full-build and overlay.

Evidence:
- <https://libc.llvm.org/overlay_mode.html>
- <https://libc.llvm.org/dev/code_style.html>

### 5) How do they test partial overlay configurations?

- In overlay mode, documented test command is `ninja check-libc`, and coverage is limited to functions in the overlay static archive.
- Full-build mode enables broader unit/integration targets.

Evidence:
- <https://libc.llvm.org/build_and_test.html>

### 6) What can we learn from GPU malloc additions?

- GPU allocator evolved from basic RPC-backed malloc/free toward an explicit slab allocator with bitfield allocation and parallel random-walk claiming.
- 2025 path history shows AMDGPU-focused `malloc`/`realloc`/`aligned_alloc` improvements and separate NVPTX constraints.
- Current `gpu/malloc.cpp` explicitly special-cases NVPTX behavior and routes non-NVPTX through internal GPU allocator hooks.

Evidence:
- <https://raw.githubusercontent.com/llvm/llvm-project/main/libc/src/__support/GPU/allocator.cpp>
- <https://raw.githubusercontent.com/llvm/llvm-project/main/libc/src/stdlib/gpu/malloc.cpp>
- Commit records:
  - `b4bc8c6f83` (2025-05-28): efficient GPU malloc
  - `10445acfa6` (2025-06-30): AMDGPU realloc
  - `24828c8c45` (2025-07-02): AMDGPU aligned_alloc
  - `256f40d0e6` (2025-01-24): NVPTX malloc behavior change

### 7) How does LLVM freelist allocator compare to FrankenLibC arena approach?

- LLVM (examined path):
  - best-fit freelist with split/merge blocks,
  - global heap object in baremetal path,
  - assertion-driven invalid/double-free checks in this implementation path.
- FrankenLibC (current project direction):
  - ABI-boundary validation membrane, generation-aware arena metadata, canaries/fingerprints, explicit strict/hardened policy routing, and auditable repair semantics.
- Main takeaway: LLVM overlay emphasizes incremental adoption and ABI-safe subset composition; FrankenLibC emphasizes dynamic safety enforcement and repair semantics on the ABI boundary.

## Side-by-Side Snapshot (Focused)

| Axis | LLVM libc Overlay | FrankenLibC |
| --- | --- | --- |
| Primary integration model | Static overlay archive + system libc fallback by link order | `LD_PRELOAD` interposition now; replacement progression planned |
| Header model in mixed mode | System headers in user code; internal proxy headers in libc sources | glibc ABI boundary with internal safe Rust core |
| ABI-sensitive symbols in mixed mode | Excluded from overlay archive if implementation-private ABI required | Routed through membrane; status tracked by support taxonomy |
| Errno mode | Configurable; overlay defaults to system-inline errno | Thread-local errno in core with membrane-governed behavior |
| Overlay test scope | `check-libc` for overlay-archive subset | Fixture-driven strict/hardened conformance and integration lanes |
| GPU allocator direction | Device slab allocator + RPC/backing allocator evolution | No GPU-specific allocator lane in main path today |

## Notes for FrankenLibC L1/L2/L3 Planning

- Keep explicit "overlay-safe subset" criteria (ABI-sensitive vs ABI-stable symbols).
- Keep mode-aware global-state abstractions (`errno`, TLS lifecycle) explicit in docs and tests.
- Keep packaging-level distinction crisp: mixed interpose lane vs full replacement lane.
