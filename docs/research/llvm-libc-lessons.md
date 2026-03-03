# LLVM libc Lessons for FrankenLibC (bd-2icq.1)

Date: 2026-03-03

This document distills actionable patterns from LLVM libc overlay/malloc design research into FrankenLibC execution guidance.

## High-Value Patterns to Adopt

### 1) Keep mixed-mode boundaries explicit

- LLVM libc draws a hard line between:
  - overlay mode (`libllvmlibc.a` + system libc),
  - full-build mode (LLVM libc as complete runtime).
- FrankenLibC should keep this same clarity across:
  - `L0/L1` interpose lanes,
  - `L2/L3` replacement lanes.

Action:
- enforce per-symbol packaging applicability in `support_matrix.json` and release gates.

### 2) Treat ABI-sensitive APIs as a first-class classification problem

- LLVM overlay excludes APIs requiring implementation-private ABI layouts (for example, `FILE`-dependent surfaces) from mixed mode.

Action:
- in FrankenLibC, classify symbols by "ABI-surface sensitivity" and require stricter closure criteria before promoting call paths from interpose to replacement.

### 3) Preserve header/type discipline when dual modes coexist

- LLVM source policy uses proxy headers (`hdr/`) with `LLVM_LIBC_FULL_BUILD` branching to avoid accidental type drift.

Action:
- keep FrankenLibC replacement-specific layout assumptions behind explicit build/mode gates; avoid silent leakage of replacement-only types into interpose assumptions.

### 4) Keep global-state policy configurable and testable

- LLVM `libc_errno` supports mode-specific storage and overlay-safe system-inline fallback.

Action:
- continue exposing explicit mode contracts for errno/TLS behavior and ensure strict/hardened tests assert these invariants per symbol family.

### 5) Evolve allocator strategy in staged lanes, not monolithically

- LLVM GPU allocator history shows iterative hardening (basic implementation -> efficient allocator -> architecture-specific refinements).

Action:
- keep FrankenLibC allocator and membrane changes in narrow, measurable slices with explicit perf and safety deltas per bead.

## What Not to Copy Directly

### 1) Assertion-only invalid-pointer handling at boundary surfaces

- LLVM allocator paths rely heavily on internal assertions in examined implementations.

Why not:
- FrankenLibC's value proposition is boundary-grade safety under hostile caller behavior, especially in hardened mode.

### 2) Overlay-mode TLS finalization ambiguity

- LLVM `exit` currently documents unresolved overlay TLS finalization caveats.

Why not:
- FrankenLibC must keep deterministic lifecycle behavior explicit for strict/hardened evidence and release gating.

### 3) Architecture-specific fallback behavior without explicit taxonomy impact

- NVPTX allocator behavior changes were pragmatic but architecture-constrained.

Why not:
- FrankenLibC should reflect such constraints immediately in support taxonomy and release contracts to avoid ambiguous claims.

## Recommended FrankenLibC Actions (L1/L2/L3)

### Near-Term (L1 interpose hardening)

1. Add "overlay-safe ABI subset" metadata to support matrix rows where mixed-mode assumptions exist.
2. Add a strict/hardened lifecycle test matrix for errno and TLS-destructor-sensitive entrypoints.
3. Add an explicit "global-state semantics" section to release evidence packets.

### Mid-Term (L2 replacement qualification)

1. Require per-family ABI-sensitivity closure checks before L2 promotion.
2. Gate L2 promotion on call-through elimination plus lifecycle determinism checks.
3. Introduce a replacement-only header/layout conformance audit similar in spirit to LLVM proxy-header discipline.

### Longer-Term (L3 replacement robustness)

1. Preserve interpose lane as a fallback/diagnostic mode with clear compatibility semantics.
2. Keep architecture-specific behavior (e.g., GPU/accelerator or ISA-specific quirks) as explicit policy-table artifacts, never implicit behavior.
3. Keep phased allocator evolution with perf/safety evidence and reversible rollout controls.

## Source Index

- Overlay mode: <https://libc.llvm.org/overlay_mode.html>
- Build/test mode split: <https://libc.llvm.org/build_and_test.html>
- Header policy + errno rules: <https://libc.llvm.org/dev/code_style.html>
- Errno implementation: <https://raw.githubusercontent.com/llvm/llvm-project/main/libc/src/__support/libc_errno.h>
- Exit/TLS caveat: <https://raw.githubusercontent.com/llvm/llvm-project/main/libc/src/stdlib/exit.cpp>
- Freelist allocator: <https://raw.githubusercontent.com/llvm/llvm-project/main/libc/src/__support/freelist_heap.h>
- GPU allocator: <https://raw.githubusercontent.com/llvm/llvm-project/main/libc/src/__support/GPU/allocator.cpp>
