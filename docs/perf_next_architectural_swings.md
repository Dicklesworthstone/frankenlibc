# Perf: next architectural swings vs glibc (frontier scoping)

Companion to `docs/NEGATIVE_EVIDENCE.md`. Records the *shape* of the remaining
measured gaps so LAND-OR-DIG turns stop re-deriving "the tractable frontier is
saturated" (independently reached on 2026-06-27 across multiple turns). Read this
**before** digging: the cheap byte-identical levers are spent; what's left are
dedicated multi-turn swings or accuracy-hard ports. Each item below is measured,
not speculative.

## What is already done (do NOT re-attempt)

- **Core string/wide scan family — SATURATED (cc/BoldFalcon 2026-06-27).** Ran
  `string_inprocess_survey_bench` (reliable in-process vs glibc). The remaining
  fl-slower rows are all already-aggressive `std::simd` kernels: `wmemchr` 1.61x,
  `wcsnlen` 1.85x, `strrchr` 1.86x — each is a 64-lane panel scan (`wmemchr`/`wcsnlen`)
  or a single-pass SIMD last-byte scan (`strrchr` via `find_last_byte_before_nul`).
  This is the documented "deeper hand-tuned-AVX2 + ifunc" gap that portable std::simd
  cannot close (prior attempts disproven; see the small-input string memory). **BENCH
  TRAP fixed:** the survey's `rawmemchr` and `wcschrnul` "scalar_current" arms were
  STALE local scalar replicas advertising phantom ~39x / ~1.5x deployed gaps — both
  deployed impls are SIMD since bd-2g7oyh. Relabeled to `scalar_historical` with
  corrected comments so future digs aren't misled. Most other string fns WIN
  (strchrnul 0.66x, strtok_r 0.67x, wcstok 0.57x, memfrob 0.60x, asctime 0.13x).
- **Membrane observe()/decide() fast-path vein — COMPLETE.** Every high-frequency
  family is in the strict fast-path set in `runtime_policy::decide`
  (`crates/frankenlibc-abi/src/runtime_policy.rs` ~line 2065): Allocator,
  StringMemory, Ctype, Loader, Stdlib, MathFenv, Stdio, IoFd, Time, Inet. The
  remaining families (Socket/Signal/Process/Poll/VirtualMemory/Resolver/Termios/
  Locale) are syscall/IO-dominated — membrane tax is negligible vs the syscall, so
  fast-pathing them is ~0-gain. Wide-char ops route through StringMemory (already
  fast-pathed); there is no separate Wchar family. The pthread hot path
  (`pthread_mutex_lock`) is already a direct futex and does **not** consult the
  membrane (the `threading_stage_context`/`record_threading_stage_outcome` helpers
  are dead code).
- **stdio registry micro-levers — spent.** Custom FNV `StreamIdHasher` (not
  SipHash) already; `parking_lot` registry mutex landed (a564ca8ae, fputs −11%).
- **f64/f32 math hot fns — done & winning** (powf/exp/exp2/log/log2/exp10/cbrt/
  hypot/tgamma, large-arg sin/cos/tan). See the math memory veins.

## Swing 1 — stdio per-stream / sharded registry lock (biggest gap)

- **Measured:** single-thread `fputs` **6.22x slower than glibc** (a564ca8ae);
  8-thread `stdio_mt_contention_8t` **8.6x slower** (fl 56.7ms vs glibc 6.61ms,
  ad3bf80cf). Root cause: ALL stdio serializes on one global
  `Mutex<StreamRegistry>`; glibc uses per-FILE locking and scales.
- **Lever:** shard the registry (e.g. 16 shards keyed by FILE* id hash) OR wrap
  the value in `Arc<Mutex<StdioStream>>` resolved *outside* the global lock.
- **Surface (why it's a dedicated turn, not 60 min):** **58** `registry().lock()`
  / `try_lock()` sites in `crates/frankenlibc-abi/src/stdio_abi.rs`, plus **5**
  all-stream iteration points (`sorted_stream_ids` at ~1849/1910/8559/10144 — the
  fflush(NULL)/atexit flush-all paths) that must lock every shard in a consistent
  order to stay deadlock-free. Conformance surface is large: `stdio_abi_test`
  (255 passing) + `conformance_diff_stdio_ext` / `_stdio_unlocked_io` /
  `_wide_stdio_write`. Validate with `stdio_mt_contention_bench` (per-crate).
  See the existing note at `stdio_abi.rs` ~line 1239.

## Swing 2 — malloc small-alloc state-machine floor

- **Measured:** deployed `malloc/calloc/free(16)` **~7x slower than glibc**
  (NEGATIVE_EVIDENCE 2026-06-27). The Allocator membrane fast-path is already
  applied; the residual is the Rust allocator state-machine/accounting cost, NOT
  the membrane and NOT the lock.
- **Disproven sub-lever (do not retry):** bypassing the native reentry-guard
  atomic RMWs by calling cached host calloc/free directly — failed
  `test_calloc_overflow_returns_null` (conformance RED). The gap needs a different
  ownership/bookkeeping model, not guard removal.

## Swing 3 — accuracy-hard math (erfc / bessel / lgamma)

- **erfc:** **1.63x slower** than glibc (fl `libm::erfc` is fdlibm-derived but
  unoptimized). TWO approaches now **DISPROVEN — do not retry erfc**:
  1. *Cephes-rational substitution* (065e1d98f): diverges from glibc's fdlibm by
     6–34 ULP, figure varies by worker glibc version. Accuracy regression.
  2. *Faithful fdlibm `erfc2` exp-branch port reusing fl's fast `super::exp::exp`*
     (cc/BoldFalcon, 2026-06-27): conformance was CLEAN (≤3 ULP vs glibc on the
     gate worker, since the algorithm/coefficients are glibc's own fdlibm), but it
     is a **1.65x perf REGRESSION** — decisive same-process A/B over |x|∈[1.25,6):
     `fl_old libm::erfc` **154.85 ns** vs `fl_new erfc2+fast-exp` **254.88 ns**.
     Root cause: fl's f64 `super::exp::exp` (exp2-based fused kernel) is *slower*
     than `libm::exp` for the erfc2 arguments, and erfc2 calls exp twice. The f64
     exp2-kernel "win" is f32-only / vs the slow generic libm exp10 path, NOT vs
     `libm::exp` itself. Reverted.
  Conclusion: an erfc speed-up needs a genuinely faster f64 `exp` (or a
  single-exp reformulation), which is a separate, larger lever — not erfc itself.
  The host-glibc dlmopen comparator is also unreliable here (varied 99/323/388 ns
  across runs for the same work); trust only same-process old-vs-new A/B.
- **bessel (j0/j1/y0/y1) / lgamma:** pure `libm` passthrough, libm is slow vs
  glibc. Risky: zeros (bessel) and lgamma≈0 at x=1,2 cause ULP blow-up; any
  rational substitution carries the same cross-worker glibc-ULP divergence as the
  rejected erfc Cephes path. Needs faithful fdlibm ports, not Cephes.

## Method reminders

- Per-crate bench only: `rch exec -- env CARGO_TARGET_DIR=… cargo bench -p <crate>`.
- ULP-vs-glibc figures are **not portable across workers** (glibc version varies);
  always assert on the worker that runs the gate.
- Build latency under fleet contention is the binding constraint (~15–30 min/round);
  budget 1–2 rounds per turn and revert anything that isn't a clear win.
