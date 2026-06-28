# Perf: next architectural swings vs glibc (frontier scoping)

Companion to `docs/NEGATIVE_EVIDENCE.md`. Records the *shape* of the remaining
measured gaps so LAND-OR-DIG turns stop re-deriving "the tractable frontier is
saturated" (independently reached on 2026-06-27 across multiple turns). Read this
**before** digging: the cheap byte-identical levers are spent; what's left are
dedicated multi-turn swings or accuracy-hard ports. Each item below is measured,
not speculative.

## CAMPAIGN STATUS (2026-06-27, cc/BoldFalcon) — frontier saturated; 2 swings remain

- **Non-architectural frontier SATURATED + verified:** math (sin/cos/tan/sincos/exp/
  log/pow/exp2/exp10/cbrt/hypot/tgamma/sinh/cosh/tanh done; erfc/bessel/lgamma
  disproven/accuracy-hard), strings/wide (wmemchr/wcsnlen/strrchr/memchr are saturated
  64-lane SIMD; rawmemchr/wcschrnul/strchr "slow" survey arms were STALE labels),
  stdio membrane (entrypoint_scope/decide/observe all fast-pathed; sub-locks masked),
  complex (mature glibc-faithful), threading (mutex_lock is direct futex).
- **Sole reliable win this campaign:** f64 `sincos` 4.30x (b43b6ca2d, same-process).
- **2 remaining gaps, BOTH architectural (dedicated turn each, scoped below):**
  swing-1 stdio MAIN `registry()` lock (6.2–8.6x), swing-2 malloc fallback-table
  bookkeeping (~7x).
- **⚠️ COORDINATION BLOCKER:** both swings live in files under ACTIVE concurrent peer
  edits — `stdio_abi.rs` (cod-a) and `malloc_abi.rs` (BlackThrush) have shown
  uncommitted peer changes every turn, and peers have already landed/rejected several
  levers there (fputs parking_lot, fgetc double-lock, calloc guard-bypass/tombstone).
  A heavy refactor by a *third* agent would collide hard. **The orchestrator should
  assign each swing to the agent already holding that file, or serialize access** —
  do not fan a fresh agent onto stdio/malloc concurrently. Until then there is no
  safe non-colliding architectural work to start.

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
- **Complex math (`math_abi.rs`) — MATURE, not a gap (cc/BoldFalcon 2026-06-27).**
  `cexp`/`clog`/`csqrt`/`cpow`/`csin`/`ccos`/`ctan`/`carg`/`cabs` are hand-written
  glibc-faithful implementations (full inf/NaN/signed-zero/branch-cut special-casing),
  NOT slow `libm` passthrough. Reformulating with fl's fast exp/log/sincos would break
  glibc-bit-matching (and fl's f64 `super::exp::exp` is anyway slower than `libm::exp`
  for general args — see the erfc note). Do not touch.
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
- **Membrane overhead CONFIRMED already eliminated (cc/BoldFalcon 2026-06-27):**
  verified by reading the hot path — `entrypoint_scope` returns a no-op guard under
  `strict_passthrough_active()` (skips trace_seq + pcc lookup + 2 thread_locals);
  `decide()` Stdio is in the strict fast-path set; cookie/memstream sub-registry locks
  are guard-skipped. So the residual 6-12x is PURELY: `registry().lock()` (parking_lot,
  uncontended-cheap) + FNV `HashMap::get_mut(&id)` + the `StdioStream` type-dispatch
  (cookie?/mem-backed?/buffer) + `buffer_write`, vs glibc's lock-free inline write-ptr
  bump. No further micro-lever exists on this path (the in-code comment at
  `write_bytes_without_runtime_policy` says the same).
- **Lever:** shard the registry (e.g. 16 shards keyed by FILE* id hash) OR wrap
  the value in `Arc<Mutex<StdioStream>>` resolved *outside* the global lock, AND give
  the single-threaded common path a lookup-free fast slot for the 3 std streams.
- **Surface (why it's a dedicated turn, not 60 min):** **58** `registry().lock()`
  / `try_lock()` sites in `crates/frankenlibc-abi/src/stdio_abi.rs`, plus **5**
  all-stream iteration points (`sorted_stream_ids` at ~1849/1910/8559/10144 — the
  fflush(NULL)/atexit flush-all paths) that must lock every shard in a consistent
  order to stay deadlock-free. Conformance surface is large: `stdio_abi_test`
  (255 passing) + `conformance_diff_stdio_ext` / `_stdio_unlocked_io` /
  `_wide_stdio_write`. Validate with `stdio_mt_contention_bench` (per-crate).
  See the existing note at `stdio_abi.rs` ~line 1239.
- **Execution plan (ordered, each step independently testable — do these in a
  dedicated turn, NOT inline in a 60m loop):**
  1. *Increment 1 — std-stream fast slot (lowest risk, biggest ST payoff).* The 3
     std streams use fixed sentinels (`STD{IN,OUT,ERR}_SENTINEL` = `0x1000_000{1,2,3}`,
     stdio_abi.rs:522) and 99% of `fputs`/`fputc`/`fwrite`/`puts` target stdout/stderr.
     Store those 3 in dedicated `static Mutex<StdioStream>` slots resolved by
     `standard_stream_id()` (already exists, line 777) BEFORE touching the registry,
     so the hot path skips the HashMap entirely. Every all-stream site
     (`sorted_stream_ids` ×5, fflush(NULL)/atexit) must also visit the 3 slots — wire
     a `for_each_stream()` helper that covers slots+registry and route all 5 sites
     through it FIRST (mechanical, no behavior change) so increment 1 only swaps the
     storage. Gate: full `stdio_abi_test` + the 3 conformance_diff gates green;
     measure with `fputs_glibc_bench`.
  2. *Increment 2 — per-FILE lock for the rest.* Change registry value to
     `Arc<Mutex<StdioStream>>`; resolve the Arc under a brief registry read, drop the
     registry lock, then lock the per-stream Mutex. Mechanically convert the 58
     `registry().lock()` sites: split each into "resolve handle" (registry) + "use
     stream" (per-FILE). Gate same; measure `stdio_mt_contention_bench` (expect the
     8.6x MT gap to collapse).
  3. *Increment 3 (optional) — shard the registry HashMap* only if MT open/close
     contention still shows; 16 shards keyed by `id` hash, all-stream sites lock
     shards in index order.

## Swing 2 — malloc small-alloc state-machine floor

- **Measured:** deployed `malloc/calloc/free(16)` **~7x slower than glibc**
  (NEGATIVE_EVIDENCE 2026-06-27). The Allocator membrane fast-path is already applied.
- **PRECISE mechanism (cc/BoldFalcon 2026-06-27):** in strict mode the deployed
  `malloc` *delegates to host glibc malloc* (~5ns) and then pays fl bookkeeping —
  `fallback_insert_sized_index` (malloc_abi.rs:1358) takes `lock_fallback_alloc_table`
  + a hash-probe insert into `FALLBACK_ALLOC_PTRS`/`SIZES`, `publish_fallback_range`
  (min/max addr atomics), `record_alloc_stats`, plus `decide`/`observe` and the
  reentry/signal guards; `free` mirrors a probe+remove. THIS aggregate per-call
  bookkeeping IS the 7x — not the host malloc, not a single heavy lock. Note
  `lock_fallback_alloc_table` is already a lightweight `AtomicBool` spinlock
  (malloc_abi.rs:1224), so there is **no parking_lot/lock-swap win** here.
- **Why it's load-bearing (not just removable):** the fallback table is what
  `known_remaining` (malloc_abi.rs:1773) reads so the membrane's bounded C-string
  scans can reject unterminated tracked buffers before host passthrough. That is why
  every bypass attempt fails conformance — the bookkeeping IS the safety contract.
- **Disproven sub-levers (do not retry):** (a) bypassing the native reentry-guard
  atomic RMWs via cached host calloc/free — failed `test_calloc_overflow_returns_null`
  (RED); (b) same-thread tombstone-reinsertion without the table lock — ~0-gain
  (9.90x). Both in NEGATIVE_EVIDENCE.
- **Real lever (dedicated turn):** replace the *side* fallback table with an
  *inline* size header on fl-owned allocations (store size just before the returned
  ptr, glibc-style), so `known_remaining`/`free` read the header with NO table lock or
  hash probe. Requires owning the allocation layout (not pure host-malloc delegation)
  + careful interop with host `free` on foreign ptrs — architectural, conformance-
  heavy (the whole malloc/calloc/realloc/free/overflow suite).

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
