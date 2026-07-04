# Perf: next architectural swings vs glibc (frontier scoping)

Companion to `docs/NEGATIVE_EVIDENCE.md`. Records the *shape* of the remaining
measured gaps so LAND-OR-DIG turns stop re-deriving "the tractable frontier is
saturated" (independently reached on 2026-06-27 across multiple turns). Read this
**before** digging: the cheap byte-identical levers are spent; what's left are
dedicated multi-turn swings or accuracy-hard ports. Each item below is measured,
not speculative.

## MATH CAMPAIGN — COMPLETE (2026-06-28, cc/BoldFalcon): 4 wins + full map + regression benches

The reliable-survey perf campaign is closed. Method = survey fl-vs-glibc reliably, then
the two-part filter (deployed slower than glibc AND gate is `within_N_ulps` not bit-exact
`same32/same64`) + a same-run 3-way A/B before landing.

- **Landed wins (regression bench in parens):** `sincos` 4.30x (`sincos_glibc_bench`),
  `lgamma`[3,13) 1.02x + `gamma` inherits (`lgamma_glibc_bench`), `acoshf` 1.26x
  (`acoshf_glibc_bench`). Run any of these per-crate to detect a regression of the win.
- **Surveyed/ruled out (reusable benches kept):** f64 transcendentals all win
  (`math_passthrough_survey_bench`); f32 transcendentals all win except the
  bit-exact-gated/marginal ones (`f32_math_survey_bench`); exact binary ops
  fmod/fmodf clean, remainder/remainderf glibc-hardware-unclosable
  (`fmod_survey_bench`,`remainder_glibc_bench`,`fmodf_survey_bench`,`fmodf_cand_bench`);
  cbrt 1.23x win (`cbrt_glibc_bench`); erfc disproven (`erfc_glibc_bench`); lgammaf/
  asinhf deferred (`lgammaf_glibc_bench`,`asinhf_glibc_bench`).
- **Deferred (maintainer/contract decisions):** `asinhf` 3.7x candidate exists but
  `conformance_diff_asinh_special` is a bit-exact `same32` gate → needs a relax-to-≤4-ULP
  decision; that gate is ALSO pre-existing-RED (glibc-2.42 drift, 1 ULP) and needs a
  re-tune-or-relax. NOT landed unilaterally (don't loosen a gate to land a perf win).
- **No more math levers.** Remaining repo perf gaps are the 2 architectural swings below.

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
- **DEPLOYED-SYMBOL small-primitive floor — CONFIRMED, do NOT re-survey (BlackThrush
  2026-07-02, verified over several turns via stdio_st_probe dlmopen A/B).** Distinct
  from the in-process-kernel note above: through the real `no_mangle` extern symbol,
  the small string/mem primitives lose glibc ~1.5–3x at small n and this is the
  **irreducible extern-call + strict-check + scanner-call floor**, NOT a kernel gap.
  The kernels are already maxed: `strlen`/`strchr`/`memchr`/`strrchr` all use
  head-mask-first-load + 32B tier + **128B unrolled folded tier** (vpminub/OR-combine);
  `memcmp` is explicit AVX2 (n≥32) + SSE16 (16–31) [9378639c0/223ee52ab];
  `strcmp`/`wcscmp`/`scan_wcscmp_simd` are 32B-SIMD two-pointer scans whose per-window
  double page-guard amortization was DISPROVEN neutral-to-regression (n=8 single-window
  already ~1.95x = pure floor; crate is `-Ctarget-feature=+avx2` so `Simd<u8,32>` is
  real AVX2). `memcpy` small-n framing is load-bearing: `raw_memcpy_bytes` is
  `#[inline(never)]` on purpose — inlining a copy loop into the interposed `memcpy`
  symbol makes LLVM lower it to `@llvm.memcpy` = infinite self-recursion. `getenv`
  (hot-ptr cache), `strtol` (single-pass + membrane fast-path), `pthread_mutex_lock`
  (1-branch+1-CAS) all maxed. glibc's equivalents are bare PLT jumps to hand-tuned
  ifunc asm; fl cannot match that through a `no_mangle` symbol + membrane boundary.
  These residual 1.5–3x rows are NOT levers — only the two architectural swings remain.
- **inet `<arpa/inet.h>` conversion family — fully fast-pathed & mostly winning
  (BlackThrush 2026-07-02, 6 commits).** pton v4 single-pass BEATS glibc 1.34x; addr
  BEATS glibc; aton/pton-v6 at parity; ntop v4/v6 have strict fast-paths (v6 direct-format).
  Only residual = the core `format_ipv6_canonical_into`/`format_ipv4` text formatter
  (v4 1.74x / v6 1.9x), which is FLOOR-BOUND (v4 already formats direct-to-dst; v6's
  temp copy is inherent to glibc's no-clobber-on-ENOSPC). Do NOT re-attempt.

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

- **SAFETY REFINEMENT + graveyard-matched alternative (BlackThrush 2026-07-02, via
  /alien-graveyard on the size-tracking symptom):** the inline-header plan has an
  unaddressed hazard — `known_remaining` has **395 call sites** and is invoked with
  *arbitrary* caller pointers (any string arg: heap, stack, static, or INTERIOR),
  not just malloc-returned ones. Reading `ptr[-8]` for a non-heap/interior ptr is
  unsound (stack/static → wild read; interior heap ptr → mid-chunk garbage that a
  weak magic could accept → wrong bound). The inline header is only salvageable with
  a two-guard prelude: (1) `publish_fallback_range` `[min,max]` heap-range check so
  the header is *never read* outside the mapped heap; (2) a strong 8-byte magic so an
  interior read (within heap, still mapped ⇒ no fault) is rejected with ~2⁻⁶⁴
  false-accept. **Cleaner alternative = a page-indexed radix tree (jemalloc `rtree`
  archetype).** Key the metadata by `ptr >> PAGE_SHIFT`, not by reading memory at the
  ptr: a non-heap ptr's page is simply absent ⇒ `None` with ZERO ptr dereference
  (structurally UB-free for arbitrary pointers, unlike the inline header); a heap ptr
  indexes its page slot (chunk base + size) and validates exact-start for the size.
  Lookup is O(1) array indexing (no open-addressing probe like today's
  `FALLBACK_ALLOC_PTRS`), insert is O(1) set-page-slot, and per-page atomics remove
  the global `lock_fallback_alloc_table` entirely.

- **CORRECTION — the page-radix alternative above is FLAWED for fl's model; inline
  header is the sound primary (BlackThrush 2026-07-02, second pass):** `fallback_key`
  (malloc_abi.rs:1247) keys on the **exact byte address** (`ptr as usize`), not the
  page — because fl `malloc` *delegates to host glibc malloc*, so many DIFFERENT-sized
  allocations coexist in one 4 KiB page (e.g. 5×`malloc(16)` at distinct 16-byte
  offsets). A radix keyed by `ptr >> PAGE_SHIFT` collapses all of them to ONE slot and
  **cannot** store per-allocation sizes — it would need each page slot to point to a
  per-page offset→size sub-map, i.e. reinventing a hash table with extra indirection
  and per-page sub-allocation. Keying finer (`ptr >> 4`, the malloc alignment) needs a
  ~2⁴⁴-leaf multi-level radix that is sparse ⇒ effectively the current hash table again.
  So the radix does NOT beat the exact-ptr table for host-delegated mixed-size allocs.
  **The sound lever is the INLINE HEADER with the two-guard prelude** (heap-range check
  + strong magic) from the refinement above: the size lives *with each allocation*, so
  there is no per-page collision; `known_remaining` reads `ptr[-16]` only when
  `min_heap+16 <= ptr <= max_heap` (mapped ⇒ no fault) and accepts only on magic match.
  The residual ~2⁻⁶⁴ interior-false-accept yields a garbage bound that is **no worse
  than glibc's baseline** (glibc bounds nothing and trusts NUL termination), so it does
  not regress safety below the strict-mode contract. EV≈3.0; Tier A; baseline comparator
  = current 262144-slot spinlocked open-addressing table. Rollback: keep the table
  behind a cfg flag; shadow-run the header (populate+assert-agree) before switching
  reads. Still a dedicated multi-turn swing + membrane-owner review (safety contract).
  **First de-risking step for that turn: a per-crate microbench of header read/write vs
  `fallback_insert_sized`/`fallback_size`/`fallback_remove` over an alloc/free churn —
  prove the header is actually cheaper before the invasive integration.**

- **DE-RISKING BENCH DONE (BlackThrush 2026-07-02, `examples/malloc_sizetrack_ab.rs`
  + `fallback_*_for_bench` hooks):** FALLBACK table insert+lookup+remove = **11.63 ns**
  vs inline header store+2loads = **0.74 ns** (16x). BUT the deployed MALLOC_FREE
  overhead over glibc is ~47 ns, so the table is **only ~25% of the gap** → swing-2
  caps malloc at ~10x→~8x, **NOT parity**. It is *necessary but not sufficient*: the
  other ~36 ns is DIFFUSE framing (reentry guards, `entrypoint_scope`, `decide`/
  `observe`, `record_alloc_stats`, `publish_fallback_range`, native malloc ~5 ns),
  confirming BoldFalcon's "no single hotspot" bisection. **A full malloc fix needs
  BOTH the inline header AND a slim-fast-path framing reduction — plan swing-2 as two
  sub-steps, not one.** (Bench uses non-cached 3-op churn = upper bound on the deployed
  cached 2-op cost; the "partial win" conclusion strengthens under the true cost.)

- **2026-07-04 refinement (BlackThrush, `rch` worker `vmi1149989`):** the ratio is still
  very real, and stronger on a fresh per-crate run: FALLBACK table
  insert+lookup+remove = **19.59 ns** vs simulated inline header store+2loads =
  **0.63 ns** (`header/table=0.032`, **18.96 ns/op saved**). However, the production
  switch is **not safe with only the coarse min/max range guard**. `known_remaining(addr)`
  receives arbitrary C pointers, and a monotone `[min,max]` allocation envelope does not
  prove that `addr - 16` is mapped for every in-range address; mmap holes or unrelated
  mapped regions can still make a header read fault before the magic check. Treat the
  inline header as a measured target, not a ready implementation, until the plan includes
  a no-fault exact-membership guard or a shadow mode that proves agreement before reads
  switch away from the fallback table. **Do not land naive min/max+magic header reads.**

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
