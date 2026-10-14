# FrankenLibC — Reality-Check Bridge Plan

> **Canonical single plan document.** Always revise in place; never create `REALITY_CHECK_BRIDGE_PLAN_v2.md` or parallel plan files.
> **Original assessment:** 2026-09-08 at commit `3bf05e3a` (`bd-reality-202609-lx578q`).
> **Second pass:** 2026-09-23 (`bd-rc0923-epic-eeuy4f`).
> **Current end-to-end reality check & revision:** 2026-10-13 at commit `9cef7fbd2`.
> **Scope:** Close the remaining gap between FrankenLibC's vision (`README.md`, `AGENTS.md`, `PROPOSED_ARCHITECTURE.md`, `PLAN_TO_PORT_GLIBC_TO_RUST.md`, `FEATURE_PARITY.md`) and executed reality at HEAD across all replacement levels (`L0` → `L1` → `L2` → `L3`).

---

## 0. Executive Summary (2026-10-13 Reality Check at `9cef7fbd2`)

Between the 2026-09-08 (`3bf05e3a`) and 2026-09-23 reality-check passes and today (`2026-10-13`, `9cef7fbd2`), FrankenLibC crossed a major threshold on its **L0/L1 `LD_PRELOAD` interposition surface**:

1. **Major Real-Program Preload Blockers Resolved (`bd-rc0923-epic-eeuy4f`):**
   - **GNU `FILE*` struct ABI (`bd-rc0923-epic-eeuy4f.1`, closed):** `fopen`/`fdopen`/`tmpfile`/`popen`/`fmemopen`/`open_memstream` now return 216-byte glibc-layout `_IO_FILE_plus` handles backed by host `fopencookie` instead of synthetic indices that caused `git`, `sed`, and `gawk` to `SIGSEGV`.
   - **C++ runtime locale initialization (`bd-rc0923-epic-eeuy4f.2`, closed):** `newlocale(1 << LC_ALL, ...)` and `LC_ALL_MASK` are accepted, unblocking `libstdc++` startup.
   - **Multi-threaded `fork` / `_Fork` / `clone` safety (`bd-rc0923-epic-eeuy4f.5`, `.27`, closed):** Lock ordering (`atfork -> stdio -> ENVIRON_LOCK -> pipeline -> malloc`), `ENVIRON_LOCK` owner-TID tracking, async-signal-safe `_Fork`, and PID-keyed runtime-log windows allow `tar -czf`, `make -j2`, and MT `fork+exec` stress suites to complete without livelock.
   - **C++ exception & forced-unwind propagation (`bd-rc0923-epic-eeuy4f.6`, closed):** Exported callback-taking entrypoints (`qsort`, `bsearch`, `pthread_once`, `dl_iterate_phdr`, `twalk`, `scandir`, `ftw`/`nftw`, `glob`) use `extern "C-unwind"` with `-C force-unwind-tables=yes`.
   - **GNU `argp`, `iconv`, `TZif`, named locales, RFC 6724, `setjmp` guard mangling, and `FRANKENLIBC_LOG` (`bd-rc0923-epic-eeuy4f.7`, `.8`, `.10`, `.11`, `.12`, `.16`, `.20`, `.21`, `.22`, `.23`, closed):** Native engines and differential gates are live in both `strict` and `hardened` modes.
   - **Support taxonomy honesty (`bd-reality-202609-lx578q.3`, `.10`, `.12`, `bd-rc0923-epic-eeuy4f.14`, closed):** `support_matrix.json` was audited and reclassified from the inflated `3,550 Implemented / 155 WrapsHostLibc / 0 Stub` snapshot to `2,399 Implemented (58.2%) / 410 RawSyscall (10.0%) / 1,266 WrapsHostLibc (30.7%) / 44 Stub (1.1%)` across 4,119 exported symbols; foreign `frankentorch-*`/`frankenjax-*` beads (1,195 rows) were separated from FrankenLibC's own `bd-*` backlog.

2. **What Still Does Not Work or Remains Unproven at `9cef7fbd2`:**
   - **L1 Promotion Is Still Blocked (`tests/conformance/replacement_levels.json`):** `current_level` remains `L0`. L1 (`Hardened Interpose`) is blocked on:
     1. **44 `Stub` symbols** (`40 SunRPC` in `rpc_abi.rs` + `4 printf registration` APIs in `glibc_internal_abi.rs`), plus unlabelled stubs (`printf_size`, `printf_size_info`) and mislabelled `ENOSYS` wrappers (`revoke`, `rexec`, `rexec_af`).
     2. **Stale checked-in `tests/conformance/ld_preload_smoke_summary.v1.json`** (still from `2026-09-24`, `a8a4110b`, `189 pass / 0 fail / 4 skip / 1 xfail`, while a 2026-10-06 run recorded 15 strict perf-ratio >2.0x failures on short-lived binaries plus `fork_multithreaded_parent`).
     3. **`fork()` 4x–7x slowdown & 328 MB strict writable `VmData` (`bd-rc0923-epic-eeuy4f.25`, `bd-4n397c`):** `ALLOCATOR_REENTRY_SLOTS` sits in `.data` (~7.4 MiB non-zero init) and `SEGMENT_RESERVE_SIZE` (~292 MiB) is mapped `PROT_READ | PROT_WRITE` upfront, breaking `setrlimit(RLIMIT_DATA, 10MB)` in gnulib and inflating `fork()` page-table copying.
   - **Newly Uncovered Hardened String/Memory Safety & Performance Defect (`NO_BEAD` at start of pass):**
     - `memcmp_validating` (`crates/frankenlibc-abi/src/string_abi.rs:5016-5037`) installs `entrypoint_scope_memcmp()` (`skip_pointer_validation: true`) *before* calling `known_remaining_for_certified_read(s1/s2)`. Because `known_remaining_for_certified_read` only consults `bump_mmap`, `segment`, and `fallback` — and steady-state **hardened** `malloc`/`calloc` allocations live in `AllocationArena` (`pipeline.allocate()`) — **hardened `memcmp` completely skips `AllocationArena` spatial bounds and quarantine UAF checks on hardened heap allocations**, while probing 64 slots of `FALLBACK_ALLOC_PTRS` twice per call on interior pointers!
     - Meanwhile, 12 of the 24 symbols in `FFI_PCC_CERTIFICATES` (`strcmp`, `strncmp`, `strchr`, `strrchr`, `strstr`, `memchr`, `memrchr`, `strnlen`, `memmove`, `memset`, `strcpy`, `strncpy` added in `bd-14baix`) **never call `runtime_policy::entrypoint_scope(...)`** in `string_abi.rs`! Their FFI-PCC certificates are 100% dead code in production (`ACTIVE_TRACE_CONTEXT` is `None`), and each entrypoint calls `check_ownership` + `known_remaining` **2 to 6 times per call** on the same pointer.
   - **Runtime Math Kernel Production Bypass & Baseline Self-Interposition:**
     - `runtime_policy::decide()` (`crates/frankenlibc-abi/src/runtime_policy.rs:2489-2596`) bypasses `RuntimeMathKernel::decide()` under `cfg(not(test))` for 11 families in `strict` mode AND 7 core families (`Allocator`, `StringMemory`, `Ctype`, `Loader`, `Stdlib`, `MathFenv`, `Stdio`) in `hardened` mode, contradicting `README.md:275` (`bd-reality-202609-lx578q.4`).
     - Removing global `+avx2,+fma` (`bd-rc0923-epic-eeuy4f.13`) left **144 call sites** in `libfrankenlibc_abi.so` (including `RuntimeMathKernel::decide`, `KTheoryController::observe`, `DroCvarController`, `microlocal`, `bloom::with_capacity`, `printf` float formatting) calling Rust `f64::mul_add`/`floor`/`ceil`/`trunc`/`round`/`rint`, which resolve to FrankenLibC's own exported `math_abi` entrypoints!
   - **Multi-Threaded Allocator Scaling & Hardened `sort` Gap:**
     - Multi-threaded `malloc` remains 36x–490x slower than glibc (`bd-rc0923-epic-eeuy4f.26`, `bd-65p87u`, `bd-dcrhgl`, `bd-ny3hsa`).
     - Hardened `LC_ALL=C sort` 120k is down from 240x to ~5.2x glibc (`0.199s` vs `0.038s`), still above the `<=3x` milestone and `<=2x` L3 contract, and UTF-8 `strcoll` calls `CStr::from_ptr` -> `strlen_validating` twice per comparison (`bd-rc0923-epic-eeuy4f.9`).
   - **L2/L3 Standalone Replacement & Verification Debt:**
     - 1,266 symbols (30.7%) remain `WrapsHostLibc`; `pthread_create`/`join`/`cancel` default to host NPTL; native thread cancellation (`FRANKENLIBC_THREAD_NATIVE=1`) and unwinding out of `main` under owned startup fail (`bd-rc0923-epic-eeuy4f.24`, `bd-reality-202609-lx578q.6`).
     - `tests/conformance/healing_oracle_report.v1.json` is still the `2026-02-25` policy-simulated artifact; `tests/conformance/support_semantic_overlay.v1.json` is still the `2026-05-25` 9-row snapshot; `scripts/check_docs_semantic_claims.sh` fails on numeric freshness; CVE triggers do not execute under `LD_PRELOAD` (`bd-rc0923-epic-eeuy4f.18`, `bd-reality-202609-lx578q.2`).

---

## 1. Phase 1 Reality Check Assessment: Vision Checklist & Gap Analysis

### 1.1 Vision Checklist & Current Status Matrix (`2026-10-13`, `9cef7fbd2`)

| ID | Vision Pillar & Concrete Requirement | Status | Code / Gate / Artifact Reality at `9cef7fbd2` | Covering Open / In-Progress Beads |
|---|---|---|---|---|
| **V1.1** | **L0/L1 Preload Compatibility:** Real C/C++/Python/Perl/CLI binaries run byte-identically under `LD_PRELOAD=libfrankenlibc_abi.so` in `strict` and `hardened` modes | `PARTIAL` | `git`, `sed`, `grep`, `awk`, `tar -czf`, `make`, `perl`, `iconv`, C++ locale/exceptions, and Python C extensions run. Stale checked-in `ld_preload_smoke_summary.v1.json` (`2026-09-24`); 2026-10-06 run had 15 strict short-lived perf-ratio (>2x) failures + `fork_multithreaded_parent`. | `bd-rc0923-epic-eeuy4f.4`, `bd-rc0923-epic-eeuy4f.3`, `bd-rc0923-epic-eeuy4f.25` |
| **V1.2** | **L1 Zero-Stub Gate (`stub_free_taxonomy`):** Zero `Stub` symbols in `support_matrix.json` and `replacement_levels.json` | `NO_BEAD` / `STUB` | `replacement_levels.json:98-109` blocks L1 on 44 `Stub` rows (`40 SunRPC` in `rpc_abi.rs` + `4 register_printf_*` in `glibc_internal_abi.rs`), plus unlabelled stubs `printf_size`/`printf_size_info`. | **`NO_BEAD`** (only `.17` classifies labels; no bead resolves the 44 L1-blocking stubs) |
| **V2.1** | **TSM Spatial & Temporal Safety in Hardened Mode:** Validating pointer pipeline + deterministic repair (`ClampSize`, `TruncateWithNull`, `IgnoreDoubleFree`, `IgnoreForeignFree`, `ReallocAsMalloc`, `ReturnSafeDefault`) | `REGRESSED` / `PARTIAL` | `AllocationArena` + `ValidationPipeline` work for `malloc`/`free`/`realloc`/`memcpy`/`strlen`. **Defect found:** `memcmp_validating` (`string_abi.rs:5017-5037`) sets `entrypoint_scope_memcmp()` (`skip_pointer_validation: true`) before `known_remaining_for_certified_read`, skipping `AllocationArena` bounds and quarantine UAF checks on hardened heap blocks! UAF guarantee is bounded by 64MB quarantine (`bd-reality-202609-lx578q.8`). | `bd-reality-202609-lx578q.8`, **`NO_BEAD`** for `memcmp` arena-validation bypass & dead FFI-PCC scopes |
| **V2.2** | **Executable Healing & CVE Fault Evidence:** Subprocess ABI fault injection + live CVE arena reproduction under `LD_PRELOAD` | `PARTIAL` | `healing_oracle.rs` (`4d7e35eed`) now spawns subprocesses and checks counter deltas, but committed `tests/conformance/healing_oracle_report.v1.json` is still from `2026-02-25` (`library: null`). CVE scripts (`generate_cve_uaf_validation.py`) only run `cc -fsyntax-only`. | `bd-reality-202609-lx578q.2`, `bd-rc0923-epic-eeuy4f.18` |
| **V3.1** | **Runtime Math Decision Kernel (~71 Modules):** Live routing/validation profile control in production with bounded overhead | `PARTIAL` / `BYPASSED` | `runtime_policy::decide()` (`runtime_policy.rs:2489-2596`) bypasses `RuntimeMathKernel::decide()` under `cfg(not(test))` for 11 families in `strict` AND 7 core families (`Allocator`, `StringMemory`, `Ctype`, `Loader`, `Stdlib`, `MathFenv`, `Stdio`) in `hardened` mode. | `bd-reality-202609-lx578q.4` |
| **V3.2** | **Zero Self-Interposition Inside Membrane & Core:** Internal math/membrane code must never re-enter exported ABI symbols | `NO_BEAD` / `REGRESSED` | Dropping global `+avx2,+fma` (`bd-rc0923-epic-eeuy4f.13`) caused 144 `f64::mul_add`/`floor`/`ceil`/`trunc`/`round`/`rint` sites in `frankenlibc-membrane` and `frankenlibc-core`/`abi` to call FrankenLibC's own exported `math_abi` entrypoints. | `bd-rc0923-epic-eeuy4f.13` (noted in review comment, **needs dedicated child bead + gate**) |
| **V4.1** | **Hardened Mode Throughput (`<= 200ns`, `<= 2x` strict):** Real workloads (`sort`, `python3`, `git`) usable in hardened mode | `PARTIAL` | Hardened `LC_ALL=C sort` 120k improved from 240x to ~5.2x (`0.199s` vs `0.038s` glibc), still above `<=3x`/`<=2x`. 12 string entrypoints in `FFI_PCC_CERTIFICATES` never call `entrypoint_scope` and call `known_remaining` 2–6x per call; UTF-8 `strcoll` calls `strlen_validating` twice. | `bd-rc0923-epic-eeuy4f.9` + **new child bead for string FFI-PCC & single-pass extent lookup** |
| **V4.2** | **Allocator & Process-Lifecycle Performance:** Multi-threaded `malloc` `<= 2x` glibc; `fork()` `<= 1.5x` glibc; `VmData < 10 MB` (`RLIMIT_DATA`) | `BLOCKED` / `PARTIAL` | MT `malloc` is 36x–490x slower (`bd-rc0923-epic-eeuy4f.26`). `fork()` is 4x/7x slower (`bd-rc0923-epic-eeuy4f.25`) and strict `VmData` is 328 MB (`bd-4n397c`) due to 7.4 MiB `.data` `ALLOCATOR_REENTRY_SLOTS` and eager writable 292 MiB `SEGMENT_RESERVE_SIZE`. | `bd-rc0923-epic-eeuy4f.25`, `bd-rc0923-epic-eeuy4f.26`, `bd-4n397c`, `bd-dcrhgl`, `bd-65p87u`, `bd-ny3hsa`, `bd-f874go` |
| **V5.1** | **POSIX / GNU / C23 Conformance & `libm` Accuracy:** Correctly rounded `libm` (`f32`/`f64`), `pthread` cancel/mutexes, `stdio` orientation/`fmemopen`, `wordexp`, `qsort`, `nsswitch` | `PARTIAL` | `f32`/`f64` `libm` sweeps (`bd-li7fb3`, `bd-otip6a`) in progress; host-thread `pthread_cancel` fixed for 67 syscall windows but native-thread cancel, `main` unwind, `thrd_sleep`, and stdio cancel remain (`bd-rc0923-epic-eeuy4f.24`); `PRIO_PROTECT` boost (`bd-rc0923-epic-eeuy4f.15`); `wordexp` (`bd-uu1wvp`), `stdio` (`bd-gtaukk`, `bd-lamxlj`), `qsort` (`bd-8p8q15`), `hosts_policy` (`bd-rc0923-epic-eeuy4f.19`). | `bd-li7fb3`, `bd-otip6a`, `bd-rc0923-epic-eeuy4f.24`, `.15`, `.19`, `bd-uu1wvp`, `bd-gtaukk`, `bd-lamxlj`, `bd-8p8q15`, `bd-o55x4n`, `bd-rv2gv6`, `bd-etgt2x` |
| **V5.2** | **Code-Derived Taxonomy & Semantic Overlay Truth:** `support_matrix.json`, `support_semantic_overlay.v1.json`, and `README.md` claims derived from code and passing CI gates | `PARTIAL` / `NO_BEAD` | `bd-rc0923-epic-eeuy4f.17` tracks deriving `support_matrix.json` from AST/call-graph. However, `support_semantic_overlay.v1.json` is still from `2026-05-25` (`3550 Implemented`, 9 rows) and `check_docs_semantic_claims.sh` fails at HEAD (`numeric_claim_freshness: fail`). | `bd-rc0923-epic-eeuy4f.17`, **`NO_BEAD`** for exhaustive `support_semantic_overlay.v1.json` & docs gate repair |
| **V6.1** | **L2/L3 Standalone Replacement (`libfrankenlibc_replace.so`):** Zero `WrapsHostLibc`, owned CRT/TLS/unwind, native `dlfcn` transitive loader, native `pthread`, native `stdio`/`locale`/`NSS`/`resolver` | `PARTIAL` / `BLOCKED` | `check_ws8_e2e_standalone_verification.sh` now fails closed (`bd-reality-202609-lx578q.1`). Owned CRT direct-link proof passes (`bd-reality-202609-lx578q.6.1`), but 1,266 `WrapsHostLibc` symbols (30.7%) remain across 28 ABI modules, blocking standalone link/boot. | `bd-reality-202609-lx578q.1`, `.5`, `.6`, `.6.1`, `.6.2`, `.6.3`, `bd-38x82` |
| **V7.1** | **Multi-Arch (`x86_64` baseline + `aarch64`), Distro Packaging & 24h Soak:** Portable baseline ISA, full `aarch64` parity, `.deb`/`.rpm` prefix validation, 24h soak | `PARTIAL` | Baseline `x86_64` gate (`check_baseline_isa.sh`) and `aarch64` `setjmp`/`longjmp` (`bd-rc0923-epic-eeuy4f.12`) pass. `dlfcn_tls.rs` TLSDESC asm is still `x86_64`-only; real workload/package/24h soak remain open. | `bd-rc0923-epic-eeuy4f.13`, `bd-reality-202609-lx578q.5`, `.9`, `bd-38x82.4` |
| **V8.1** | **Formal Proof Obligations & Workspace Gate Hygiene:** SOS barriers bound to deployed runtime state, mechanized safety proofs, green `clippy`/`fmt`/ABI test sweep | `PARTIAL` / `NO_BEAD` | `frankenlibc-membrane/build.rs` verifies 3 static `.task` Gram matrices, but `evaluate_size_class_barrier` is only called in undeployed `frankenlibc-core/src/malloc/allocator.rs` and `SosBarrierController` is bypassed on hot families; 0 mechanized proofs exist. `clippy` and `fmt` remain red (`bd-reality-202609-lx578q.11`). | `bd-reality-202609-lx578q.11`, `bd-g8zy5p`, `bd-blnp4u`, **`NO_BEAD`** for deployed SOS/proof binding |

---

### 1.2 The Five Core Gap Analysis Questions

1. **What works at HEAD (`9cef7fbd2`)?**
   - **Real-world `LD_PRELOAD` interposition (`L0`)** works across a broad corpus of real C, C++, Perl, and Python binaries (`git`, `sed`, `grep`, `awk`, `find`, `tar -czf/-cJf`, `gzip`, `make -j2`, `perl`, `iconv`, `getent`, `python3` with `sqlite3`/`ssl`/`ctypes`/`_decimal`, C++ `std::locale` and callback unwinding).
   - **Membrane spatial/temporal enforcement** works on `malloc`/`free`/`realloc`/`calloc`/`memcpy`/`strlen` in `hardened` mode: 24B SipHash header + 8B trailing canary + 64MB quarantine queue + signal-safe `FRANKENLIBC_LOG` JSONL sink (`bd-rc0923-epic-eeuy4f.16`) + live subprocess `healing_oracle.rs` (`4d7e35eed`).
   - **Baseline `x86_64` portability (`bd-rc0923-epic-eeuy4f.13`)**: `.cargo/config.toml` builds for baseline `x86-64` with `-Cllvm-args=-enable-tlsdesc`, `avx2_fma_dispatch!` runtime multiversioning, and `scripts/check_baseline_isa.sh` verifying zero unguarded AVX/FMA instructions and execution under `qemu-x86_64 -cpu Nehalem` and `qemu64`.
   - **AArch64 `setjmp`/`longjmp` (`bd-rc0923-epic-eeuy4f.12`)**: Exported with pointer guard mangling and verified under `qemu-aarch64`.

2. **What doesn't work?**
   - **Hardened `memcmp` Arena Bounds & UAF Bypass:** Because `memcmp_validating` installs `entrypoint_scope_memcmp()` (`skip_pointer_validation: true`) before `known_remaining_for_certified_read`, steady-state hardened heap allocations in `AllocationArena` are invisible to `memcmp` (no bounds clamping, no quarantine UAF detection), while `fallback_remaining` still wastes up to 128 hash-slot probes per call.
   - **Dead FFI-PCC Certificates & Multiple Validation Lookups in `string_abi.rs`:** 12 certified string symbols never call `entrypoint_scope` and call `known_remaining`/`check_ownership` 2–6 times per call.
   - **Production Bypass of `RuntimeMathKernel` & Self-Interposition of `libm`:** `runtime_policy::decide()` bypasses `RuntimeMathKernel::decide()` for the 7 highest-traffic families even in `hardened` mode, while 144 baseline float sites in `membrane`/`core`/`abi` call FrankenLibC's own exported `fma`/`floor`/`ceil`/`trunc`/`round`/`rint`.
   - **Multi-Threaded `malloc` (36x–490x) & `fork()` (4x–7x) / `VmData` (328 MB):** Thread-slot lookup/stats contention and eager writable 292 MiB segment reservation + 7.4 MiB `.data` reentry table.
   - **Incomplete `pthread_cancel` & Standalone Services:** Native-thread cancellation (`FRANKENLIBC_THREAD_NATIVE=1`), unwinding out of `main` under owned startup, stdio/`thrd_sleep` cancellation points, and 1,266 `WrapsHostLibc` symbols.
   - **Non-Executing / Stale Evidence Artifacts:** Committed `ld_preload_smoke_summary.v1.json` (`2026-09-24`), `healing_oracle_report.v1.json` (`2026-02-25`), `support_semantic_overlay.v1.json` (`2026-05-25`), syntax-only CVE triggers, and failing `check_docs_semantic_claims.sh`.

3. **What is blocking progression (`L0` → `L1` → `L2` → `L3`)?**
   - **`L0` → `L1` (`Hardened Interpose`) Blockers:**
     1. 44 `Stub` symbols in `support_matrix.json` (`40 SunRPC` + `4 register_printf_*`) + unlabelled stubs (`printf_size`, `printf_size_info`).
     2. Hardened `memcmp` arena-validation bug + hardened `sort` / string latency (`~5.2x` C locale, higher in UTF-8 `strcoll`).
     3. `fork()` 4x–7x slowdown and 328 MB `VmData` (`bd-rc0923-epic-eeuy4f.25`, `bd-4n397c`) + 15 short-lived process strict perf-ratio failures in `ld_preload_smoke.sh` (`bd-rc0923-epic-eeuy4f.4`).
     4. Multi-threaded `malloc` 36x–490x slowdown (`bd-rc0923-epic-eeuy4f.26`).
   - **`L1` → `L2` (`Partial Replacement`) & `L3` (`Full Replacement`) Blockers:**
     1. 1,266 `WrapsHostLibc` symbols across 28 ABI modules (`math_abi` 510, `glibc_internal_abi` 207, `stdio_abi` 113, `unistd_abi` 67, `io_internal_abi` 63, `stdlib_abi` 60, `wchar_abi` 54, `string_abi` 36, `pthread_abi` 28, `rpc_abi` 26, etc.).
     2. Native thread creation/cancellation (`FRANKENLIBC_THREAD_NATIVE=1`) and owned-startup `main` unwind landing pad (`bd-rc0923-epic-eeuy4f.24`, `bd-reality-202609-lx578q.6.1`).
     3. Standalone `dlfcn` transitive loader + `dladdr`/`dl_iterate_phdr` unification + `aarch64` TLSDESC (`bd-rc0923-epic-eeuy4f.3`, `bd-reality-202609-lx578q.5`).
     4. Standalone native `stdio` FILE lifecycle (`bd-reality-202609-lx578q.6.2`) and native `locale`/`iconv`/`NSS`/`resolver` services (`bd-reality-202609-lx578q.6.3`).

4. **Would completing all currently open and in-progress beads close the gap?**
   - **No.** Completing the 48 currently non-closed beads would close ~80% of the gap, **but would leave five critical gaps open** because they either lack bead coverage (`NO_BEAD`) or fall between existing beads' acceptance criteria:
     1. The **hardened `memcmp` `AllocationArena` bypass** (`skip_pointer_validation: true` before `known_remaining`) and the **12 dead FFI-PCC certificates + 2x–6x redundant `known_remaining` calls** across `string_abi.rs`.
     2. The **44 L1-blocking `Stub` symbols** (`4 register_printf_*` + `printf_size`/`printf_size_info` + `40 SunRPC` symbols) in `replacement_levels.json`.
     3. The **144 self-interposed `fma`/`floor`/`ceil`/`trunc`/`round`/`rint` ABI calls** inside `frankenlibc-membrane` and `frankenlibc-core`/`abi` under the baseline `x86-64` build.
     4. The **stale `support_semantic_overlay.v1.json` (`2026-05-25`) and failing `check_docs_semantic_claims.sh` gate**.
     5. The **disconnected SOS barrier / proof obligations** (`evaluate_size_class_barrier` wired only to undeployed `frankenlibc-core/src/malloc/allocator.rs`, and `SosBarrierController` bypassed on `Allocator`/`StringMemory` in production).

5. **What vision goals had `NO_BEAD` coverage prior to this pass?**
   - We created dedicated, self-contained beads under `bd-rc0923-epic-eeuy4f` and `bd-reality-202609-lx578q` in Phase 3a/4 of this pass to cover all five `NO_BEAD` gaps above (`.28`, `.29`, `.30`, `.31`, `.32`).

---

## 2. Updated Workstreams & Bridge Plan (`WS-0` through `WS-9`)

### Dependency & Execution Order

```
WS-0 (Truth Gates, Semantic Overlay & Executable Evidence: .17, .18, .31, lx578q.2, lx578q.11)
  │
  ├──► WS-1 (Hardened String/Memory Safety, FFI-PCC Unification & Sort <2x: .9, .28)
  │
  ├──► WS-2 (Runtime-Math Production Routing, Zero Self-Interposition & SOS Binding: lx578q.4, .13, .29, .32)
  │
  ├──► WS-3 (Deployed Allocator Scaling, Zero-Init .bss & Demand-Paged Segments: .25, .26, .28, 4n397c, dcrhgl, 65p87u, ny3hsa)
  │
  ├──► WS-4 (L1 Promotion Closure — Printf Specifier Registry, SunRPC Disposition & Fresh Corpus: .4, .30)
  │
  ├──► WS-5 (POSIX/GNU Conformance & Correctly-Rounded libm: .15, .19, .24, li7fb3, otip6a, g8zy5p)
  │
  └──► WS-6/7/8 (L2/L3 Standalone Replacement, Native Loader/CRT/Pthread/Stdio/NSS, AArch64 & 24h Soak: .3, lx578q.1, .5, .6.*, .9, 38x82)
```

---

### WS-0 — Truth Gates, Source-Derived Taxonomy & Executable Evidence (`P0`/`P1`)
**Goal:** Ensure every status table, semantic overlay, CVE gate, healing oracle report, and completion contract is source-derived, freshly executed against HEAD, and capable of failing when behaviour regresses.

- **Active Beads:**
  - `bd-rc0923-epic-eeuy4f.17` (`in_progress`, P2): Derive `support_matrix.json` status from AST/call-graph census across all 4,119 exported symbols (`tools/ verify/census`).
  - `bd-reality-202609-lx578q.2` (`in_progress`, P0): Regenerate `tests/conformance/healing_oracle_report.v1.json` from the live subprocess probe (`crates/frankenlibc-harness/src/healing_oracle.rs`, `tests/integration/fixture_malloc.c`) with non-null `library_sha256`, `probe_sha256`, and `source_commit`.
  - `bd-rc0923-epic-eeuy4f.18` (`open`, P2): Execute all 7 CVE trigger C programs under `LD_PRELOAD` in `strict` and `hardened` modes (`scripts/generate_cve_uaf_validation.py`, `scripts/cve_arena_gate.sh`), classify the 282 completion contracts as `receipt` vs `executes` and convert the top 30 to executing gates, and eliminate the 218 fail-open `return Ok(())` skip sites in `crates/frankenlibc-harness/tests/`.
  - `bd-rc0923-epic-eeuy4f.31` (**NEW**, P1): Reconcile `tests/conformance/support_semantic_overlay.v1.json` (currently stuck at `2026-05-25`, 9 rows, `3550 Implemented`) with the 4,119-symbol source-derived taxonomy (`Implemented: 2399`, `RawSyscall: 410`, `WrapsHostLibc: 1266`, `Stub: 44`), audit remaining `No-op`/`Fallback`/`Bootstrap`/`Unsupported` surfaces (`revoke`, `rexec`, `rexec_af`, `mcheck`, `encrypt`, `_nss_files_*`), and update `README.md` + `scripts/check_docs_semantic_claims.sh` so the semantic claims gate exits `0`.
  - `bd-reality-202609-lx578q.11` (`in_progress`, P2) & `bd-blnp4u` (`in_progress`, P2): Clear the remaining `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --check` findings and wire `scripts/check_test_extern_symbols.sh` into pre-test verification.

---

### WS-1 — Hardened String/Memory Safety, FFI-PCC Unification & `sort` Performance (`P0`/`P1`)
**Goal:** Restore full `AllocationArena` spatial/quarantine protection across all read-only string/memory entrypoints while driving hardened `sort` and string microbenchmarks under `<= 2x` strict (`<= 200ns/call`).

- **Legacy Anchor:** `legacy_glibc_code/glibc/string/` (`memcmp.c`, `strlen.c`, `strcmp.c`, `strcoll_l.c`, `sysdeps/x86_64/multiarch/`).
- **Root Causes Identified in Phase 1:**
  1. `memcmp_validating` (`crates/frankenlibc-abi/src/string_abi.rs:5016-5037`) enters `entrypoint_scope_memcmp()` before `known_remaining`, activating `skip_pointer_validation: true` (`FFI_PCC_READ_ONLY_FLAGS`) and calling `known_remaining_for_certified_read(addr)`, which skips `validate_ptr` (`AllocationArena`) and probes 64 slots of `FALLBACK_ALLOC_PTRS` twice per call.
  2. 12 certified symbols in `FFI_PCC_CERTIFICATES` (`strcmp`, `strncmp`, `strchr`, `strrchr`, `strstr`, `memchr`, `memrchr`, `strnlen`, `memmove`, `memset`, `strcpy`, `strncpy`) never call `entrypoint_scope` in `string_abi.rs`, leaving their FFI-PCC certificates dead and calling `check_ownership` + `known_remaining` 2–6 times per call.
  3. Interior pointers inside `sort`'s large line buffer miss exact-base caches in `TlsValidationCache` (`ptr_validator.rs`) and `FALLBACK_ALLOC_PTRS`, causing repeated multi-stage arena/fallback misses on every line comparison.
  4. In UTF-8 locales (`en_US.UTF-8`), `strcoll` (`string_abi.rs:10632`) calls `CStr::from_ptr(s1)` and `CStr::from_ptr(s2)`, which invoke `strlen` -> `strlen_validating` twice per comparison before `tables.compare(a, b)`.
- **Active Beads:**
  - `bd-rc0923-epic-eeuy4f.9` (`open`, P1): Drive hardened `sort` 100k/120k lines from `~5.2x` (`LC_ALL=C`) and UTF-8 `strcoll` down to `<= 3x` glibc (milestone 1) and `<= 2x` strict (L3 contract).
  - `bd-rc0923-epic-eeuy4f.28` (**NEW**, P0): Fix hardened `memcmp` `AllocationArena` bounds/quarantine bypass, wire `entrypoint_scope` + single-pass `known_remaining` across all 14 string/memory entrypoints in `string_abi.rs`, and add base-interval range caching to `TlsValidationCache` (`crates/frankenlibc-membrane/src/tls_cache.rs`) so interior pointers into an already-validated heap buffer resolve in O(1) (`[user_base, user_base + user_size)`) without re-locking arena shards or probing 64 fallback slots.

---

### WS-2 — Runtime-Math Production Routing, Zero Self-Interposition & SOS/Proof Binding (`P1`)
**Goal:** Make `RuntimeMathKernel` genuinely govern production routing via O(1) precomputed/epoch-updated policy tables without hot-path lock overhead, eliminate all 144 baseline self-interposed `libm` calls, and bind SOS barrier certificates to live deployed allocator/thread telemetry.

- **Legacy Anchor:** `legacy_glibc_code/glibc/math/` (`s_fma.c`, `s_floor.c`, `s_ceil.c`, `s_trunc.c`, `s_round.c`, `s_rint.c`) and `crates/frankenlibc-membrane/src/runtime_math/`.
- **Active Beads:**
  - `bd-reality-202609-lx578q.4` (`in_progress`, P1): Replace the unconditional `cfg(not(test))` kernel bypass in `runtime_policy::decide()` (`runtime_policy.rs:2489-2596`) with cadence-gated / epoch-published atomic routing tables so `RuntimeMathKernel` decisions (`ValidationProfile::Fast` vs `Full`, `Repair`, `Deny`) actively govern production hardened calls at `< 5ns` fast-path read cost, and reconcile `README.md` with exact per-family routing truth.
  - `bd-rc0923-epic-eeuy4f.13` (`in_progress`, P1): Complete export-level dispatch / twin coverage for baseline `x86-64` (`strlen 4096`, `strnlen`, `wcsnlen`, `strcmp`) and verify stdout/stderr parity in `scripts/check_baseline_isa.sh`.
  - `bd-rc0923-epic-eeuy4f.29` (**NEW**, P1): Eliminate all 144 baseline `x86-64` self-interposed calls to `fma`, `fmaf`, `floor`, `ceil`, `trunc`, `round`, and `rint` across `frankenlibc-membrane` (`runtime_math/mod.rs`, `k_theory.rs`, `dro_cvar.rs`, `microlocal.rs`, `bloom.rs`), `frankenlibc-core` (`stdio/printf.rs`, `stdlib/ecvt.rs`, `math/`), and `frankenlibc-abi` by replacing float-intrinsic calls with pure IEEE-754 integer bit-manipulation helpers (for `floor`/`ceil`/`trunc`/`round`/`rint`) and internal non-ABI `core_fma` dispatch, enforced by an `objdump -d -r` gate in `scripts/check_baseline_isa.sh` that forbids internal PLT/relocation edges to exported `math_abi` symbols.
  - `bd-rc0923-epic-eeuy4f.32` (**NEW**, P2): Wire the build-time Cholesky-verified SOS barrier evaluators (`evaluate_fragmentation_barrier`, `evaluate_thread_safety_barrier`, `evaluate_size_class_barrier`, `evaluate_quarantine_barrier`, `evaluate_provenance_barrier` in `crates/frankenlibc-membrane/src/runtime_math/sos_barrier.rs`) into the **deployed** `malloc_abi.rs` and `AllocationArena` cadence telemetry path, and add deterministic property-based / Kani proof harnesses for the core Galois soundness, arena generation-monotonicity, and SOS barrier-invariance obligations (`bd-reality-202609-lx578q.8`).

---

### WS-3 — Deployed Allocator Scaling, Zero-Init `.bss` & Demand-Paged Segments (`P0`/`P1`)
**Goal:** Bring `fork()` latency (`<= 1.5x` glibc), private writable `VmData` (`< 10 MB` under `RLIMIT_DATA`), and 1-to-4-thread `malloc`/`free` throughput (`<= 2x` glibc) into compliance without sacrificing temporal/spatial guarantees.

- **Legacy Anchor:** `legacy_glibc_code/glibc/malloc/malloc.c` (`ptmalloc3` per-thread `tcache_perthread_struct`, `arena_get2`, `sysmalloc`) and Linux `mm/mmap.c` (`may_expand_vm` charging `VM_WRITE & !VM_SHARED` against `RLIMIT_DATA`).
- **Active Beads:**
  - `bd-rc0923-epic-eeuy4f.25` (`open`, P1) & `bd-4n397c` (`open`, P3):
    1. Make `ALLOCATOR_REENTRY_SLOTS` (`malloc_abi.rs:215`, 4,096 slots, ~7.4 MiB) 100% zero-initialized so the linker places it in demand-zero `.bss` instead of initialized `.data`: encode `fallback_cache_index` as `index + 1` (`0 = None`), `SegmentLocalClass.active_segment` as `segment + 1` (`0 = None`), and `SegmentMagazineEntry::EMPTY` as `0` (`offset + 1`).
    2. Change `ensure_segment_arena` (`malloc_abi.rs:651`) to reserve `SEGMENT_RESERVE_SIZE` (~292 MiB) with `PROT_NONE` (`MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE`) and `mprotect` individual 4 MiB segments and their 512 KiB sidecar slices `PROT_READ | PROT_WRITE` lazily when `SEGMENT_NEXT_UNUSED` claims a segment (or coalesce active segment permissions). This drops initial strict `VmData` from ~328 MB to `< 5 MB` (passing gnulib `dprintf-posix2`/`fprintf-posix3` under `RLIMIT_DATA = 10 MB`) and slashes `fork()` VMA/PTE copy time.
  - `bd-rc0923-epic-eeuy4f.26` (`blocked`, P0), `bd-dcrhgl` (`in_progress`, P1), `bd-65p87u` (`in_progress`, P2), `bd-ny3hsa` (`in_progress`, P2), `bd-f874go` (`in_progress`, P2):
    - Replace per-call multi-threaded global stats spinlock / atomic RMW triple (`allocator_depth` CAS + magazine/sidecar RMW + stats fold) with TCB-keyed (`%fs:0` / `tpidr_el0`) thread-local magazines and deferred epoch stats folding, achieving `<= 2x` glibc on 1 and 4 worker threads in `mtm.c`.

---

### WS-4 — L1 Promotion Closure: Printf Specifier Registry, SunRPC Disposition & Fresh Corpus Gate (`P0`/`P1`)
**Goal:** Satisfy every objective obligation in `tests/conformance/replacement_levels.json` so FrankenLibC can honestly promote `current_level` and `current_release_level` from `L0` to `L1` (`Hardened Interpose`).

- **Legacy Anchor:** `legacy_glibc_code/glibc/stdio-common/` (`reg-printf.c`, `reg-modifier.c`, `reg-type.c`, `printf-parsemb.c`, `printf_size.c`) and `legacy_glibc_code/glibc/sunrpc/`.
- **Active Beads:**
  - `bd-rc0923-epic-eeuy4f.30` (**NEW**, P1): Eliminate the 44 `Stub` symbols blocking `stub_free_taxonomy` in `tests/conformance/replacement_levels.json`:
    1. Implement native custom printf registration table (`register_printf_specifier`, `register_printf_function`, `register_printf_modifier`, `register_printf_type`) and `printf_size` / `printf_size_info` in `crates/frankenlibc-core/src/stdio/printf.rs` + `crates/frankenlibc-abi/src/glibc_internal_abi.rs`, wired into `vfprintf`/`vsnprintf` when custom specifiers are registered (zero cost on default path via an `AtomicBool` fast-check `CUSTOM_PRINTF_REGISTERED`).
    2. For the 40 deprecated TIRPC/SunRPC symbols in `crates/frankenlibc-abi/src/rpc_abi.rs` (`authnone_create`, `clnt_create`, `svc_register`, `pmap_set`, etc.), implement host-libc `dlsym(RTLD_NEXT)` interpose wrappers (matching the other 26 `WrapsHostLibc` RPC symbols in `rpc_abi.rs`) with deterministic fallback when host glibc omits obsolete SunRPC exports, and reclassify historical removed Linux syscalls (`revoke`, `rexec`, `rexec_af`, `nfsservctl`, `bdflush`, `create_module`, `get_kernel_syms`, `query_module`, `__sysctl`) consistently in `support_matrix.json` and `support_semantic_overlay.v1.json`.
  - `bd-rc0923-epic-eeuy4f.4` (`in_progress`, P0): Fix the remaining short-lived-process strict startup overhead (lazy segment/runtime init from WS-3) so all ~329 cases in `scripts/ld_preload_smoke.sh` pass with `0 fails` and `0 xfails` in both `strict` and `hardened` modes, regenerate `tests/conformance/ld_preload_smoke_summary.v1.json` via `scripts/check_ld_preload_smoke_regeneration.sh`, and run `scripts/check_replacement_levels.sh` to verify L1 gate readiness.

---

### WS-5 — POSIX / GNU / C23 Conformance & Correctly-Rounded `libm` (`P1`/`P2`)
**Goal:** Close behavioral divergences against glibc 2.43 across `libm`, `pthread`, `stdio`, `stdlib`, `posix`, and `resolv`.

- **Legacy Anchor:** `legacy_glibc_code/glibc/sysdeps/ieee754/` (CORE-MATH `f32`/`f64` kernels), `nptl/` (`pthread_cancel.c`, `pthread_mutex_lock.c`, `unwind.c`), `libio/` (`fmemopen.c`, `iofwide.c`), `posix/wordexp.c`, `stdlib/msort.c`.
- **Active Beads:**
  - `bd-li7fb3` (`in_progress`, P1) & `bd-otip6a` (`in_progress`, P1) & `bd-etgt2x` (`open`, P2): Complete correctly-rounded `f32` (via exact `f64` evaluation + round-to-odd/FMA guard) and `f64` (`asin`, `acos`, `exp`, `log2`, `log10`, `sinh`, `tanh`, `j0`/`j1`/`y0`/`y1`) CORE-MATH ports while keeping `cos`/`tan` within glibc latency budgets.
  - `bd-rc0923-epic-eeuy4f.24` (`in_progress`, P1): Complete `pthread_cancel` parity:
    1. Install a `__libc_start_call_main`-equivalent `setjmp` + `__pthread_register_cancel` unwind landing pad in `crates/frankenlibc-abi/src/startup_abi.rs` so `pthread_exit` or cancellation of `main` under owned startup terminates cleanly instead of `SIGSEGV`ing in `unwind_stop`.
    2. Wire cancellation windows for `thrd_sleep`, `sem_wait`/`sem_timedwait` pre-check, stdio blocking paths, and the opt-in native thread backend (`FRANKENLIBC_THREAD_NATIVE=1`).
  - `bd-rc0923-epic-eeuy4f.15` (`open`, P2): Complete `PTHREAD_PRIO_PROTECT` scheduler priority ceiling enforcement (`sched_setscheduler`/`ENOSYS`/`EINVAL` parity with glibc) and document/optimize robust-mutex owner-death detection.
  - `bd-rc0923-epic-eeuy4f.19` (`open`, P2): Add hermetic namespace DNS/NSS differential tests (`curl`, `ssh -G`, `getent`) for `hosts_policy.rs`.
  - `bd-gtaukk` (`open`, P3), `bd-lamxlj` (`open`, P3), `bd-o55x4n` (`open`, P2), `bd-rv2gv6` (`in_progress`, P2): Enforce `FILE` stream byte/wide orientation (`fwide` state machine), match glibc `fmemopen` deferred write-overflow reporting on `fflush`, and optimize locked `putc`/`fputc` and `fmemopen` `fread`.
  - `bd-uu1wvp` (`in_progress`, P3) & `bd-8p8q15` (`open`, P3) & `bd-g8zy5p` (`open`, P2): Implement `wordexp` command substitution (`fork`+`pipe`+`/bin/sh -c` when `WRDE_NOCMD` is not set), stabilize `qsort` tie order for `n >= 31`, and clear remaining test-sweep failures (`conformance_diff_lfs64_aliases`, `conformance_diff_setfsuid`).

---

### WS-6/7/8 — L2 Partial & L3 Full Standalone Replacement (`libfrankenlibc_replace.so`), Multi-Arch (`aarch64`) & 24h Soak (`P1`/`P3`)
**Goal:** Eliminate `WrapsHostLibc` dependencies on the standalone replacement path, unify the native ELF loader and owned CRT/TLS/pthread/stdio/NSS runtime into a self-hosting `libfrankenlibc_replace.so`, complete `aarch64` TLSDESC/loader parity, and pass the fail-closed WS-8 E2E and 24-hour soak gates.

- **Legacy Anchor:** `legacy_glibc_code/glibc/csu/libc-start.c`, `elf/dl-load.c`, `elf/dl-reloc.c`, `sysdeps/aarch64/dl-tlsdesc.S`, `nptl/pthread_create.c`.
- **Active Beads:**
  - `bd-rc0923-epic-eeuy4f.3` (`in_progress`, P0) & `bd-reality-202609-lx578q.5` (`in_progress`, P1): Unify native `dlopen` link-map registry with `dladdr` and `dl_iterate_phdr` so libgcc/libunwind can unwind through natively loaded DSOs; complete `DT_RPATH`/`DT_RUNPATH`/`LD_LIBRARY_PATH` transitive loading, `DF_1_NODELETE`, and `aarch64` TLSDESC resolver trampoline in `crates/frankenlibc-abi/src/dlfcn_tls.rs`.
  - `bd-reality-202609-lx578q.6` (`open`, P1), `.6.1` (`in_progress`, P1), `.6.2` (`in_progress`, P1), `.6.3` (`blocked`, P1):
    - `.6.1`: Complete owned CRT + TLS + native `clone3`/`futex` thread lifecycle and `__libc_start_call_main` unwind integration without host `libpthread`/`libc`.
    - `.6.2`: Replace the 113 `WrapsHostLibc` `stdio_abi` symbols and 63 `io_internal_abi` symbols on the standalone build profile with native `NativeFile` buffered streams (no host `fopencookie` dependency in standalone mode).
    - `.6.3`: Complete standalone native `locale`, `iconv`, `pwd`/`grp`/`spwd` NSS files, and UDP/TCP DNS resolver backends without host fallback.
  - `bd-reality-202609-lx578q.1` (`in_progress`, P0), `bd-reality-202609-lx578q.9` (`open`, P1), `bd-38x82` (`blocked`, P3), `bd-38x82.4` (`blocked`, P3):
    - Execute `scripts/check_ws8_e2e_standalone_verification.sh --build` and `--check` across `x86_64` and `aarch64` (`qemu-aarch64`), verify `/proc/self/maps` contains zero host `libc.so.6` mappings for standalone probes, validate `.deb` package extraction in an isolated rootfs prefix, and run the 24-hour multi-workload soak harness (`bd-38x82.4`).

---

## 3. Ambition Round 1 — Alien-Artifact Mathematical & Algorithmic Elevation (`alien-artifact-coding`)

> **Core Transparency Invariant (`PLAN_TO_PORT_GLIBC_TO_RUST.md` § "Transparency Rule"):** All high-powered mathematical synthesis runs offline or at startup/epoch boundaries; the hot runtime path executes only plain, deterministic, zero-lock data structures (flat lookup tables, interval caches, bitmasks, seqlocks, and compile-time/startup-verified tokens).

### 3.1 Galois Interval-Projection Cache for O(1) Interior-Pointer Validation (`WS-1` / `bd-rc0923-epic-eeuy4f.9`, `.28`)
- **Problem:** In `hardened` mode, `ValidationPipeline::validate(addr)` (`crates/frankenlibc-membrane/src/ptr_validator.rs:769`) caches `addr -> ValidationOutcome` in `TlsValidationCache` (`tls_cache.rs`) keyed by `(addr >> 4)` (16-byte granularity). When a workload like GNU `sort` allocates a single 4 MiB line buffer `[B, B + L)` and calls `memcmp(p_i, p_j, n)` or `strlen(p_i)` on 120,000 distinct interior line pointers `p_i \in [B, B + L)`, **every distinct 16-byte-aligned interior pointer misses the TLS cache** and falls back to the 16-shard `AllocationArena` lock (`BTreeMap::range(..=addr).next_back()`) or 64-probe `FALLBACK_ALLOC_PTRS` scan!
- **Mathematical Formulation (Abstract Interpretation over Interval Domains, Cousot & Cousot 1977):**
  - An allocation is not a point; it is a contiguous spatial-temporal interval $\mathcal{I}_g = ([b, b + s), g, \sigma)$ with base $b$, length $s$, generation $g$, and safety state $\sigma \in \{\text{Valid}, \text{Quarantined}\}$.
  - Define the Galois insertion $(\alpha, \gamma)$ between concrete interior pointers $p \in \text{Addr}$ and the thread-local interval-ring abstract domain $\mathcal{D}_{\text{TLS}} = \mathcal{I}^K$ ($K = 4$ MRU allocation extents per thread, fitting in two 64-byte L1 cache lines):
    $$\gamma([b, e, g, \text{epoch}]) = \{ p \in [b, e) \mid \text{rem}(p) = e - p \}.$$
  - Soundness condition: as long as `arena.release_epoch() == cached_epoch` (a single `Ordering::Acquire` load of a global `AtomicU64` incremented only when a block is freed/quarantined), any query $p \in [b, e)$ is guaranteed in-bounds with exact remaining bytes $\text{rem}(p) = e - p$ in **4 integer instructions (`sub`, `cmp`, `ja`, `sub`) and 0 locks**!
- **Runtime Artifact (`crates/frankenlibc-membrane/src/tls_cache.rs` & `crates/frankenlibc-abi/src/malloc_abi.rs`):**
  - Add a 4-way MRU **Base-Extent Interval Cache** (`[(base: usize, end: usize, generation: u64, state: SafetyState); 4]`) guarded by `ARENA_RELEASE_EPOCH: AtomicU64` (and `FALLBACK_ALLOC_TABLE_SEQ` for fallback allocations).
  - On any arena or fallback lookup that resolves $p \in [b, b + s)$, insert the full extent $[b, b + s)$ into the thread's 4-slot interval ring.
  - Subsequent `known_remaining(p')` calls for *any* interior pointer $p' \in [b, b + s)$ hit slot 0 in `< 2 ns` (0 locks, 0 hash probes, 0 SipHash recomputations), collapsing `sort`'s 120,000 interior-pointer validations into **1 arena lookup + 119,999 L1 register range checks**!

### 3.2 Static FFI-PCC Token Monomorphization & Single-Pass Validation Synthesis (`WS-1` / `bd-rc0923-epic-eeuy4f.28`)
- **Problem:**
  1. `FFI_PCC_READ_ONLY_FLAGS` (`runtime_policy.rs:405`) sets `skip_pointer_validation: true`, which caused `validate_ptr_in_slot` to return `Unknown` and blinded `memcmp_validating` to `AllocationArena` bounds and quarantine UAFs in hardened mode.
  2. Calling `entrypoint_scope(symbol)` dynamically hashes `(first_8_bytes, len)` and touches TLS twice, while 12 string functions omit `entrypoint_scope` and call `known_remaining` 2–6 times per call.
- **Mathematical Formulation (Proof-Carrying Code Witness Specialization, Necula 1997):**
  - Separate **Stage-Ordering / Kernel-Consult Elision** (`skip_stage_ordering: true`, sound for all 24 certified deterministic string/memory/allocator morphisms) from **Arena-Extent Projection** (`validate_ptr_in_slot`, which *must* remain active in hardened mode so `AllocationArena` bounds and `SafetyState::Quarantined` UAFs are enforced).
  - Factor every unary (`strlen`, `strnlen`, `strchr`, `strrchr`, `memchr`, `memrchr`, `strdup`, `strndup`) and binary (`memcmp`, `memcpy`, `memmove`, `strcmp`, `strncmp`, `strcpy`, `strncpy`, `strcat`, `strncat`, `strstr`, `strcasestr`, `strspn`, `strcspn`, `strpbrk`) hardened string entrypoint into a **Single-Lookup Extent Kernel**:
    $$\text{ExtentSnapshot}(p_1, p_2) = (\text{known\_remaining}(p_1), \text{known\_remaining}(p_2))$$
    computed **exactly once** per call before trace-scope installation, feeding `recent_page`, `bloom_negative`, `decide_certified(PccIndex::SYMBOL, ...)`, and `maybe_clamp_copy_len` from the same register pair.

### 3.3 Bijective Zero-Initialized State Encoding & Demand-Paged VM Geometry (`WS-3` / `bd-rc0923-epic-eeuy4f.25`, `bd-4n397c`)
- **Problem:** Linux `copy_page_range` during `fork()` scales with VMA count and populated PTE count, while `may_expand_vm` (`mm/mmap.c`) rejects any `mmap`/`brk` when private writable pages (`VM_WRITE & !VM_SHARED`) exceed `RLIMIT_DATA`. FrankenLibC's `ALLOCATOR_REENTRY_SLOTS` uses sentinel `usize::MAX`/`u16::MAX`/`u64::MAX` (`~7.4 MiB` in `.data`), and `SEGMENT_RESERVE_SIZE` (`~292 MiB`) is mapped `PROT_READ | PROT_WRITE` upfront.
- **Mathematical Formulation (Affine Sentinel Bijection & Lazy Viability Envelopes):**
  - Define the affine bijection $\phi: \{\text{None}\} \cup \{0, \dots, N-1\} \to \{0, \dots, N\}$ by $\phi(\text{None}) = 0$ and $\phi(i) = i + 1$. Under $\phi$, the identity initial state of `AllocatorReentrySlot` is the zero vector $\mathbf{0} \in \{0\}^{1856}$, moving all $4096 \times 1856 = 7.60\text{ MiB}$ from `.data` (file-backed/dirty COW pages) into `.bss` (unpopulated kernel zero pages).
  - Reserve the 292 MiB segment arena with `mmap(..., PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE)`. Because `PROT_NONE` has `vm_flags & VM_WRITE == 0`, Linux charges **0 bytes** against `RLIMIT_DATA`. When size class $c$ claims segment $k$, transition only $[B + k \cdot 4\text{ MiB}, B + (k+1) \cdot 4\text{ MiB})$ and its sidecar slice via `mprotect(..., PROT_READ | PROT_WRITE)`.

### 3.4 Lock-Free TCB-Keyed Magazine & Hierarchical Counter Folding (`WS-3` / `bd-rc0923-epic-eeuy4f.26`, `bd-65p87u`)
- **Problem:** Multi-threaded `malloc`/`free` is 36x–490x slower than glibc because each pair executes multiple contended atomic RMWs and global stats combiner locks.
- **Mathematical Formulation (Mean-Field Contention Decoupling & Bounded-Drift Martingale Counters):**
  - Key thread reentry slots directly by the architectural TCB self-pointer (`%fs:0` on x86_64, `tpidr_el0` on aarch64) with a direct-mapped thread-local index hint so steady-state `current_allocator_reentry_slot()` executes **zero syscalls and zero shared-cache-line writes**.
  - Replace the per-op global `FlatCombiningStats` spinlock in MT mode with per-slot relaxed accumulators (`SlotMtCounters`) that fold into global stats only every $M = 256$ operations via `try_lock` (never spinning when another thread holds the combiner lock).

### 3.5 IEEE-754 Bit-Level Morphisms for Zero-Reentrancy `libm` Primitives (`WS-2` / `bd-rc0923-epic-eeuy4f.29`)
- **Problem:** In baseline `x86-64` builds without global `+avx2,+fma`, Rust `f64::floor`, `ceil`, `trunc`, `round`, `rint`, and `mul_add` emit calls to the C symbols `floor`, `ceil`, `trunc`, `round`, `rint`, `fma` — which resolve to FrankenLibC's own exported ABI functions (`math_abi.rs`), causing membrane controllers to re-enter the ABI layer!
- **Mathematical Formulation (Bit-Lattice Decomposition of IEEE-754 Binary64):**
  - For any finite $x \in \mathbb{F}_{64}$ with biased exponent $e = ((u \gg 52) \mathbin{\&} \text{0x7ff}) - 1023$:
    - If $e < 0$, $\text{trunc}(x) = \pm 0.0$, $\text{floor}(x) \in \{0.0, -1.0\}$, $\text{ceil}(x) \in \{+0.0, +1.0\}$.
    - If $0 \le e < 52$, the fractional mask is $m = (1 \ll (52 - e)) - 1$; clearing bits $u \mathbin{\&} \sim m$ yields $\text{trunc}(x)$ in **6 branch-free ALU instructions** with zero FPU state or symbol calls!
    - If $e \ge 52$ (or NaN/Inf), $x$ is already an integral float ($x + 0.0$).
  - For `mul_add(a, b, c)` inside internal crates, route through an internal `frankenlibc_core::math::internal_fma(a, b, c)` that dispatches via cached CPUID (`fma` instruction when available, pure Dekkers-Veltkamp `dd_mul_add` software FMA otherwise) without touching `extern "C" fn fma`.

---

## 4. Ambition Round 2 — Extreme Systems Optimization & Verification Architecture (`extreme-software-optimization`)

### 4.1 Zero-Cost Default Path for Custom Printf Registry (`WS-4` / `bd-rc0923-epic-eeuy4f.30`)
- **Design:** GNU `register_printf_specifier` / `register_printf_function` / `register_printf_modifier` / `register_printf_type` and `printf_size` / `printf_size_info` are required by `stub_free_taxonomy` for L1 promotion and by gnulib/systemd-style formatters.
- **Optimization:** Maintain a single `CUSTOM_PRINTF_COUNT: AtomicU32 = AtomicU32::new(0)` in `frankenlibc-abi`. When `CUSTOM_PRINTF_COUNT.load(Ordering::Relaxed) == 0` (99.99% of processes), `vfprintf`/`vsnprintf` stays on the exact existing fused/core fast path with **zero extra branches in the format-specifier inner loop**! Only when a process calls `register_printf_*` does `CUSTOM_PRINTF_COUNT` become non-zero, activating the read-mostly `RwLock<PrintfExtensionRegistry>` table lookup on unknown/registered conversion specifiers.

### 4.2 Unified Host/Native Cancellation & `__libc_start_call_main` Unwind Frame (`WS-5` / `bd-rc0923-epic-eeuy4f.24`)
- **Design:** Under owned startup (`__libc_start_main` in `crates/frankenlibc-abi/src/startup_abi.rs`), calling `pthread_exit` from `main` or cancelling the main thread currently `SIGSEGV`s in libgcc's `unwind_stop` because there is no outer `pthread_unwind_buf` registered on the main thread's stack.
- **Architecture:**
  1. Model `startup_abi.rs` directly on `legacy_glibc_code/glibc/sysdeps/nptl/libc_start_call_main.h`: allocate a `pthread_unwind_buf` on the stack frame of `__libc_start_main`, initialize its `cancel_jmp_buf` via `__sigsetjmp(&mut buf, 0)`, register it via `__pthread_register_cancel(&mut buf)` when `setjmp == 0`, invoke `main(argc, argv, envp)`, and on non-zero `setjmp` return (forced unwind / `pthread_exit` from `main`), call `__pthread_cleanup_routine` and `exit(0)` (or wait for remaining threads via `_exit` when last thread exits).
  2. For native threads (`FRANKENLIBC_THREAD_NATIVE=1`), send `SIGRTMIN` (`SIGCANCEL`) via `tgkill(pid, tid, SIGCANCEL)` on `pthread_cancel`, and in the signal handler, when the interrupted `ucontext_t` PC lies within `[__frankenlibc_cancel_region_start, __frankenlibc_cancel_region_end)` (or async cancel is enabled), invoke `_Unwind_ForcedUnwind` directly from the signal frame.

### 4.3 Live Deployed SOS Barrier Telemetry & Mechanized Invariant Harnesses (`WS-2` / `bd-rc0923-epic-eeuy4f.32`)
- **Design:** Connect the 5 SOS polynomial certificates in `crates/frankenlibc-membrane/src/runtime_math/sos_barrier.rs` (`fragmentation`, `thread_safety`, `size_class`, `quarantine`, `provenance`) to the **actual deployed allocator and validator state** in `crates/frankenlibc-abi/src/malloc_abi.rs` and `crates/frankenlibc-membrane/src/arena.rs` on every 256th allocation/free fold epoch:
  - Feed real `(requested_bytes, class_size, waste_ppm)`, `(active_threads, contention_events, lock_hold_ns)`, and `(quarantine_bytes, arena_live_bytes, adverse_rate_ppm)` into `evaluate_*_barrier(...)`.
  - When any SOS barrier certificate headroom drops below `0` (`SosBarrierState::Violated`), atomically escalate `AllocationArena` quarantine drain cadence and force `ValidationProfile::Full` across all threads, logging a structured `sos_barrier_violation` event to `FRANKENLIBC_LOG`.

---

## 5. Complete Bead Mapping & Backlog Matrix (`2026-10-13`)

### 5.1 Newly Created Beads in This Pass (Closing All `NO_BEAD` Gaps)

| Bead ID | Priority | Parent Epic | Workstream | Title & Scope |
|---|---|---|---|---|
| `bd-rc0923-epic-eeuy4f.28` | `P0` | `bd-rc0923-epic-eeuy4f` | `WS-1` | **[RC-1013] Fix hardened `memcmp` Arena bypass, wire dead FFI-PCC scopes across 12 `string_abi` entrypoints, and add 4-way TLS Base-Extent Interval Cache for O(1) interior-pointer validation** |
| `bd-rc0923-epic-eeuy4f.29` | `P1` | `bd-rc0923-epic-eeuy4f` | `WS-2` | **[RC-1013] Eliminate 144 baseline x86-64 self-interposed `fma`/`floor`/`ceil`/`trunc`/`round`/`rint` ABI calls in membrane/core/abi with bit-level IEEE-754 kernels + relocation gate** |
| `bd-rc0923-epic-eeuy4f.30` | `P1` | `bd-rc0923-epic-eeuy4f` | `WS-4` | **[RC-1013] Unblock L1 `stub_free_taxonomy` gate: implement native `register_printf_*` + `printf_size` registry and host-fallback/reclassify the 40 SunRPC stubs** |
| `bd-rc0923-epic-eeuy4f.31` | `P1` | `bd-rc0923-epic-eeuy4f` | `WS-0` | **[RC-1013] Reconcile `support_semantic_overlay.v1.json` with 4,119-symbol taxonomy and restore `check_docs_semantic_claims.sh` to green** |
| `bd-rc0923-epic-eeuy4f.32` | `P2` | `bd-rc0923-epic-eeuy4f` | `WS-2` | **[RC-1013] Bind Cholesky SOS barrier evaluators to deployed `malloc_abi`/`AllocationArena` telemetry and add mechanized Galois/arena/SOS property proof harnesses** |

### 5.2 Existing Open / In-Progress / Blocked Beads Across Workstreams

| Workstream | Bead IDs | Current Status | Key Deliverable |
|---|---|---|---|
| **WS-0 (Truth & Evidence)** | `bd-rc0923-epic-eeuy4f.17`, `.18`, `.31`, `bd-reality-202609-lx578q.2`, `.11`, `bd-blnp4u` | `in_progress` / `open` | Source-derived `support_matrix.json`, refreshed `support_semantic_overlay.v1.json`, live `healing_oracle_report.v1.json`, executing CVE & completion gates, green `clippy`/`fmt`/`check_docs_semantic_claims.sh`. |
| **WS-1 (Hardened String & `sort`)** | `bd-rc0923-epic-eeuy4f.9`, `.28` | `open` | Hardened `memcmp` bounds/UAF fix, all 24 FFI-PCC scopes active, 4-way TLS Base-Extent Interval Cache, single-pass `known_remaining`, hardened `sort` `<= 2x` strict. |
| **WS-2 (Runtime Math, ISA & SOS)** | `bd-reality-202609-lx578q.4`, `bd-rc0923-epic-eeuy4f.13`, `.29`, `.32` | `in_progress` / `open` | Epoch-published production `RuntimeMathKernel` routing, 0 self-interposed `libm` calls in baseline `.so`, deployed SOS barrier telemetry + mechanized proof tests. |
| **WS-3 (Allocator & `fork` Perf)** | `bd-rc0923-epic-eeuy4f.25`, `.26`, `bd-4n397c`, `bd-dcrhgl`, `bd-65p87u`, `bd-ny3hsa`, `bd-f874go` | `open` / `in_progress` / `blocked` | Zero-init `.bss` `ALLOCATOR_REENTRY_SLOTS`, lazy `PROT_NONE` → `PROT_READ\|PROT_WRITE` segment activation (`VmData < 10 MB`, `fork <= 1.5x`), TCB-keyed MT magazines (`mtm.c <= 2x`). |
| **WS-4 (L1 Promotion Gate)** | `bd-rc0923-epic-eeuy4f.4`, `.30` | `in_progress` / `open` | `stub = 0` in `replacement_levels.json`, fresh `ld_preload_smoke_summary.v1.json` (`0 fails`, `0 xfails` across ~329 cases in strict + hardened), L0 → L1 promotion. |
| **WS-5 (POSIX / `libm` / `pthread`)** | `bd-li7fb3`, `bd-otip6a`, `bd-etgt2x`, `bd-rc0923-epic-eeuy4f.15`, `.19`, `.24`, `bd-gtaukk`, `bd-lamxlj`, `bd-o55x4n`, `bd-rv2gv6`, `bd-uu1wvp`, `bd-8p8q15`, `bd-g8zy5p` | `in_progress` / `open` | Correctly-rounded `f32`/`f64` `libm`, `__libc_start_call_main` cancel landing pad + native-thread cancel, `PRIO_PROTECT` boost, `fwide` orientation, `fmemopen` flush, `wordexp` `$(cmd)`, hermetic DNS tests. |
| **WS-6/7/8 (Standalone L2/L3 & Soak)** | `bd-rc0923-epic-eeuy4f.3`, `bd-reality-202609-lx578q.1`, `.5`, `.6`, `.6.1`, `.6.2`, `.6.3`, `.7`, `.8`, `.9`, `bd-38x82`, `bd-38x82.4` | `in_progress` / `open` / `blocked` | Native `dlfcn` + `dl_iterate_phdr` + `aarch64` TLSDESC, standalone CRT/TLS/pthread/stdio/NSS without `WrapsHostLibc`, fail-closed WS-8 E2E and 24h soak pass. |

---

## 6. Success Metrics & Exit Gates

| Workstream | Metric | Target | Verification Gate |
|---|---|---|---|
| **WS-0** | Stale/contradictory JSON artifacts or non-executing CVE/healing gates | `0` | `bash scripts/check_docs_semantic_claims.sh && bash scripts/cve_arena_gate.sh` |
| **WS-1** | Hardened `memcmp` arena bounds/UAF bypasses; redundant `known_remaining` calls per string op; hardened `sort` 120k ratio vs glibc | `0` bypasses; `1` lookup/ptr; `<= 2.0x` strict (`<= 3.0x` glibc) | `rch exec -- cargo test -p frankenlibc-abi --test string_abi_test --test hardened_mode_safety_test` + pinned `sort` 120k A/B |
| **WS-2** | Self-interposed `fma`/`floor`/`ceil`/`trunc`/`round`/`rint` relocations in `libfrankenlibc_abi.so`; production families with audited `RuntimeMathKernel` routing | `0` self-calls; `100%` families documented & gated | `bash scripts/check_baseline_isa.sh` + `rch exec -- cargo test -p frankenlibc-abi --test runtime_policy_test` |
| **WS-3** | Strict/hardened initial `VmData`; `fork+exit+wait` ratio vs glibc; 1T/4T `mtm.c` ratio vs glibc | `VmData < 10 MB`; `fork <= 1.5x`; `mtm <= 2.0x` | `fixture_fork_mt`, gnulib `dprintf-posix2` (`RLIMIT_DATA=10MB`), `mtm.c` 1T/4T benchmark |
| **WS-4** | `Stub` symbol count in `support_matrix.json`; `ld_preload_smoke.sh` fails/xfails in strict & hardened | `0` stubs; `0` fails / `0` xfails | `bash scripts/check_replacement_levels.sh && bash scripts/check_ld_preload_smoke_regeneration.sh` |
| **WS-5** | `f32`/`f64` non-CR outliers on CORE-MATH domain; `pthread_cancel` hang/SIGSEGV rows across 186-case probe | `0` unaccepted diffs; `0` hangs / `0` SIGSEGVs | `fixture_pthread_cancel`, `conformance_diff_math*`, `wordexp`/`stdio`/`qsort` differential tests |
| **WS-6/7/8** | Host `libc.so.6` mappings in `/proc/self/maps` for L3 standalone binary; WS-8 E2E status | `0` host mappings; `PASS` on `x86_64` + `aarch64` | `bash scripts/check_ws8_e2e_standalone_verification.sh --check` |

---

## 7. Verification Discipline (Applies to Every Bead)

- **No silent or uncompiled gates:** Always compile and execute named test targets via `rch exec -- cargo test ...` with `--keep-going` where appropriate, and quote the `test result: ok. N passed` line (`N > 0`).
- **Incumbent live in the same invocation:** Every performance claim requires live glibc and the incumbent FrankenLibC `.so` measured in the same order-rotated invocation under `scripts/check_perf_ledger_integrity.py`.
- **Companion tests + negative controls:** Every implementation bead carries unit tests (happy/edge/error), an E2E/preload probe emitting structured JSONL logs (`trace_id`, `mode`, `api_family`, `symbol`, `decision_path`, `healing_action`, `errno`, `latency_ns`), and a planted negative control proving the gate fails when the invariant is broken.
- **No file deletion (Rule 1) & worktree hygiene:** Never delete files without explicit user permission; never revert or touch uncommitted work from other agents.
