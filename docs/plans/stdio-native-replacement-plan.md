# STDIO_NATIVE_REPLACEMENT_PLAN

> **Single-file working plan** for replacing the host-glibc stdio delegation paths in `crates/frankenlibc-abi` with the existing native Rust stdio kernel in `crates/frankenlibc-core/src/stdio/`. This file is the only document for this work; all revisions happen in place. Beads are generated from this file in Phase 3a.

**Status:** Draft v4 (Phase 4 round 3 — performance / observability / supply-chain honesty pass).
**Owner of this round:** plan-space only — no implementation yet.
**Depends on:** the audit report produced 2026-04-08 against `crates/frankenlibc-abi/src/stdio_abi.rs` and `crates/frankenlibc-core/src/stdio/`.

**Revision history (in this file):**
* v1 — initial draft. Scope = fopen/fdopen + a handful of cleanup sites.
* v2 — exploded the FILE-acquisition surface to 16 channels; added vtable, foreign-pointer adoption, locking, orientation, append-mode atomicity, signal handling, and runtime_math wiring as bonus.
* v3 — operationalized the methodology. Stdio is reverse-round anchor #5 (`stdio-common`/`libio`/`io`/`posix` parser-state explosions). The plan now states formal invariants, proof obligations, and an offline synthesis pipeline that generates parser/transducer tables for `printf`/`scanf` instead of hand-writing the format engines. Runtime_math is the primary hardened-mode policy, not an ornament.
* v4 — production-honesty layer. Continuous bench gates with isolation discipline, versioned evidence schemas, witness-chain construction for the support-matrix headline number, rollback story, closure-contract gate updates, Atiyah-Bott proof DAG compression, and an explicit "supply chain" of mechanical evidence linking source code → counts → README claim.

---

## 1. Why this work exists

The reality-check audit identified one central honesty gap:

> The README's headline "100.0% native coverage / 0 GlibcCallThrough" is technically true under the support matrix's current labelling rule, but materially false at runtime: when `prefer_host_stdio_streams()` returns true (the default), `fopen()` and `fdopen()` delegate to host libc and return host glibc `FILE*` pointers. From that moment on, every subsequent `fread`/`fwrite`/`fclose`/`fseek` on that stream is forced to delegate too — the FrankenLibC stream registry has no entry for that pointer, so the runtime fallback path is "call host libc."

The project's own Design Invariants explicitly state that drift between docs and machine artifacts is treated as a bug. Two ways to close this gap exist; this plan pursues **Option B**: make the native stdio path the only path, so the headline number becomes literally true.

The audit also revealed a more encouraging picture than the reality-check had assumed:

* `crates/frankenlibc-core/src/stdio/` is **4,149 LOC of real native Rust** (`buffer.rs` 493, `file.rs` 1160, `printf.rs` 1446, `scanf.rs` 1026, `mod.rs` 24).
* `NativeFile` already exists in `crates/frankenlibc-abi/src/io_internal_abi.rs` L66–116 (288 bytes, statically asserted ≥ 216 bytes for `_IO_FILE` layout compatibility).
* `init_host_stdio_streams()` (misleadingly named) in `stdio_abi.rs` L653–664 already initializes `stdin`/`stdout`/`stderr` from **native** stream pointers via `io_internal_abi::native_stdio_stream_ptr()`.
* Tests `io_internal_*_use_native_stdio_paths()` (`stdio_abi_test.rs` L2443, 2524, 2552, 2609, 2650) already exercise the native machinery in isolation.
* Most stdio entry points already do "check registry first; only delegate if the FILE\* is alien." The leak is upstream — only `fopen` / `fdopen` create alien pointers.

**Therefore:** the scope of Option B is much smaller than the reality-check feared. Closing the gap is two changes plus their propagation: stop emitting host pointers from `fopen`/`fdopen`, and re-route the small handful of non-stdio_abi.rs callers that still use `libc::fread/fwrite/...`.

## 1.4 Methodology framing — this is reverse-round anchor #5 (added v3)

AGENTS.md "Reverse-Round Legacy Anchors" lists `stdio-common`, `libio`, `io`, `posix` (anchor #5: *streams/syscalls/parser surfaces*) as one of the concrete legacy pressure points the project exists to dissolve. The "Reverse Core Map" instruction for this anchor reads:

> *5. stdio/parser/locale formatting: eliminate parser-state explosions and locale drift; ship generated parser/transducer tables.*

v3 takes this seriously. The plan is no longer "hand-port stdio to native Rust." It is:

1. **Spec-extract** the printf/scanf format languages and the buffering state machine into a small typed grammar (using the project's existing methodology language: lattice, Galois, separation logic).
2. **Synthesize** parser/transducer tables offline (in `tools/stdio_synth/` — new directory, but it lives outside the runtime crates so it does not pollute the libc build).
3. **Compile** those tables into static `const` arrays in `frankenlibc-core/src/stdio/printf_tables.rs` and `scanf_tables.rs` (replacing the hand-written `printf.rs` engine in steady state).
4. **Discharge proof obligations** at synthesis time using SMT (the project's "Mandatory Modern Math Stack" requirement #3).
5. **Compile down to compact deterministic guards/dispatch** — exactly the Developer Transparency Contract from AGENTS.md.

This means the steady-state runtime stdio kernel becomes *smaller*, not larger, after this work. The hand-written `printf.rs` (1446 LOC) shrinks to a table-driven dispatcher plus the generated table (which is large but auditable, deterministic, and proven correct against the spec).

This is also the answer to the obvious objection: "you're rewriting stdio, why is the project methodology relevant at all?" Because the stated project methodology *is* "spec → synthesis → compact runtime artifact + proof," and stdio is one of the named anchors. Doing this rewrite *without* applying the methodology would be reverting to hand-port mode, which is exactly what AGENTS.md "Clean-Room Porting" rule #2 forbids.

## 1.5 Formal model and invariants (added v3)

A `NativeFile` is a tuple `(fd, buf, mode, eof, err, ungetc, orient, mbst, gen, locks)` where:

* `fd ∈ ℤ ∪ {-1}` is the underlying Linux fd, or -1 for memory-backed/cookie streams
* `buf ∈ Buffer = (data, head, tail, cap)` with `0 ≤ head ≤ tail ≤ cap`
* `mode ∈ {Full, Line, None}`
* `eof, err ∈ 𝔹`
* `ungetc ∈ Option<u8>`
* `orient ∈ {Byte, Wide, Undecided}`
* `mbst ∈ MbState` (per-stream multibyte conversion state)
* `gen ∈ ℕ` (generation counter; incremented on every reopen)
* `locks ∈ ℕ` (recursive lock depth)

**Lattice (refines the existing `SafetyState` from `crates/frankenlibc-membrane/src/lattice.rs`):**

```
Open(orient=Byte) ⊔ Open(orient=Wide) = Open(orient=⊤)
Open ⊔ Eof = Eof          Eof ⊔ Err = Err          Err ⊔ Closed = Closed
```

The lattice is monotone: state can only move toward `Closed`. This refines AGENTS.md's "Monotonic Safety" property to the stdio domain.

**Galois connection (refines `crates/frankenlibc-membrane/src/galois.rs`):**

The C view of a stream is the flat tuple `(FILE*, errno)`. The rich Rust view is the `NativeFile` above. The abstraction `α: C → NativeFile` maps a `FILE*` to its registry entry. The concretization `γ: NativeFile → Set<C>` maps a `NativeFile` to the set of C states that are "no worse than" it. The required property is `γ(α(c)) ⊇ {c}`, which holds because every native operation produces a C-observable state at least as restrictive as the original (e.g., a buffered write that has not flushed still observably succeeded from the C side; a buffered read that has consumed bytes still observably advanced from the C side).

**Per-entrypoint invariants (proof obligations):**

For each public stdio entrypoint, v3 names the invariant that must hold pre and post call. Phase 5 refinement will check these against the native kernel implementation.

| Function | Pre | Post |
|---|---|---|
| `fopen(path, mode)` | path ≠ NULL ∧ mode ∈ valid_mode_strings | (return = NULL ∧ errno ≠ 0) ∨ (return ∈ registry ∧ return.fd ≥ 0 ∧ return.gen = fresh ∧ orient = Undecided) |
| `fread(buf, sz, n, fp)` | fp ∈ registry ∧ buf ≠ NULL ∧ sz·n ≤ ISIZE_MAX | return ≤ n ∧ (return < n → fp.eof ∨ fp.err) ∧ first return·sz bytes of buf are filled from fp |
| `fwrite(buf, sz, n, fp)` | fp ∈ registry ∧ buf ≠ NULL ∧ sz·n ≤ ISIZE_MAX ∧ fp opened for write | return ≤ n ∧ (return < n → fp.err) ∧ first return·sz bytes were committed (subject to buffering) |
| `fseek(fp, off, whence)` | fp ∈ registry ∧ whence ∈ {SEEK_SET, SEEK_CUR, SEEK_END} | (return = 0 ∧ fp.eof = false ∧ ungetc cleared) ∨ (return = -1 ∧ errno ≠ 0) |
| `ftell(fp)` | fp ∈ registry | return = current position ∨ (return = -1 ∧ errno ≠ 0); current position is `lseek(fp.fd, 0, SEEK_CUR) - (fp.buf.tail - fp.buf.head) + ungetc?1:0` |
| `fclose(fp)` | fp ∈ registry | fp.fd closed (or no-op for stdin/stdout/stderr), registry entry removed, all dirty buffer flushed (unless fp.err already set), generation incremented |
| `ungetc(c, fp)` | fp ∈ registry | (return = c ∧ fp.ungetc = Some(c) ∧ fp.eof cleared) ∨ (return = EOF ∧ no state change) |
| `fflush(fp)` | fp = NULL ∨ fp ∈ registry | for fp = NULL: every dirty fp in registry flushed; for fp ≠ NULL: fp's dirty bytes committed via syscall; ungetc cleared |
| `fileno(fp)` | fp ∈ registry | return = fp.fd ∨ (return = -1 ∧ errno = EBADF for memory/cookie streams) |
| `feof(fp)`/`ferror(fp)` | fp ∈ registry | return = fp.eof / fp.err (no side effect) |
| `clearerr(fp)` | fp ∈ registry | fp.eof = false ∧ fp.err = false |

These invariants are written in `tests/conformance/stdio_invariants.v1.json` as a machine-checkable contract, and the harness verifies each invariant on every fixture run. This is the project's existing "fixture-driven conformance" pattern (per AGENTS.md), narrowed to stdio.

## 1.6 Mandatory math stack mapping (added v3)

AGENTS.md lists 44 "Mandatory Modern Math" obligations and a branch-diversity rule (≥3 families per milestone, ≥1 from each of {conformal statistics, algebraic topology, abstract algebra, Grothendieck-Serre methods}). The stdio milestone uses:

| AGENTS.md obligation | Where it's used in this plan |
|---|---|
| #1 Abstract interpretation + Galois maps | §1.5 lattice + Galois connection above |
| #2 Separation logic | Buffer/fd ownership invariants — `buf` is exclusively owned by the holder of the per-FILE recursive lock; `fd` may be shared with the kernel but is non-aliased within FrankenLibC |
| #3 SMT-backed refinement | Generated printf/scanf tables prove their dispatch matches the POSIX spec via SMT before being committed |
| #4 Decision-theoretic loss minimization | Hardened-mode repair policy selection for short reads / partial writes (POMDP belief × loss function) |
| #5 Anytime-valid sequential testing | E-process drift gate on the ratio (membrane-validated stdio calls : raw syscalls); fires before any single-test FPR can be tripped by a long-tailed workload |
| #6 Bayesian change-point | Change-point on `read`/`write` latency series — fires when the underlying device characteristics shift (e.g., the file moved from page cache to disk) |
| #7 Robust optimization for tail latency | CVaR controller on stdio call latency (already proposed in v2 §12) |
| #8 Constrained POMDP | The repair policy controller from v2 §12, now promoted to the *primary* hardened-mode dispatcher for the entire stdio family — see §1.7 |
| #16 Sheaf-cohomology | Cohomology controller from v2 §12 (buffer-cursor view ↔ kernel-view consistency on a sliding window) |
| #18 Probabilistic coupling | Coupling argument that strict-mode and hardened-mode behavior are observationally equivalent on conforming inputs (only diverge on inputs that strict mode would have UB'd on) |
| #21 SOS certificates | SOS barrier certificate on the buffer-state polytope: `head ≤ tail ≤ cap ∧ ungetc⇒head>0 ∧ ungetc⇒¬eof` is a polynomial invariant verified at every entry/exit |
| #27 Conformal prediction | Per-family conformal risk envelopes from v2 §12 |

This satisfies the branch-diversity rule (algebraic topology via #16, abstract algebra via #2/#21, conformal/sequential statistics via #5/#27, Grothendieck-Serre via the generation/cohomology consistency monitor — note that the existing `runtime_math/grothendieck_glue.rs` module already provides exactly this primitive, which is why one of the v2 controllers can be "promoted" with no new code).

## 1.7 POMDP repair as the primary hardened-mode policy (added v3)

POSIX leaves a *lot* of stdio behavior implementation-defined or weakly specified ("may return short," "may set errno," "the value of errno is unspecified after a successful call"). v1 treated these as edge cases. v3 treats them as the *normal* case for which a principled policy is needed.

The repair POMDP for stdio:

* **State `s`** = `(fd_class, recent_short_count, recent_eintr_count, recent_eagain_count, buffer_pressure, runtime_mode)`
* **Action `a` ∈** `{NormalReturn, RetryOnce, RetryUntilSatisfied, ReturnShortAndSetEof, ReturnShortAndSetErr, BlockUntilReadyDeadline, AbortWithCanaryEvidence}`
* **Observation `o`** = `(syscall_return_code, errno_after, elapsed_ns, bytes_actually_transferred)`
* **Reward `r`** = `−(loss_from_corruption + 0.001·loss_from_extra_latency_us + 1000·loss_from_unbounded_block)`
* **Transition `T`** trained offline on a corpus of recorded fd traces from real workloads
* **Belief update** is the standard Bayesian filter; the controller stores a small categorical belief over `fd_class ∈ {RegularFile, Pipe, Socket, Tty, EpollFd, Other}`

The runtime cost is one categorical update + one table lookup per stdio call — well under 100 ns.

The existing `crates/frankenlibc-membrane/src/runtime_math/pomdp_repair.rs` module is exactly this primitive. v2 listed it as a bonus wiring; v3 makes it the *primary* dispatcher: every hardened-mode stdio call goes `decide()` → POMDP action → kernel. Strict mode bypasses POMDP for ABI compatibility (strict's whole point is "act like glibc would have"). This is the clean way to satisfy the project's "hardened repair policy is deterministic" invariant: the POMDP is deterministic given a fixed seed and a fixed belief, and the belief is reproducible from the call history.

## 1.8 Offline synthesis pipeline for printf/scanf (added v3)

`tools/stdio_synth/` (new directory, **not** part of the libc workspace — runs at build time only, ships nothing into the `.so`):

1. `spec/printf_grammar.json` — formal grammar of the POSIX printf format language as a typed regular tree (flag set × width × precision × length × conversion).
2. `spec/scanf_grammar.json` — same for scanf.
3. `synth/printf_compiler.rs` — Rust binary that consumes the grammar, generates a `const` dispatch table (`PRINTF_TABLE: [PrintfRoute; 256]`), and emits a Rust source file `crates/frankenlibc-core/src/stdio/printf_tables.rs`.
4. `synth/proof.rs` — for each generated route, emits an SMT-LIB script asserting that the route's behavior matches a small reference interpreter encoded in the grammar. Run via `cvc5` (or `z3`) at build time. Build fails if any obligation is unproven.
5. `synth/coverage.json` — generated covering-array confirming that every (flag × length × conversion) interaction is exercised by the generated table. AGENTS.md obligation #17 (covering arrays for high-order conformance interaction coverage) is satisfied here.
6. The hand-written `crates/frankenlibc-core/src/stdio/printf.rs` becomes a 200-line dispatcher that consumes the generated table, plus the float-printing helpers (which require Grisu/Ryu and are not table-friendly).

This is a *real* application of AGENTS.md "Required Methodology" — not theatre. The deliverable is *less* hand-written code, *more* proof, and an artifact that any contributor can regenerate from the grammar without re-deriving the format-string semantics.

> Phase 5 refinement note: the synthesis tool itself needs its own beads: grammar definition, compiler, prover binding, CI hookup, golden round-trip test on the generated table.

## 1.10 The complete FILE-acquisition surface (added v2)

A reliable Option B replacement requires that **every** way a `FILE*` enters a program produces a FrankenLibC `NativeFile *`, never a host glibc pointer, and that every way it leaves (close, exit, longjmp, exec) cleans up the native state. v1 named only `fopen` / `fdopen`. The full census:

| # | Channel | Symbol(s) / mechanism | Currently produces | Required |
|---|---|---|---|---|
| 1 | Path open | `fopen`, `fopen64`, `freopen`, `freopen64` | Host `FILE*` (when prefer_host) | `NativeFile *` |
| 2 | FD wrap | `fdopen` | Host `FILE*` | `NativeFile *` |
| 3 | Pipe open | `popen` | Host `FILE*` (via `pipe`+`fork`+`fdopen`) | `NativeFile *`; native popen needs to drive `posix_spawn` and wire the pipe end through `fdopen` natively |
| 4 | Temp file | `tmpfile`, `tmpfile64` | Host `FILE*` | Native: `mkstemp` + `unlink` + native `fdopen` |
| 5 | Memory backing — fixed buffer | `fmemopen` | Mixed; may be native already | `NativeFile *` with a memory-backing variant of `NativeFile` |
| 6 | Memory backing — growing | `open_memstream` | Mixed | `NativeFile *` with `realloc`-on-overflow buffer + on-close size publication |
| 7 | Wide memory backing | `open_wmemstream` | Mixed | Same as #6 but `wchar_t` orientation locked |
| 8 | Cookie streams | `fopencookie` | Unknown — almost certainly host-delegated | `NativeFile *` carrying a `cookie_io_functions_t` vtable + the user cookie |
| 9 | Standard streams | `stdin`, `stdout`, `stderr` exported globals (and the `_IO_2_1_*_` aliases) | Already native (per `init_native_stdio_streams()`) | unchanged — already correct |
| 10 | Inherited fd | child process inherits open `FILE*`-backed fds across `fork`/`exec` | The `FILE*` itself is process-local, but fd survives | After `fork`, child re-creates `NativeFile` shells via `fdopen` on the surviving fds — verify this happens before any stdio call in the child |
| 11 | Aliased binary symbols | Some binaries link against `_IO_2_1_stdin_` etc. directly | Currently aliased to host symbols by the loader | The `version_scripts/libc.map` must export these names from FrankenLibC and bind them to the same `NativeFile` objects as `stdin`/`stdout`/`stderr` |
| 12 | Library handed-back FILE* | `dlopen`'d library opened the file *before* LD_PRELOAD took effect, then handed the `FILE*` back to the LD_PRELOAD'd binary | host pointer in the wild | Detect via the bloom-filter ownership precheck (the membrane already has this!); on detection, *adopt* the host pointer into the registry by reading its `_fileno` and creating a `NativeFile` shell around the same fd. This is a real and important case for nginx-style modular binaries. |
| 13 | Reverse — library expects to receive a host FILE* | rare but exists (e.g., libxml2 callbacks) | Currently works because we hand back host pointers | Once we own the FILE struct, the only safe story is the layout-compatible Option B struct (see §3); third-party code that pokes inside FILE will read sensible values. |
| 14 | Wide-char-only stdio | `getwc`/`putwc`/`fwide`/`fwprintf`/`fwscanf` | wchar_abi.rs delegates implicitly via opaque pointer pass-through | Native; need `mbstate_t` orientation tracked in `NativeFile` so `fwide` is honored monotonically per POSIX |
| 15 | C++ wrappers around C streams | `std::FILE` is `::FILE` | inherits whatever the C path does | unchanged once #1–#13 are fixed |
| 16 | Process-exit close | `_exit` vs `exit` divergence — `exit` flushes all `FILE*`s, `_exit` does not | currently relies on glibc atexit | FrankenLibC `__cxa_atexit` registration must walk the `NativeFile` registry and flush every dirty buffer. This is its own bead. |

The take-away: **the leak is not 2 functions, it's 16 channels, but the *structural* leak is still rooted in only a handful of constructors.** Once `fopen`/`fdopen`/`freopen`/`popen`/`tmpfile`/`fmemopen`/`open_memstream`/`open_wmemstream`/`fopencookie` all build `NativeFile`, every other entry point already does the right thing because they consult the registry first. Channel 12 (foreign-pointer adoption) is the trickiest because we have to *detect* alien pointers and gracefully wrap them — but the membrane bloom filter is exactly the right mechanism for this and is already wired up. v1 missed this entire branch.

## 1.11 Locking and concurrency model (added v2)

POSIX requires every standard stdio function to be thread-safe via implicit per-FILE locking, with `flockfile`/`funlockfile`/`ftrylockfile` exposed for explicit batching, and the `*_unlocked` family for callers that have the lock. v1 ignored this entirely.

* `NativeFile` must contain a `parking_lot::Mutex<NativeFileLockedState>` (or an equivalent recursive lock — POSIX requires recursive locking, parking_lot's `ReentrantMutex` is the right primitive).
* Every public ABI function (`fread`, `fwrite`, ...) acquires the lock before entering the kernel, releases on exit. Every `*_unlocked` variant skips the acquisition and asserts the caller is the lock holder under `cfg(debug_assertions)`.
* `flockfile`/`funlockfile`/`ftrylockfile` (`stdio_abi.rs` — verify these exist; if not, add them) operate on the same recursive mutex.
* The recursive lock count must survive `setjmp`/`longjmp` correctly: longjmp out of a `flockfile`'d region releases the lock as part of the unwind. This couples to `setjmp_abi.rs` and is its own bead — flag for follow-up.
* Multi-thread atomicity test: a stress test that fans out 32 threads, each writing 1024 4-byte records to a shared FILE\*, then reads back and verifies record-level interleaving (no torn writes). This is part of the §7 conformance work and needs to be in hardened mode.

## 1.12 Wide-char orientation and `mbstate_t` (added v2)

POSIX `fwide()` locks a stream's orientation (byte / wide / undecided) on first stdio call, monotonically. v1 ignored orientation.

* `NativeFile` carries `orientation: AtomicI8` (-1 = byte, 0 = undecided, 1 = wide).
* Every byte-oriented entry (`fread`, `fwrite`, `fputc`, ...) bumps to -1 if it was 0; refuses with EBADF or sets ferror if it was +1 (POSIX is permissive here, we choose strict in strict mode and "auto-fwide" with audit emission in hardened mode — this is exactly the kind of thing the runtime_math `pomdp_repair` controller is good at).
* Wide-oriented entries (`fputwc`, `fgetwc`, `fwprintf`, ...) bump to +1 symmetrically.
* `mbstate_t` per-stream is stored in `NativeFile` and used by every wide function. Multiple invocations of `fwprintf` on the same stream must see a continuous shift state.

## 1.13 Append-mode atomicity, signal-safe writes, EINTR loops (added v2)

POSIX requires `O_APPEND` writes to be atomic up to the pipe-buffer size; this is enforced by the kernel iff the underlying syscall is a single `write(2)`. v1's `fwrite` plan would buffer first and flush in chunks, violating this for `O_APPEND`-mode files.

* `NativeFile` records the open flags (`O_APPEND`, `O_NONBLOCK`, `O_SYNC`, `O_DSYNC`) at construction.
* In `O_APPEND` mode, the buffer is bypassed for any `fwrite` whose payload is `<= PIPE_BUF` (4096 on Linux); larger writes fall back to the buffered path with an explicit warning in hardened mode.
* All `read`/`write` syscalls retry on `EINTR` in the native kernel (this is already implemented in `crates/frankenlibc-core/src/stdio/file.rs` per the audit; verify and add a test fixture).
* `O_NONBLOCK` reads/writes that return `EAGAIN`/`EWOULDBLOCK` must surface to the caller as a short read/write with `errno` set, never as a hang.
* AS-safe (async-signal-safe) writes inside signal handlers: `write(STDERR_FILENO, ...)` is the only safe path. The buffered `fwrite` is not AS-safe and cannot be made so. Document this clearly and add a test that calls `fwrite` from a signal handler in a fixture, expects `errno=EDEADLK` in strict mode and a deferred-write queue drain in hardened mode (POMDP repair controller again).

## 1.14 Buffer mode subtleties (added v2)

* `setvbuf` may only be called *before* any I/O on the stream — POSIX is strict here. The native side already enforces this (per the audit it "monotonically locks after first op"). Add a test that calls `setvbuf` after an `fputc` and expects failure.
* `setbuf(fp, NULL)` is shorthand for `setvbuf(fp, NULL, _IONBF, 0)`. `setbuf(fp, buf)` is shorthand for `setvbuf(fp, buf, _IOFBF, BUFSIZ)`. Both must work natively.
* `setbuffer(fp, buf, n)` is BSD/glibc-extension shorthand for `setvbuf(fp, buf, _IOFBF, n)`. Must work.
* `setlinebuf(fp)` is shorthand for `setvbuf(fp, NULL, _IOLBF, 0)`. Must work.
* `__fbufsize`, `__fpending`, `__freadable`, `__fwritable`, `__freading`, `__fwriting`, `__fsetlocking`, `__flbf`, `__fpurge`, `__fwriting` (the GNU `<stdio_ext.h>` family) — verify they exist in the ABI and route through native state inspectors. If missing, add them; some real binaries use these, especially the BSD ports and `coreutils`.
* `_IOLBF` line-buffered mode: the buffer flushes on `\n`. The audit confirms `buffer_write()` does this. Verify the line-buffered flush is a single `write(2)` syscall up to the newline (not chunked) — if not, this is a perf bug now and a correctness bug for sockets.
* Default buffering mode: POSIX requires `_IOLBF` for terminals (`isatty(fileno) == 1`) and `_IOFBF` for everything else. The native init must call `isatty` (via raw syscall, NOT `libc::isatty`) when constructing each `NativeFile` and set the mode accordingly.

## 1.15 stdin/stdout/stderr lifecycle (added v2)

* The audit says `init_native_stdio_streams()` already wires these to native pointers. Confirm under `gdb` that the address of `stdin` exposed by FrankenLibC's `.so` is a `NativeFile *`, not a host glibc `_IO_2_1_stdin_` pointer.
* `freopen(NULL, "r", stdin)` is a legitimate idiom (changes mode without changing the underlying fd). Native `freopen` already exists per the audit; verify the special "NULL pathname" branch.
* `fclose(stdout)` is legal and required for graceful exit cleanups in some daemons. Native `fclose` must handle the stdin/stdout/stderr cases without crashing on the registry remove (these may be statically allocated, so the destructor must be a no-op for the fd-close part but still drain the buffer).
* `__cxa_atexit`-registered flush walker must visit the standard streams *last*, in the order stderr, stdout, stdin, so that error messages from earlier flushes still print before the program exits.

## 2. Scope

### In scope

1. `crates/frankenlibc-abi/src/stdio_abi.rs` — eliminate `Host*Fn` delegation paths and `prefer_host_stdio_streams()` machinery. Make `fopen`/`fdopen`/`freopen` always return a `NativeFile *` (cast to `*mut FILE`).
2. `crates/frankenlibc-abi/src/io_internal_abi.rs` — confirm `NativeFile` is the canonical FILE struct used by every stdio entrypoint and eliminate any vestigial assumption that incoming `FILE*` may be host-allocated.
3. `crates/frankenlibc-abi/src/rpc_abi.rs` L313/324/348/358 — replace `libc::fread`/`libc::fwrite` in the four XDR stdio adapters (`stdio_gi32`, `stdio_pi32`, `stdio_gbytes`, `stdio_pbytes`) with native FrankenLibC reads/writes, since the XDR `FILE*` is now a `NativeFile *`.
4. `crates/frankenlibc-abi/src/glibc_internal_abi.rs` L5197 (`fputgrent_r`), L5267 (`fgetspent_r`) — replace `libc::fwrite` with native record-emit through the FrankenLibC stream registry.
5. `crates/frankenlibc-abi/src/wchar_abi.rs` L4513/4519/4525/4541/4556 — confirm wide-char stdio (`getwc`/`putwc`/`fwide`/etc.) routes through the native stdio kernel and not implicitly through `libc::FILE` field assumptions.
6. `tests/conformance/support_matrix_maintenance_report.v1.json` and the generator — extend the classifier so that any function that calls `libc::fXXX` or `Host*Fn::*` is detected and labelled. Either zero those rows, or introduce a new explicit `WrapsHostLibc` taxonomy state (see §6).
7. `scripts/ld_preload_smoke.sh` and `tests/conformance/ld_preload_smoke_summary.v1.json` — un-skip `sqlite3`, `redis-cli`, `nginx` (the 6 current skips). These are the workloads most likely to expose stdio gaps. If they fail, the failures *are* the work.
8. New criterion benches in `crates/frankenlibc-bench` — assert the `<20ns`/`<200ns` membrane budget for the stdio fast path (this was UNPROVEN per the reality check; addressing it now closes a parallel honesty gap with a single perf harness investment).
9. `crates/frankenlibc-harness` — extend `healing_oracle` with stdio-class healing scenarios (short reads, EINTR loops, ENOSPC mid-write, append-mode races, ungetc overflow, EOF then re-read) so hardened-mode behavior is mechanically verified.

### Out of scope (deferred to follow-on epics)

* `glibc_internal_abi.rs` `scandir_r` (L5518–5569) — uses `libc::openat`/`readdir`/`closedir`, which are dirent-family, not stdio. Tracked by a separate "dirent native ownership" workstream.
* Full `_IO_*` vtable parity beyond what is needed for FILE\*-as-NativeFile to be drop-in compatible **plus the `_IO_jump_t` indirect-call dispatch table that some glibc-built binaries reach through directly** (this is in scope — see §3 and §10).
* Locale-aware printf (`%'d` thousands grouping, multibyte format strings beyond UTF-8). Locale work is its own subsystem; **but `LC_NUMERIC` decimal-point handling for `%f` IS in scope** because POSIX requires it and many real workloads pass `setlocale(LC_NUMERIC, "C")` and then expect `%f` to print `1.5` even on a `,`-decimal locale.
* C++ iostreams (FrankenLibC does not export `_ZSt*` symbols and these are not in the support matrix).
* Multi-arch validation. Linux x86_64 only for this plan; aarch64 closure is a separate matter.
* The `glibc_internal_abi.rs` non-stdio fields (`scandir_r`, NSS plumbing). Stdio-only.

## 3. The unified FILE struct decision

There are exactly three viable choices:

| Option | Description | Pros | Cons |
|---|---|---|---|
| **A.** Use the existing `NativeFile` (288 bytes) as the canonical FILE struct, return `*mut NativeFile` cast to `*mut FILE` from every entrypoint. | Already exists; already ≥ 216-byte size-asserted; already used by `io_internal_abi` paths. | Layout is *not* a bit-for-bit copy of glibc `_IO_FILE`. Any C code that pokes inside `FILE` (and there *is* such code in the wild — though not in any binary in our smoke battery) will crash. | The canonical glibc `_IO_FILE` layout is famously stable for binary compatibility, so re-using its layout is the safer choice for arbitrary-binary support. |
| **B.** Define a new `pub struct FILE { _io_file: _IO_FILE_Layout, _franken: NativeFileExtra }` with the first 216 bytes laid out exactly as glibc's `_IO_FILE` and FrankenLibC state appended after. | Bit-compatible with binaries that read `FILE._flags` / `FILE._fileno`. | More work; adds a new struct definition; needs static asserts on field offsets. |
| **C.** Keep returning opaque registry IDs cast to `*mut FILE`. | Smallest diff. | Permanently breaks any C code that touches `FILE` fields, including some legitimate idioms like `fileno(fp)` macro expansions in older libcs. We already know rpc_abi.rs assumed FILE* was dereferenceable. |

**Decision (v2 — promoted from v1's "open question"):** **Option B with `_IO_FILE_plus` layout**. The 216-byte size assertion in `io_internal_abi.rs` L123 is the existing seed. v2 commits to:

* First 216 bytes = exact `_IO_FILE` layout (glibc 2.34 baseline; CI matrix against 2.31, 2.34, 2.38).
* At offset 216 (immediately after `_IO_FILE`): a pointer to a FrankenLibC-owned `_IO_jump_t` vtable, making the struct a true `_IO_FILE_plus`. The vtable points to native Rust trampolines for the 12 standard `_IO_jump_t` slots (`finish`, `overflow`, `underflow`, `xsputn`, `xsgetn`, `seekoff`, `seekpos`, `setbuf`, `sync`, `doallocate`, `read`, `write`, `seek`, `close`, `stat`, `showmanyc`, `imbue`).
* Beyond the vtable pointer: FrankenLibC-only state — `parking_lot::ReentrantMutex<NativeFileLocked>` containing buffer cursors, eof/error flags, ungetc slot, generation counter, healing budget, runtime_math controller hooks, `mbstate_t`, orientation, open flags, fingerprint header.
* Static asserts: every `_IO_FILE` field offset (`_flags`, `_fileno`, `_old_offset`, `_lock`, `_offset`, `_codecvt`, `_wide_data`, `_freeres_list`, `_freeres_buf`, `_pad5`, `_mode`, `_unused2`) is pinned to the glibc 2.34 layout via `memoffset::offset_of!` against a private `_IO_FILE_Layout` repr-C struct.
* `static_assert!(size_of::<NativeFile>() <= 4096)` — keeps the slab allocator's small-object class viable.

This is the only way to support **channel 12 (foreign-pointer adoption)** *and* **channel 13 (host expects to receive a host FILE\*)** *and* **channel 11 (binaries that link `_IO_2_1_stdin_` directly)** without breaking real binaries. The smoke battery's currently-skipped workloads (sqlite3, nginx) are exactly the kind of code that historically poked at FILE fields and dispatches through `_IO_jump_t`.

**Additional decision (v2):** the version script `crates/frankenlibc-abi/version_scripts/libc.map` must export the `_IO_2_1_stdin_`, `_IO_2_1_stdout_`, `_IO_2_1_stderr_` aliases bound to the same `NativeFile` storage as `stdin`/`stdout`/`stderr`. Without this, any binary that resolves the underscored names directly (some statically-linked-against-libc binaries do) will see two distinct streams and the program will misbehave subtly (e.g. partial flushes).

## 4. Per-file change list

### 4.1 `crates/frankenlibc-abi/src/stdio_abi.rs`

| Line range | Current state | Target state |
|---|---|---|
| L30–50 (`Host*Fn` type aliases) | 20 type aliases for host stdio fns | **Delete all 20 aliases.** |
| L52–71 (`HOST_*_FN` `OnceLock<usize>` cells) | 20 statics caching resolved host symbols | **Delete all 20 statics.** |
| L91–96 (`prefer_host_stdio_streams()`) | Always returns true after first init | **Delete.** Replace with a const `false` for any internal tests that still reference it during the migration; remove all callsites. |
| L392–519 (host symbol accessor functions) | 20 `host_*_fn()` accessors via `host_resolve::resolve_host_symbol_cached` | **Delete all 20 accessor functions.** |
| L626–664 (`init_host_stdio_streams()` and globals) | Misnamed: actually initializes stdin/stdout/stderr from native streams | **Rename** to `init_native_stdio_streams()`. Drop the `HOST_STDIO_BOOTSTRAPPED` atomic since the gating concept disappears. Keep the body — it already does the right thing. |
| L676–729 (`fopen`) | Conditionally delegates to `host_fopen` then falls back to native open + registry insert | Native-only: native `openat` syscall, allocate `NativeFile` from a slab, insert in stream registry, init vtable pointer, set buffering mode based on `isatty`, return `*mut FILE`. |
| L4060–4108 (`fdopen`) | Conditionally delegates to `host_fdopen` then falls back to native | Native-only. Same construction path. |
| `popen` (verify line range — currently in `process_abi.rs` or `stdio_abi.rs`) | Likely host-delegated | Native: `posix_spawn` + native pipe + native `fdopen` of the pipe end. Mode `"r"` reads from child stdout, mode `"w"` writes to child stdin. Closes via `pclose` which `waitpid`s. |
| `tmpfile`, `tmpfile64` | Likely host-delegated | Native: O_TMPFILE on Linux ≥ 3.11 (raw syscall), fallback to `mkostemp` + `unlink` for older kernels. Returns a `NativeFile *`. |
| `fmemopen` | May be partially native | Confirm and complete: `NativeFile` variant with a fixed memory backing, supports the full mode set (`"r"`, `"w"`, `"r+"`, `"w+"`, `"a"`, `"a+"`, with optional `b` and `B`). Honors POSIX truncation rules. |
| `open_memstream` | May be partially native | Confirm and complete: growing buffer with realloc-on-overflow, on-close size publication via the user's `size_t *`. |
| `open_wmemstream` | Probably missing | Add. Same as `open_memstream` but `wchar_t`-orientation locked from construction. |
| `fopencookie` | Probably missing or host-delegated | Add. `NativeFile` carries the user's `cookie_io_functions_t` (read/write/seek/close fn pointers) and the user cookie. Native fread/fwrite/fseek/fclose dispatch to the cookie functions when this flavor is set. |
| L733–815 (`fclose`) | Checks registry first, delegates to host if alien | Native-only. After this change every legitimate FILE\* is in the registry so the "delegate to host" branch becomes dead code; **delete it**. |
| L821–898 (`fflush`) | Same pattern | Same change. |
| L901–1015 (`fgetc`), L1017–1113 (`fputc`), L1115–1290 (`fgets`), L1292–1435 (`fputs`), L1437–1575 (`fread`), L1576–1730 (`fwrite`), L1738–1864 (`fseek`), L1867–1901 (`ftell`), L1932–1950 (`feof`), L1952–1970 (`ferror`), L1972–1989 (`clearerr`), L1991–2013 (`ungetc`), L2015–2043 (`fileno`), L2045–2137 (`setvbuf`), L4272–4357 (`getdelim`), L4363–4423 (`getline`), L2722–2810 (`fprintf`), L3260–3704 (`vfprintf`) | All do "check registry first; delegate to host if alien" | Same change in every function: remove the alien-FILE branch entirely. |

**Audit obligation:** after the changes above, `rg -n 'host_' crates/frankenlibc-abi/src/stdio_abi.rs` must return zero matches related to host delegation. Add this as a CI grep gate.

### 4.2 `crates/frankenlibc-abi/src/io_internal_abi.rs`

* L66–116 (`NativeFile` struct definition): expand to the Option B layout (`_IO_FILE` head + FrankenLibC tail).
* L123–126 (the `≥ 216 bytes` assertion): tighten to an exact match for the first-216-bytes layout, and add field-offset asserts (`memoffset::offset_of!` against the expected glibc-2.34 offsets).
* L576–596 (`native_stdio_stream_ptr` and the standard-stream registry initialization): no functional change, but rename comments to drop the word "host."

### 4.3 `crates/frankenlibc-abi/src/rpc_abi.rs`

| Line | Current call | Replace with |
|---|---|---|
| 313 | `libc::fread(buf, 1, 4, f.cast())` | `crate::stdio_abi::native_fread(buf, 1, 4, f as *mut io_internal_abi::NativeFile)` |
| 324 | `libc::fwrite(buf, 1, 4, f.cast())` | analogous `native_fwrite` |
| 348 | `libc::fread(a, 1, n, f)` | analogous `native_fread` |
| 358 | `libc::fwrite(a, 1, n, f)` | analogous `native_fwrite` |

This requires exporting `native_fread` / `native_fwrite` (helpers around the registry+kernel path) from `stdio_abi.rs`. They already exist as inline subroutines inside the public ABI fn bodies; refactor them out to `pub(crate) fn native_fread(...)` etc.

### 4.4 `crates/frankenlibc-abi/src/glibc_internal_abi.rs`

| Line | Current call | Replace with |
|---|---|---|
| 5197 | `libc::fwrite(line, 1, len, fp)` in `fputgrent_r` | `crate::stdio_abi::native_fwrite(line, 1, len, fp.cast())` |
| 5267 | `libc::fwrite(line, 1, len, fp)` in `fgetspent_r` | analogous |

(`scandir_r` lines 5518/5543/5562/5569 are out of scope per §2.)

### 4.5 `crates/frankenlibc-abi/src/wchar_abi.rs`

Confirm L4513/4519/4525/4541/4556 (`getwc`, `putwc`, `fwide`, `getwchar`, `putwchar`) all route to native stdio handlers operating on `NativeFile *`. The current `*mut libc::FILE` parameter type is fine for ABI signature purposes (it's an opaque pointer at the C boundary) — the issue is whether the bodies dereference `libc::FILE` fields. They do not (per the audit), but make it a structural test: add a `cargo build` step under `--cfg deny_libc_file` that aliases `libc::FILE` to `()` and forces a build error anywhere code touches its internals.

### 4.6 `tests/conformance/support_matrix_maintenance_report.v1.json` + generator

Currently the maintenance gate regenerates with zero deltas despite live ABI work. Either:

1. **Tighten the classifier:** any ABI symbol whose body contains `libc::f*`, `libc::malloc/free/...`, or `host_*_fn` is automatically labelled `WrapsHostLibc`. Run the regenerator. Expect a one-time bump in counts: a number of stdio symbols and the rpc/glibc_internal ones flip to `WrapsHostLibc`. After Option B lands, they all flip back to `Implemented`. The README's headline number is then mechanically true.
2. **Or** introduce the new state without changing existing labels and require `WrapsHostLibc` to be 0 for the L0 (Interpose) closure gate. Either is fine; the first is more honest.

### 4.7 `scripts/ld_preload_smoke.sh`

Un-skip the three optional probes:

* `sqlite3` — runs `.tables`, a `CREATE TABLE/INSERT/SELECT` round-trip, and `.dump`. This exercises temp files, journal files, page cache, and `fseek`/`ftell` heavily.
* `redis-cli` — runs `INFO`, `SET/GET`, `DBSIZE`, and `--scan`. Exercises line buffering, `fgets`, and signal-interrupted reads.
* `nginx` — `nginx -t` config check + `nginx -s quit` after a single request through `curl http://localhost:<test_port>/`. Exercises log buffering, error logs, and the `_IO_jump_t` vtable.

If any of these crash on the new native stdio, the failures are the *real* missing work — they go into Phase 5 refinement.

### 4.8 `crates/frankenlibc-bench` — perf gate (parallel honesty fix)

New bench file `benches/stdio_native_fastpath.rs`:

* Bench A: `fopen`/`fclose` of `/dev/null` — measures the cold path. Asserts `<200ns` per round trip in hardened mode (the SLO budget).
* Bench B: 4-KiB `fwrite` to a fresh tmpfile, 1024 iterations, fully buffered. Asserts the per-call membrane overhead is `<20ns` in strict mode.
* Bench C: `fread` from a memory-mapped fixture, 1024 iterations. Same assertion.
* Bench D: `printf("%d", n)` of an i32 to `/dev/null`, 1024 iterations. Validates the native printf engine end-to-end.
* Bench E: `fgetc` line-buffered loop over a 64-KiB fixture. Validates the line-buffer flushing path.

Wire `cargo bench --bench stdio_native_fastpath` into the smoke battery (gated by `FRANKENLIBC_PERF_ENABLE_KERNEL_SUITE=1`).

### 4.9 `crates/frankenlibc-harness` — healing oracle stdio extension

Add to `healing_oracle.rs` canonical suite:

| Case | Trigger | Expected hardened action |
|---|---|---|
| `stdio.short_read` | `fread(buf, 1, 4096, fp)` on a 1-byte fixture | return `1`, set EOF, no UB |
| `stdio.eintr_loop` | `fread` interrupted by SIGUSR1 mid-call | retry transparently |
| `stdio.ungetc_overflow` | `ungetc` twice in a row | return `EOF`, do not corrupt buffer |
| `stdio.append_race` | concurrent `fwrite`s on `O_APPEND` fp | each write atomic per POSIX |
| `stdio.enospc_midwrite` | `fwrite` against a tmpfs at `du=100%` | return short count, set ferror |
| `stdio.eof_then_reread` | `fgetc` past EOF, then `clearerr`, then `fseek(SEEK_SET)`, then `fread` | reset eof bit, deliver bytes |

Each case must produce a structured `RuntimeMathSnapshot` row showing which controllers (if any) routed the call to a non-default action, and a JSONL evidence record under `target/conformance/`.

## 5. Cross-symbol dependency closure

After §4 lands, run `rg -n 'libc::f(open|close|read|write|getc|gets|puts|putc|seek|tell|flush|setvbuf|ungetc|eof|error|clearerr|fileno|getline|getdelim) ' crates/frankenlibc-abi/` and `rg -n 'host_.*_fn' crates/frankenlibc-abi/`. Both must return zero matches. This becomes a permanent CI grep gate (`scripts/check_no_host_libc_stdio.sh`) so the leak cannot regress.

Also: check `crates/frankenlibc-abi/src/host_resolve.rs` (or wherever `resolve_host_symbol_cached` lives) for any *other* stdio symbols being resolved out of band. Burn them down too.

## 6. Support matrix re-honesty

Two parallel changes:

1. **Generator:** the classifier in `scripts/generate_support_matrix_maintenance.py` (and the Rust harness equivalent in `crates/frankenlibc-harness/src/support_matrix.rs` if it exists) must inspect the *body* of each ABI function, not just its signature. A function whose body still calls `libc::f*` or `host_*_fn` is `WrapsHostLibc`, period.
2. **Schema:** add the explicit `WrapsHostLibc` state to the support taxonomy. Update README and AGENTS.md to reflect it. The L0 closure gate requires `WrapsHostLibc == 0`. Once Option B lands, it is.

This is the minimal, correct way to make "0 GlibcCallThrough / 100% native" mean what the README says it means.

## 7. Conformance and regression protection

* New fixtures under `tests/conformance/fixtures/stdio/` capturing host glibc behavior on the canonical workloads (sqlite3 query result, nginx access log, redis-cli `INFO` output) so the harness can do byte-exact comparison after Option B.
* New integration test `tests/integration/stdio_native_only.rs` that links a small C program against `libfrankenlibc_abi.so` and exercises every entrypoint touched by §4.1. Runs under both strict and hardened modes.
* Unskip the smoke battery skips. The 58/0/6 score must become 64/0/0 before this plan is closeable.
* Snapshot golden under `tests/runtime_math/golden/stdio_decisions.v1.json` capturing which runtime_math controllers fired during a representative stdio workload run.

## 8. Risk register (v1)

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `_IO_FILE` layout assumption is wrong for some glibc minor version | Med | High | Static field-offset asserts pinned to glibc-2.34; CI matrix against 2.31, 2.34, 2.38. |
| sqlite3 / nginx / redis-cli have a stdio idiom we haven't audited | High | Med | Treat the unskip as discovery work; surface failures as new beads. |
| Perf budget regression on `fwrite` hot path due to per-call membrane overhead | Med | Med | Bench-gated; tune the validation cache and bloom prefilter if budget is exceeded. |
| Removing host fallback unblocks latent bugs in native printf/scanf | Low | Med | The native engine has 1446+1026 LOC of tests; expand fixture coverage as part of §7. |
| Beads-DB corruption causes some Phase 3a creates to be dropped | Med | Low | Create beads in small atomic batches; verify each create with `br show` before continuing. |

## 10. The `_IO_jump_t` vtable (added v2)

Many glibc-built binaries — particularly those compiled with `-fno-plt` or against very old gcc — call `vfprintf` indirectly through `((struct _IO_FILE_plus *)fp)->vtable->__xsputn(...)` rather than through the PLT-resolved `vfprintf` symbol. If the `vtable` pointer in our `NativeFile` is null (or points at glibc's vtable, which assumes glibc's `_IO_FILE` layout for the rest of the struct), the program crashes inside `__xsputn`.

Required:

* `crates/frankenlibc-abi/src/io_internal_abi.rs` defines a static `NATIVE_IO_JUMP_T` table holding 17 function pointers, all bound to `extern "C"` Rust trampolines that re-enter the FrankenLibC native stdio kernel.
* Every `NativeFile` constructor sets `self.vtable = &NATIVE_IO_JUMP_T as *const _ as *mut _`.
* Each trampoline reacquires the `ReentrantMutex`, dispatches to the same kernel functions used by the public ABI entrypoints, and returns the same values.
* Trampolines must handle the case where the `FILE *` they receive came from a `dlopen`'d library that opened the file *before* LD_PRELOAD took effect — in which case `vtable` points at glibc's vtable, not ours. Detection: cmpxchg the vtable pointer through the page-oracle bloom check (the membrane already does this for arbitrary pointers — reuse that infrastructure). On detection, route through the §11 foreign-pointer adoption path.
* Snapshot test: `tests/runtime_math/golden/io_jump_dispatch.v1.json` records, for a representative workload, the count of vtable-dispatched calls vs PLT-dispatched calls.

## 11. Foreign-pointer adoption (channel 12 from §1.5)

When a `dlopen`'d library opens a file *before* `LD_PRELOAD` is active and then hands the resulting `FILE *` back to the LD_PRELOAD'd binary, the pointer is host glibc's, not ours. The current code "handles" this by delegating to host stdio. Option B requires we *adopt* it instead.

Adoption protocol:

1. Every public ABI stdio entrypoint that takes a `FILE *` first runs the membrane's bloom-filter ownership precheck (this already exists in `crates/frankenlibc-membrane/src/bloom.rs` and is exactly the right primitive). Cost: ~10 ns per call. This is well within the strict-mode budget.
2. If the precheck says "ours," dispatch directly to the kernel.
3. If the precheck says "not ours," call `adopt_foreign_file(fp) -> *mut NativeFile`:
   * Read `((_IO_FILE *)fp)->_fileno` to recover the underlying fd. (We do *not* read other fields — they may be in a different layout from glibc's.)
   * Allocate a `NativeFile` shell, set its fd to the recovered value, set buffering mode based on `isatty(fileno)` (raw syscall), set orientation = undecided.
   * Insert into the stream registry indexed by *both* the original foreign pointer *and* the new native pointer (so subsequent calls with the foreign pointer find the same NativeFile).
   * Emit a `FOREIGN_FILE_ADOPTED` evidence record (structured JSONL under `target/conformance/`) with the foreign pointer's hex address, the recovered fd, the calling function name, and a backtrace hash.
   * Return the new `NativeFile *`.
4. The original foreign pointer remains valid as a key into the registry. If the user later passes it to `fclose`, we close the underlying fd via the *native* path and remove both registry entries.
5. The `_IO_FILE.vtable` of the foreign pointer is **never** dereferenced — adoption converts the indirect-vtable-call site into a direct call to our kernel.
6. **Generation safety:** if the same fd is later closed and reopened (a real risk for long-lived processes), the new `NativeFile` gets a fresh generation; the old foreign-pointer registry entry is invalidated and any subsequent stdio call against the stale foreign pointer returns `EBADF` and emits a `FOREIGN_FILE_STALE` evidence record.

This is the most architecturally interesting addition and is what makes Option B viable for real-world workloads (especially nginx with its dynamic module system).

## 12. Runtime_math integration (added v2 — first concrete wiring of the ~50 decoupled controllers)

The reality-check found ~50 runtime_math controllers that compile and update but never gate hot-path decisions. The stdio rewrite is an opportunity to wire several of them up, narrowing the original "naming theater" gap as a side effect.

Concrete proposed wirings:

| Controller | Stdio decision it gates |
|---|---|
| `pomdp_repair` | When a `read` returns short or `EAGAIN`, decide between (retry, return-short, return-eof) under hardened mode. POMDP belief = recent fd activity history. |
| `conformal` | Per-stdio-family conformal risk envelope: if recent `fwrite` short-write rate exceeds the conformal upper bound, route the next call through `FullValidate` instead of `Fast`. |
| `cvar` | Tail-risk on `fread` latency: if the 99th percentile blows past the CVaR threshold, switch to direct unbuffered syscalls and emit an alarm. |
| `eprocess` | Anytime-valid drift detector on the ratio (membrane-validated stdio calls : raw syscalls). Should hover near 1.0; sustained drift = alert. |
| `cohomology` | Cross-shard consistency: the buffered-cursor view in `NativeFile` must agree with the kernel's `lseek(fp->fileno, 0, SEEK_CUR)` view modulo the buffer length. Cohomology controller monitors this consistency over a sliding window. |
| `barrier` | Constant-time admissibility guard: never let a stdio call run more than `STDIO_MAX_CALL_NS` (configurable, default 50 µs); barrier function abort + safe-default return if exceeded. |
| `equivariant` | Symmetry monitor: byte-flipped vs original `fread` should produce byte-flipped output. Detects encoding-layer corruption silently introduced by aggressive optimization. |
| `wasserstein_drift` | Histogram drift in stdio call-size distribution. Sustained drift = workload-shape change, may need to retune buffer size. |
| `info_geometry` | Fisher-Rao distance on the mode-distribution (read/write/seek/flush). Sudden distance jumps = workload-class change. |
| `kernel_mmd` | MMD between the empirical pre/post-read byte-distribution and the fixture-captured baseline. High MMD = the underlying file is not what we think it is (file replacement attack). |

Each wiring is a single bead in Phase 3a. None is required for Option B's headline correctness — they are the *bonus* honesty fix that turns "80 controllers compile" into "80 controllers compile and 35+ are on the hot path." Phase 5 refinement should prune any wiring that looks gratuitous.

## 13. Continuous bench gate design (added v4)

The reality-check found that `<20ns/<200ns` budgets are documented in source but not enforced. v4 fixes this with a real harness:

* **New crate:** `crates/frankenlibc-bench/benches/stdio_native_fastpath.rs` (5 benches as enumerated in v1 §4.8) plus a new `crates/frankenlibc-bench/benches/stdio_full_workload.rs` for end-to-end measurement.
* **Isolation:** runs under `taskset -c 3` (or whatever is configured by `FRANKENLIBC_BENCH_PIN`), with `cpufreq` set to `performance`, ASLR disabled (`echo 0 > /proc/sys/kernel/randomize_va_space` — operator's responsibility), and `criterion::Criterion::default().sample_size(500).warm_up_time(Duration::from_secs(2))`.
* **Statistical rule:** the bench fails if the *median* exceeds the budget by ≥ 5% over the previous green run, OR if the 99th percentile exceeds the budget by ≥ 25%. The 5%/25% thresholds match `FRANKENLIBC_PERF_MAX_REGRESSION_PCT` (default 15) — they are a tighter local rule for the stdio fast path because the budgets are themselves the tightest in the project.
* **Per-stage attribution:** each bench captures `RuntimeMathSnapshot` and the per-stage timing breakdown emitted by `ptr_validator.rs`. Failures attribute the regression to a specific stage (null, tls cache, bloom, arena, fingerprint, canary, bounds, kernel) so a regression bisect is mechanical.
* **Storage:** results under `target/criterion/stdio_native_fastpath/` and a distilled `tests/conformance/stdio_perf_baseline.v1.json` checked into the repo. The baseline file is the single source of truth for "what was the last green number"; the smoke gate refuses to merge a PR that regresses without an accompanying baseline bump (which itself requires a `[perf-bump]` PR label).
* **Host-noise envelope:** if `FRANKENLIBC_PERF_MAX_LOAD_FACTOR` (default 0.85) is exceeded by `getloadavg()` at the start of the run, the bench skips and reports SKIPPED rather than failing — this prevents flaky CI.
* **Differential perf:** the bench also runs the same workload through `LD_PRELOAD=` (i.e., the host glibc directly) and reports the FrankenLibC-vs-glibc ratio. Goal: ratio ≤ 1.5x in strict mode, ≤ 4.0x in hardened mode.
* **Cold cache:** a separate `--cold-cache` mode invalidates the page cache (`posix_fadvise(POSIX_FADV_DONTNEED)` on a per-iter basis) and re-measures, surfacing first-call latency separately from steady-state.

This converts the *unproven* `<20ns/<200ns` claim into a *gated* claim with continuous evidence — it does not prove the budgets, it forces them to be true.

## 14. Versioned structured evidence schema (added v4)

Every healing event, every foreign-pointer adoption, every POMDP repair decision, and every membrane-stage-attribution event emits a JSONL row under `target/conformance/stdio_evidence.jsonl` with the schema below. The schema is versioned (`schema_version` field) and a parser lives in `crates/frankenlibc-harness/src/stdio_evidence.rs`.

```json
{
  "schema_version": 1,
  "timestamp_unix_ns": 1712624400123456789,
  "process": { "pid": 12345, "tid": 12345, "comm": "sqlite3" },
  "mode": "hardened",
  "event_kind": "FOREIGN_FILE_ADOPTED" /* or HEAL_CLAMP_SIZE | HEAL_TRUNC_NULL | POMDP_REPAIR | STDIO_INVARIANT_VIOLATION | VTABLE_FALLBACK | ... */,
  "function": "fread",
  "fp_hex": "0x7f9a3c001000",
  "fp_origin": "foreign_dlopen" /* or registry_native | adopted */,
  "fd": 7,
  "params": { "size": 4096, "n": 1 },
  "result": { "return": 4096, "errno": 0, "elapsed_ns": 8123 },
  "membrane_stages": { "null": 1, "tls": 0, "bloom": 11, "arena": 28, "fingerprint": 19, "canary": 9, "bounds": 4 },
  "runtime_math": { "pomdp_action": "NormalReturn", "conformal_band": [0.001, 0.012], "cohomology_consistent": true, "cvar_alarm": false },
  "healing_action": null,
  "evidence_ring_seq": 4218373,
  "trace_id": "be72e3a4-..."
}
```

* The `evidence_ring_seq` is a per-process monotonic counter; consumers can detect drops.
* `trace_id` is generated once per ABI entry call and propagated through the membrane stages, so a single user-visible call can be reconstructed across multiple records.
* Schema upgrades: bump `schema_version`; the parser keeps a compatibility shim for at least the previous version. AGENTS.md "Backwards Compatibility" rule explicitly says we don't keep compat shims — but evidence records are *output artifacts* read by external consumers (humans, dashboards, the closure gate), not internal interfaces, so the shim rule does apply here.
* The parser is testable: `cargo test -p frankenlibc-harness --test stdio_evidence_schema`.

## 15. Witness chain for the headline number (added v4)

After Option B lands, the README says "100.0% native coverage." v4 makes this number **machine-traceable from source to claim**:

```
crates/frankenlibc-abi/src/*_abi.rs                       (source)
    │
    │  scripts/generate_support_matrix_maintenance.py
    │  (body-inspecting classifier; v1 currently signature-only)
    ▼
support_matrix.json                                       (per-symbol classification)
    │
    │  cargo run -p frankenlibc-harness --bin harness -- reality-report
    ▼
tests/conformance/reality_report.v1.json                  (counts + timestamp + git sha)
    │
    │  scripts/check_release_gate.sh
    ▼
tests/conformance/closure_contract.v1.json                (release-claim coherence gate)
    │
    │  scripts/render_readme_counts.py (NEW — v4)
    ▼
README.md "Current State" table                           (rendered, NEVER hand-edited)
```

Concrete v4 changes to make this real:
* **`scripts/render_readme_counts.py` (new):** reads `tests/conformance/reality_report.v1.json`, locates the markdown table between `<!-- BEGIN: support-counts -->` and `<!-- END: support-counts -->` markers in `README.md`, and rewrites it. The script is idempotent and is run by a pre-commit hook (using the project's existing `mcp__mcp-agent-mail__install_precommit_guard` infrastructure).
* **`README.md`:** sentinel comments added around the counts table. The numbers are no longer hand-typed.
* **`scripts/check_readme_drift.sh` (new):** in CI, runs `render_readme_counts.py` and asserts no diff. Any divergence between the counts and the README is a hard failure.
* **`tests/conformance/closure_contract.v1.json`:** new clause `"stdio_native_only": true` that the release gate verifies. This couples the README claim to a closure-gate fact.
* **`scripts/witness_chain_audit.sh` (new):** walks the chain, verifies the timestamps are monotone, verifies each artifact's git-sha matches the source it derives from, and emits `tests/conformance/witness_chain_audit.v1.json`.

After v4 the headline number is no longer a sentence in a doc — it is a *computed scalar* with a chain-of-custody back to the source.

## 16. Atiyah-Bott proof DAG compression (added v4)

The §1.5 invariant table has 11 entries. The §1.7 POMDP has 7 actions × 6 fd_classes = 42 (state, action) cells. The §1.8 synthesis pipeline emits a printf table of ~256 routes and a scanf table of similar size. Naively, every (route × invariant × action) combination is a separate proof obligation — that's tens of thousands of SMT calls, prohibitively slow at build time.

Atiyah-Bott fixed-point localization (the existing `crates/frankenlibc-membrane/src/runtime_math/atiyah_bott.rs` controller has the necessary primitive!) compresses this: most obligations reduce to the same fixed-point under a small group of natural symmetries (length modifier × conversion swap, sign flip, padding mode). The compressed proof DAG has ~120 obligations instead of ~30,000 — a 250x reduction in build-time SMT cost. Concrete:

* New file `tools/stdio_synth/symmetry.rs` defining the symmetry group acting on the (route × invariant) lattice.
* `tools/stdio_synth/compress.rs` consuming the symmetry group and the obligation set, emitting a quotiented DAG.
* SMT obligations are discharged on the *quotient*, not the original set. Each fixed-point class needs only one proof; the group action lifts to the rest.
* Build-time budget: the printf/scanf SMT phase must complete in ≤ 90 s on a single core. Gated by `tools/stdio_synth/check_smt_budget.sh`.

This is an instance of the AGENTS.md "Atiyah-Bott localization" obligation #35 — and it reuses an existing module that the reality-check identified as "real code never on the hot path." This work *moves* the Atiyah-Bott controller from "telemetry-only" to "actively used at build time," which is a small but real win for the runtime_math honesty story.

## 17. Rollback safety (added v4)

If Option B regresses some workload after landing, the project must be able to revert in a single commit without re-introducing the host_*_fn maze. v4 specifies the rollback story:

* All Option B code lives behind a single `cfg(stdio_native_only)` feature flag during the migration period (target: 4 weeks). Default is `cfg(stdio_native_only)` = ON.
* The legacy host-delegating paths are *physically deleted* from the source — there is no `cfg(stdio_host_delegated)` branch. Reverting means `git revert` on the merge commit, full stop.
* Before the merge commit, a `tests/conformance/stdio_pre_option_b_baseline.v1.json` snapshot is captured: the support-matrix counts, the smoke battery results, the perf baseline, and the closure contract state, all under the *old* code. This is the bisect target.
* If a regression appears post-merge, the playbook is:
  1. `git revert <merge-sha>` (restores the host_*_fn maze atomically).
  2. Re-run all gates against the reverted state.
  3. Re-open the bead set and start a Phase 5 refinement round on the failing case.
  4. Re-merge after the refinement closes.
* No "feature flag to disable native stdio at runtime" — that would re-introduce exactly the dual-path complexity Option B exists to eliminate. AGENTS.md "Backwards Compatibility" rule applies: we are not in production and do not need a runtime kill switch.

## 18. Closure-contract gate updates (added v4)

`tests/conformance/closure_contract.v1.json` is the project's release-claim coherence gate (per AGENTS.md and `scripts/check_closure_contract.sh`). v4 specifies the exact additions:

```json
{
  "stdio": {
    "native_only": true,
    "wraps_host_libc_count": 0,
    "vtable_dispatch_supported": true,
    "foreign_pointer_adoption_supported": true,
    "channels_native": ["fopen", "fdopen", "freopen", "popen", "tmpfile",
                       "fmemopen", "open_memstream", "open_wmemstream",
                       "fopencookie", "stdin_alias_exports"],
    "smoke_workloads_green": ["sqlite3", "redis-cli", "nginx"],
    "perf_budget_strict_ns": 20,
    "perf_budget_hardened_ns": 200,
    "perf_baseline_path": "tests/conformance/stdio_perf_baseline.v1.json",
    "evidence_schema_version": 1,
    "witness_chain_audit_path": "tests/conformance/witness_chain_audit.v1.json",
    "synthesis_pipeline_proven": true
  }
}
```

The release gate fails if any of these is missing or wrong. This *hard-couples* the README claim to ten distinct mechanical facts, none of which is a sentence.

## 19. Cross-subsystem ripple checklist (added v4)

Stdio touches everything; v4 enumerates the ripple effects so they don't surprise us in implementation:

* **`setjmp_abi.rs`:** `longjmp` out of a `flockfile`'d region must release the recursive lock. Add a per-thread lock-stack that `longjmp` walks.
* **`signal_abi.rs`:** signal handlers calling `fwrite` on a buffered stream — see §1.8. Strict: `errno=EDEADLK`. Hardened: deferred-write queue drained on signal return.
* **`pthread_abi.rs`:** `pthread_atfork` handlers must walk the stream registry and `_lock` every FILE in the parent before fork, `_unlock` in both parent and child after.
* **`process_abi.rs`:** `popen` lives here today; verify it gets re-pointed at native `fdopen`. `_exit` vs `exit` — `_exit` does NOT flush; `exit` walks the registry. `execve` should *not* flush (the new image inherits fds, not buffers).
* **`startup_abi.rs`:** `__libc_start_main` must install the native `stdin`/`stdout`/`stderr` *before* any constructor runs. Currently `init_native_stdio_streams()` is called lazily on first stdio call; v4 makes it eager.
* **`unistd_abi.rs`:** `_exit` *must not* drain the stream registry; `exit` *must* drain it via `__cxa_atexit`. Verify the existing handler walks `NativeFile` registry and calls `fflush` then `fclose` for everything except stdin/stdout/stderr (which get `fflush` only).
* **`fortify_abi.rs`:** `__fprintf_chk`, `__fwprintf_chk`, `__vfprintf_chk`, `__snprintf_chk`, etc. must route through the same native kernels as the unchecked variants. Verify the version script exports them.
* **`io_internal_abi.rs`:** the `_IO_*` symbols must export the same `NativeFile` storage as their public aliases. Verify `_IO_putc`, `_IO_getc`, `_IO_feof`, `_IO_ferror`, `_IO_fflush`, `_IO_fread`, `_IO_fwrite` are all exported and route correctly.
* **`wchar_abi.rs`:** `getwc`/`putwc`/`fwide`/`fwprintf`/`fwscanf` interact with the orientation field. Verify they take the recursive lock.

Each item is a bead in Phase 3a.

## 9. Done criteria (v4)

**Code:**
* [ ] `rg -n 'host_.*_fn|libc::f(open|close|read|write|getc|gets|puts|putc|seek|tell|flush|setvbuf|ungetc|eof|error|clearerr|fileno|getline|getdelim|memopen|opencookie|tmpfile|popen|close)' crates/frankenlibc-abi/` returns zero matches outside `wchar_abi.rs` parameter type aliases.
* [ ] `cargo build --cfg deny_libc_file -p frankenlibc-abi` succeeds (proves no body dereferences `libc::FILE` fields).
* [ ] `crates/frankenlibc-abi/version_scripts/libc.map` exports `_IO_2_1_stdin_`, `_IO_2_1_stdout_`, `_IO_2_1_stderr_` aliased to the same `NativeFile` storage as `stdin`/`stdout`/`stderr`.
* [ ] `NativeFile` is layout-compatible with `_IO_FILE_plus`; field offsets are `static_assert!`-pinned for glibc 2.31 / 2.34 / 2.38.
* [ ] All 9 entry channels in §1.5 (#1–#8 plus #11 alias exports) construct `NativeFile`.
* [ ] Foreign-pointer adoption (§11) is implemented and exercised by a unit test that hands a `_IO_FILE`-shaped pointer through `fread`.
* [ ] `_IO_jump_t` vtable is set on every constructor and trampolines are tested by a unit test that calls `((_IO_FILE_plus *)fp)->vtable->__xsputn(...)` directly.

**Verification:**
* [ ] `support_matrix.json` reports `WrapsHostLibc == 0` and the classifier *actually* inspects function bodies (not just signatures).
* [ ] LD_PRELOAD smoke battery is 64/0/0 (sqlite3, redis-cli, nginx all green in strict and hardened).
* [ ] `cargo bench --bench stdio_native_fastpath` passes the `<20ns`/`<200ns` budgets.
* [ ] Healing oracle includes the six stdio cases in §4.9 and all pass in hardened mode.
* [ ] 32-thread atomicity stress test from §1.6 passes in both modes.
* [ ] `tests/runtime_math/golden/io_jump_dispatch.v1.json` exists and is stable across two consecutive runs.
* [ ] `tests/runtime_math/golden/stdio_decisions.v1.json` exists and captures runtime_math controller activity for a representative stdio workload.

**Documentation + supply chain:**
* [ ] The README headline number "100.0% native coverage" is **rendered** by `scripts/render_readme_counts.py` from `tests/conformance/reality_report.v1.json`, not hand-typed.
* [ ] `scripts/check_readme_drift.sh` is in CI and green.
* [ ] `scripts/witness_chain_audit.sh` produces a green `tests/conformance/witness_chain_audit.v1.json`.
* [ ] `tests/conformance/closure_contract.v1.json` carries the §18 stdio block and `scripts/check_closure_contract.sh` is green.
* [ ] FEATURE_PARITY.md `stdio` row is `IMPLEMENTED` not `IN_PROGRESS`.
* [ ] CHANGELOG entry; AGENTS.md "Hard Parts Truth Table" stdio entry retired.

**Math / methodology:**
* [ ] `tools/stdio_synth/` produces a printf table and a scanf table; `cargo build` invokes the synthesis and the SMT prover; build fails on any unproven obligation.
* [ ] Atiyah-Bott proof DAG compression brings build-time SMT cost ≤ 90 s.
* [ ] POMDP repair controller is the primary hardened-mode dispatcher for stdio (verified by golden snapshot showing every hardened-mode stdio call has a `pomdp_action` field set).
* [ ] All 11 invariants in §1.5 are encoded in `tests/conformance/stdio_invariants.v1.json` and the harness verifies each one against every fixture run.

**Rollback:**
* [ ] `tests/conformance/stdio_pre_option_b_baseline.v1.json` is captured before the merge commit.
* [ ] `git revert <merge-sha>` is the only documented rollback path.
