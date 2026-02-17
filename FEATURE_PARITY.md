# FEATURE_PARITY.md

## Current Reality

Source of truth for implementation parity is `tests/conformance/reality_report.v1.json` (generated `2026-02-13T18:07:59Z`).
Reality snapshot: total_exported=307, implemented=202, raw_syscall=97, glibc_call_through=8, stub=0.
Counts below reflect that generated snapshot and will change as matrix drift fixes land.

Current exported ABI surface is **307 symbols**, classified as:
- `Implemented`: 202
- `RawSyscall`: 97
- `GlibcCallThrough`: 8
- `Stub`: 0

This means the current artifact is a **hybrid interposition profile** (mixed Rust-owned behavior, raw syscalls, host-glibc delegation, and deterministic stubs), not a full replacement profile.

Legend:
- `Implemented`: Native Rust behavior, no host glibc dependency for that symbol
- `RawSyscall`: Direct Linux syscall veneer, no host glibc dependency for that symbol
- `GlibcCallThrough`: Host glibc delegation with membrane pre/post checks
- `Stub`: Deterministic fallback/error contract (documented and testable)
- `DONE` / `IN_PROGRESS` / `PLANNED`: roadmap status for broader subsystem goals

## Macro Coverage Targets

| Area | Target | Status |
|---|---|---|
| Exported symbol classification | 100% of current exports explicitly classified in support taxonomy | DONE |
| POSIX/GNU replacement completeness | Remove `GlibcCallThrough` + `Stub` classes from critical surfaces | IN_PROGRESS |
| ABI symbol/version fidelity | Preserve exported ABI and classify each exported symbol state | IN_PROGRESS |
| Strict mode conformance | Differential parity on supported symbol set | IN_PROGRESS |
| Hardened mode safety | Deterministic repair/deny coverage on membrane-gated paths | IN_PROGRESS |
| Transparent Safety Membrane enforcement | Pointer-sensitive APIs validated before dispatch | IN_PROGRESS |
| Conformance harness | Fixture-driven validation + drift gates | IN_PROGRESS |
| Benchmark gates | Regression-blocking + budget evidence | IN_PROGRESS |

### Hardened Safety Evidence (In Progress)

- Deterministic matrix artifact: `tests/conformance/hardened_repair_deny_matrix.v1.json`
- Gate script + harness integration: `scripts/check_hardened_repair_deny_matrix.sh` and `crates/frankenlibc-harness/tests/hardened_repair_deny_matrix_test.rs`
- Proof narrative + mapping: `docs/proofs/hardened_mode_safety.md` and `docs/proofs/repair_posix_mapping.md`
- Current matrix coverage is expanded but still bounded to currently fixture-backed invalid-input classes/families; additional membrane-gated families continue to be onboarded as hardened fixtures land.

## Symbol Coverage by ABI Module (Taxonomy)

| Taxonomy | Primary modules |
|---|---|
| `Implemented` | `string_abi`, `wchar_abi`, `math_abi`, `stdlib_abi`, `malloc_abi`, `ctype_abi`, `inet_abi`, `errno_abi`, `resolv_abi`, `locale_abi`, `iconv_abi` |
| `RawSyscall` | `unistd_abi`, `socket_abi`, `termios_abi`, `time_abi`, `dirent_abi`, `process_abi`, `poll_abi`, `io_abi`, `mmap_abi`, `resource_abi`, `signal_abi` |
| `GlibcCallThrough` | `stdio_abi`, `dlfcn_abi` |
| `Stub` | none (current exported surface) |

## Hard-Parts Truth Table

Source of truth: `tests/conformance/hard_parts_truth_table.v1.json` (generated `2026-02-13T08:48:00Z`).

- `startup`: `IMPLEMENTED_PARTIAL` — implemented scope: phase-0 startup fixture path (`__libc_start_main`, `__frankenlibc_startup_phase0`, snapshot invariants). Deferred scope: full `csu`/TLS init-order hardening and secure-mode closure campaign.
- `threading`: `IN_PROGRESS` — implemented scope: runtime-math threading routing and selected pthread semantics are live, including lifecycle and rwlock native routing. Deferred scope: close lifecycle/TLS stress beads.
- `resolver`: `IMPLEMENTED_PARTIAL` — implemented scope: bootstrap numeric resolver ABI (`getaddrinfo`, `freeaddrinfo`, `getnameinfo`, `gai_strerror`). Deferred scope: full retry/cache/poisoning hardening campaign.
- `nss`: `IMPLEMENTED_PARTIAL` — implemented scope: passwd/group APIs are exported as `Implemented` via `pwd_abi`/`grp_abi`. Deferred scope: hosts/backend breadth plus NSS concurrency/cache-coherence closure.
- `locale`: `IMPLEMENTED_PARTIAL` — implemented scope: bootstrap `setlocale`/`localeconv` C/POSIX path. Deferred scope: catalog, collation, and transliteration parity expansion.
- `iconv`: `IMPLEMENTED_PARTIAL` — implemented scope: phase-1 `iconv_open`/`iconv`/`iconv_close` conversions for UTF-8/ISO-8859-1/UTF-16LE/UTF-32 with deterministic strict+hardened fixtures; codec scope/exclusions are locked in `tests/conformance/iconv_codec_scope_ledger.v1.json`. Deferred scope: full `iconvdata` breadth and deterministic table-generation closure.

## Deterministic Stub Surface

Current stubbed symbols (explicit deterministic contracts):
- none

## Mode-Specific Parity Matrix

| Family | Strict Mode | Hardened Mode | Status |
|---|---|---|---|
| memory ops | host-glibc differential parity | policy-validated clamp/truncate/deny | DONE |
| string ops | host-glibc differential parity | termination-safe repair paths | DONE |
| math ops | strict IEEE-style scalar behavior (no membrane rewrite) | non-finite sanitization only when repair action is selected | DONE |
| allocator boundary | host-glibc parity for defined behavior | temporal/provenance repair policies | IN_PROGRESS |
| stdio file ops | host-glibc parity for file stream ops | invalid mode repair, buffering fallbacks | DONE |
| process ops | host-glibc parity for fork/exec/wait | exit status clamping, wait options sanitization | DONE |
| virtual memory ops | host-glibc parity for mmap/mprotect | invalid prot→PROT_READ, missing visibility→MAP_PRIVATE, invalid msync→MS_ASYNC, unknown madvise→MADV_NORMAL | DONE |
| pthread sync ops | host-glibc parity for mutex/cond/rwlock | EBUSY destroy→force-unlock+retry, EPERM unlock→silent ignore | DONE |
| poll ops | host-glibc parity for poll/select | nfds clamping for oversized values | DONE |

## Runtime Math Kernel Matrix

| Runtime Kernel | Live Role | Status |
|---|---|---|
| `runtime_math::risk` | online risk upper bound per API family (`risk_upper_bound_ppm`) | DONE |
| `runtime_math::bandit` | constrained `Fast` vs `Full` validation-depth routing | DONE |
| `runtime_math::control` | primal-dual runtime threshold tuning | DONE |
| `runtime_math::pareto` | mode-aware latency/risk Pareto profile selection + cumulative regret tracking + per-family hard regret caps | DONE |
| `runtime_math::barrier` | constant-time admissibility guard | DONE |
| `runtime_math::cohomology` | overlap-consistency fault detection for sharded metadata | IN_PROGRESS |
| `runtime_math::design` | D-optimal heavy-probe selection under strict/hardened budget with online identifiability tracking | DONE |
| `runtime_math::sparse` | online L1 sparse-recovery latent-cause inference from executed-probe anomaly vectors, with focused/diffuse/critical state gating | DONE |
| `runtime_math::fusion` | adaptive robust weighted fusion over heterogeneous kernel severities with online entropy/drift telemetry and fused risk bonus | DONE |
| `runtime_math::equivariant` | representation-stability/group-action monitor for cross-family semantic drift with symmetry-breaking escalation and orbit telemetry | DONE |
| `runtime_math::eprocess` | anytime-valid sequential testing (e-value alarms) per API family | DONE |
| `runtime_math::cvar` | distributionally-robust CVaR tail-risk control with runtime alarm gating | DONE |
| sampled conformal risk fusion (`risk_engine`) | sampled high-order conformal alarm/full-check signal feeds live risk bonus | DONE |
| sampled stage-order oracle fusion (`check_oracle`) | contextual ordering executes on live pointer-validation stages with exact stage-exit feedback loop | DONE |
| quarantine controller fusion (`quarantine_controller`) | allocator observations feed primal-dual quarantine depth publication | DONE |
| tropical latency compositor (`tropical_latency`) | min-plus (tropical) algebra for provable worst-case pipeline latency bounds | DONE |
| spectral phase monitor (`spectral_monitor`) | Marchenko-Pastur / Tracy-Widom random matrix theory phase transition detection | DONE |
| rough-path signature monitor (`rough_path`) | truncated depth-3 path signatures (Terry Lyons theory) for universal noncommutative feature extraction — captures ALL moments + temporal ordering | DONE |
| persistent homology detector (`persistence`) | 0-dimensional Vietoris-Rips persistent homology for topological anomaly detection — sees data *shape* invisible to all statistical methods | DONE |
| Schrödinger bridge controller (`schrodinger_bridge`) | entropic optimal transport (Sinkhorn-Knopp) between action policy and equilibrium — canonical information-theoretic regime transition distance (Cuturi 2013, Léonard 2014) | DONE |
| large-deviations monitor (`large_deviations`) | Cramér rate function (binary KL divergence) for exact exponential failure probability bounds — strictly dominates Hoeffding/CLT | DONE |
| HJI reachability controller (`hji_reachability`) | Hamilton-Jacobi-Isaacs differential game reachability — value-iteration safety certificates with worst-case adversary (Isaacs 1965, Mitchell/Tomlin 2005) | DONE |
| mean-field game contention controller (`mean_field_game`) | Lasry-Lions mean-field Nash equilibrium via Picard fixed-point — congestion collapse detection for validation resource contention (Lasry-Lions 2006, Huang-Malhamé-Caines 2006) | DONE |
| p-adic valuation error calculus (`padic_valuation`) | Non-Archimedean p-adic valuation for floating-point exceptional regime control — detects denormal/overflow/NaN regimes via ultrametric distance (math #40) | DONE |
| symplectic reduction IPC guard (`symplectic_reduction`) | GIT/symplectic reduction for System V IPC admissibility — moment-map deadlock detection + Marsden-Weinstein quotient stability (math #39) | DONE |
| higher-topos descent controller (`higher_topos`) | Higher-categorical descent diagnostics for locale/catalog coherence — sheaf gluing axiom validation over locale fallback chains with EWMA violation tracking (math #42) | DONE |
| commitment-audit controller (`commitment_audit`) | Commitment-algebra + martingale-audit for tamper-evident session/accounting traces — hash-chain commitments, replay ring buffer, anytime-valid sequential hypothesis test (math #44) | DONE |
| Bayesian change-point detector (`changepoint`) | Adams & MacKay (2007) online Bayesian change-point detection — truncated run-length posterior with Beta-Bernoulli conjugate model, hazard function drift/shift classification (math #6) | DONE |
| conformal risk controller (`conformal`) | Split conformal prediction (Vovk et al. 2005) for finite-sample coverage guarantees — sliding-window calibration, conformal p-values, EWMA coverage tracking, distribution-free miscoverage detection (math #27) | DONE |
| ADMM budget allocator (`admm_budget`) | ADMM operator-splitting for online risk/latency/coverage budget optimization — O(n log n) simplex projection, primal-dual convergence tracking, shadow price telemetry (math #26) | DONE |
| spectral-sequence obstruction detector (`obstruction_detector`) | d² ≈ 0 cross-layer consistency defect detection — 12 tracked controller pairs, Frobenius norm obstruction scoring, covariance break tracking (math #28) | DONE |
| operator-norm spectral radius monitor (`operator_norm`) | Online power iteration spectral radius estimation — amplification ratio tracking with directional coherence weighting for ensemble dynamics stability | DONE |
| Malliavin sensitivity controller (`malliavin_sensitivity`) | Discrete Malliavin calculus decision-boundary fragility detection — two-timescale Clark-Ocone variance decomposition, per-controller weighted sensitivity scoring | DONE |
| information geometry monitor (`info_geometry`) | Fisher-Rao geodesic distance on categorical manifold of controller states — Bhattacharyya angle, per-controller divergence profiles, structural regime shift detection (Amari 1985) | DONE |
| matrix concentration monitor (`matrix_concentration`) | Matrix Bernstein inequality (Tropp 2012) finite-sample spectral bounds on ensemble covariance — anytime-valid confidence sets, Gershgorin spectral deviation estimation | DONE |
| nerve complex monitor (`nerve_complex`) | Čech nerve theorem correlation coherence — Betti number (β₀ connected components, β₁ 1-cycles) tracking on controller correlation graph, union-find component counting, Euler characteristic cycle detection | DONE |
| Wasserstein drift monitor (`wasserstein_drift`) | 1-Wasserstein (Earth Mover's) distance on severity histograms — closed-form CDF difference computation, ordinal metric awareness (severity magnitude), per-controller drift profiling (Kantorovich-Rubinstein 1958) | DONE |
| kernel MMD monitor (`kernel_mmd`) | Maximum Mean Discrepancy (Gretton et al. 2012) with RBF kernel — RKHS embedding, mean-embedding approximation with variance correction, distribution-free two-sample testing for joint distributional shifts | DONE |
| Stein discrepancy monitor (`stein_discrepancy`) | Kernelized Stein Discrepancy (Liu, Lee, Jordan 2016) goodness-of-fit testing — KL-divergence between live empirical and calibration-frozen reference models, per-controller divergence profiling, regime shift detection | DONE |
| POMDP repair controller (`pomdp_repair`) | Constrained POMDP belief-space optimal repair policy — risk-conditioned action selection with belief state tracking for latent hazard estimation | DONE |
| K-theory contract monitor (`ktheory`) | Algebraic K-theory contract drift detection — K₀/K₁ group element tracking for cross-family compatibility obligation monitoring | DONE |
| SOS invariant synthesizer (`sos_invariant`) | Sum-of-squares polynomial Lyapunov certificate synthesis — SDP-relaxed invariant verification for controller stability under stress | DONE |
| pointer validator integration | runtime-math decisions affect bloom-miss/deep-check behavior and adaptive stage ordering | DONE |
| allocator integration | runtime-math routing active across allocator ABI (`malloc`, `free`, `calloc`, `realloc`, `posix_memalign`, `memalign`, `aligned_alloc`) with exact check-order stage outcome feedback | DONE |
| string/memory integration | runtime-math routing active for bootstrap `<string.h>` entrypoints (`mem*`, `strlen`, `strcmp`, `strcpy`, `strncpy`, `strcat`, `strncat`, `strchr`, `strrchr`, `strstr`, `strtok`, `strtok_r`) with exact stage-outcome feedback on `memcpy`, `memmove`, `memset`, `memcmp`, `memchr`, `memrchr`, `strlen`, `strcmp`, `strcpy`, `strncpy`, `strcat`, `strncat`, `strchr`, `strrchr`, `strstr`, `strtok`, `strtok_r` | IN_PROGRESS |
| math/fenv integration | runtime-math routing active for bootstrap `<math.h>` entrypoints (`sin`, `cos`, `tan`, `asin`, `acos`, `atan`, `atan2`, `exp`, `log`, `log10`, `pow`, `fabs`, `ceil`, `floor`, `round`, `fmod`, `erf`, `tgamma`, `lgamma`) | DONE |
| stdio integration | runtime-math routing active for `<stdio.h>` entrypoints (`fopen`, `fclose`, `fread`, `fwrite`, `fgets`, `fputs`, `fgetc`, `fputc`, `fseek`, `ftell`, `fflush`, `fprintf`, `printf`, `sprintf`, `snprintf`, `perror`) under `ApiFamily::Stdio` with stream registry, buffered I/O, and full printf format engine | DONE |
| pthread/futex integration | runtime-math routing active for mutex (`init`, `destroy`, `lock`, `trylock`, `unlock`), cond (`init`, `destroy`, `wait`, `signal`, `broadcast`), rwlock (`init`, `destroy`, `rdlock`, `wrlock`, `unlock`) under `ApiFamily::Threading` with null-check validation + hardened EBUSY/EPERM repair | DONE |
| process integration | runtime-math routing active for `fork`, `_exit`, `execve`, `execvp`, `waitpid`, `wait` under `ApiFamily::Process` with strict/hardened exit-status clamping and wait-options sanitization | DONE |
| virtual memory integration | runtime-math routing active for `mmap`, `munmap`, `mprotect`, `msync`, `madvise` under `ApiFamily::VirtualMemory` with strict/hardened prot/flags/advice validation + repair | DONE |
| poll integration | runtime-math routing active for `poll`, `ppoll`, `select`, `pselect` under `ApiFamily::Poll` with strict/hardened nfds clamping | DONE |
| resolver/NSS integration | runtime-math routing active for bootstrap resolver ABI (`getaddrinfo`, `freeaddrinfo`, `getnameinfo`) with exact check-order stage outcomes; full NSS/cache/poisoning campaign still pending | IN_PROGRESS |
| unistd/POSIX integration | runtime-math routing active for `<unistd.h>` entrypoints (`read`, `write`, `close`, `lseek`, `stat`, `access`, `getcwd`, `chdir`, `unlink`, `link`, `symlink`, `readlink`, `fsync`, `sleep`) under `ApiFamily::IoFd` with strict/hardened whence/mode/path validation + repair | DONE |
| socket integration | runtime-math routing active for `<sys/socket.h>` entrypoints (`socket`, `bind`, `listen`, `accept`, `connect`, `send`, `recv`, `sendto`, `recvfrom`, `shutdown`, `setsockopt`, `getsockopt`, `getpeername`, `getsockname`) under `ApiFamily::Socket` with strict/hardened AF/type/how validation + repair | DONE |
| inet integration | runtime-math routing active for `<arpa/inet.h>` entrypoints (`htons`, `htonl`, `ntohs`, `ntohl`, `inet_pton`, `inet_ntop`, `inet_addr`) under `ApiFamily::Inet` | DONE |
| locale integration | runtime-math routing active for `<locale.h>` entrypoints (`setlocale`, `localeconv`) under `ApiFamily::Locale` with strict/hardened locale validation + C-locale fallback repair | DONE |
| termios integration | runtime-math routing active for `<termios.h>` entrypoints (`tcgetattr`, `tcsetattr`, `cfget*speed`, `cfset*speed`, `tcdrain`, `tcflush`, `tcflow`, `tcsendbreak`) under `ApiFamily::Termios` with strict/hardened optional_actions/queue/flow validation + repair | DONE |
| dlfcn integration | dlfcn boundary policy: interpose allows host call-through for `dlopen`/`dlsym`/`dlclose`, hardened invalid-flags repair is `RTLD_NOW`, replacement forbids host fallback; thread-local `dlerror` state remains local | DONE |

## Reverse Core Coverage Matrix

| Surface | Failure Target | Required Runtime Artifact | Status |
|---|---|---|---|
| loader/symbol/IFUNC | global compatibility drift | resolver automata + compatibility witness ledgers | PLANNED |
| allocator | temporal/provenance corruption | allocator policy tables + admissibility guards | IN_PROGRESS |
| hot string/memory kernels | overlap/alignment/dispatch edge faults | regime classifier + certified kernel routing tables | IN_PROGRESS |
| futex/pthread/cancellation | race/starvation/timeout inconsistency | transition kernels + fairness budgets | IN_PROGRESS |
| stdio/parser/locale formatting | parser-state explosion + locale divergence | generated parser/transducer tables | IN_PROGRESS |
| signal/setjmp transfer | invalid non-local transitions | admissible jump/signal/cancel transition matrices | PLANNED |
| time/timezone/rt timers | discontinuity/overrun semantic drift | temporal transition DAGs + timing envelopes | PLANNED |
| nss/resolv/nscd/sunrpc | poisoning/retry/cache instability | deterministic lookup DAGs + calibrated anomaly thresholds | PLANNED |
| locale/iconv/transliteration | conversion-state inconsistency | minimized codec automata + consistency certificates | PLANNED |
| ABI/time64/layout bridges | release compatibility fracture | invariant ledgers + drift alarms | PLANNED |
| VM transitions | unsafe map/protection trajectories | VM transition guard complexes | PLANNED |
| strict/hardened decision layer | threshold calibration drift | coverage-certified decision sets + abstain/escalate gates | PLANNED |
| process bootstrap (`csu`, TLS init, auxv, secure mode) | init-order races + secure-mode misclassification | startup dependency DAG + secure-mode policy automaton + init witness hashes | PLANNED |
| cross-ISA syscall glue (`sysdeps/*`) | architecture-specific semantic drift | per-ISA obligation matrices + dispatch witness cache | PLANNED |
| System V IPC (`sysvipc`) | capability drift + semaphore deadlock trajectories | semaphore admissibility guard polytopes + deadlock-cut certificates | PLANNED |
| i18n catalogs (`intl`, `catgets`, `localedata`) | fallback incoherence + catalog/version skew | catalog resolution automata + locale-consistency witness hashes | PLANNED |
| diagnostics/unwinding (`debug`, backtrace) | unsafe/non-deterministic frame-walk behavior | unwind stratification tables + safe-cut fallback matrix | PLANNED |
| session accounting (`login`, `utmp/wtmp`) | replay/tamper ambiguity + racey state updates | deterministic session-ledger transitions + anomaly thresholds | PLANNED |
| profiling hooks (`gmon`, sampling/probe paths) | probe-induced benchmark distortion | minimal probe schedules + deterministic debias weights | PLANNED |
| floating-point edges (`soft-fp`, `fenv` exceptional paths) | denormal/NaN/payload drift across regimes | regime-indexed numeric guard tables + certified fallback kernels | PLANNED |

## TSM Coverage Matrix (Planned)

| Safety Dimension | Description | Status |
|---|---|---|
| provenance checks | track pointer origin/ownership | PLANNED |
| bounds checks | enforce region length constraints | PLANNED |
| temporal checks | detect freed/quarantined states | PLANNED |
| repair policies | clamp/truncate/no-op/deny deterministic fixes | PLANNED |
| evidence logging | record repaired/denied operations | PLANNED |

## Legacy-Driven Engine Matrix

| Engine | Legacy Anchors | Required Artifact Class | Status |
|---|---|---|---|
| loader engine | `elf`, `sysdeps/*/dl-*` | symbol-scope automata + relocation envelopes | PLANNED |
| allocator-thread engine | `malloc`, `nptl` | contention control policies + safety certificates | PLANNED |
| format-locale engine | `stdio-common`, `wcsmbs`, `locale` | parser/transducer generated artifacts | PLANNED |
| name-service engine | `nss`, `resolv` | lookup policy DAG + anomaly confidence reports | PLANNED |
| numeric engine | `math`, `soft-fp`, `sysdeps/ieee754` | ULP/error/fenv proof bundles | PLANNED |
| cross-ISA glue engine | `sysdeps` | ISA witness bundles + campaign coverage proofs | PLANNED |
| stream-syscall engine | `libio`, `io`, `posix` | stream automata + lock/flush strategy certificates | PLANNED |
| locale-encoding engine | `localedata`, `locale`, `iconvdata`, `iconv`, `wcsmbs` | codec factorization proofs + locale-consistency diagnostics | PLANNED |
| temporal semantics engine | `time`, `timezone` | DST/leap transition proofs + temporal drift reports | PLANNED |
| cache-rpc coherence engine | `nscd`, `sunrpc`, `nss`, `resolv` | security-game equilibria + tail-risk bounds + coherence witnesses | PLANNED |
| bootstrap-observability engine | `csu`, `debug`, `support` | init-order proofs + observability-optimal probe sets | PLANNED |
| loader-audit security engine | `elf` (`dl-*`), hwcaps, tunables, audit | namespace/audit consistency certificates + robust policy maps | PLANNED |
| async-control engine | `signal`, `setjmp`, `nptl` cancellation | continuation-safety proofs + transition admissibility kernels | PLANNED |
| terminal-session engine | `termios`, `login`, `io`, `posix` | ioctl/termios guard polytopes + PTY policy tail bounds | PLANNED |
| launch-pattern engine | `spawn/exec`, `glob/fnmatch/regex`, env/path | launch DAG proofs + complexity bounds + interaction campaign evidence | PLANNED |
| secure-bootstrap policy engine | `csu`, `elf`, secure mode, diagnostics | noninterference proofs + calibrated admission-risk reports | PLANNED |
| conformal-calibration engine | cross-surface strict/hardened decision layer | finite-sample calibrated decision sets + validity monitors | PLANNED |
| topological-obstruction engine | cross-layer interaction complexes | obstruction witnesses + persistent defect signatures | IN_PROGRESS |
| algebraic-normalization engine | policy/parser/dispatch compositions | canonical normal forms + certificate-carrying rewrites | PLANNED |
| noncommutative-concurrency risk engine | `nptl`, allocator/thread hot paths | contention-spectrum bounds + operator-stability controls | IN_PROGRESS |
| Serre-invariant transport engine | cross-layer subsystem towers | spectral-page witnesses + extension-obstruction diagnostics | PLANNED |
| Grothendieck-coherence engine | cross-layer runtime + ABI/ISA compatibility glue | site/topos reconciliation + descent/stackification certificates | PLANNED |
| families-index engine | cross-variant compatibility transport | index-zero ledgers + incompatibility localization traces | IN_PROGRESS |
| equivariant-localization engine | proof/benchmark symmetry reductions | fixed-point compressed obligations + bounded-error certificates | PLANNED |
| Clifford-kernel engine | `string/memory` SIMD overlap/alignment surfaces | kernel normal forms + Spin/Pin guard witnesses | PLANNED |

## Proof and Math Matrix

| Obligation | Evidence Artifact | Status |
|---|---|---|
| strict refinement theorem | SMT/proof notes + differential fixtures | PLANNED |
| hardened safety theorem | invariant checks + policy proof notes | IN_PROGRESS |
| deterministic replay theorem | reproducibility campaign logs | PLANNED |
| sequential regression control | e-process monitoring reports | PLANNED |
| drift detection reliability | change-point validation reports | PLANNED |
| CPOMDP admissibility | policy feasibility certificates + replay logs | IN_PROGRESS |
| CHC/CEGAR convergence | abstraction refinement logs + resolved counterexamples | PLANNED |
| superoptimization soundness | SMT equivalence certificates per accepted rewrite | PLANNED |
| tail-risk control | EVT/CVaR reports for p99/p999 slices | PLANNED |
| barrier invariance | barrier-certificate proof artifacts + runtime checks | PLANNED |
| robust-radius guarantee | Wasserstein robustness reports + constraint audits | PLANNED |
| concurrent linearizability | mechanized concurrency proof notes + stress evidence | PLANNED |
| HJI viability | viability-kernel artifacts + adversarial trace audits | IN_PROGRESS |
| sheaf consistency detection | cohomology diagnostics + inconsistency replay cases | PLANNED |
| combinatorial interaction coverage | covering-array/matroid campaign proofs | IN_PROGRESS |
| probabilistic coupling bounds | coupled-trace divergence certificates + concentration reports | PLANNED |
| mean-field stability | equilibrium/stability reports + contention replay evidence | IN_PROGRESS |
| entropic transition safety | Schrödinger-bridge transport-cost/overshoot reports | PLANNED |
| SOS invariant synthesis | SDP outputs + certificate validation artifacts | IN_PROGRESS |
| large-deviation catastrophe bounds | rare-event estimation reports + threshold audits | PLANNED |
| topological anomaly detection | persistent-homology summaries + detection benchmarks | IN_PROGRESS |
| rough-signature feature stability | perturbation-stability reports + model-input audits | IN_PROGRESS |
| tropical latency composition | min-plus envelope proofs + end-to-end bound reports | IN_PROGRESS |
| online optimizer convergence | primal-dual/ADMM convergence diagnostics + rollback logs | IN_PROGRESS |
| coalgebraic stream bisimulation | minimized stream-machine proofs + protocol replay logs | PLANNED |
| Krohn-Rhodes codec factorization | automata decomposition artifacts + equivalence checks | PLANNED |
| hybrid temporal reachability | reachable-set artifacts + DST/leap edge replay audits | PLANNED |
| Stackelberg cache-security equilibria | equilibrium certificates + adversarial simulation reports | PLANNED |
| observability-rate optimality | rate-distortion/probe design reports + overhead audits | PLANNED |
| loader namespace sheaf consistency | obstruction diagnostics + namespace replay proofs | PLANNED |
| async nonlocal-control admissibility | pushdown/hybrid transition proof bundles + replay traces | PLANNED |
| termios/ioctl polyhedral safety | admissibility polytope artifacts + edge-case replay evidence | PLANNED |
| launch-pattern complexity guarantees | symbolic automata bounds + adversarial fixture audits | PLANNED |
| secure-mode noninterference | relational proof notes + leak-budget test reports | PLANNED |
| conformal decision validity | coverage/risk-control reports + calibration replay logs | PLANNED |
| spectral-sequence obstruction convergence | obstruction diagnostics + localized witness traces | IN_PROGRESS |
| algebraic normal-form uniqueness | canonicalization proofs + rewrite certificate ledgers | PLANNED |
| noncommutative contention stability | random-matrix/free-probability tail reports + stress replays | IN_PROGRESS |
| arithmetic compatibility integrity | invariant ledgers + drift/fracture threshold audits | PLANNED |
| Serre spectral convergence integrity | page-wise witness ledgers + extension-obstruction replay reports | PLANNED |
| Grothendieck descent coherence | site/topos/descent certificates + nongluable-case diagnostics | PLANNED |
| families-index nullity | index ledgers + localized nonzero-index defect reports | IN_PROGRESS |
| Atiyah-Bott localization conservativity | fixed-point/full-obligation equivalence reports + error bounds | IN_PROGRESS |
| Clifford kernel equivalence | regime-partition proofs + cross-ISA witness bundles | PLANNED |
| derived t-structure bootstrap ordering | t-structure filtration proofs + orthogonality violation traces | IN_PROGRESS |

## Gap Summary

1. ~~No Rust libc crates in repo yet.~~ Workspace scaffold with 6 crates created.
2. Initial conformance fixtures committed (`tests/conformance/fixtures/`); full capture pending.
3. Benchmark harnesses exist, but committed baseline evidence + regression thresholds are still pending.
4. Version script scaffold created (`libc.map`); full symbol/version verification pending.
5. No formal proof artifacts are committed yet.
6. Runtime math kernel is live in membrane and pointer validation; cross-family ABI wiring remains incomplete.
7. Sequential-statistical guardrails are wired with deterministic calibration evidence (`tests/runtime_math/risk_pareto_calibration.v1.json`) and enforced via `scripts/check_runtime_math_risk_pareto_calibration.sh`.
8. Bootstrap string/memory + allocator boundary implementations exist; initial strict/hardened fixture evidence is now committed (`tests/conformance/fixtures/membrane_mode_split.json`), full differential campaign remains pending.
8. Core allocator subsystem (size classes, thread cache, large allocator, MallocState) implemented with 50+ tests.
9. Stdlib numeric conversion (`atoi`, `atol`, `strtol`, `strtoul`), process control (`exit`, `atexit`), and sorting (`qsort`, `bsearch`) implemented with core logic and ABI membrane integration.
10. All string functions (mem*, str*, strtok, strtok_r, wide) implemented with comprehensive tests.
11. Tropical latency compositor live — min-plus algebra for provable worst-case pipeline bounds (math item #25).
11. Spectral phase monitor live — Marchenko-Pastur/Tracy-Widom eigenvalue edge detection for regime changes (math item #31).
12. Rough-path signature monitor live — truncated depth-3 path signatures in T(R^4) for universal noncommutative feature extraction (math items #24, #29).
13. Persistent homology detector live — 0-dimensional Vietoris-Rips persistent homology for topological anomaly detection (math item #23).
14. Schrödinger bridge controller live — entropic optimal transport (Sinkhorn-Knopp) for canonical regime transition detection (math item #20).
15. Large-deviations monitor live — Cramér rate function (binary KL divergence) for exact exponential catastrophic failure probability bounds (math item #22).
16. HJI reachability controller live — Hamilton-Jacobi-Isaacs value iteration on 64-state discrete game grid (4×4×4: risk/latency/adverse_rate), controller vs adversary minimax safety certificates (math item #15).
17. Mean-field game contention controller live — Lasry-Lions Nash equilibrium via Picard fixed-point with logit best response, congestion collapse detection for validation resource contention (math item #19).
18. String/Memory ABI fully wired — `memset`, `memcmp`, `memchr`, `strtok`, `strtok_r`, `memrchr` now delegate to `frankenlibc-core` safe implementations after membrane validation; `memcpy` and `memmove` retain local logic due to strict aliasing constraints.
19. D-optimal probe scheduler live — runtime selection of heavy monitors via information-gain-per-cost budgeting with identifiability feedback in hot-path decisioning (math item #41).
20. Sparse latent-cause recovery live — runtime ISTA-based L1 controller infers concentrated vs diffuse fault sources from probe anomaly vectors and feeds strict/hardened risk escalation (math item #41 sparse recovery component).
21. Robust fusion controller live — online multiplicative-weights fusion computes `fusion_bonus_ppm` from cross-kernel severities, reducing double-counted noise while accelerating coherent multi-signal escalation.
22. Equivariant transport controller live — representation-stability/group-action canonicalization across API-family orbits detects cross-family symmetry breaking and escalates fractured runtime regimes (math item #43).
21. P-adic valuation error calculus live — non-Archimedean ultrametric regime detection for floating-point exceptional paths (denormal/overflow/NaN), with p-adic distance metric and regime-indexed guard tables (math item #40).
22. Symplectic reduction IPC guard live — GIT/symplectic moment-map admissibility for System V IPC resource requests, Marsden-Weinstein quotient deadlock detection, and stability certificates (math item #39).
23. Core `<math.h>` scalar functions implemented in safe Rust core (`trig`, `exp/log`, `float`, `special`) with bootstrap tests; removed TODO panics on numeric hot path.
24. ABI `<math.h>` entrypoints now runtime-math gated under `ApiFamily::MathFenv` with strict/hardened mode split and non-finite repair behavior wired into observation telemetry.
23. Higher-topos descent controller live — higher-categorical sheaf gluing axiom validation over locale fallback chains, EWMA-tracked violation rate with Calibrating/Coherent/DescentViolation/Incoherent state machine (math item #42).
24. Commitment-audit controller live — hash-chain commitments (SipHash), replay ring buffer (128 entries), supermartingale sequential hypothesis test with anytime-valid tamper detection for session/accounting traces (math item #44).
25. Bayesian change-point detector live — Adams & MacKay (2007) online Bayesian change-point detection with truncated run-length posterior (256-horizon), Beta-Bernoulli conjugate model, geometric hazard function, drift/shift/stable classification (math item #6).
26. Conformal risk controller live — split conformal prediction (Vovk et al. 2005) with sliding-window calibration (256 entries), conformal p-values, EWMA coverage tracking, distribution-free finite-sample miscoverage detection (math item #27).
27. Five new POSIX function families ported: `<unistd.h>` (27 entrypoints), `<sys/socket.h>` (14 entrypoints), `<arpa/inet.h>` (7 entrypoints), `<locale.h>` (2 entrypoints), `<termios.h>` (10 entrypoints). All routed through the RuntimeMathKernel via new ApiFamily variants (Socket=13, Locale=14, Termios=15, Inet=16). Core modules provide pure-Rust validators and constants; ABI modules wrap libc with membrane gating.
28. Six new runtime math monitors integrated: Malliavin sensitivity, Fisher-Rao information geometry, matrix concentration (Bernstein), Čech nerve complex, Wasserstein drift, kernel MMD. Total test count: 792 (up from 608).
29. `<dlfcn.h>` boundary locked — dlfcn boundary policy: interpose allows host call-through for `dlopen`/`dlsym`/`dlclose`, hardened invalid-flags repair is `RTLD_NOW`, replacement forbids host fallback; `dlerror` remains thread-local state.
30. Stein discrepancy monitor fixed — replaced mean-score-norm KSD (broken for deterministic inputs) with KL divergence D(current||reference) between live EWMA and calibration-frozen models; all 7 tests pass.
31. Five additional runtime math monitors verified: Stein discrepancy (KSD goodness-of-fit), POMDP repair (belief-space policy), K-theory (contract drift), SOS invariant (Lyapunov synthesis). Total test count: 792.
32. POSIX Batch 3: stdio file ops (27 ABI entrypoints wired via stream registry), process control (6 entrypoints under `ApiFamily::Process=17`: fork, _exit, execve, execvp, waitpid, wait), virtual memory (5 entrypoints under `ApiFamily::VirtualMemory=18`: mmap, munmap, mprotect, msync, madvise), pthread sync (15 entrypoints extending `ApiFamily::Threading`: mutex init/destroy/lock/trylock/unlock, cond init/destroy/wait/signal/broadcast, rwlock init/destroy/rdlock/wrlock/unlock), I/O multiplexing (4 entrypoints under `ApiFamily::Poll=19`: poll, ppoll, select, pselect). ApiFamily::COUNT expanded from 17 to 20. Total test count: 897.

## Update Policy

No entry may move to `DONE` without:

1. fixture-based conformance evidence,
2. benchmark result entry,
3. documented membrane policy behavior for that API family,
4. mode-specific strict/hardened evidence,
5. proof artifact references for applicable obligations.
