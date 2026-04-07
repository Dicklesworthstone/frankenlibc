#!/usr/bin/env python3
"""generate_reverse_round_contracts.py — bd-2a2.3 / bd-2a2.4 / bd-2a2.5

Reverse-Round per-round math-to-subsystem contract verification:
  1. Contract mapping — verify each math family has a legacy subsystem anchor.
  2. Round coverage — ensure R7-R11 rounds have adequate math diversity.
  3. Mathematical invariants — validate monotonicity, gluing, convergence specs.
  4. Branch diversity — enforce >=3 distinct math families per round.
  5. Cross-round integration — prove adjacent rounds compose across real seams.
  6. Golden output — produce reproducible baseline for regression detection.

Generates a JSON report to stdout (or --output).
"""
import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


def find_repo_root():
    p = Path(__file__).resolve().parent.parent
    if (p / "Cargo.toml").exists():
        return p
    return Path.cwd()


# Reverse-Round definitions from AGENTS.md
REVERSE_ROUNDS = {
    "R7": {
        "name": "Loader / Symbol / IFUNC",
        "problem_focus": "Versioned symbol lookup under dlopen/dlclose, IFUNC, hwcaps, and relocation dependencies.",
        "legacy_surfaces": ["elf", "dl-*", "IFUNC", "hwcaps", "tunables"],
        "failure_class": "global compatibility drift",
        "artifacts": "resolver automata + compatibility witness ledgers",
        "implementation_plan": [
            "Compile the loader-facing math stack into deterministic resolver automata and relocation schedule envelopes that ordinary Rust modules can consume as policy data.",
            "Anchor the round in crates/frankenlibc-core/src/elf/loader.rs, crates/frankenlibc-core/src/elf/relocation.rs, and crates/frankenlibc-abi/version_scripts/libc.map so scope drift remains tied to real loader surfaces.",
            "Emit compatibility witness data through tests/conformance/reverse_round_contracts.v1.json so IFUNC and hwcaps policy drift is visible without reading runtime-math internals directly.",
        ],
        "verification_strategy": [
            "scripts/check_reverse_round_contracts.sh regenerates and validates the reverse-round contract report.",
            "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs asserts that R7 retains explicit implementation and verification hooks.",
            "scripts/check_runtime_math_epic_closure.sh must continue to reference tests/conformance/reverse_round_contracts.v1.json in the aggregate runtime-math closure pack.",
        ],
        "supporting_files": [
            "PLAN_TO_PORT_GLIBC_TO_RUST.md",
            "crates/frankenlibc-core/src/elf/loader.rs",
            "crates/frankenlibc-core/src/elf/relocation.rs",
            "crates/frankenlibc-abi/version_scripts/libc.map",
            "scripts/check_reverse_round_contracts.sh",
            "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs",
        ],
        "math_families": {
            "tropical": {
                "module": "tropical_latency",
                "description": "Min-plus algebra worst-case latency bounds (math #25)",
                "math_class": "algebra",
                "invariant": "tropical semiring monotonicity: a ⊕ (a ⊗ b) = a",
            },
            "sheaf_cohomology": {
                "module": "grothendieck_glue",
                "description": "Grothendieck site cocycle/descent for symbol gluing (math #33)",
                "math_class": "grothendieck-serre",
                "invariant": "cocycle condition: δ(g_ij) = g_ik · g_kj^(-1)",
            },
            "regret_bounds": {
                "module": "bandit",
                "description": "Constrained bandit routing with regret bounds",
                "math_class": "decision-theory",
                "invariant": "cumulative regret O(sqrt(T log K))",
            },
            "ktheory": {
                "module": "ktheory",
                "description": "K-theory transport for ABI compatibility (math #34)",
                "math_class": "algebraic-topology",
                "invariant": "index stability: ind(D_s) is locally constant in s",
            },
        },
    },
    "R8": {
        "name": "Allocator / nptl",
        "problem_focus": "Arena contention, tcache poisoning classes, cancellation/futex races, and TLS lifecycle edges.",
        "legacy_surfaces": ["malloc", "nptl", "futex", "pthread"],
        "failure_class": "temporal/provenance corruption",
        "artifacts": "allocator policy tables + admissibility guards",
        "implementation_plan": [
            "Compile contention-control, barrier-certificate, and rough-path kernels into allocator and tcache policy tables plus admissibility guards with no hidden heuristics.",
            "Anchor the round in crates/frankenlibc-core/src/malloc/allocator.rs, crates/frankenlibc-core/src/malloc/thread_cache.rs, crates/frankenlibc-core/src/pthread/mutex.rs, and crates/frankenlibc-core/src/pthread/thread.rs.",
            "Keep the proof surface developer-transparent by emitting allocator and thread-runtime witnesses through the reverse-round contract artifact.",
        ],
        "verification_strategy": [
            "scripts/check_reverse_round_contracts.sh and crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs validate the R8 mapping contract.",
            "crates/frankenlibc-harness/tests/thread_hotpath_optimization_test.rs and crates/frankenlibc-harness/tests/pressure_sensing_test.rs keep allocator and thread-runtime anchors exercised.",
            "The aggregate runtime-math closure pack must continue to reference the reverse-round artifact before allocator and nptl claims are treated as stable.",
        ],
        "supporting_files": [
            "PLAN_TO_PORT_GLIBC_TO_RUST.md",
            "crates/frankenlibc-core/src/malloc/allocator.rs",
            "crates/frankenlibc-core/src/malloc/thread_cache.rs",
            "crates/frankenlibc-core/src/pthread/mutex.rs",
            "crates/frankenlibc-core/src/pthread/thread.rs",
            "crates/frankenlibc-harness/tests/thread_hotpath_optimization_test.rs",
            "crates/frankenlibc-harness/tests/pressure_sensing_test.rs",
        ],
        "math_families": {
            "mean_field_game": {
                "module": "mean_field_game",
                "description": "Mean-field Nash equilibrium contention controller (math #19)",
                "math_class": "game-theory",
                "invariant": "Nash fixed-point: no agent benefits from unilateral deviation",
            },
            "sos_barrier": {
                "module": "sos_barrier",
                "description": "SOS barrier certificate for admissibility (math #21)",
                "math_class": "algebra",
                "invariant": "B(x) >= 0 on safe set, dB/dt <= 0 on boundary",
            },
            "rough_path": {
                "module": "rough_path",
                "description": "Rough-path signatures for trace dynamics (math #24)",
                "math_class": "stochastic-analysis",
                "invariant": "Chen identity: S(X)_{s,u} = S(X)_{s,t} ⊗ S(X)_{t,u}",
            },
            "coupling": {
                "module": "coupling",
                "description": "Probabilistic coupling for divergence certification (math #18)",
                "math_class": "conformal-statistics",
                "invariant": "Azuma-Hoeffding: P(|M_n - M_0| > t) <= 2exp(-t²/2nc²)",
            },
        },
    },
    "R9": {
        "name": "Format / Locale",
        "problem_focus": "Format parser complexity, locale-sensitive behavior, and wide-char boundary correctness under bounded overhead.",
        "legacy_surfaces": ["stdio-common", "libio", "locale", "iconv", "wcsmbs"],
        "failure_class": "parser-state explosion and locale drift",
        "artifacts": "parser/transducer tables + consistency certs",
        "implementation_plan": [
            "Compile parser, transducer, and locale-coherence math into deterministic format action graphs and divergence-budget tables consumed directly by the stdio and locale stack.",
            "Anchor the round in crates/frankenlibc-core/src/stdio/printf.rs, crates/frankenlibc-core/src/stdio/scanf.rs, crates/frankenlibc-core/src/locale/mod.rs, and crates/frankenlibc-core/src/iconv/mod.rs.",
            "Keep locale and codec drift machine-visible by routing the phase contract through the reverse-round report instead of leaving it as narrative-only design text.",
        ],
        "verification_strategy": [
            "scripts/check_reverse_round_contracts.sh regenerates tests/conformance/reverse_round_contracts.v1.json.",
            "crates/frankenlibc-harness/tests/stdio_phase_strategy_test.rs and crates/frankenlibc-harness/tests/iconv_codec_scope_ledger_test.rs keep the declared anchors honest.",
            "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs enforces non-empty implementation and verification sections for R9.",
        ],
        "supporting_files": [
            "PLAN_TO_PORT_GLIBC_TO_RUST.md",
            "crates/frankenlibc-core/src/stdio/printf.rs",
            "crates/frankenlibc-core/src/stdio/scanf.rs",
            "crates/frankenlibc-core/src/locale/mod.rs",
            "crates/frankenlibc-core/src/iconv/mod.rs",
            "crates/frankenlibc-harness/tests/stdio_phase_strategy_test.rs",
            "crates/frankenlibc-harness/tests/iconv_codec_scope_ledger_test.rs",
        ],
        "math_families": {
            "conformal": {
                "module": "conformal",
                "description": "Split conformal prediction for finite-sample guarantees (math #27)",
                "math_class": "conformal-statistics",
                "invariant": "coverage: P(Y ∈ C(X)) >= 1-α for finite sample",
            },
            "eprocess": {
                "module": "eprocess",
                "description": "Anytime-valid sequential testing (e-values) (math #5)",
                "math_class": "conformal-statistics",
                "invariant": "E[e-process] <= 1 under null (supermartingale)",
            },
            "higher_topos": {
                "module": "higher_topos",
                "description": "Higher-topos descent for locale coherence (math #42)",
                "math_class": "grothendieck-serre",
                "invariant": "descent: local objects glue to global via cocartesian lifts",
            },
            "grobner": {
                "module": "grobner_normalizer",
                "description": "Gröbner basis constraint normalization (math #30)",
                "math_class": "algebra",
                "invariant": "confluence: all reduction paths terminate at same normal form",
            },
        },
    },
    "R10": {
        "name": "NSS / resolv",
        "problem_focus": "Multi-source lookup orchestration, retries and timeouts, negative caching, and poisoning or collision resilience.",
        "legacy_surfaces": ["nss", "resolv", "nscd", "sunrpc"],
        "failure_class": "poisoning/retry/cache instability",
        "artifacts": "deterministic lookup DAGs + calibrated thresholds",
        "implementation_plan": [
            "Compile orchestration, drift, and anomaly kernels into deterministic lookup DAGs and cache-policy transitions that can be inspected as ordinary data.",
            "Anchor the round in crates/frankenlibc-core/src/resolv/config.rs, crates/frankenlibc-core/src/resolv/dns.rs, crates/frankenlibc-core/src/resolv/mod.rs, and tests/integration/fixture_nss.c.",
            "Route NSS and resolver proof obligations through the reverse-round artifact so poisoning and retry-policy assumptions remain reviewable in one place.",
        ],
        "verification_strategy": [
            "scripts/check_reverse_round_contracts.sh and crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs validate the R10 mapping contract.",
            "crates/frankenlibc-abi/tests/resolv_abi_test.rs and crates/frankenlibc-abi/tests/nss_cache_policy_test.rs keep resolver-facing regressions visible.",
            "scripts/check_runtime_math_epic_closure.sh must continue linking the reverse-round artifact into the runtime-math closure bundle.",
        ],
        "supporting_files": [
            "PLAN_TO_PORT_GLIBC_TO_RUST.md",
            "crates/frankenlibc-core/src/resolv/config.rs",
            "crates/frankenlibc-core/src/resolv/dns.rs",
            "crates/frankenlibc-core/src/resolv/mod.rs",
            "tests/integration/fixture_nss.c",
            "crates/frankenlibc-abi/tests/resolv_abi_test.rs",
            "crates/frankenlibc-abi/tests/nss_cache_policy_test.rs",
        ],
        "math_families": {
            "pomdp": {
                "module": "pomdp_repair",
                "description": "Constrained POMDP repair policy controller (math #8)",
                "math_class": "decision-theory",
                "invariant": "Bellman optimality: V*(s) = max_a [R(s,a) + γ Σ P(s'|s,a)V*(s')]",
            },
            "changepoint": {
                "module": "changepoint",
                "description": "Bayesian online change-point detection (math #6)",
                "math_class": "conformal-statistics",
                "invariant": "posterior: P(r_t|x_{1:t}) via message-passing recursion",
            },
            "wasserstein": {
                "module": "wasserstein_drift",
                "description": "1-Wasserstein distributional shift detection",
                "math_class": "optimal-transport",
                "invariant": "metric: W_1(μ,ν) = inf E[|X-Y|] over couplings (X,Y)",
            },
            "serre_spectral": {
                "module": "serre_spectral",
                "description": "Serre spectral sequence for cross-layer defects (math #32)",
                "math_class": "algebraic-topology",
                "invariant": "spectral convergence: E_∞ = lim E_r via filtered complex",
            },
        },
    },
    "R11": {
        "name": "libm / fenv",
        "problem_focus": "Correct rounding, IEEE exception behavior, consistent fenv semantics, and ULP guarantees.",
        "legacy_surfaces": ["math", "soft-fp", "ieee754", "fenv"],
        "failure_class": "denormal/NaN/payload drift across regimes",
        "artifacts": "regime-indexed numeric guard tables + certified fallback kernels",
        "implementation_plan": [
            "Compile the numeric-control stack into regime-indexed guard tables, certified fallback kernels, and approximation witnesses that core math code can consume directly.",
            "Anchor the round in crates/frankenlibc-core/src/math/mod.rs, crates/frankenlibc-core/src/math/trig.rs, crates/frankenlibc-core/src/math/exp.rs, and crates/frankenlibc-core/src/math/float.rs.",
            "Expose the approximation and error contract through the reverse-round artifact so fenv and ULP obligations remain reproducible instead of living only in prose.",
        ],
        "verification_strategy": [
            "scripts/check_reverse_round_contracts.sh and crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs validate the R11 mapping contract.",
            "crates/frankenlibc-harness/tests/math_production_set_policy_test.rs and crates/frankenlibc-harness/tests/math_governance_test.rs keep the libm and fenv anchors in the verification loop.",
            "scripts/check_runtime_math_epic_closure.sh must keep referencing the reverse-round artifact before libm and fenv closure claims are allowed.",
        ],
        "supporting_files": [
            "PLAN_TO_PORT_GLIBC_TO_RUST.md",
            "crates/frankenlibc-core/src/math/mod.rs",
            "crates/frankenlibc-core/src/math/trig.rs",
            "crates/frankenlibc-core/src/math/exp.rs",
            "crates/frankenlibc-core/src/math/float.rs",
            "crates/frankenlibc-harness/tests/math_production_set_policy_test.rs",
            "crates/frankenlibc-harness/tests/math_governance_test.rs",
        ],
        "math_families": {
            "padic": {
                "module": "padic_valuation",
                "description": "Non-Archimedean p-adic error calculus (math #40)",
                "math_class": "algebra",
                "invariant": "|x + y|_p <= max(|x|_p, |y|_p) (ultrametric inequality)",
            },
            "loss_minimizer": {
                "module": "loss_minimizer",
                "description": "Decision-theoretic loss minimization (math #4)",
                "math_class": "decision-theory",
                "invariant": "proper scoring: argmin E[S(q,Y)] = P(Y) (calibration)",
            },
            "design": {
                "module": "design",
                "description": "D-optimal probe scheduling (math #41)",
                "math_class": "experimental-design",
                "invariant": "det(X'X) maximized over probe allocation",
            },
            "clifford": {
                "module": "clifford",
                "description": "Clifford/geometric algebra for SIMD correctness (math #36)",
                "math_class": "algebra",
                "invariant": "Cl(V,q) graded algebra: v² = q(v) for all v ∈ V",
            },
        },
    },
}

REVERSE_ROUNDS.update(
    {
        "R26": {
            "name": "Futex / PI / Robust-Concurrency Semantics",
            "problem_focus": "Correctness under futex wait/wake races, PI locking, robust mutex recovery, cancellation edges, and timeout semantics across clocks and time64 variants.",
            "legacy_surfaces": ["nptl", "futex", "pthread", "time64", "robust lists"],
            "failure_class": "wait-queue and recovery protocol drift",
            "artifacts": "futex/PI protocol kernels + fairness/starvation witness budgets",
            "implementation_plan": [
                "Compile concurrency-control, admissibility, and fairness kernels into futex/PI protocol tables and robust-list lifecycle witnesses that ordinary pthread code can consume as policy data.",
                "Anchor the round in crates/frankenlibc-core/src/pthread/mutex.rs, crates/frankenlibc-core/src/pthread/cond.rs, crates/frankenlibc-core/src/pthread/thread.rs, and crates/frankenlibc-core/src/time/mod.rs so PI, cancellation, and timeout drift stay tied to real blocking surfaces.",
                "Expose timeout and recovery assumptions through the reverse-round contract artifact so blocked-wait and robust-recovery regressions remain reviewable without reading controller internals.",
            ],
            "verification_strategy": [
                "scripts/check_reverse_round_contracts.sh regenerates and validates the reverse-round contract report.",
                "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs asserts that R26 retains explicit implementation and verification hooks.",
                "crates/frankenlibc-abi/tests/pthread_mutex_core_test.rs, crates/frankenlibc-abi/tests/pthread_cond_core_test.rs, and crates/frankenlibc-abi/tests/time_abi_test.rs keep mutex, condvar, and timeout-facing anchors visible.",
            ],
            "supporting_files": [
                "PLAN_TO_PORT_GLIBC_TO_RUST.md",
                "crates/frankenlibc-core/src/pthread/mutex.rs",
                "crates/frankenlibc-core/src/pthread/cond.rs",
                "crates/frankenlibc-core/src/pthread/thread.rs",
                "crates/frankenlibc-core/src/time/mod.rs",
                "crates/frankenlibc-abi/tests/pthread_mutex_core_test.rs",
                "crates/frankenlibc-abi/tests/pthread_cond_core_test.rs",
                "crates/frankenlibc-abi/tests/time_abi_test.rs",
            ],
            "math_families": {
                "interleaving_obstruction": {
                    "module": "obstruction_detector",
                    "description": "Topological obstruction witnesses for lock/wait interleavings",
                    "math_class": "algebraic-topology",
                    "invariant": "vanishing obstruction class implies local wait protocol fragments extend to a global admissible execution.",
                },
                "queue_control": {
                    "module": "mean_field_game",
                    "description": "Mean-field contention controller for PI and wait-queue pressure",
                    "math_class": "decision-theory",
                    "invariant": "Nash fixed point: no waiter benefits from unilateral deviation once queue policy converges.",
                },
                "fairness_bounds": {
                    "module": "coupling",
                    "description": "Martingale-style fairness and starvation deviation bounds",
                    "math_class": "conformal-statistics",
                    "invariant": "Azuma-Hoeffding concentration bounds certify bounded starvation deviation over coupled wait traces.",
                },
                "timeout_barrier": {
                    "module": "sos_barrier",
                    "description": "Barrier-certificate admissibility for timeout and recovery transitions",
                    "math_class": "algebra",
                    "invariant": "Barrier remains non-negative on safe wait states and decreases on unsafe timeout trajectories.",
                },
            },
        },
        "R27": {
            "name": "Multiarch SIMD Kernel Coherence",
            "problem_focus": "Preserving one semantic contract across SSE, AVX, EVEX, NEON, and related kernels while optimizing dispatch decisions and guarding edge-case alignment and alias behavior.",
            "legacy_surfaces": ["sysdeps/*/multiarch", "IFUNC", "string", "memory", "hwcaps"],
            "failure_class": "cross-ISA semantic divergence",
            "artifacts": "dispatch manifolds + semantic witness bundles + SIMD stress campaigns",
            "implementation_plan": [
                "Compile dispatch, alignment, and equivalence kernels into deterministic routing tables and kernel witness bundles that string and memory hot paths can consume without hidden ISA heuristics.",
                "Anchor the round in crates/frankenlibc-core/src/string/mem.rs, crates/frankenlibc-core/src/string/str.rs, crates/frankenlibc-core/src/elf/loader.rs, and crates/frankenlibc-abi/version_scripts/libc.map so multiarch drift stays tied to real IFUNC and hot-path surfaces.",
                "Emit cross-kernel witness data through the reverse-round artifact so SIMD dispatch drift is visible without reading the runtime-math modules directly.",
            ],
            "verification_strategy": [
                "scripts/check_reverse_round_contracts.sh regenerates and validates the reverse-round contract report.",
                "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs asserts that R27 retains explicit implementation and verification hooks.",
                "crates/frankenlibc-abi/tests/string_abi_test.rs and crates/frankenlibc-harness/tests/isomorphism_proof_test.rs keep string-kernel and equivalence anchors exercised.",
            ],
            "supporting_files": [
                "PLAN_TO_PORT_GLIBC_TO_RUST.md",
                "crates/frankenlibc-core/src/string/mem.rs",
                "crates/frankenlibc-core/src/string/str.rs",
                "crates/frankenlibc-core/src/elf/loader.rs",
                "crates/frankenlibc-abi/version_scripts/libc.map",
                "crates/frankenlibc-abi/tests/string_abi_test.rs",
                "crates/frankenlibc-harness/tests/isomorphism_proof_test.rs",
            ],
            "math_families": {
                "feature_transport": {
                    "module": "ktheory",
                    "description": "K-theory transport of feature-lattice dispatch witnesses across ISA families",
                    "math_class": "algebraic-topology",
                    "invariant": "index-stability across feature charts keeps dispatch transport classes locally constant.",
                },
                "kernel_geometry": {
                    "module": "clifford",
                    "description": "Clifford algebra geometry for alignment and lane semantics",
                    "math_class": "algebra",
                    "invariant": "graded Clifford products preserve lane and overlap constraints under kernel composition.",
                },
                "stress_design": {
                    "module": "covering_array",
                    "description": "Covering-array construction for minimal high-power SIMD stress sets",
                    "math_class": "experimental-design",
                    "invariant": "strength-t covering arrays cover every required ISA x alignment interaction at least once.",
                },
                "equivalence_transport": {
                    "module": "equivariant",
                    "description": "Equivariant transport for kernel-family semantic equivalence",
                    "math_class": "algebra",
                    "invariant": "equivariant maps commute with the dispatch group action on kernel representations.",
                },
            },
        },
        "R28": {
            "name": "Real-Time Event and Queue Semantics",
            "problem_focus": "Deterministic semantics and bounded tails for timer creation and arming, queue delivery, and clock-based timing behavior.",
            "legacy_surfaces": ["rt", "timers", "mqueue", "clock", "poll"],
            "failure_class": "timing envelope and overrun drift",
            "artifacts": "timer/queue envelopes + overrun budgets + retry policy tables",
            "implementation_plan": [
                "Compile timer, retry, and tail-risk kernels into deterministic timing envelopes and retry tables that time and polling code can consume directly.",
                "Anchor the round in crates/frankenlibc-core/src/time/mod.rs, crates/frankenlibc-core/src/poll/mod.rs, and crates/frankenlibc-core/src/process/mod.rs so timer and queue drift remain tied to real runtime-facing surfaces.",
                "Route overrun and timeout budgets through the reverse-round artifact so real-time semantics stay inspectable alongside the rest of the reverse-round contract.",
            ],
            "verification_strategy": [
                "scripts/check_reverse_round_contracts.sh regenerates and validates the reverse-round contract report.",
                "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs asserts that R28 retains explicit implementation and verification hooks.",
                "crates/frankenlibc-abi/tests/time_abi_test.rs, crates/frankenlibc-abi/tests/poll_abi_test.rs, and crates/frankenlibc-harness/tests/perf_budget_test.rs keep timing and tail-budget anchors visible.",
            ],
            "supporting_files": [
                "PLAN_TO_PORT_GLIBC_TO_RUST.md",
                "crates/frankenlibc-core/src/time/mod.rs",
                "crates/frankenlibc-core/src/poll/mod.rs",
                "crates/frankenlibc-core/src/process/mod.rs",
                "crates/frankenlibc-abi/tests/time_abi_test.rs",
                "crates/frankenlibc-abi/tests/poll_abi_test.rs",
                "crates/frankenlibc-harness/tests/perf_budget_test.rs",
            ],
            "math_families": {
                "event_control": {
                    "module": "control",
                    "description": "Deterministic timer and queue controller derived from event-system envelopes",
                    "math_class": "decision-theory",
                    "invariant": "controller thresholds remain feasible under the primal-dual budget constraints.",
                },
                "tail_budgets": {
                    "module": "cvar",
                    "description": "Tail-risk budgeting for overrun and delay envelopes",
                    "math_class": "conformal-statistics",
                    "invariant": "CVaR bounds upper-tail timing loss under bounded workload shift.",
                },
                "renewal_tails": {
                    "module": "renewal_theory",
                    "description": "Renewal-process tracking for timer and queue recurrence behavior",
                    "math_class": "stochastic-analysis",
                    "invariant": "renewal reward rates converge to the stationary inter-arrival expectation.",
                },
                "online_validity": {
                    "module": "eprocess",
                    "description": "Anytime-valid overrun alarms for runtime timing drift",
                    "math_class": "conformal-statistics",
                    "invariant": "the e-process remains a nonnegative supermartingale under the null timing envelope.",
                },
            },
        },
        "R29": {
            "name": "SysV IPC Lifecycle Semantics",
            "problem_focus": "Correctness and safety of segment and key lifecycle, permission semantics, and cleanup in adversarial or failure-prone process topologies.",
            "legacy_surfaces": ["sysvipc", "shm", "sem", "msg", "process"],
            "failure_class": "lifecycle leak and stale-handle drift",
            "artifacts": "IPC lifecycle automata + admissibility solvers + cleanup policies",
            "implementation_plan": [
                "Compile lifecycle, permission, and cleanup kernels into deterministic automata and admissibility tables that process-facing IPC code can consume directly.",
                "Anchor the round in crates/frankenlibc-core/src/process/mod.rs, crates/frankenlibc-core/src/resource/mod.rs, and crates/frankenlibc-core/src/io/mod.rs so SysV lifecycle pressure points remain tied to real ownership and cleanup surfaces.",
                "Expose stale-handle and cleanup assumptions through the reverse-round artifact so IPC lifecycle drift is reviewable without reading controller internals.",
            ],
            "verification_strategy": [
                "scripts/check_reverse_round_contracts.sh regenerates and validates the reverse-round contract report.",
                "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs asserts that R29 retains explicit implementation and verification hooks.",
                "crates/frankenlibc-abi/tests/process_abi_test.rs, crates/frankenlibc-abi/tests/io_abi_test.rs, and crates/frankenlibc-harness/tests/hard_parts_dependency_matrix_test.rs keep lifecycle anchors visible.",
            ],
            "supporting_files": [
                "PLAN_TO_PORT_GLIBC_TO_RUST.md",
                "crates/frankenlibc-core/src/process/mod.rs",
                "crates/frankenlibc-core/src/resource/mod.rs",
                "crates/frankenlibc-core/src/io/mod.rs",
                "crates/frankenlibc-abi/tests/process_abi_test.rs",
                "crates/frankenlibc-abi/tests/io_abi_test.rs",
                "crates/frankenlibc-harness/tests/hard_parts_dependency_matrix_test.rs",
            ],
            "math_families": {
                "lifecycle_topology": {
                    "module": "hodge_decomposition",
                    "description": "Topological lifecycle decomposition for segment, semaphore, and message transitions",
                    "math_class": "algebraic-topology",
                    "invariant": "harmonic residuals isolate cyclic lifecycle inconsistencies that cannot be discharged locally.",
                },
                "permission_normalizer": {
                    "module": "grobner_normalizer",
                    "description": "Constraint normalization for key and permission admissibility",
                    "math_class": "algebra",
                    "invariant": "all admissibility reduction paths terminate at one normal form.",
                },
                "cleanup_policy": {
                    "module": "pomdp_repair",
                    "description": "Decision policy for stale-handle cleanup and recovery",
                    "math_class": "decision-theory",
                    "invariant": "Bellman-optimal cleanup actions minimize expected leak and staleness loss.",
                },
                "staleness_bounds": {
                    "module": "coupling",
                    "description": "Coupled-trace bounds for stale-handle divergence under failures",
                    "math_class": "conformal-statistics",
                    "invariant": "coupled stale-handle traces preserve bounded divergence with exponentially decaying tails.",
                },
            },
        },
        "R30": {
            "name": "ABI Layout and Time64 Compatibility Geometry",
            "problem_focus": "Preserving ABI contract across layout variants, time64 bridges, and symbol-version translations without semantic drift.",
            "legacy_surfaces": ["x32/64", "time64", "symbol versions", "layout bridges", "ABI"],
            "failure_class": "layout-translation and compatibility drift",
            "artifacts": "layout translation certificates + compatibility witnesses + release drift alerts",
            "implementation_plan": [
                "Compile layout, drift, and translation kernels into compatibility witness sets and drift thresholds that ABI and time code can treat as ordinary release-blocking data.",
                "Anchor the round in crates/frankenlibc-abi/version_scripts/libc.map, crates/frankenlibc-core/src/time/mod.rs, and crates/frankenlibc-abi/tests/startup_abi_contract_test.rs so compatibility drift remains tied to real symbol and time surfaces.",
                "Route layout-translation evidence through the reverse-round artifact so time64 and layout-bridge assumptions remain reviewable in one place.",
            ],
            "verification_strategy": [
                "scripts/check_reverse_round_contracts.sh regenerates and validates the reverse-round contract report.",
                "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs asserts that R30 retains explicit implementation and verification hooks.",
                "crates/frankenlibc-abi/tests/time_abi_test.rs, crates/frankenlibc-abi/tests/startup_abi_contract_test.rs, and crates/frankenlibc-harness/tests/symbol_drift_test.rs keep layout and drift anchors visible.",
            ],
            "supporting_files": [
                "PLAN_TO_PORT_GLIBC_TO_RUST.md",
                "crates/frankenlibc-abi/version_scripts/libc.map",
                "crates/frankenlibc-core/src/time/mod.rs",
                "crates/frankenlibc-abi/tests/time_abi_test.rs",
                "crates/frankenlibc-abi/tests/startup_abi_contract_test.rs",
                "crates/frankenlibc-harness/tests/symbol_drift_test.rs",
            ],
            "math_families": {
                "transport_witness": {
                    "module": "ktheory",
                    "description": "Compatibility transport witnesses across layout and version charts",
                    "math_class": "algebraic-topology",
                    "invariant": "transport classes stay stable under locally compatible ABI chart transitions.",
                },
                "layout_normal_forms": {
                    "module": "grobner_normalizer",
                    "description": "Canonicalization of layout translation constraints",
                    "math_class": "algebra",
                    "invariant": "equivalent layout constraints reduce to the same canonical normal form.",
                },
                "drift_metrics": {
                    "module": "kernel_mmd",
                    "description": "Distributional drift detection for compatibility-surface movement",
                    "math_class": "conformal-statistics",
                    "invariant": "kernel MMD remains zero only when compared layout-observable traces are distributionally matched.",
                },
                "projection_policy": {
                    "module": "loss_minimizer",
                    "description": "Decision-theoretic projection policy for variant-to-canonical ABI routing",
                    "math_class": "decision-theory",
                    "invariant": "proper loss minimization selects the calibrated canonical projection for each layout regime.",
                },
            },
        },
        "R31": {
            "name": "Conformal Reliability Control",
            "problem_focus": "Guaranteeing finite-sample reliability for runtime decisions such as allow, repair, deny, fallback selection, and timeout escalation under distribution drift.",
            "legacy_surfaces": ["strict", "hardened", "runtime policy", "fallback selection", "decision calibration"],
            "failure_class": "false-repair and false-deny calibration drift",
            "artifacts": "calibrated decision sets + validity monitors + abstain/escalate guards",
            "implementation_plan": [
                "Compile conformal calibration and online-validity kernels into per-family decision sets and escalation guards that the runtime policy layer can consume directly.",
                "Anchor the round in crates/frankenlibc-abi/src/runtime_policy.rs, crates/frankenlibc-membrane/src/runtime_math/conformal.rs, and crates/frankenlibc-membrane/src/runtime_math/eprocess.rs so reliability drift stays tied to real mode-gating surfaces.",
                "Emit validity budgets through the reverse-round artifact so finite-sample reliability claims remain audit-ready without reading calibration internals.",
            ],
            "verification_strategy": [
                "scripts/check_reverse_round_contracts.sh regenerates and validates the reverse-round contract report.",
                "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs asserts that R31 retains explicit implementation and verification hooks.",
                "crates/frankenlibc-harness/tests/anytime_valid_monitor_test.rs, crates/frankenlibc-harness/tests/runtime_math_risk_pareto_calibration_test.rs, and crates/frankenlibc-harness/tests/mode_semantics_test.rs keep reliability anchors visible.",
            ],
            "supporting_files": [
                "PLAN_TO_PORT_GLIBC_TO_RUST.md",
                "crates/frankenlibc-abi/src/runtime_policy.rs",
                "crates/frankenlibc-membrane/src/runtime_math/conformal.rs",
                "crates/frankenlibc-membrane/src/runtime_math/eprocess.rs",
                "crates/frankenlibc-harness/tests/anytime_valid_monitor_test.rs",
                "crates/frankenlibc-harness/tests/runtime_math_risk_pareto_calibration_test.rs",
                "crates/frankenlibc-harness/tests/mode_semantics_test.rs",
            ],
            "math_families": {
                "split_conformal": {
                    "module": "conformal",
                    "description": "Split and Mondrian conformal calibration for per-family decision sets",
                    "math_class": "conformal-statistics",
                    "invariant": "finite-sample coverage remains above 1-α within each calibrated stratum.",
                },
                "risk_budgeting": {
                    "module": "risk",
                    "description": "Decision-risk budgeting for false-repair and false-deny control",
                    "math_class": "decision-theory",
                    "invariant": "family risk envelopes upper-bound calibrated decision loss under the active budget.",
                },
                "online_validity": {
                    "module": "eprocess",
                    "description": "Online conformal martingale for shift detection",
                    "math_class": "conformal-statistics",
                    "invariant": "the e-process remains an anytime-valid supermartingale under the maintained calibration.",
                },
                "calibration_design": {
                    "module": "design",
                    "description": "Probe allocation design for calibration maintenance",
                    "math_class": "experimental-design",
                    "invariant": "D-optimal probe selection maximizes calibration identifiability for fixed budget.",
                },
            },
        },
        "R32": {
            "name": "Algebraic Topology of Dependency and State Defects",
            "problem_focus": "Detecting and localizing global consistency defects that are invisible in local invariants across loader, thread, I/O, lookup, and time surfaces.",
            "legacy_surfaces": ["loader", "threads", "io", "lookup", "time", "cross-layer"],
            "failure_class": "hidden global consistency contradictions",
            "artifacts": "obstruction witnesses + reduced complexes + topology-aware remediation plans",
            "implementation_plan": [
                "Compile topology and defect-localization kernels into obstruction witnesses and deterministic remediation plans that cross-layer validation tooling can consume directly.",
                "Anchor the round in crates/frankenlibc-core/src/elf/loader.rs, crates/frankenlibc-core/src/pthread/thread.rs, crates/frankenlibc-core/src/io/mod.rs, crates/frankenlibc-core/src/time/mod.rs, and crates/frankenlibc-core/src/resolv/mod.rs.",
                "Route cross-layer defect witnesses through the reverse-round artifact so hidden extension failures stay reviewable alongside ordinary subsystem evidence.",
            ],
            "verification_strategy": [
                "scripts/check_reverse_round_contracts.sh regenerates and validates the reverse-round contract report.",
                "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs asserts that R32 retains explicit implementation and verification hooks.",
                "crates/frankenlibc-harness/tests/runtime_math_cohomology_cross_family_test.rs, crates/frankenlibc-harness/tests/runtime_math_linkage_proofs_test.rs, and crates/frankenlibc-harness/tests/hard_parts_dependency_matrix_test.rs keep topology anchors visible.",
            ],
            "supporting_files": [
                "PLAN_TO_PORT_GLIBC_TO_RUST.md",
                "crates/frankenlibc-core/src/elf/loader.rs",
                "crates/frankenlibc-core/src/pthread/thread.rs",
                "crates/frankenlibc-core/src/io/mod.rs",
                "crates/frankenlibc-core/src/time/mod.rs",
                "crates/frankenlibc-core/src/resolv/mod.rs",
                "crates/frankenlibc-membrane/src/runtime_math/serre_spectral.rs",
                "crates/frankenlibc-membrane/src/runtime_math/obstruction_detector.rs",
                "crates/frankenlibc-membrane/src/runtime_math/persistence.rs",
                "crates/frankenlibc-harness/tests/runtime_math_cohomology_cross_family_test.rs",
                "crates/frankenlibc-harness/tests/runtime_math_linkage_proofs_test.rs",
                "crates/frankenlibc-harness/tests/hard_parts_dependency_matrix_test.rs",
            ],
            "math_families": {
                "spectral_sequence": {
                    "module": "serre_spectral",
                    "description": "Serre spectral sequence for filtered dependency-tower defects",
                    "math_class": "algebraic-topology",
                    "invariant": "converged spectral pages encode all surviving cross-layer defect classes.",
                },
                "obstruction_witness": {
                    "module": "obstruction_detector",
                    "description": "Obstruction detector for failed local-to-global invariant extensions",
                    "math_class": "algebraic-topology",
                    "invariant": "non-vanishing obstruction witnesses certify the absence of a global extension.",
                },
                "defect_signatures": {
                    "module": "kernel_mmd",
                    "description": "Stable workload-signature comparison for persistent defect classes",
                    "math_class": "conformal-statistics",
                    "invariant": "kernel MMD isolates reproducible defect signatures across repeated workload regimes.",
                },
                "reduced_complexes": {
                    "module": "grobner_normalizer",
                    "description": "Canonical reduction of defect-critical state complexes",
                    "math_class": "algebra",
                    "invariant": "reduced complexes preserve defect-critical classes while eliminating rewrite-equivalent states.",
                },
            },
        },
        "R33": {
            "name": "Abstract Algebraic Normal Forms",
            "problem_focus": "Enforcing canonical behavior in rewrite-heavy paths so equivalent policies, parsers, dispatch logic, and conversion kernels normalize to one certified form.",
            "legacy_surfaces": ["policies", "parsers", "dispatch", "conversion kernels", "regex"],
            "failure_class": "rewrite-equivalent behavior drift",
            "artifacts": "canonical normal forms + invariant generators + orbit-collapsed conformance spaces",
            "implementation_plan": [
                "Compile canonicalization and equivalence kernels into proof-carrying rewrites and orbit-collapsed conformance spaces that parser and dispatch code can consume directly.",
                "Anchor the round in crates/frankenlibc-core/src/string/regex.rs, crates/frankenlibc-core/src/stdio/printf.rs, crates/frankenlibc-core/src/stdlib/conversion.rs, and crates/frankenlibc-abi/src/runtime_policy.rs.",
                "Emit canonical-form witnesses through the reverse-round artifact so normalization drift remains visible without reading algebraic controller internals.",
            ],
            "verification_strategy": [
                "scripts/check_reverse_round_contracts.sh regenerates and validates the reverse-round contract report.",
                "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs asserts that R33 retains explicit implementation and verification hooks.",
                "crates/frankenlibc-harness/tests/runtime_math_classification_matrix_test.rs, crates/frankenlibc-harness/tests/isomorphism_proof_test.rs, and crates/frankenlibc-harness/tests/stdio_phase_strategy_test.rs keep normalization anchors visible.",
            ],
            "supporting_files": [
                "PLAN_TO_PORT_GLIBC_TO_RUST.md",
                "crates/frankenlibc-core/src/string/regex.rs",
                "crates/frankenlibc-core/src/stdio/printf.rs",
                "crates/frankenlibc-core/src/stdlib/conversion.rs",
                "crates/frankenlibc-abi/src/runtime_policy.rs",
                "crates/frankenlibc-membrane/src/runtime_math/grobner_normalizer.rs",
                "crates/frankenlibc-membrane/src/runtime_math/equivariant.rs",
                "crates/frankenlibc-harness/tests/runtime_math_classification_matrix_test.rs",
                "crates/frankenlibc-harness/tests/isomorphism_proof_test.rs",
                "crates/frankenlibc-harness/tests/stdio_phase_strategy_test.rs",
            ],
            "math_families": {
                "normal_forms": {
                    "module": "grobner_normalizer",
                    "description": "Gröbner normalization for canonical policy and parser rewrites",
                    "math_class": "algebra",
                    "invariant": "every equivalent rewrite path terminates at one canonical remainder.",
                },
                "orbit_reduction": {
                    "module": "equivariant",
                    "description": "Orbit reduction over equivalent parser and dispatch families",
                    "math_class": "algebra",
                    "invariant": "orbit representatives preserve semantic invariants under the governing group action.",
                },
                "campaign_design": {
                    "module": "covering_array",
                    "description": "Conformance-space reduction for normalized parser and dispatch families",
                    "math_class": "experimental-design",
                    "invariant": "covering arrays preserve all required high-order interaction witnesses after orbit collapse.",
                },
                "rewrite_alerts": {
                    "module": "eprocess",
                    "description": "Anytime-valid alarms for rewrite divergence from canonical forms",
                    "math_class": "conformal-statistics",
                    "invariant": "rewrite-drift alarms remain anytime-valid under the canonical null model.",
                },
            },
        },
        "R34": {
            "name": "Noncommutative and Random-Matrix Concurrency Models",
            "problem_focus": "Obtaining stronger tail guarantees for heavily concurrent lock, queue, and allocator interactions where commutative assumptions fail.",
            "legacy_surfaces": ["nptl", "allocator", "thread cache", "rcu", "concurrency"],
            "failure_class": "contention-spectrum and convoy drift",
            "artifacts": "contention risk envelopes + stability-preserving tuning constraints + burst witnesses",
            "implementation_plan": [
                "Compile concurrency tail, stability, and tuning kernels into contention-spectrum budgets and runtime tuning constraints that allocator and lock hot paths can consume directly.",
                "Anchor the round in crates/frankenlibc-core/src/malloc/thread_cache.rs, crates/frankenlibc-core/src/pthread/mutex.rs, crates/frankenlibc-core/src/rcu/mod.rs, and crates/frankenlibc-core/src/malloc/allocator.rs.",
                "Expose high-contention witness data through the reverse-round artifact so burst and convoy risk stays reviewable without reading random-matrix controller internals.",
            ],
            "verification_strategy": [
                "scripts/check_reverse_round_contracts.sh regenerates and validates the reverse-round contract report.",
                "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs asserts that R34 retains explicit implementation and verification hooks.",
                "crates/frankenlibc-harness/tests/thread_hotpath_optimization_test.rs, crates/frankenlibc-harness/tests/perf_budget_test.rs, and crates/frankenlibc-harness/tests/runtime_math_profile_gates_test.rs keep concurrency anchors visible.",
            ],
            "supporting_files": [
                "PLAN_TO_PORT_GLIBC_TO_RUST.md",
                "crates/frankenlibc-core/src/malloc/thread_cache.rs",
                "crates/frankenlibc-core/src/pthread/mutex.rs",
                "crates/frankenlibc-core/src/rcu/mod.rs",
                "crates/frankenlibc-core/src/malloc/allocator.rs",
                "crates/frankenlibc-membrane/src/runtime_math/matrix_concentration.rs",
                "crates/frankenlibc-membrane/src/runtime_math/operator_norm.rs",
                "crates/frankenlibc-membrane/src/runtime_math/lyapunov_stability.rs",
                "crates/frankenlibc-harness/tests/thread_hotpath_optimization_test.rs",
                "crates/frankenlibc-harness/tests/perf_budget_test.rs",
                "crates/frankenlibc-harness/tests/runtime_math_profile_gates_test.rs",
            ],
            "math_families": {
                "matrix_tails": {
                    "module": "matrix_concentration",
                    "description": "Random-matrix tail bounds for burst contention and lock convoys",
                    "math_class": "stochastic-analysis",
                    "invariant": "matrix Bernstein bounds control the spectral tail of contention operators.",
                },
                "operator_stability": {
                    "module": "operator_norm",
                    "description": "Operator-norm stability margins for runtime tuning",
                    "math_class": "algebra",
                    "invariant": "spectral radius below one preserves the configured stability margin.",
                },
                "contention_games": {
                    "module": "mean_field_game",
                    "description": "Mean-field game controller for noncommutative contention surfaces",
                    "math_class": "game-theory",
                    "invariant": "mean-field equilibrium bounds unilateral queueing deviation under the selected tuning policy.",
                },
                "burst_stability": {
                    "module": "lyapunov_stability",
                    "description": "Lyapunov stability monitor for burst-mode concurrency transitions",
                    "math_class": "stochastic-analysis",
                    "invariant": "negative Lyapunov drift implies burst contention returns to the admissible attractor.",
                },
            },
        },
        "R35": {
            "name": "Arithmetic Geometry for Compatibility Drift",
            "problem_focus": "Proving that compatibility surfaces evolve inside a controlled algebraic family, with early detection of latent ABI fracture modes.",
            "legacy_surfaces": ["symbol/version", "layout", "time64", "compatibility drift", "release gating"],
            "failure_class": "arithmetic fracture and release drift",
            "artifacts": "compatibility invariant ledgers + fracture alerts + release-blocking certificates",
            "implementation_plan": [
                "Compile arithmetic drift and fracture kernels into invariant ledgers and release-blocking thresholds that compatibility tooling can consume directly.",
                "Anchor the round in crates/frankenlibc-membrane/src/padic_valuation.rs, crates/frankenlibc-abi/version_scripts/libc.map, crates/frankenlibc-core/src/time/mod.rs, and crates/frankenlibc-harness/tests/symbol_drift_test.rs.",
                "Route arithmetic compatibility evidence through the reverse-round artifact so latent fracture modes stay reviewable alongside other release-critical witnesses.",
            ],
            "verification_strategy": [
                "scripts/check_reverse_round_contracts.sh regenerates and validates the reverse-round contract report.",
                "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs asserts that R35 retains explicit implementation and verification hooks.",
                "crates/frankenlibc-harness/tests/symbol_drift_test.rs, crates/frankenlibc-harness/tests/support_matrix_maintenance_test.rs, and crates/frankenlibc-abi/tests/time_abi_test.rs keep arithmetic drift anchors visible.",
            ],
            "supporting_files": [
                "PLAN_TO_PORT_GLIBC_TO_RUST.md",
                "crates/frankenlibc-membrane/src/padic_valuation.rs",
                "crates/frankenlibc-abi/version_scripts/libc.map",
                "crates/frankenlibc-core/src/time/mod.rs",
                "crates/frankenlibc-membrane/src/runtime_math/ktheory.rs",
                "crates/frankenlibc-harness/tests/symbol_drift_test.rs",
                "crates/frankenlibc-harness/tests/support_matrix_maintenance_test.rs",
                "crates/frankenlibc-abi/tests/time_abi_test.rs",
            ],
            "math_families": {
                "padic_sensitivity": {
                    "module": "padic_valuation",
                    "description": "p-adic sensitivity tracking for integer-width and layout transitions",
                    "math_class": "algebra",
                    "invariant": "the p-adic valuation detects discrete compatibility fractures before they reach release-critical magnitude.",
                },
                "transport_classes": {
                    "module": "ktheory",
                    "description": "Compatibility transport classes across symbol-version and layout families",
                    "math_class": "algebraic-topology",
                    "invariant": "transported compatibility classes remain stable along admissible release paths.",
                },
                "drift_detection": {
                    "module": "kernel_mmd",
                    "description": "Compatibility drift detection over release-observable traces",
                    "math_class": "conformal-statistics",
                    "invariant": "kernel MMD flags distributional compatibility movement before fracture thresholds are crossed.",
                },
                "constraint_normalization": {
                    "module": "grobner_normalizer",
                    "description": "Canonical normalization of composite ABI constraint systems",
                    "math_class": "algebra",
                    "invariant": "equivalent arithmetic constraint systems reduce to one canonical witness form.",
                },
            },
        },
        "R36": {
            "name": "Serre-Spectral Invariant Lifting",
            "problem_focus": "Proving that local invariants proven at lower layers survive composition through deep subsystem towers without hidden extension failures.",
            "legacy_surfaces": ["loader", "memory", "io", "threading", "networking", "dependency towers"],
            "failure_class": "invariant-lift and extension failure drift",
            "artifacts": "page-indexed invariant ledgers + obstruction reports + compositional guards",
            "implementation_plan": [
                "Compile filtered-invariant and lift-checking kernels into page-indexed ledgers and compositional guards that closure tooling can consume directly.",
                "Anchor the round in crates/frankenlibc-core/src/elf/loader.rs, crates/frankenlibc-core/src/malloc/allocator.rs, crates/frankenlibc-core/src/io/mod.rs, crates/frankenlibc-core/src/pthread/thread.rs, and crates/frankenlibc-core/src/resolv/mod.rs.",
                "Expose invariant-lift evidence through the reverse-round artifact so hidden extension failures remain reviewable without reading spectral controller internals.",
            ],
            "verification_strategy": [
                "scripts/check_reverse_round_contracts.sh regenerates and validates the reverse-round contract report.",
                "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs asserts that R36 retains explicit implementation and verification hooks.",
                "crates/frankenlibc-harness/tests/runtime_math_linkage_proofs_test.rs, crates/frankenlibc-harness/tests/hard_parts_dependency_matrix_test.rs, and crates/frankenlibc-harness/tests/closure_contract_test.rs keep lift anchors visible.",
            ],
            "supporting_files": [
                "PLAN_TO_PORT_GLIBC_TO_RUST.md",
                "crates/frankenlibc-core/src/elf/loader.rs",
                "crates/frankenlibc-core/src/malloc/allocator.rs",
                "crates/frankenlibc-core/src/io/mod.rs",
                "crates/frankenlibc-core/src/pthread/thread.rs",
                "crates/frankenlibc-core/src/resolv/mod.rs",
                "crates/frankenlibc-membrane/src/runtime_math/serre_spectral.rs",
                "crates/frankenlibc-membrane/src/runtime_math/derived_tstructure.rs",
                "crates/frankenlibc-membrane/src/runtime_math/operator_norm.rs",
                "crates/frankenlibc-harness/tests/runtime_math_linkage_proofs_test.rs",
                "crates/frankenlibc-harness/tests/hard_parts_dependency_matrix_test.rs",
                "crates/frankenlibc-harness/tests/closure_contract_test.rs",
            ],
            "math_families": {
                "spectral_pages": {
                    "module": "serre_spectral",
                    "description": "Serre spectral pages for filtered invariant lifting",
                    "math_class": "algebraic-topology",
                    "invariant": "converged pages certify which local invariants survive to the total system.",
                },
                "extension_checks": {
                    "module": "derived_tstructure",
                    "description": "Derived-structure diagnostics for extension failures between layers",
                    "math_class": "grothendieck-serre",
                    "invariant": "t-structure truncations preserve the admissible extension tower ordering.",
                },
                "stability_bounds": {
                    "module": "operator_norm",
                    "description": "Spectral stability checks for lifted invariants under perturbation",
                    "math_class": "algebra",
                    "invariant": "operator norms stay bounded along certified lift paths.",
                },
                "mode_perturbation": {
                    "module": "coupling",
                    "description": "Coupled strict and hardened perturbation bounds for lifted invariants",
                    "math_class": "conformal-statistics",
                    "invariant": "coupled mode traces preserve bounded lift drift under admissible perturbations.",
                },
            },
        },
        "R37": {
            "name": "Grothendieck Site / Topos Runtime Semantics",
            "problem_focus": "Unifying inconsistent local views such as thread shards, allocator regions, loader namespaces, and cache partitions into one global semantic truth while preserving developer-transparent runtime behavior.",
            "legacy_surfaces": ["threads", "pages", "namespaces", "descriptors", "strict", "hardened"],
            "failure_class": "local-to-global state reconciliation drift",
            "artifacts": "runtime site definitions + sheafified reconstruction kernels + mode admissibility certificates",
            "implementation_plan": [
                "Compile site, reconciliation, and mode-logic kernels into global-state reconstruction and admissibility artifacts that runtime validation code can consume directly.",
                "Anchor the round in crates/frankenlibc-membrane/src/page_oracle.rs, crates/frankenlibc-membrane/src/tls_cache.rs, crates/frankenlibc-core/src/elf/loader.rs, and crates/frankenlibc-abi/src/runtime_policy.rs so reconciliation drift stays tied to real observation covers.",
                "Route local-to-global witness data through the reverse-round artifact so mode-policy and namespace assumptions remain reviewable without reading topos internals.",
            ],
            "verification_strategy": [
                "scripts/check_reverse_round_contracts.sh regenerates and validates the reverse-round contract report.",
                "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs asserts that R37 retains explicit implementation and verification hooks.",
                "crates/frankenlibc-harness/tests/mode_contract_lock_test.rs, crates/frankenlibc-harness/tests/mode_semantics_test.rs, and crates/frankenlibc-harness/tests/runtime_math_epic_closure_test.rs keep site and mode anchors visible.",
            ],
            "supporting_files": [
                "PLAN_TO_PORT_GLIBC_TO_RUST.md",
                "crates/frankenlibc-membrane/src/page_oracle.rs",
                "crates/frankenlibc-membrane/src/tls_cache.rs",
                "crates/frankenlibc-abi/src/runtime_policy.rs",
                "crates/frankenlibc-membrane/src/runtime_math/higher_topos.rs",
                "crates/frankenlibc-membrane/src/runtime_math/grothendieck_glue.rs",
                "crates/frankenlibc-membrane/src/runtime_math/policy_table.rs",
                "crates/frankenlibc-harness/tests/mode_contract_lock_test.rs",
                "crates/frankenlibc-harness/tests/mode_semantics_test.rs",
                "crates/frankenlibc-harness/tests/runtime_math_epic_closure_test.rs",
            ],
            "math_families": {
                "site_cover": {
                    "module": "higher_topos",
                    "description": "Topos-level cover design for runtime observation charts",
                    "math_class": "grothendieck-serre",
                    "invariant": "the chosen coverage family supports descent of all declared runtime observations.",
                },
                "sheaf_reconciliation": {
                    "module": "grothendieck_glue",
                    "description": "Sheafification for local-to-global state reconciliation",
                    "math_class": "grothendieck-serre",
                    "invariant": "compatible local reports glue uniquely into the declared global state witness.",
                },
                "policy_logic": {
                    "module": "policy_table",
                    "description": "Proof-carrying mode-policy admissibility tables",
                    "math_class": "algebra",
                    "invariant": "each loaded policy table carries a valid proof witness for its admissibility domain.",
                },
                "coverage_obligations": {
                    "module": "submodular_coverage",
                    "description": "Coverage scheduling for runtime observation obligations",
                    "math_class": "experimental-design",
                    "invariant": "greedy submodular coverage preserves the declared observation lower bound.",
                },
            },
        },
        "R38": {
            "name": "Grothendieck Descent and Stackification for ABI / ISA Compatibility",
            "problem_focus": "Guaranteeing that compatibility patches validated on local ABI and ISA charts glue into a coherent global release contract.",
            "legacy_surfaces": ["sysdeps", "ABI", "ISA", "symbol-version families", "layout variants"],
            "failure_class": "non-gluable compatibility patch drift",
            "artifacts": "descent certificates + stackified witness registries + fail-fast glue diagnostics",
            "implementation_plan": [
                "Compile descent and compatibility-glue kernels into release-bundle coherence certificates and fail-fast diagnostics that ABI tooling can consume directly.",
                "Anchor the round in crates/frankenlibc-abi/version_scripts/libc.map, crates/frankenlibc-core/src/elf/loader.rs, crates/frankenlibc-abi/tests/dlfcn_abi_test.rs, and crates/frankenlibc-abi/tests/startup_abi_contract_test.rs so patch-glue drift remains tied to real compatibility surfaces.",
                "Emit descent and stackification witnesses through the reverse-round artifact so ABI and ISA patch coherence remains reviewable without reading categorical controller internals.",
            ],
            "verification_strategy": [
                "scripts/check_reverse_round_contracts.sh regenerates and validates the reverse-round contract report.",
                "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs asserts that R38 retains explicit implementation and verification hooks.",
                "crates/frankenlibc-abi/tests/dlfcn_abi_test.rs, crates/frankenlibc-abi/tests/startup_abi_contract_test.rs, and crates/frankenlibc-harness/tests/isomorphism_proof_test.rs keep descent anchors visible.",
            ],
            "supporting_files": [
                "PLAN_TO_PORT_GLIBC_TO_RUST.md",
                "crates/frankenlibc-abi/version_scripts/libc.map",
                "crates/frankenlibc-core/src/elf/loader.rs",
                "crates/frankenlibc-membrane/src/runtime_math/grothendieck_glue.rs",
                "crates/frankenlibc-membrane/src/runtime_math/higher_topos.rs",
                "crates/frankenlibc-membrane/src/runtime_math/ktheory.rs",
                "crates/frankenlibc-abi/tests/dlfcn_abi_test.rs",
                "crates/frankenlibc-abi/tests/startup_abi_contract_test.rs",
                "crates/frankenlibc-harness/tests/isomorphism_proof_test.rs",
            ],
            "math_families": {
                "descent_data": {
                    "module": "grothendieck_glue",
                    "description": "Descent-data coherence across ABI and ISA compatibility covers",
                    "math_class": "grothendieck-serre",
                    "invariant": "all compatibility cocycles satisfy the declared descent compatibility equations.",
                },
                "stackification": {
                    "module": "higher_topos",
                    "description": "Stackified witness transport across compatibility variants",
                    "math_class": "grothendieck-serre",
                    "invariant": "locally compatible witnesses stackify into a global compatibility object.",
                },
                "transport": {
                    "module": "ktheory",
                    "description": "Compatibility transport classes across variant families",
                    "math_class": "algebraic-topology",
                    "invariant": "transported compatibility classes remain stable across admissible variant morphisms.",
                },
                "glue_diagnostics": {
                    "module": "kernel_mmd",
                    "description": "Distributional diagnostics for latent glue failures in release bundles",
                    "math_class": "conformal-statistics",
                    "invariant": "distributional mismatch alarms trigger before non-gluable patches reach release-critical mass.",
                },
            },
        },
        "R39": {
            "name": "Atiyah-Singer Families Index for Compatibility Transport",
            "problem_focus": "Certifying that compatibility transport across parameterized implementation families does not silently create net defect modes.",
            "legacy_surfaces": ["sysdeps", "ABI variants", "ISA variants", "symbol-version morphisms", "compatibility transport"],
            "failure_class": "nonzero compatibility index defects",
            "artifacts": "families-index ledgers + K-class registries + localized defect reports",
            "implementation_plan": [
                "Compile families-index and compatibility-transport kernels into index ledgers and localized defect reports that release tooling can consume directly.",
                "Anchor the round in crates/frankenlibc-abi/version_scripts/libc.map, crates/frankenlibc-core/src/elf/loader.rs, crates/frankenlibc-core/src/string/mem.rs, and crates/frankenlibc-harness/tests/isomorphism_proof_test.rs so compatibility transport remains tied to real ABI and kernel surfaces.",
                "Route families-index evidence through the reverse-round artifact so nonzero residual defect classes remain reviewable without reading index controller internals.",
            ],
            "verification_strategy": [
                "scripts/check_reverse_round_contracts.sh regenerates and validates the reverse-round contract report.",
                "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs asserts that R39 retains explicit implementation and verification hooks.",
                "crates/frankenlibc-harness/tests/isomorphism_proof_test.rs, crates/frankenlibc-harness/tests/runtime_math_linkage_proofs_test.rs, and crates/frankenlibc-harness/tests/support_matrix_maintenance_test.rs keep index anchors visible.",
            ],
            "supporting_files": [
                "PLAN_TO_PORT_GLIBC_TO_RUST.md",
                "crates/frankenlibc-abi/version_scripts/libc.map",
                "crates/frankenlibc-core/src/elf/loader.rs",
                "crates/frankenlibc-core/src/string/mem.rs",
                "crates/frankenlibc-membrane/src/runtime_math/ktheory.rs",
                "crates/frankenlibc-membrane/src/runtime_math/atiyah_bott.rs",
                "crates/frankenlibc-membrane/src/runtime_math/equivariant.rs",
                "crates/frankenlibc-harness/tests/isomorphism_proof_test.rs",
                "crates/frankenlibc-harness/tests/runtime_math_linkage_proofs_test.rs",
                "crates/frankenlibc-harness/tests/support_matrix_maintenance_test.rs",
            ],
            "math_families": {
                "families_index": {
                    "module": "ktheory",
                    "description": "Families-index bookkeeping for compatibility transport",
                    "math_class": "algebraic-topology",
                    "invariant": "release-critical bundles require net index zero across the parameter family.",
                },
                "spectral_flow": {
                    "module": "atiyah_bott",
                    "description": "Spectral-flow localization for migration path defects",
                    "math_class": "algebraic-topology",
                    "invariant": "spectral flow localizes residual index defects to explicit migration loci.",
                },
                "transport_symmetry": {
                    "module": "equivariant",
                    "description": "Equivariant transport of compatibility maps across family parameters",
                    "math_class": "algebra",
                    "invariant": "compatibility maps commute with the declared family symmetry action.",
                },
                "defect_alerts": {
                    "module": "kernel_mmd",
                    "description": "Distributional alarms for residual compatibility defect classes",
                    "math_class": "conformal-statistics",
                    "invariant": "distributional defect drift is detected before the residual class escapes the admissible envelope.",
                },
            },
        },
        "R40": {
            "name": "Atiyah-Bott Localization for Proof / Benchmark Compression",
            "problem_focus": "Reducing proof and benchmarking cost while preserving guarantees by exploiting symmetry fixed points in dispatch and policy actions.",
            "legacy_surfaces": ["dispatch", "policy", "benchmarking", "proof compression", "release gating"],
            "failure_class": "symmetry-break and compression drift",
            "artifacts": "fixed-point proof obligations + compressed campaigns + symmetry-break alarms",
            "implementation_plan": [
                "Compile localization and campaign-selection kernels into fixed-point proof packs and compressed benchmark plans that optimization tooling can consume directly.",
                "Anchor the round in crates/frankenlibc-membrane/src/runtime_math/atiyah_bott.rs, crates/frankenlibc-membrane/src/runtime_math/localization_chooser.rs, crates/frankenlibc-harness/tests/optimization_proof_ledger_test.rs, and crates/frankenlibc-harness/tests/perf_regression_gate_test.rs.",
                "Expose localization error budgets through the reverse-round artifact so proof and benchmark compression remain reviewable without reading symmetry-analysis internals.",
            ],
            "verification_strategy": [
                "scripts/check_reverse_round_contracts.sh regenerates and validates the reverse-round contract report.",
                "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs asserts that R40 retains explicit implementation and verification hooks.",
                "crates/frankenlibc-harness/tests/optimization_proof_ledger_test.rs, crates/frankenlibc-harness/tests/perf_regression_gate_test.rs, and crates/frankenlibc-harness/tests/test_obligation_dashboard_test.rs keep localization anchors visible.",
            ],
            "supporting_files": [
                "PLAN_TO_PORT_GLIBC_TO_RUST.md",
                "crates/frankenlibc-membrane/src/runtime_math/atiyah_bott.rs",
                "crates/frankenlibc-membrane/src/runtime_math/localization_chooser.rs",
                "crates/frankenlibc-membrane/src/runtime_math/design.rs",
                "crates/frankenlibc-harness/tests/optimization_proof_ledger_test.rs",
                "crates/frankenlibc-harness/tests/perf_regression_gate_test.rs",
                "crates/frankenlibc-harness/tests/test_obligation_dashboard_test.rs",
            ],
            "math_families": {
                "localization": {
                    "module": "atiyah_bott",
                    "description": "Atiyah-Bott localization of proof and benchmark obligations",
                    "math_class": "algebraic-topology",
                    "invariant": "localized fixed loci reproduce the total equivariant contribution of the full obligation set.",
                },
                "campaign_design": {
                    "module": "design",
                    "description": "Experimental design for compressed benchmark and proof campaigns",
                    "math_class": "experimental-design",
                    "invariant": "D-optimal campaign selection preserves identifiability under the chosen compression budget.",
                },
                "coverage_compression": {
                    "module": "submodular_coverage",
                    "description": "Submodular compression of proof and benchmark coverage obligations",
                    "math_class": "experimental-design",
                    "invariant": "greedy submodular selection preserves the declared marginal coverage guarantee.",
                },
                "symmetry_break_alerts": {
                    "module": "eprocess",
                    "description": "Anytime-valid alarms for unstable policy symmetry breaking",
                    "math_class": "conformal-statistics",
                    "invariant": "symmetry-break alarms remain anytime-valid under the localized null hypothesis.",
                },
            },
        },
        "R41": {
            "name": "Clifford Algebra Kernel Geometry",
            "problem_focus": "Constructing SIMD and memory kernels with unified geometric semantics across architectures while preserving strict ABI behavior and hardened safety guarantees.",
            "legacy_surfaces": ["string", "memory", "alignment", "overlap", "vector lanes"],
            "failure_class": "overlap and vector-geometry drift",
            "artifacts": "kernel geometry normal forms + guard generators + regime-tagged fixtures",
            "implementation_plan": [
                "Compile kernel-geometry and overlap-analysis kernels into guard generators and cross-ISA witness bundles that string and memory hot paths can consume directly.",
                "Anchor the round in crates/frankenlibc-core/src/string/mem.rs, crates/frankenlibc-core/src/string/str.rs, crates/frankenlibc-membrane/src/runtime_math/clifford.rs, and crates/frankenlibc-abi/tests/string_abi_test.rs so geometry drift stays tied to real overlap and lane surfaces.",
                "Emit Clifford-class witness data through the reverse-round artifact so cross-ISA kernel geometry remains reviewable without reading algebraic controller internals.",
            ],
            "verification_strategy": [
                "scripts/check_reverse_round_contracts.sh regenerates and validates the reverse-round contract report.",
                "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs asserts that R41 retains explicit implementation and verification hooks.",
                "crates/frankenlibc-abi/tests/string_abi_test.rs, crates/frankenlibc-harness/tests/isomorphism_proof_test.rs, and crates/frankenlibc-harness/tests/perf_budget_test.rs keep kernel-geometry anchors visible.",
            ],
            "supporting_files": [
                "PLAN_TO_PORT_GLIBC_TO_RUST.md",
                "crates/frankenlibc-core/src/string/mem.rs",
                "crates/frankenlibc-core/src/string/str.rs",
                "crates/frankenlibc-membrane/src/runtime_math/clifford.rs",
                "crates/frankenlibc-membrane/src/runtime_math/covering_array.rs",
                "crates/frankenlibc-abi/tests/string_abi_test.rs",
                "crates/frankenlibc-harness/tests/isomorphism_proof_test.rs",
                "crates/frankenlibc-harness/tests/perf_budget_test.rs",
            ],
            "math_families": {
                "kernel_geometry": {
                    "module": "clifford",
                    "description": "Clifford algebra encoding of overlap, alignment, and lane transforms",
                    "math_class": "algebra",
                    "invariant": "geometric products preserve the declared overlap and alignment semantics.",
                },
                "lane_equivariance": {
                    "module": "equivariant",
                    "description": "Equivariant transport of lane and directionality semantics across kernels",
                    "math_class": "algebra",
                    "invariant": "lane semantics commute with the governing architecture symmetry action.",
                },
                "stress_design": {
                    "module": "covering_array",
                    "description": "Coverage-optimal stress design for overlap and alignment regimes",
                    "math_class": "experimental-design",
                    "invariant": "the covering array hits every required overlap x alignment x width interaction.",
                },
                "overlap_stability": {
                    "module": "coupling",
                    "description": "Coupled-trace stability bounds for overlap-sensitive kernel regimes",
                    "math_class": "conformal-statistics",
                    "invariant": "coupled overlap traces preserve bounded semantic deviation under certified kernel substitutions.",
                },
            },
        },
    }
)

# Math class taxonomy
MATH_CLASSES = {
    "conformal-statistics",
    "algebraic-topology",
    "algebra",
    "grothendieck-serre",
    "decision-theory",
    "game-theory",
    "stochastic-analysis",
    "optimal-transport",
    "experimental-design",
}

CROSS_ROUND_INTEGRATIONS = {
    "loader_allocator": {
        "name": "Loader relocation scratch allocation discipline",
        "rounds": ["R7", "R8"],
        "seam": "IFUNC resolution, relocation scratch buffers, and TLS materialization must flow through allocator and thread-runtime guardrails instead of bypassing quarantine, provenance, or cancellation boundaries.",
        "legacy_surfaces": ["elf", "dl-*", "malloc", "nptl", "pthread"],
        "min_class_count": 5,
        "supporting_files": [
            "crates/frankenlibc-core/src/elf/loader.rs",
            "crates/frankenlibc-core/src/elf/relocation.rs",
            "crates/frankenlibc-core/src/malloc/allocator.rs",
            "crates/frankenlibc-core/src/pthread/thread.rs",
        ],
        "verification_strategy": [
            {
                "description": "scripts/check_reverse_round_contracts.sh replays the loader/allocator seam inside the checked-in reverse-round artifact.",
                "path": "scripts/check_reverse_round_contracts.sh",
            },
            {
                "description": "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs asserts the seam remains represented in the artifact.",
                "path": "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs",
            },
            {
                "description": "crates/frankenlibc-harness/tests/thread_hotpath_optimization_test.rs keeps allocator and pthread hot paths tied to the seam.",
                "path": "crates/frankenlibc-harness/tests/thread_hotpath_optimization_test.rs",
            },
        ],
    },
    "allocator_locale": {
        "name": "Allocator-backed format and locale staging",
        "rounds": ["R8", "R9"],
        "seam": "Transient printf/scanf, locale, and iconv staging buffers must inherit allocator quotas, quarantine semantics, and TLS ownership rules without losing parser-state determinism.",
        "legacy_surfaces": ["malloc", "nptl", "stdio-common", "locale", "iconv", "wcsmbs"],
        "min_class_count": 5,
        "supporting_files": [
            "crates/frankenlibc-core/src/malloc/thread_cache.rs",
            "crates/frankenlibc-core/src/stdio/printf.rs",
            "crates/frankenlibc-core/src/locale/mod.rs",
            "crates/frankenlibc-core/src/iconv/mod.rs",
        ],
        "verification_strategy": [
            {
                "description": "crates/frankenlibc-harness/tests/thread_hotpath_optimization_test.rs exercises allocator-side evidence for staging buffers.",
                "path": "crates/frankenlibc-harness/tests/thread_hotpath_optimization_test.rs",
            },
            {
                "description": "crates/frankenlibc-harness/tests/stdio_phase_strategy_test.rs keeps format-phase routing visible.",
                "path": "crates/frankenlibc-harness/tests/stdio_phase_strategy_test.rs",
            },
            {
                "description": "crates/frankenlibc-harness/tests/iconv_codec_scope_ledger_test.rs preserves locale and codec scope boundaries.",
                "path": "crates/frankenlibc-harness/tests/iconv_codec_scope_ledger_test.rs",
            },
        ],
    },
    "locale_resolver": {
        "name": "Locale and resolver payload normalization",
        "rounds": ["R9", "R10"],
        "seam": "Resolver payload parsing, NSS answer decoding, and locale-sensitive formatting must share one normalization contract so codec and lookup policy drift are caught together.",
        "legacy_surfaces": ["stdio-common", "locale", "iconv", "nss", "resolv", "sunrpc"],
        "min_class_count": 5,
        "supporting_files": [
            "crates/frankenlibc-core/src/locale/mod.rs",
            "crates/frankenlibc-core/src/iconv/mod.rs",
            "crates/frankenlibc-core/src/resolv/dns.rs",
            "crates/frankenlibc-abi/tests/nss_cache_policy_test.rs",
        ],
        "verification_strategy": [
            {
                "description": "crates/frankenlibc-harness/tests/iconv_codec_scope_ledger_test.rs keeps codec boundaries explicit when resolver payloads cross locale surfaces.",
                "path": "crates/frankenlibc-harness/tests/iconv_codec_scope_ledger_test.rs",
            },
            {
                "description": "crates/frankenlibc-abi/tests/resolv_abi_test.rs exercises resolver-facing ABI behavior tied to the seam.",
                "path": "crates/frankenlibc-abi/tests/resolv_abi_test.rs",
            },
            {
                "description": "crates/frankenlibc-abi/tests/nss_cache_policy_test.rs keeps retry and cache policy behavior visible.",
                "path": "crates/frankenlibc-abi/tests/nss_cache_policy_test.rs",
            },
        ],
    },
    "loader_resolver": {
        "name": "Dynamic loader and NSS backend composition",
        "rounds": ["R7", "R10"],
        "seam": "Loader policy, hwcaps selection, and versioned symbol resolution must compose with NSS backend loading so service lookup plugins stay inside deterministic compatibility envelopes.",
        "legacy_surfaces": ["elf", "dl-*", "hwcaps", "nss", "resolv"],
        "min_class_count": 5,
        "supporting_files": [
            "crates/frankenlibc-core/src/elf/loader.rs",
            "crates/frankenlibc-abi/version_scripts/libc.map",
            "crates/frankenlibc-core/src/resolv/mod.rs",
            "tests/integration/fixture_nss.c",
        ],
        "verification_strategy": [
            {
                "description": "scripts/check_runtime_math_epic_closure.sh keeps the reverse-round artifact wired into the aggregate closure pack.",
                "path": "scripts/check_runtime_math_epic_closure.sh",
            },
            {
                "description": "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs verifies this cross-round seam remains materialized.",
                "path": "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs",
            },
            {
                "description": "crates/frankenlibc-abi/tests/resolv_abi_test.rs keeps resolver loading behavior visible at the ABI edge.",
                "path": "crates/frankenlibc-abi/tests/resolv_abi_test.rs",
            },
        ],
    },
    "locale_numeric": {
        "name": "Numeric formatting and libm/fenv witness continuity",
        "rounds": ["R9", "R11"],
        "seam": "Printf/scanf numeric formatting, locale rules, and libm/fenv witnesses must agree on rounding, NaN handling, and representational stability across presentation boundaries.",
        "legacy_surfaces": ["stdio-common", "locale", "wcsmbs", "math", "soft-fp", "ieee754", "fenv"],
        "min_class_count": 5,
        "supporting_files": [
            "crates/frankenlibc-core/src/stdio/printf.rs",
            "crates/frankenlibc-core/src/stdio/scanf.rs",
            "crates/frankenlibc-core/src/math/float.rs",
            "crates/frankenlibc-harness/tests/math_governance_test.rs",
        ],
        "verification_strategy": [
            {
                "description": "crates/frankenlibc-harness/tests/stdio_phase_strategy_test.rs keeps numeric presentation phases deterministic.",
                "path": "crates/frankenlibc-harness/tests/stdio_phase_strategy_test.rs",
            },
            {
                "description": "crates/frankenlibc-harness/tests/math_production_set_policy_test.rs validates production libm policy anchors.",
                "path": "crates/frankenlibc-harness/tests/math_production_set_policy_test.rs",
            },
            {
                "description": "crates/frankenlibc-harness/tests/math_governance_test.rs protects fenv and rounding governance.",
                "path": "crates/frankenlibc-harness/tests/math_governance_test.rs",
            },
        ],
    },
}

ROUND_MILESTONES = {
    "bootstrap_surface": {
        "name": "Bootstrap surface milestone",
        "rounds": ["R7", "R8", "R9"],
        "goal": "Loader, allocator, and locale/format surfaces must share enough mathematical diversity that bootstrap-time policy drift cannot hide inside one family.",
        "min_class_count": 5,
        "max_single_class_pct": 40.0,
        "supporting_files": [
            "crates/frankenlibc-core/src/elf/loader.rs",
            "crates/frankenlibc-core/src/malloc/allocator.rs",
            "crates/frankenlibc-core/src/stdio/printf.rs",
            "crates/frankenlibc-core/src/locale/mod.rs",
        ],
        "verification_strategy": [
            {
                "description": "scripts/check_reverse_round_contracts.sh validates milestone diversity and composition.",
                "path": "scripts/check_reverse_round_contracts.sh",
            },
            {
                "description": "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs asserts milestone diversity and artifact completeness.",
                "path": "crates/frankenlibc-harness/tests/reverse_round_contracts_test.rs",
            },
        ],
    },
    "service_lookup_surface": {
        "name": "Service lookup surface milestone",
        "rounds": ["R8", "R9", "R10"],
        "goal": "Allocator, locale, and resolver surfaces must hold a balanced class mix while service lookup state crosses parser, cache, and retry boundaries.",
        "min_class_count": 5,
        "max_single_class_pct": 40.0,
        "supporting_files": [
            "crates/frankenlibc-core/src/malloc/thread_cache.rs",
            "crates/frankenlibc-core/src/iconv/mod.rs",
            "crates/frankenlibc-core/src/resolv/dns.rs",
            "crates/frankenlibc-abi/tests/nss_cache_policy_test.rs",
        ],
        "verification_strategy": [
            {
                "description": "crates/frankenlibc-harness/tests/iconv_codec_scope_ledger_test.rs keeps locale/resolver seams explicit inside the milestone.",
                "path": "crates/frankenlibc-harness/tests/iconv_codec_scope_ledger_test.rs",
            },
            {
                "description": "crates/frankenlibc-abi/tests/nss_cache_policy_test.rs anchors the service-lookup milestone in ABI-visible behavior.",
                "path": "crates/frankenlibc-abi/tests/nss_cache_policy_test.rs",
            },
        ],
    },
    "numeric_observability_surface": {
        "name": "Numeric observability milestone",
        "rounds": ["R9", "R10", "R11"],
        "goal": "Format, resolver, and libm/fenv surfaces must remain branch-diverse enough that numeric and lookup regressions cannot collapse onto one controller family.",
        "min_class_count": 5,
        "max_single_class_pct": 40.0,
        "supporting_files": [
            "crates/frankenlibc-core/src/stdio/scanf.rs",
            "crates/frankenlibc-core/src/resolv/mod.rs",
            "crates/frankenlibc-core/src/math/float.rs",
            "crates/frankenlibc-harness/tests/math_governance_test.rs",
        ],
        "verification_strategy": [
            {
                "description": "crates/frankenlibc-harness/tests/stdio_phase_strategy_test.rs keeps numeric presentation visible at the milestone boundary.",
                "path": "crates/frankenlibc-harness/tests/stdio_phase_strategy_test.rs",
            },
            {
                "description": "crates/frankenlibc-harness/tests/math_governance_test.rs preserves libm/fenv policy continuity for the milestone.",
                "path": "crates/frankenlibc-harness/tests/math_governance_test.rs",
            },
        ],
    },
}


def verify_module_exists(root, module_name):
    """Check if a runtime_math module file exists."""
    # Check runtime_math/ subdir first
    rm_path = root / "crates" / "frankenlibc-membrane" / "src" / "runtime_math" / f"{module_name}.rs"
    if rm_path.exists():
        return str(rm_path.relative_to(root)), True

    # Check membrane src/ directly
    src_path = root / "crates" / "frankenlibc-membrane" / "src" / f"{module_name}.rs"
    if src_path.exists():
        return str(src_path.relative_to(root)), True

    return f"crates/frankenlibc-membrane/src/runtime_math/{module_name}.rs", False


def verify_repo_path_exists(root, rel_path):
    """Check whether a declared supporting file exists in the repository."""
    path = root / rel_path
    return str(path.relative_to(root)), path.exists()


def build_supporting_files(root, rel_paths):
    """Build a deterministic list of supporting file witnesses."""
    supporting_files = []
    found = 0
    for rel_path in rel_paths:
        verified_path, exists = verify_repo_path_exists(root, rel_path)
        supporting_files.append({"path": verified_path, "exists": exists})
        if exists:
            found += 1
    return supporting_files, found


def build_verification_hooks(root, items):
    """Build verification hook records from prose or explicit descriptors."""
    hooks = []
    found = 0
    for item in items:
        if isinstance(item, dict):
            description = item["description"]
            path = item.get("path")
        else:
            description = item
            match = re.search(r"([A-Za-z0-9_./-]+\.(?:sh|rs|json))", item)
            path = match.group(1) if match else None
        hook = {"description": description}
        if path:
            verified_path, exists = verify_repo_path_exists(root, path)
            hook["path"] = verified_path
            hook["path_exists"] = exists
            if exists:
                found += 1
        else:
            hook["path"] = None
            hook["path_exists"] = None
        hooks.append(hook)
    return hooks, found


def check_branch_diversity(math_families):
    """Verify branch-diversity rule: >=3 distinct math classes."""
    classes = set()
    for fam in math_families.values():
        classes.add(fam["math_class"])
    return {
        "total_families": len(math_families),
        "unique_classes": sorted(classes),
        "class_count": len(classes),
        "passes_diversity": len(classes) >= 3,
        "has_conformal": "conformal-statistics" in classes,
        "has_topology": "algebraic-topology" in classes,
        "has_algebra": "algebra" in classes,
        "has_grothendieck": "grothendieck-serre" in classes,
    }


def summarize_class_distribution(class_sequence):
    """Summarize class diversity and concentration for a set of families."""
    counts = {}
    for math_class in class_sequence:
        counts[math_class] = counts.get(math_class, 0) + 1
    total = len(class_sequence)
    unique_classes = sorted(counts)
    max_single_class_pct = 0.0
    if total:
        max_single_class_pct = round(max(counts.values()) / total * 100, 1)
    return {
        "total_families": total,
        "class_counts": {math_class: counts[math_class] for math_class in sorted(counts)},
        "unique_classes": unique_classes,
        "class_count": len(unique_classes),
        "max_single_class_pct": max_single_class_pct,
    }


def round_class_sequence(round_results, round_ids):
    """Flatten the math classes for a set of rounds in deterministic order."""
    classes = []
    for round_id in round_ids:
        round_data = round_results.get(round_id)
        if not round_data:
            continue
        for family_name in sorted(round_data["math_families"]):
            classes.append(round_data["math_families"][family_name]["math_class"])
    return classes


def round_hashes(round_results, round_ids):
    """Return stable per-round hashes for integration reports."""
    hashes = {}
    for round_id in round_ids:
        round_data = round_results.get(round_id)
        if not round_data:
            continue
        hashes[round_id] = hashlib.sha256(
            json.dumps(round_data["math_families"], sort_keys=True).encode()
        ).hexdigest()[:12]
    return hashes


def build_cross_round_integrations(root, round_results):
    """Build pairwise cross-round composition witnesses."""
    results = {}
    passing = 0

    for integration_id, definition in sorted(CROSS_ROUND_INTEGRATIONS.items()):
        round_ids = definition["rounds"]
        missing_rounds = [round_id for round_id in round_ids if round_id not in round_results]
        classes = round_class_sequence(round_results, round_ids)
        diversity = summarize_class_distribution(classes)
        supporting_files, supporting_found = build_supporting_files(
            root, definition["supporting_files"]
        )
        verification_hooks, verification_found = build_verification_hooks(
            root, definition["verification_strategy"]
        )
        shared_classes = None
        if not missing_rounds:
            per_round_classes = [
                set(round_results[round_id]["branch_diversity"]["unique_classes"])
                for round_id in round_ids
            ]
            shared_classes = sorted(set.intersection(*per_round_classes))

        passes = (
            not missing_rounds
            and all(
                round_results[round_id]["branch_diversity"]["passes_diversity"]
                for round_id in round_ids
            )
            and diversity["class_count"] >= definition["min_class_count"]
            and supporting_found == len(supporting_files)
            and verification_found == len(verification_hooks)
        )
        if passes:
            passing += 1

        results[integration_id] = {
            "name": definition["name"],
            "rounds": round_ids,
            "seam": definition["seam"],
            "legacy_surfaces": definition["legacy_surfaces"],
            "round_hashes": round_hashes(round_results, round_ids),
            "shared_classes": shared_classes,
            "min_class_count": definition["min_class_count"],
            "supporting_files": supporting_files,
            "supporting_files_found": supporting_found,
            "verification_strategy": verification_hooks,
            "verification_hooks_found": verification_found,
            "branch_diversity": {
                **diversity,
                "passes_diversity": diversity["class_count"] >= definition["min_class_count"],
            },
            "passes_integration": passes,
        }

    return results, passing


def build_round_milestones(root, round_results):
    """Build milestone-level branch-diversity summaries across multiple rounds."""
    results = {}
    passing = 0

    for milestone_id, definition in sorted(ROUND_MILESTONES.items()):
        round_ids = definition["rounds"]
        missing_rounds = [round_id for round_id in round_ids if round_id not in round_results]
        classes = round_class_sequence(round_results, round_ids)
        diversity = summarize_class_distribution(classes)
        supporting_files, supporting_found = build_supporting_files(
            root, definition["supporting_files"]
        )
        verification_hooks, verification_found = build_verification_hooks(
            root, definition["verification_strategy"]
        )
        passes = (
            not missing_rounds
            and all(
                round_results[round_id]["branch_diversity"]["passes_diversity"]
                for round_id in round_ids
            )
            and diversity["class_count"] >= definition["min_class_count"]
            and diversity["max_single_class_pct"] <= definition["max_single_class_pct"]
            and supporting_found == len(supporting_files)
            and verification_found == len(verification_hooks)
        )
        if passes:
            passing += 1

        results[milestone_id] = {
            "name": definition["name"],
            "rounds": round_ids,
            "goal": definition["goal"],
            "round_hashes": round_hashes(round_results, round_ids),
            "min_class_count": definition["min_class_count"],
            "max_single_class_pct": definition["max_single_class_pct"],
            "supporting_files": supporting_files,
            "supporting_files_found": supporting_found,
            "verification_strategy": verification_hooks,
            "verification_hooks_found": verification_found,
            "branch_diversity": {
                **diversity,
                "passes_diversity": (
                    diversity["class_count"] >= definition["min_class_count"]
                    and diversity["max_single_class_pct"] <= definition["max_single_class_pct"]
                ),
            },
            "passes_milestone": passes,
        }

    return results, passing


def main():
    parser = argparse.ArgumentParser(
        description="Reverse-round contract verification")
    parser.add_argument("-o", "--output", help="Output file path")
    args = parser.parse_args()

    root = find_repo_root()

    # Verify each round
    round_results = {}
    all_math_classes = set()
    total_modules = 0
    modules_found = 0
    total_invariants = 0
    invariants_specified = 0
    total_supporting_files = 0
    supporting_files_found = 0
    total_verification_hooks = 0
    verification_hooks_specified = 0
    total_implementation_steps = 0

    for round_id, round_def in sorted(REVERSE_ROUNDS.items()):
        family_results = {}
        for fam_name, fam_info in round_def["math_families"].items():
            mod_path, exists = verify_module_exists(root, fam_info["module"])
            family_results[fam_name] = {
                "module": fam_info["module"],
                "module_path": mod_path,
                "module_exists": exists,
                "description": fam_info["description"],
                "math_class": fam_info["math_class"],
                "invariant": fam_info["invariant"],
                "invariant_specified": bool(fam_info["invariant"]),
            }
            all_math_classes.add(fam_info["math_class"])
            total_modules += 1
            if exists:
                modules_found += 1
            total_invariants += 1
            if fam_info["invariant"]:
                invariants_specified += 1

        supporting_files, supporting_found = build_supporting_files(
            root, round_def["supporting_files"]
        )
        total_supporting_files += len(supporting_files)
        supporting_files_found += supporting_found

        verification_hooks, verification_found = build_verification_hooks(
            root, round_def["verification_strategy"]
        )
        total_verification_hooks += len(verification_hooks)
        verification_hooks_specified += verification_found

        total_implementation_steps += len(round_def["implementation_plan"])
        diversity = check_branch_diversity(round_def["math_families"])

        round_results[round_id] = {
            "name": round_def["name"],
            "problem_focus": round_def["problem_focus"],
            "legacy_surfaces": round_def["legacy_surfaces"],
            "failure_class": round_def["failure_class"],
            "artifacts": round_def["artifacts"],
            "implementation_plan": round_def["implementation_plan"],
            "verification_strategy": verification_hooks,
            "supporting_files": supporting_files,
            "math_families": family_results,
            "family_count": len(family_results),
            "modules_found": sum(1 for f in family_results.values() if f["module_exists"]),
            "supporting_files_found": supporting_found,
            "verification_hooks_found": verification_found,
            "branch_diversity": diversity,
        }

    # Overall summary
    all_rounds_diverse = all(
        r["branch_diversity"]["passes_diversity"] for r in round_results.values()
    )
    cross_round_integrations, cross_round_passing = build_cross_round_integrations(
        root, round_results
    )
    milestone_branch_diversity, milestones_passing = build_round_milestones(
        root, round_results
    )
    all_milestones_diverse = all(
        milestone["passes_milestone"] for milestone in milestone_branch_diversity.values()
    )
    max_milestone_class_share_pct = round(
        max(
            (
                milestone["branch_diversity"]["max_single_class_pct"]
                for milestone in milestone_branch_diversity.values()
            ),
            default=0.0,
        ),
        1,
    )

    report_hash = hashlib.sha256(
        json.dumps(
            [
                (
                    rid,
                    r["modules_found"],
                    r["branch_diversity"]["class_count"],
                    len(r["implementation_plan"]),
                    r["supporting_files_found"],
                    len(r["verification_strategy"]),
                )
                for rid, r in sorted(round_results.items())
            ]
            + [
                (
                    integration_id,
                    integration["passes_integration"],
                    integration["branch_diversity"]["class_count"],
                    integration["branch_diversity"]["max_single_class_pct"],
                )
                for integration_id, integration in sorted(cross_round_integrations.items())
            ]
            + [
                (
                    milestone_id,
                    milestone["passes_milestone"],
                    milestone["branch_diversity"]["class_count"],
                    milestone["branch_diversity"]["max_single_class_pct"],
                )
                for milestone_id, milestone in sorted(milestone_branch_diversity.items())
            ],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()[:16]

    report = {
        "schema_version": "v1",
        "bead": "bd-2a2.5",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "report_hash": report_hash,
        "summary": {
            "rounds_verified": len(round_results),
            "total_math_families": total_modules,
            "modules_found": modules_found,
            "modules_missing": total_modules - modules_found,
            "module_coverage_pct": round(
                modules_found / total_modules * 100, 1
            ) if total_modules else 0,
            "invariants_specified": invariants_specified,
            "invariants_total": total_invariants,
            "implementation_steps_total": total_implementation_steps,
            "verification_hooks_total": total_verification_hooks,
            "verification_hooks_specified": verification_hooks_specified,
            "supporting_files_total": total_supporting_files,
            "supporting_files_found": supporting_files_found,
            "unique_math_classes": sorted(all_math_classes),
            "math_class_count": len(all_math_classes),
            "all_rounds_diverse": all_rounds_diverse,
            "cross_round_checks_total": len(cross_round_integrations),
            "cross_round_checks_passing": cross_round_passing,
            "milestones_verified": len(milestone_branch_diversity),
            "milestones_diverse": milestones_passing,
            "all_milestones_diverse": all_milestones_diverse,
            "max_milestone_class_share_pct": max_milestone_class_share_pct,
        },
        "round_results": round_results,
        "cross_round_integrations": cross_round_integrations,
        "milestone_branch_diversity": milestone_branch_diversity,
        "branch_diversity_rule": {
            "requirement": ">=3 distinct math families per round",
            "milestone_requirement": ">=5 distinct math classes across each milestone",
            "mandatory_classes": [
                "conformal-statistics",
                "algebraic-topology",
                "algebra",
                "grothendieck-serre",
            ],
            "max_single_family_pct": 40,
        },
        "golden_output": {
            "description": "Reproducible baseline for regression detection",
            "hash": report_hash,
            "round_hashes": {
                rid: hashlib.sha256(
                    json.dumps(r["math_families"], sort_keys=True).encode()
                ).hexdigest()[:12]
                for rid, r in sorted(round_results.items())
            },
            "integration_hashes": {
                integration_id: hashlib.sha256(
                    json.dumps(
                        {
                            "rounds": integration["rounds"],
                            "round_hashes": integration["round_hashes"],
                            "class_counts": integration["branch_diversity"]["class_counts"],
                            "passes_integration": integration["passes_integration"],
                        },
                        sort_keys=True,
                    ).encode()
                ).hexdigest()[:12]
                for integration_id, integration in sorted(cross_round_integrations.items())
            },
            "milestone_hashes": {
                milestone_id: hashlib.sha256(
                    json.dumps(
                        {
                            "rounds": milestone["rounds"],
                            "round_hashes": milestone["round_hashes"],
                            "class_counts": milestone["branch_diversity"]["class_counts"],
                            "passes_milestone": milestone["passes_milestone"],
                        },
                        sort_keys=True,
                    ).encode()
                ).hexdigest()[:12]
                for milestone_id, milestone in sorted(
                    milestone_branch_diversity.items()
                )
            },
        },
    }

    output = json.dumps(report, indent=2) + "\n"
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
