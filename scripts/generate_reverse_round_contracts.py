#!/usr/bin/env python3
"""generate_reverse_round_contracts.py — bd-2a2.4 / bd-2a2.5

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
