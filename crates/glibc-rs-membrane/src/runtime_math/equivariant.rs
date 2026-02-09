//! Runtime equivariant transport controller.
//!
//! This kernel applies representation-stability ideas to runtime membrane
//! telemetry. Closely related API families (memory, control, I/O, numeric)
//! should evolve under stable group actions; persistent symmetry breaking
//! indicates semantic drift and raises risk in both strict and hardened modes.

use crate::config::SafetyLevel;

use super::{ApiFamily, ValidationProfile};

const ORBITS: usize = 4;
const FEATURES: usize = 4;
const WARMUP: u64 = 96;

/// Equivariant alignment regime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EquivariantState {
    Calibrating,
    Aligned,
    Drift,
    Fractured,
}

/// Snapshot-friendly summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EquivariantSummary {
    pub state: EquivariantState,
    pub alignment_ppm: u32,
    pub drift_count: u64,
    pub fractured_count: u64,
    pub dominant_orbit: u8,
}

/// Online equivariant transport controller.
///
/// We maintain orbit centroids and evaluate a canonicalized residual. The
/// canonicalization is a tiny representation of a runtime group action:
/// - orbit permutation by family class,
/// - strict/hardened affine mode action,
/// - profile/adverse sign-preserving coordinate action.
pub struct EquivariantTransportController {
    centroids: [[f64; FEATURES]; ORBITS],
    orbit_mass: [f64; ORBITS],
    observations: u64,
    drift_ewma: f64,
    drift_count: u64,
    fractured_count: u64,
    state: EquivariantState,
}

impl EquivariantTransportController {
    #[must_use]
    pub fn new() -> Self {
        Self {
            centroids: [[0.0; FEATURES]; ORBITS],
            orbit_mass: [0.0; ORBITS],
            observations: 0,
            drift_ewma: 0.0,
            drift_count: 0,
            fractured_count: 0,
            state: EquivariantState::Calibrating,
        }
    }

    pub fn observe(
        &mut self,
        family: ApiFamily,
        mode: SafetyLevel,
        profile: ValidationProfile,
        estimated_cost_ns: u64,
        adverse: bool,
        risk_bound_ppm: u32,
    ) {
        let orbit = orbit_of_family(family);
        let raw = feature_vector(mode, profile, estimated_cost_ns, adverse, risk_bound_ppm);
        let canon = canonicalize_by_action(raw, family, mode, profile);

        if self.observations == 0 {
            self.centroids[orbit] = canon;
        }

        let alpha = if self.observations < 512 {
            0.045
        } else {
            0.015
        };
        let old = self.centroids[orbit];
        let residual = l2_distance(&canon, &old);
        blend_into(&mut self.centroids[orbit], canon, alpha);

        self.orbit_mass[orbit] = (0.98 * self.orbit_mass[orbit] + 0.02).clamp(0.0, 1.0);
        for (i, m) in self.orbit_mass.iter_mut().enumerate() {
            if i != orbit {
                *m *= 0.998;
            }
        }

        self.drift_ewma = 0.96 * self.drift_ewma + 0.04 * residual;
        self.observations = self.observations.saturating_add(1);

        self.state = classify(self.observations, self.drift_ewma, adverse, risk_bound_ppm);
        if matches!(
            self.state,
            EquivariantState::Drift | EquivariantState::Fractured
        ) {
            self.drift_count = self.drift_count.saturating_add(1);
        }
        if matches!(self.state, EquivariantState::Fractured) {
            self.fractured_count = self.fractured_count.saturating_add(1);
        }
    }

    #[must_use]
    pub fn state(&self) -> EquivariantState {
        self.state
    }

    #[must_use]
    pub fn summary(&self) -> EquivariantSummary {
        let aligned = (1.0 - self.drift_ewma.clamp(0.0, 1.0)).clamp(0.0, 1.0);
        EquivariantSummary {
            state: self.state,
            alignment_ppm: (aligned * 1_000_000.0) as u32,
            drift_count: self.drift_count,
            fractured_count: self.fractured_count,
            dominant_orbit: argmax(&self.orbit_mass) as u8,
        }
    }
}

impl Default for EquivariantTransportController {
    fn default() -> Self {
        Self::new()
    }
}

fn orbit_of_family(family: ApiFamily) -> usize {
    match family {
        ApiFamily::PointerValidation
        | ApiFamily::Allocator
        | ApiFamily::StringMemory
        | ApiFamily::Stdlib => 0, // memory/value-transform orbit
        ApiFamily::Threading | ApiFamily::Loader => 1, // control/ordering orbit
        ApiFamily::Stdio | ApiFamily::Resolver => 2,   // io/network orbit
        ApiFamily::MathFenv => 3,                      // numeric orbit
    }
}

fn feature_vector(
    mode: SafetyLevel,
    profile: ValidationProfile,
    estimated_cost_ns: u64,
    adverse: bool,
    risk_bound_ppm: u32,
) -> [f64; FEATURES] {
    let risk = f64::from(risk_bound_ppm) / 1_000_000.0;
    let latency = (estimated_cost_ns as f64).ln_1p() / 8.0;
    let adverse_f = if adverse { 1.0 } else { 0.0 };
    let policy = match (mode, profile) {
        (SafetyLevel::Strict, ValidationProfile::Fast) => 0.1,
        (SafetyLevel::Strict, ValidationProfile::Full) => 0.4,
        (SafetyLevel::Hardened, ValidationProfile::Fast) => 0.5,
        (SafetyLevel::Hardened, ValidationProfile::Full) => 0.8,
        (SafetyLevel::Off, _) => 0.0,
    };
    [risk, latency.clamp(0.0, 1.0), adverse_f, policy]
}

fn canonicalize_by_action(
    mut v: [f64; FEATURES],
    family: ApiFamily,
    mode: SafetyLevel,
    profile: ValidationProfile,
) -> [f64; FEATURES] {
    // Small action of C2 (strict/hardened) × C2 (fast/full):
    // normalize policy coordinate and rebalance risk-latency plane.
    if mode.heals_enabled() {
        v[0] = (1.08 * v[0] + 0.04 * v[2]).clamp(0.0, 1.0);
        v[1] = (0.92 * v[1]).clamp(0.0, 1.0);
    } else {
        v[0] = (0.96 * v[0]).clamp(0.0, 1.0);
        v[1] = (1.04 * v[1]).clamp(0.0, 1.0);
    }

    if matches!(profile, ValidationProfile::Full) {
        v.swap(0, 1);
        v[3] = (v[3] + 0.15).clamp(0.0, 1.0);
    }

    // Orbit-specific permutation (representation-induced canonical basis).
    match orbit_of_family(family) {
        0 => {
            // Memory orbit: [risk, latency, adverse, policy]
        }
        1 => {
            // Control orbit: [latency, adverse, risk, policy]
            v = [v[1], v[2], v[0], v[3]];
        }
        2 => {
            // IO orbit: [adverse, risk, latency, policy]
            v = [v[2], v[0], v[1], v[3]];
        }
        3 => {
            // Numeric orbit: [risk, policy, latency, adverse]
            v = [v[0], v[3], v[1], v[2]];
        }
        _ => {}
    }

    v
}

fn classify(
    observations: u64,
    drift_ewma: f64,
    adverse: bool,
    risk_bound_ppm: u32,
) -> EquivariantState {
    if observations < WARMUP {
        return EquivariantState::Calibrating;
    }

    if drift_ewma < 0.085 {
        return EquivariantState::Aligned;
    }

    if drift_ewma < 0.18 {
        return EquivariantState::Drift;
    }

    if adverse || risk_bound_ppm > 700_000 {
        return EquivariantState::Fractured;
    }

    EquivariantState::Drift
}

fn blend_into(dst: &mut [f64; FEATURES], src: [f64; FEATURES], alpha: f64) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = (1.0 - alpha) * *d + alpha * *s;
    }
}

fn l2_distance(a: &[f64; FEATURES], b: &[f64; FEATURES]) -> f64 {
    let mut s = 0.0;
    for (av, bv) in a.iter().zip(b.iter()) {
        let d = av - bv;
        s += d * d;
    }
    s.sqrt().clamp(0.0, 2.0)
}

fn argmax(values: &[f64; ORBITS]) -> usize {
    let mut idx = 0usize;
    let mut best = values[0];
    for (i, &v) in values.iter().enumerate().skip(1) {
        if v > best {
            best = v;
            idx = i;
        }
    }
    idx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let c = EquivariantTransportController::new();
        assert_eq!(c.state(), EquivariantState::Calibrating);
    }

    #[test]
    fn stable_trace_converges_to_aligned() {
        let mut c = EquivariantTransportController::new();
        for _ in 0..256 {
            c.observe(
                ApiFamily::PointerValidation,
                SafetyLevel::Strict,
                ValidationProfile::Fast,
                8,
                false,
                20_000,
            );
        }
        assert_eq!(c.state(), EquivariantState::Aligned);
    }

    #[test]
    fn unstable_trace_reaches_drift_or_fractured() {
        let mut c = EquivariantTransportController::new();
        for i in 0..320 {
            let adverse = i % 3 == 0;
            let family = if i % 2 == 0 {
                ApiFamily::Resolver
            } else {
                ApiFamily::MathFenv
            };
            let mode = if i % 4 == 0 {
                SafetyLevel::Hardened
            } else {
                SafetyLevel::Strict
            };
            let profile = if i % 5 == 0 {
                ValidationProfile::Full
            } else {
                ValidationProfile::Fast
            };
            c.observe(
                family,
                mode,
                profile,
                250 + (i % 97) as u64,
                adverse,
                850_000,
            );
        }
        assert!(matches!(
            c.state(),
            EquivariantState::Drift | EquivariantState::Fractured
        ));
    }

    #[test]
    fn summary_fields_are_bounded() {
        let mut c = EquivariantTransportController::new();
        for _ in 0..180 {
            c.observe(
                ApiFamily::Threading,
                SafetyLevel::Hardened,
                ValidationProfile::Full,
                64,
                true,
                500_000,
            );
        }
        let s = c.summary();
        assert!(s.alignment_ppm <= 1_000_000);
        assert!((s.dominant_orbit as usize) < ORBITS);
    }
}
