//! Runtime sparse-recovery kernel.
//!
//! Uses online L1-regularized recovery (ISTA) to infer a low-dimensional
//! latent fault vector from probe anomaly observations. The controller
//! distinguishes focused faults (few active causes) from diffuse instability
//! and feeds that classification into membrane policy decisions.

use super::design::Probe;

const LATENT_CAUSES: usize = 6;
const ETA: f64 = 0.18;
const LAMBDA: f64 = 0.045;
const SUPPORT_EPS: f64 = 0.06;
const WARMUP: u64 = 64;

/// Sparse-recovery state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SparseState {
    Calibrating,
    Stable,
    Focused,
    Diffuse,
    Critical,
}

/// Sparse-kernel summary for telemetry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SparseSummary {
    pub state: SparseState,
    pub support_size: u8,
    pub l1_energy: f64,
    pub residual_ewma: f64,
    pub critical_count: u64,
}

/// Online sparse-recovery controller.
pub struct SparseRecoveryController {
    x: [f64; LATENT_CAUSES],
    residual_ewma: f64,
    observations: u64,
    critical_count: u64,
    state: SparseState,
}

impl SparseRecoveryController {
    #[must_use]
    pub fn new() -> Self {
        Self {
            x: [0.0; LATENT_CAUSES],
            residual_ewma: 0.0,
            observations: 0,
            critical_count: 0,
            state: SparseState::Calibrating,
        }
    }

    /// Observe one probe-anomaly vector (masked to executed probes).
    pub fn observe(&mut self, observed_mask: u32, anomalies: [bool; Probe::COUNT], adverse: bool) {
        if observed_mask == 0 {
            return;
        }

        let mut grad = [0.0; LATENT_CAUSES];
        let mut residual_sq = 0.0;
        let mut n_obs = 0u32;

        for i in 0..Probe::COUNT {
            let bit = 1u32 << i;
            if (observed_mask & bit) == 0 {
                continue;
            }
            n_obs += 1;
            let y = if anomalies[i] { 1.0 } else { 0.0 };
            let pred = dot(&A[i], &self.x).clamp(0.0, 1.5);
            let r = pred - y;
            residual_sq += r * r;
            for (j, g) in grad.iter_mut().enumerate() {
                *g += A[i][j] * r;
            }
        }

        if n_obs == 0 {
            return;
        }

        // One ISTA step with nonnegative soft-thresholding.
        for (j, xj) in self.x.iter_mut().enumerate() {
            let z = (*xj - ETA * grad[j]).max(0.0);
            *xj = soft_threshold(z, LAMBDA).min(4.0);
        }

        let residual_rms = (residual_sq / f64::from(n_obs)).sqrt();
        self.residual_ewma = 0.93 * self.residual_ewma + 0.07 * residual_rms;
        self.observations = self.observations.saturating_add(1);

        let support = support_size(&self.x);
        let l1 = l1_energy(&self.x);
        self.state = classify(self.observations, self.residual_ewma, support, l1, adverse);
        if matches!(self.state, SparseState::Critical) {
            self.critical_count = self.critical_count.saturating_add(1);
        }
    }

    #[must_use]
    pub fn state(&self) -> SparseState {
        self.state
    }

    #[must_use]
    pub fn summary(&self) -> SparseSummary {
        SparseSummary {
            state: self.state,
            support_size: support_size(&self.x),
            l1_energy: l1_energy(&self.x),
            residual_ewma: self.residual_ewma,
            critical_count: self.critical_count,
        }
    }
}

impl Default for SparseRecoveryController {
    fn default() -> Self {
        Self::new()
    }
}

fn dot(a: &[f64; LATENT_CAUSES], b: &[f64; LATENT_CAUSES]) -> f64 {
    let mut s = 0.0;
    for i in 0..LATENT_CAUSES {
        s += a[i] * b[i];
    }
    s
}

fn soft_threshold(z: f64, lambda: f64) -> f64 {
    if z > lambda { z - lambda } else { 0.0 }
}

fn support_size(x: &[f64; LATENT_CAUSES]) -> u8 {
    x.iter().filter(|&&v| v > SUPPORT_EPS).count() as u8
}

fn l1_energy(x: &[f64; LATENT_CAUSES]) -> f64 {
    x.iter().sum()
}

fn classify(
    observations: u64,
    residual_ewma: f64,
    support_size: u8,
    l1_energy: f64,
    adverse: bool,
) -> SparseState {
    if observations < WARMUP {
        return SparseState::Calibrating;
    }
    if adverse && residual_ewma > 0.40 && support_size <= 2 && l1_energy > 0.65 {
        return SparseState::Critical;
    }
    if residual_ewma < 0.08 && l1_energy < 0.35 {
        return SparseState::Stable;
    }
    if support_size <= 2 {
        return SparseState::Focused;
    }
    SparseState::Diffuse
}

// Probe-to-latent mixing matrix.
//
// Columns represent latent failure causes:
// c0: temporal/provenance
// c1: tail-latency/congestion
// c2: topological/path-complexity
// c3: transition/regime-shift
// c4: numeric/floating exceptional
// c5: resource-admissibility
const A: [[f64; LATENT_CAUSES]; Probe::COUNT] = [
    [0.30, 0.40, 0.10, 0.35, 0.08, 0.14], // Spectral
    [0.10, 0.20, 0.55, 0.18, 0.04, 0.12], // RoughPath
    [0.08, 0.10, 0.60, 0.16, 0.03, 0.10], // Persistence
    [0.22, 0.45, 0.08, 0.20, 0.06, 0.10], // Anytime
    [0.20, 0.52, 0.06, 0.18, 0.07, 0.12], // Cvar
    [0.12, 0.18, 0.08, 0.64, 0.05, 0.10], // Bridge
    [0.18, 0.44, 0.08, 0.22, 0.05, 0.10], // LargeDeviations
    [0.36, 0.30, 0.06, 0.24, 0.04, 0.22], // Hji
    [0.22, 0.56, 0.06, 0.16, 0.04, 0.16], // MeanField
    [0.06, 0.12, 0.10, 0.14, 0.68, 0.08], // Padic
    [0.24, 0.22, 0.06, 0.14, 0.04, 0.62], // Symplectic
    [0.10, 0.14, 0.52, 0.20, 0.06, 0.08], // HigherTopos
    [0.16, 0.38, 0.10, 0.30, 0.04, 0.14], // CommitmentAudit
    [0.28, 0.36, 0.12, 0.42, 0.06, 0.12], // Changepoint
    [0.18, 0.48, 0.14, 0.22, 0.08, 0.10], // Conformal
    [0.22, 0.34, 0.16, 0.28, 0.10, 0.14], // LossMinimizer
    [0.20, 0.30, 0.12, 0.36, 0.06, 0.18], // Coupling
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let s = SparseRecoveryController::new();
        assert_eq!(s.state(), SparseState::Calibrating);
    }

    #[test]
    fn stable_traffic_reaches_stable_state() {
        let mut s = SparseRecoveryController::new();
        let mask = Probe::all_mask();
        for _ in 0..256 {
            s.observe(mask, [false; Probe::COUNT], false);
        }
        assert_eq!(s.state(), SparseState::Stable);
    }

    #[test]
    fn concentrated_faults_yield_focused_state() {
        let mut s = SparseRecoveryController::new();
        let mask = Probe::all_mask();
        let mut vec = [false; Probe::COUNT];
        vec[Probe::Hji as usize] = true;
        vec[Probe::Symplectic as usize] = true;
        for _ in 0..256 {
            s.observe(mask, vec, false);
        }
        assert!(matches!(
            s.state(),
            SparseState::Focused | SparseState::Critical
        ));
    }

    #[test]
    fn adverse_spike_can_trigger_critical() {
        let mut s = SparseRecoveryController::new();
        let mask = Probe::all_mask();
        for _ in 0..128 {
            s.observe(mask, [false; Probe::COUNT], false);
        }
        let mut vec = [false; Probe::COUNT];
        vec[Probe::Hji as usize] = true;
        vec[Probe::Bridge as usize] = true;
        for _ in 0..128 {
            s.observe(mask, vec, true);
        }
        assert!(matches!(
            s.state(),
            SparseState::Focused | SparseState::Critical
        ));
    }
}
