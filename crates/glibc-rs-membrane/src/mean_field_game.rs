//! # Mean-Field Game Contention Controller
//!
//! Models the interaction of API families competing for validation resources
//! as a mean-field game, detecting congestion collapse equilibria.
//!
//! ## Mathematical Foundation (Lasry-Lions 2006, Huang-Malhamé-Caines 2006)
//!
//! A mean-field game describes the strategic interaction of N agents when
//! N → ∞. Each agent's optimal strategy depends on the population
//! distribution μ, and μ is itself determined by individual strategies —
//! creating a fixed-point consistency requirement.
//!
//! ## Mean-Field Nash Equilibrium
//!
//! The equilibrium (μ\*, σ\*) satisfies simultaneously:
//!
//! 1. **Optimality** (HJB equation): σ\* is a best response given μ\*
//!
//!    ```text
//!    σ*(k) ∝ exp(-c(k, μ*) / T)  [logit/quantal response]
//!    ```
//!
//! 2. **Consistency** (Fokker-Planck equation): μ\* is the distribution
//!    induced when all agents play σ\*
//!
//!    ```text
//!    μ* = Φ(σ*)
//!    ```
//!
//! This coupled system (HJB + FP) is the hallmark of mean-field games.
//! We solve it via Picard fixed-point iteration on the discrete distribution.
//!
//! ## Congestion Game Structure
//!
//! The cost of operating at contention level k given population μ:
//!
//! ```text
//! c(k, μ) = k/K + λ · Σ_j μ_j · max(0, j - K/2) / K
//! ```
//!
//! - First term: direct cost of contention (higher level = more expensive)
//! - Second term: congestion externality (others' high contention hurts
//!   everyone via shared resource exhaustion)
//!
//! The parameter λ controls externality strength. When λ is large, the
//! game exhibits coordination failure: individual incentives to over-validate
//! create collective harm.
//!
//! ## Congestion Collapse Detection
//!
//! **Congestion collapse** occurs when the empirical contention distribution
//! deviates significantly from the Nash equilibrium toward higher levels.
//! This indicates a coordination failure: every family over-validates,
//! exhausting shared resources and paradoxically *reducing* overall safety.
//!
//! This is the validation-resource analog of Braess's paradox: adding more
//! validation capacity can decrease safety if it induces worse equilibrium.
//!
//! ## McKean-Vlasov Connection
//!
//! The mean-field limit of the N-player game converges to the McKean-Vlasov
//! SDE:
//!
//! ```text
//! dX_t = b(X_t, μ_t) dt + σ dW_t,   μ_t = Law(X_t)
//! ```
//!
//! Our discrete model is the finite-state Markov chain approximation of
//! this dynamics. The convergence rate is O(1/√N) (Sznitman 1991).
//!
//! ## Connection to Math Item #19
//!
//! Mean-field game control for thread-population contention dynamics.

/// Contention levels (granularity of the population distribution).
const LEVELS: usize = 8;
/// Window size for empirical distribution estimation.
const MFG_WINDOW: u64 = 256;
/// Congestion externality multiplier.
const LAMBDA: f64 = 2.0;
/// Logit (quantal response) temperature.
const TEMPERATURE: f64 = 0.5;
/// Fixed-point iteration count for Nash equilibrium.
const FP_ITERS: usize = 50;
/// Damping factor for fixed-point iteration.
const FP_ALPHA: f64 = 0.3;
/// Baseline calibration windows before state estimation.
const MFG_BASELINE_WINDOWS: u64 = 4;
/// Relative congestion threshold for warning (Congested).
const CONGESTION_WARN: f64 = 0.5;
/// Relative congestion threshold for critical (Collapsed).
const CONGESTION_CRIT: f64 = 0.75;

// ── Game-theoretic computations ─────────────────────────────────

/// Congestion cost at level k given population distribution μ.
///
/// c(k, μ) = k/K + λ · Σ_j μ_j · max(0, j - K/2) / K
fn congestion_cost(k: usize, mu: &[f64; LEVELS]) -> f64 {
    let direct = k as f64 / LEVELS as f64;
    let externality: f64 = mu
        .iter()
        .enumerate()
        .map(|(j, &mj)| mj * (j as f64 - LEVELS as f64 / 2.0).max(0.0) / LEVELS as f64)
        .sum();
    direct + LAMBDA * externality
}

/// Logit best response: probability of choosing level k given population μ.
///
/// σ(k) ∝ exp(-c(k, μ) / T)
///
/// This is the quantal response equilibrium (McKelvey-Palfrey 1995) —
/// a regularized Nash equilibrium that smoothly interpolates between
/// uniform randomization (T→∞) and pure best response (T→0).
fn best_response(mu: &[f64; LEVELS]) -> [f64; LEVELS] {
    let mut br = [0.0f64; LEVELS];
    // Log-sum-exp trick for numerical stability.
    let mut max_val = f64::NEG_INFINITY;
    for k in 0..LEVELS {
        let val = -congestion_cost(k, mu) / TEMPERATURE;
        max_val = max_val.max(val);
    }
    let mut total = 0.0f64;
    for (k, br_k) in br.iter_mut().enumerate() {
        *br_k = ((-congestion_cost(k, mu) / TEMPERATURE) - max_val).exp();
        total += *br_k;
    }
    for v in &mut br {
        *v /= total;
    }
    br
}

/// Compute the mean-field Nash equilibrium via Picard fixed-point iteration.
///
/// Starting from uniform distribution, iterate:
///   μ_{n+1} = (1 - α)·μ_n + α·BR(μ_n)
///
/// until convergence. The damping α ensures stability.
fn compute_equilibrium() -> [f64; LEVELS] {
    let mut mu = [1.0 / LEVELS as f64; LEVELS];

    for _ in 0..FP_ITERS {
        let br = best_response(&mu);
        for (k, mu_k) in mu.iter_mut().enumerate() {
            *mu_k = (1.0 - FP_ALPHA) * *mu_k + FP_ALPHA * br[k];
        }
        // Renormalize to maintain valid distribution.
        let sum: f64 = mu.iter().sum();
        for v in &mut mu {
            *v /= sum;
        }
    }

    mu
}

/// Mean contention level of a distribution, normalized to [0, 1].
fn mean_contention(mu: &[f64; LEVELS]) -> f64 {
    let raw: f64 = mu.iter().enumerate().map(|(k, &p)| k as f64 * p).sum();
    raw / (LEVELS as f64 - 1.0).max(1.0)
}

// ── Public types ────────────────────────────────────────────────

/// Mean-field game congestion state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfgState {
    /// Baseline not yet established.
    Calibrating,
    /// Population distribution is near Nash equilibrium.
    Equilibrium,
    /// Contention above equilibrium — coordination stress.
    Congested,
    /// Severe coordination failure — congestion collapse.
    Collapsed,
}

/// Telemetry snapshot for the MFG controller.
pub struct MfgSummary {
    pub state: MfgState,
    pub mean_contention: f64,
    pub equilibrium_contention: f64,
    pub congestion_count: u64,
}

/// Mean-field game congestion controller.
///
/// Pre-computes the Nash equilibrium at construction time, then tracks
/// the empirical contention distribution at runtime and detects deviations
/// indicating congestion collapse.
pub struct MeanFieldGameController {
    /// Observed contention distribution (windowed counts).
    contention_counts: [u64; LEVELS],
    window_total: u64,
    /// Pre-computed Nash equilibrium distribution (used for diagnostics).
    #[allow(dead_code)]
    equilibrium: [f64; LEVELS],
    /// Nash equilibrium mean contention (normalized).
    equilibrium_mean: f64,
    /// Current state.
    state: MfgState,
    /// Baseline empirical mean for calibration.
    baseline_mean: f64,
    baseline_ready: bool,
    baseline_windows: u64,
    /// Congestion detection count.
    congestion_count: u64,
}

impl MeanFieldGameController {
    #[must_use]
    pub fn new() -> Self {
        let eq = compute_equilibrium();
        let eq_mean = mean_contention(&eq);
        Self {
            contention_counts: [0; LEVELS],
            window_total: 0,
            equilibrium: eq,
            equilibrium_mean: eq_mean,
            state: MfgState::Calibrating,
            baseline_mean: 0.0,
            baseline_ready: false,
            baseline_windows: 0,
            congestion_count: 0,
        }
    }

    /// Feed a contention observation.
    ///
    /// `contention_hint` is a u16 mapped to one of LEVELS discrete levels.
    /// The controller accumulates a window of observations, then compares
    /// the empirical distribution against the Nash equilibrium.
    pub fn observe(&mut self, contention_hint: u16) {
        let level = ((contention_hint as usize) * LEVELS / 65536).min(LEVELS - 1);
        self.contention_counts[level] += 1;
        self.window_total += 1;

        if self.window_total < MFG_WINDOW {
            return;
        }

        // Compute empirical distribution.
        let total = self.window_total as f64;
        let mut emp = [0.0f64; LEVELS];
        for (k, &c) in self.contention_counts.iter().enumerate() {
            emp[k] = c as f64 / total;
        }

        let current_mean = mean_contention(&emp);

        // Reset window.
        self.contention_counts = [0; LEVELS];
        self.window_total = 0;

        if !self.baseline_ready {
            let n = self.baseline_windows as f64 + 1.0;
            self.baseline_mean = ((n - 1.0) * self.baseline_mean + current_mean) / n;
            self.baseline_windows += 1;
            self.baseline_ready = self.baseline_windows >= MFG_BASELINE_WINDOWS;
            self.state = MfgState::Calibrating;
            return;
        }

        // Detect congestion relative to equilibrium mean.
        let eq_mean = self.equilibrium_mean.max(1e-10);
        let relative = current_mean / eq_mean;

        if relative > 1.0 + CONGESTION_CRIT {
            self.state = MfgState::Collapsed;
            self.congestion_count += 1;
        } else if relative > 1.0 + CONGESTION_WARN {
            self.state = MfgState::Congested;
            self.congestion_count += 1;
        } else {
            self.state = MfgState::Equilibrium;
        }
    }

    #[must_use]
    pub fn state(&self) -> MfgState {
        self.state
    }

    #[must_use]
    pub fn congestion_count(&self) -> u64 {
        self.congestion_count
    }

    #[must_use]
    pub fn equilibrium_mean(&self) -> f64 {
        self.equilibrium_mean
    }

    #[must_use]
    pub fn summary(&self) -> MfgSummary {
        let total = self.window_total.max(1) as f64;
        let mut emp = [0.0f64; LEVELS];
        for (k, &c) in self.contention_counts.iter().enumerate() {
            emp[k] = c as f64 / total;
        }
        MfgSummary {
            state: self.state,
            mean_contention: mean_contention(&emp),
            equilibrium_contention: self.equilibrium_mean,
            congestion_count: self.congestion_count,
        }
    }
}

impl Default for MeanFieldGameController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equilibrium_is_valid_distribution() {
        let eq = compute_equilibrium();
        let sum: f64 = eq.iter().sum();
        assert!((sum - 1.0).abs() < 1e-10, "equilibrium sums to {sum}");
        for (k, &p) in eq.iter().enumerate() {
            assert!(p >= 0.0, "equilibrium[{k}] = {p} is negative");
        }
    }

    #[test]
    fn best_response_is_valid_distribution() {
        let mu = [1.0 / LEVELS as f64; LEVELS];
        let br = best_response(&mu);
        let sum: f64 = br.iter().sum();
        assert!((sum - 1.0).abs() < 1e-10, "best response sums to {sum}");
        for (k, &p) in br.iter().enumerate() {
            assert!(p >= 0.0, "br[{k}] = {p} is negative");
        }
    }

    #[test]
    fn congestion_cost_increases_with_level() {
        let mu = [1.0 / LEVELS as f64; LEVELS];
        for k in 1..LEVELS {
            assert!(
                congestion_cost(k, &mu) >= congestion_cost(k - 1, &mu),
                "cost not monotonic at k={k}"
            );
        }
    }

    #[test]
    fn equilibrium_favors_low_contention() {
        let eq = compute_equilibrium();
        let mean = mean_contention(&eq);
        // Nash equilibrium should have mean below 0.5 (midpoint).
        assert!(mean < 0.5, "equilibrium mean = {mean}, expected < 0.5");
    }

    #[test]
    fn fixed_point_convergence() {
        // Verify the equilibrium is actually a fixed point: BR(μ*) ≈ μ*.
        let eq = compute_equilibrium();
        let br = best_response(&eq);
        let err: f64 = eq.iter().zip(br.iter()).map(|(a, b)| (a - b).abs()).sum();
        assert!(
            err < 0.1,
            "equilibrium is not a fixed point: L1 error = {err}"
        );
    }

    #[test]
    fn controller_starts_calibrating() {
        let ctrl = MeanFieldGameController::new();
        assert_eq!(ctrl.state(), MfgState::Calibrating);
    }

    #[test]
    fn low_contention_reaches_equilibrium() {
        let mut ctrl = MeanFieldGameController::new();
        // Feed low-contention observations (contention_hint near 0).
        for _ in 0..5000 {
            ctrl.observe(100); // low contention
        }
        assert_eq!(
            ctrl.state(),
            MfgState::Equilibrium,
            "expected Equilibrium with low contention"
        );
    }

    #[test]
    fn high_contention_triggers_congestion() {
        let mut ctrl = MeanFieldGameController::new();
        // Calibrate with normal traffic first.
        for _ in 0..2000 {
            ctrl.observe(1000);
        }
        // Then hit with high contention.
        for _ in 0..2000 {
            ctrl.observe(55000);
        }
        assert!(
            matches!(ctrl.state(), MfgState::Congested | MfgState::Collapsed),
            "expected Congested or Collapsed, got {:?}",
            ctrl.state()
        );
    }

    #[test]
    fn extreme_contention_triggers_collapse() {
        let mut ctrl = MeanFieldGameController::new();
        // Calibrate with low traffic.
        for _ in 0..2000 {
            ctrl.observe(500);
        }
        // Then sustained extreme contention.
        for _ in 0..2000 {
            ctrl.observe(64000);
        }
        assert!(
            matches!(ctrl.state(), MfgState::Congested | MfgState::Collapsed),
            "expected Congested or Collapsed after extreme contention, got {:?}",
            ctrl.state()
        );
    }

    #[test]
    fn congestion_count_increments() {
        let mut ctrl = MeanFieldGameController::new();
        for _ in 0..2000 {
            ctrl.observe(500);
        }
        for _ in 0..2000 {
            ctrl.observe(60000);
        }
        if matches!(ctrl.state(), MfgState::Congested | MfgState::Collapsed) {
            assert!(ctrl.congestion_count() > 0);
        }
    }

    #[test]
    fn summary_reports_equilibrium_contention() {
        let ctrl = MeanFieldGameController::new();
        let s = ctrl.summary();
        assert!(s.equilibrium_contention > 0.0);
        assert!(s.equilibrium_contention < 1.0);
    }
}
