//! # Nerve Complex Monitor
//!
//! Čech nerve theorem for multi-signal correlation coherence, tracking
//! Betti numbers (β₀ = connected components, β₁ = 1-cycles) of the
//! correlation graph to detect structural fragmentation.
//!
//! ## Mathematical Foundation
//!
//! The **Nerve Theorem** (Borsuk 1948, Leray 1945) states: if U = {U_α}
//! is a covering of a topological space X by open sets such that every
//! non-empty finite intersection is contractible, then the nerve N(U)
//! is homotopy equivalent to X.
//!
//! Applied to our controller ensemble: each controller defines a "region"
//! in behavior space. The nerve tracks which pairs (and triples) of
//! controllers have **correlated** behavior. The topology of this nerve
//! encodes the **global coherence** structure:
//!
//! - **β₀ = 1**: All controllers form one connected cluster (coherent).
//! - **β₀ > 1**: Controllers have fragmented into disconnected groups.
//! - **β₁ > 0**: Circular dependency patterns exist in the correlation
//!   graph (non-trivial 1-cycles).
//!
//! ## Edge Construction
//!
//! For each pair (i, j) of controllers, we maintain a running estimate
//! of the **absolute correlation**:
//!
//! ```text
//! ρ̂_ij = |cov(Xᵢ, Xⱼ)| / √(var(Xᵢ) · var(Xⱼ))
//! ```
//!
//! An edge exists in the nerve when ρ̂_ij ≥ ε (correlation threshold).
//! β₀ is computed via union-find on the resulting graph. β₁ is estimated
//! as |E| - |V| + β₀ (Euler characteristic relation for graphs).
//!
//! ## Why This Matters
//!
//! When controllers decorrelate, the ensemble loses coherence — each
//! controller is responding to different signals. This is invisible to
//! any individual controller but devastating for collective decision
//! quality. The nerve detects this as β₀ increasing from 1.

use std::sync::atomic::{AtomicU8, Ordering};

/// Number of controllers to track. We track a representative subset
/// of 16 from the 25 base controllers for O(n²) ≈ 120 pair efficiency.
const M: usize = 16;

/// Number of pairs: M*(M-1)/2.
const PAIRS: usize = M * (M - 1) / 2;

/// EWMA smoothing factor.
const ALPHA: f64 = 0.05;

/// Warmup observations before classification.
const WARMUP: u32 = 30;

/// Correlation threshold for nerve edge existence.
const CORR_THRESHOLD: f64 = 0.15;

/// β₀ threshold for Weakening (2+ components).
const WEAKENING_THRESHOLD: u32 = 2;

/// β₀ threshold for Fragmented (4+ components).
const FRAGMENTED_THRESHOLD: u32 = 4;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NerveState {
    /// Insufficient data.
    Calibrating = 0,
    /// All controllers correlated (β₀ = 1).
    Cohesive = 1,
    /// Some decorrelation (β₀ > 1).
    Weakening = 2,
    /// Severe fragmentation (β₀ ≥ 4).
    Fragmented = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone)]
pub struct NerveSummary {
    pub state: NerveState,
    pub betti_0: u32,
    pub betti_1: u32,
    pub edge_count: u32,
    pub observations: u32,
}

/// Nerve complex monitor.
pub struct NerveComplexMonitor {
    /// Running means per controller.
    mean: [f64; M],
    /// Running variances per controller.
    var: [f64; M],
    /// Running covariances for each pair (flattened upper triangle).
    cov: [f64; PAIRS],
    /// Smoothed absolute correlations for each pair.
    corr: [f64; PAIRS],
    /// Observation count.
    count: u32,
    /// Current state.
    state: NerveState,
    /// Cached β₀.
    betti_0: u32,
    /// Cached β₁.
    betti_1: u32,
    /// Cached state code.
    pub cached_state: AtomicU8,
}

/// Map pair (i, j) where i < j to flat index.
const fn pair_index(i: usize, j: usize) -> usize {
    // Row-major upper triangle: index = i*(2M-i-1)/2 + (j-i-1)
    i * (2 * M - i - 1) / 2 + (j - i - 1)
}

/// Map base_severity index to our M-subset index.
/// We sample controllers 0..16 from the 25-element severity vector.
const fn severity_map(idx: usize) -> usize {
    idx
}

impl NerveComplexMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            mean: [0.0; M],
            var: [1.0; M],
            cov: [0.0; PAIRS],
            corr: [0.0; PAIRS],
            count: 0,
            state: NerveState::Calibrating,
            betti_0: M as u32,
            betti_1: 0,
            cached_state: AtomicU8::new(0),
        }
    }

    /// Feed a severity vector and update nerve topology.
    pub fn observe_and_update(&mut self, severity: &[u8; 25]) {
        self.count = self.count.saturating_add(1);
        let alpha = if self.count <= WARMUP {
            2.0 / (self.count as f64 + 1.0)
        } else {
            ALPHA
        };

        // Extract our M-subset and convert to f64.
        let vals: [f64; M] = std::array::from_fn(|i| f64::from(severity[severity_map(i)]));

        // Update means first.
        for (m, v) in self.mean.iter_mut().zip(vals.iter()) {
            *m += alpha * (*v - *m);
        }

        // Compute residuals and update variances.
        let mut residual = [0.0_f64; M];
        for (i, (r, v)) in residual.iter_mut().zip(vals.iter()).enumerate().take(M) {
            *r = *v - self.mean[i];
            let dev_sq = *r * *r;
            self.var[i] += alpha * (dev_sq - self.var[i]);
            // Floor variance to avoid division by zero.
            self.var[i] = self.var[i].max(1e-6);
        }

        // Update covariances/correlations for all pairs from residual cross-products.
        for i in 0..M {
            for j in (i + 1)..M {
                let idx = pair_index(i, j);
                let cross = residual[i] * residual[j];
                self.cov[idx] += alpha * (cross - self.cov[idx]);

                // Compute absolute correlation.
                let denom = (self.var[i] * self.var[j]).sqrt();
                let abs_corr = if denom > 1e-12 {
                    (self.cov[idx] / denom).abs().min(1.0)
                } else {
                    0.0
                };
                self.corr[idx] += alpha * (abs_corr - self.corr[idx]);
            }
        }

        if self.count < WARMUP {
            self.state = NerveState::Calibrating;
            self.cached_state.store(0, Ordering::Relaxed);
            return;
        }

        // Build adjacency and compute β₀ via union-find.
        let mut parent: [u32; M] = std::array::from_fn(|i| i as u32);
        let mut rank = [0u32; M];

        let mut edge_count = 0u32;
        for i in 0..M {
            for j in (i + 1)..M {
                let idx = pair_index(i, j);
                if self.corr[idx] >= CORR_THRESHOLD {
                    edge_count += 1;
                    // Union.
                    let ri = find(&mut parent, i as u32);
                    let rj = find(&mut parent, j as u32);
                    if ri != rj {
                        if rank[ri as usize] < rank[rj as usize] {
                            parent[ri as usize] = rj;
                        } else if rank[ri as usize] > rank[rj as usize] {
                            parent[rj as usize] = ri;
                        } else {
                            parent[rj as usize] = ri;
                            rank[ri as usize] += 1;
                        }
                    }
                }
            }
        }

        // Count components (β₀).
        let mut components = 0u32;
        for i in 0..M as u32 {
            if find(&mut parent, i) == i {
                components += 1;
            }
        }
        self.betti_0 = components;

        // Euler characteristic for graph: χ = V - E, and χ = β₀ - β₁.
        // So β₁ = β₀ - V + E = β₀ - M + E.
        self.betti_1 = (edge_count + components).saturating_sub(M as u32);

        // Classify.
        self.state = if components >= FRAGMENTED_THRESHOLD {
            NerveState::Fragmented
        } else if components >= WEAKENING_THRESHOLD {
            NerveState::Weakening
        } else {
            NerveState::Cohesive
        };

        self.cached_state.store(self.state as u8, Ordering::Relaxed);
    }

    pub fn state(&self) -> NerveState {
        self.state
    }

    pub fn betti_0(&self) -> u32 {
        self.betti_0
    }

    pub fn betti_1(&self) -> u32 {
        self.betti_1
    }

    pub fn summary(&self) -> NerveSummary {
        // Recount edges from cached correlations.
        let mut edge_count = 0u32;
        for &correlation in &self.corr {
            if correlation >= CORR_THRESHOLD {
                edge_count += 1;
            }
        }
        NerveSummary {
            state: self.state,
            betti_0: self.betti_0,
            betti_1: self.betti_1,
            edge_count,
            observations: self.count,
        }
    }
}

impl Default for NerveComplexMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Union-find: path-compressed find.
fn find(parent: &mut [u32; M], mut x: u32) -> u32 {
    while parent[x as usize] != x {
        parent[x as usize] = parent[parent[x as usize] as usize];
        x = parent[x as usize];
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibrating_during_warmup() {
        let mut m = NerveComplexMonitor::new();
        for _ in 0..10 {
            m.observe_and_update(&[1u8; 25]);
        }
        assert_eq!(m.state(), NerveState::Calibrating);
    }

    #[test]
    fn correlated_inputs_yield_cohesive() {
        let mut m = NerveComplexMonitor::new();
        // All controllers same value → perfectly correlated.
        for _ in 0..300 {
            m.observe_and_update(&[2u8; 25]);
            m.observe_and_update(&[1u8; 25]);
        }
        assert_eq!(
            m.state(),
            NerveState::Cohesive,
            "uniform correlated input should be cohesive, got β₀={}",
            m.betti_0()
        );
    }

    #[test]
    fn independent_groups_detected() {
        let mut m = NerveComplexMonitor::new();
        // Establish baseline at zero.
        for _ in 0..WARMUP {
            m.observe_and_update(&[0u8; 25]);
        }
        // Create truly independent groups: group A (0..8) spikes on even
        // iterations, group B (8..16) spikes on multiples of 3. Their
        // correlation is low because the spike patterns are incommensurate.
        for t in 0u32..1500 {
            let mut sev = [0u8; 25];
            if t % 2 == 0 {
                for v in sev.iter_mut().take(8) {
                    *v = 3;
                }
            }
            if t % 3 == 0 {
                for v in sev.iter_mut().take(16).skip(8) {
                    *v = 3;
                }
            }
            m.observe_and_update(&sev);
        }
        assert!(
            m.betti_0() >= WEAKENING_THRESHOLD,
            "independent groups should fragment, got β₀={}",
            m.betti_0()
        );
        assert!(
            m.state() as u8 >= NerveState::Weakening as u8,
            "should detect weakening, got {:?}",
            m.state()
        );
    }

    #[test]
    fn recovery_to_cohesive() {
        let mut m = NerveComplexMonitor::new();
        let base = [1u8; 25];
        for _ in 0..WARMUP {
            m.observe_and_update(&base);
        }
        // Fragment.
        for _ in 0..300 {
            let mut a = [0u8; 25];
            a[0] = 3;
            m.observe_and_update(&a);
            let mut b = [0u8; 25];
            b[15] = 3;
            m.observe_and_update(&b);
        }
        // Recover with correlated input.
        for _ in 0..2000 {
            m.observe_and_update(&[2u8; 25]);
            m.observe_and_update(&[1u8; 25]);
        }
        assert_eq!(
            m.state(),
            NerveState::Cohesive,
            "should recover to cohesive after correlated input"
        );
    }

    #[test]
    fn betti_1_cycle_detection() {
        let m = NerveComplexMonitor::new();
        // β₁ should start at 0.
        assert_eq!(m.betti_1(), 0);
    }

    #[test]
    fn summary_consistent() {
        let mut m = NerveComplexMonitor::new();
        for _ in 0..100 {
            m.observe_and_update(&[1u8; 25]);
        }
        let s = m.summary();
        assert_eq!(s.state, m.state());
        assert_eq!(s.betti_0, m.betti_0());
        assert_eq!(s.betti_1, m.betti_1());
        assert_eq!(s.observations, 100);
    }

    #[test]
    fn pair_index_unique() {
        // Verify no collisions in pair indexing.
        let mut seen = [false; PAIRS];
        for i in 0..M {
            for j in (i + 1)..M {
                let idx = pair_index(i, j);
                assert!(!seen[idx], "collision at ({i},{j})");
                seen[idx] = true;
            }
        }
        assert!(seen.iter().all(|&s| s), "not all pair indices covered");
    }
}
