//! # Hodge Decomposition Coherence Monitor
//!
//! Detects cyclic inconsistencies in the controller severity ordering
//! via the combinatorial Hodge decomposition (Jiang et al. 2011),
//! separating the pairwise comparison graph into gradient (consistent),
//! harmonic (cyclic), and curl (locally cyclic) components.
//!
//! ## Mathematical Foundation
//!
//! Given N controllers with severity signals, we construct a **pairwise
//! comparison graph** where edge weight w_{ij} = severity_i - severity_j.
//! The Hodge decomposition of this edge flow is:
//!
//! ```text
//! w = d·s + δ·Φ + h
//! ```
//!
//! where:
//! - **d·s** (gradient component): there exists a global ranking s such
//!   that w_{ij} ≈ s_i - s_j. This is the "consistent" part.
//! - **δ·Φ** (curl component): local 3-cycles where A>B>C>A. These
//!   are locally cyclic inconsistencies.
//! - **h** (harmonic component): global cycles that cannot be removed
//!   by either gradient or curl. These are the most structurally deep
//!   inconsistencies.
//!
//! ## Simplified Online Approach
//!
//! Full Hodge decomposition requires solving a large least-squares
//! problem on the comparison graph. For runtime efficiency, we:
//!
//! 1. Track pairwise EWMA differences: d̄_{ij} = EWMA(severity_i - severity_j)
//! 2. Detect **3-cycle inconsistencies**: for each triple (i,j,k),
//!    check if d̄_{ij} + d̄_{jk} + d̄_{ki} ≈ 0 (consistent) or far
//!    from zero (cyclic inconsistency).
//! 3. The **curl energy** is the average squared cycle residual over
//!    sampled triples.
//! 4. The **gradient energy** is the variance of the global ranking
//!    (which we estimate as the row-mean of the comparison matrix).
//! 5. The **inconsistency ratio** = curl_energy / (gradient_energy + curl_energy)
//!    measures how much of the ordering structure is cyclic.
//!
//! ## Why Hodge Instead of Simple Ranking?
//!
//! - A **simple ranking** (sort by average severity) hides cyclic
//!   inconsistencies. Controller A might dominate B, B dominates C,
//!   but C dominates A — a ranking exists but is misleading.
//! - The **Hodge decomposition** explicitly quantifies HOW MUCH of
//!   the comparison structure is cyclically inconsistent, providing
//!   a principled measure of ensemble coherence.
//!
//! ## Legacy Anchor
//!
//! `locale`, `iconv`, `intl` (internationalization/locale subsystem) —
//! locale facets (collation, monetary, numeric) must maintain a
//! consistent ordering. Hodge decomposition detects when the ensemble's
//! implied orderings are cyclically inconsistent, signaling that the
//! facet composition is incoherent.

/// Number of base controllers.
const N: usize = 25;

/// EWMA smoothing for pairwise differences.
const ALPHA: f64 = 0.03;

/// Warmup observations.
const WARMUP: u32 = 40;

/// Inconsistency ratio threshold for Inconsistent.
const INCONSISTENT_THRESHOLD: f64 = 0.15;

/// Inconsistency ratio threshold for Incoherent.
const INCOHERENT_THRESHOLD: f64 = 0.35;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HodgeState {
    /// Insufficient data.
    Calibrating = 0,
    /// Low cycle energy — ordering is approximately consistent.
    Coherent = 1,
    /// Moderate cycle energy — some cyclic inconsistencies.
    Inconsistent = 2,
    /// High cycle energy — ordering is deeply incoherent.
    Incoherent = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct HodgeSummary {
    /// Current state.
    pub state: HodgeState,
    /// Inconsistency ratio: curl_energy / (gradient_energy + curl_energy).
    pub inconsistency_ratio: f64,
    /// Curl energy (average squared cycle residual).
    pub curl_energy: f64,
    /// Total observations.
    pub observations: u32,
}

/// A sampled triple for cycle detection.
struct Triple {
    i: usize,
    j: usize,
    k: usize,
}

/// Hodge decomposition coherence monitor.
pub struct HodgeDecompositionMonitor {
    /// Pairwise EWMA differences: diff[i][j] ≈ E[severity_i - severity_j].
    /// Only upper triangle is maintained (i < j); diff[j][i] = -diff[i][j].
    /// To save memory, we use a flat array for the upper triangle.
    /// Index: i*N - i*(i+1)/2 + (j - i - 1) for i < j.
    pair_diffs: Vec<f64>,
    /// Sampled triples for cycle detection.
    triples: Vec<Triple>,
    /// Smoothed curl energy.
    curl_energy: f64,
    /// Smoothed inconsistency ratio.
    inconsistency_ratio: f64,
    /// Observation count.
    count: u32,
    /// Current state.
    state: HodgeState,
}

impl HodgeDecompositionMonitor {
    /// Upper-triangle index for pair (i, j) where i < j.
    fn pair_index(i: usize, j: usize) -> usize {
        debug_assert!(i < j);
        i * N - i * (i + 1) / 2 + (j - i - 1)
    }

    /// Get the smoothed difference d̄_{ij} (signed: positive if i > j).
    fn get_diff(&self, i: usize, j: usize) -> f64 {
        if i == j {
            return 0.0;
        }
        if i < j {
            self.pair_diffs[Self::pair_index(i, j)]
        } else {
            -self.pair_diffs[Self::pair_index(j, i)]
        }
    }

    #[must_use]
    pub fn new() -> Self {
        let n_pairs = N * (N - 1) / 2;

        // Deterministic triple selection spanning diverse controller regions.
        let triples = vec![
            Triple { i: 0, j: 4, k: 8 },
            Triple { i: 1, j: 5, k: 9 },
            Triple { i: 2, j: 6, k: 10 },
            Triple { i: 3, j: 7, k: 11 },
            Triple { i: 4, j: 12, k: 20 },
            Triple { i: 5, j: 13, k: 21 },
            Triple { i: 6, j: 14, k: 22 },
            Triple { i: 7, j: 15, k: 23 },
            Triple { i: 0, j: 12, k: 24 },
            Triple { i: 1, j: 13, k: 20 },
            Triple { i: 8, j: 16, k: 24 },
            Triple { i: 9, j: 17, k: 22 },
            Triple {
                i: 10,
                j: 18,
                k: 23,
            },
            Triple {
                i: 11,
                j: 19,
                k: 21,
            },
            Triple { i: 0, j: 8, k: 16 },
            Triple { i: 3, j: 11, k: 19 },
        ];

        Self {
            pair_diffs: vec![0.0; n_pairs],
            triples,
            curl_energy: 0.0,
            inconsistency_ratio: 0.0,
            count: 0,
            state: HodgeState::Calibrating,
        }
    }

    /// Feed a severity vector and update Hodge decomposition estimates.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);
        let alpha = if self.count <= WARMUP {
            2.0 / (self.count as f64 + 1.0)
        } else {
            ALPHA
        };

        // Update pairwise differences (upper triangle only).
        for i in 0..N {
            for j in (i + 1)..N {
                let diff = f64::from(severity[i]) - f64::from(severity[j]);
                let idx = Self::pair_index(i, j);
                self.pair_diffs[idx] += alpha * (diff - self.pair_diffs[idx]);
            }
        }

        // Compute cycle residuals for sampled triples.
        // For a consistent ordering, d_{ij} + d_{jk} + d_{ki} = 0.
        // The residual measures how far we are from this.
        let mut curl_sum = 0.0;
        for triple in &self.triples {
            let d_ij = self.get_diff(triple.i, triple.j);
            let d_jk = self.get_diff(triple.j, triple.k);
            let d_ki = self.get_diff(triple.k, triple.i);
            let residual = d_ij + d_jk + d_ki;
            curl_sum += residual * residual;
        }
        self.curl_energy = curl_sum / self.triples.len() as f64;

        // Estimate gradient energy: variance of row-means.
        // Row-mean[i] = (1/N) Σ_j d_{ij} ≈ the global score of controller i.
        let mut row_means = [0.0_f64; N];
        for (i, rm) in row_means.iter_mut().enumerate() {
            let mut sum = 0.0;
            for j in 0..N {
                if i != j {
                    sum += self.get_diff(i, j);
                }
            }
            *rm = sum / (N - 1) as f64;
        }
        let grand_mean: f64 = row_means.iter().sum::<f64>() / N as f64;
        let gradient_energy: f64 = row_means
            .iter()
            .map(|&rm| (rm - grand_mean) * (rm - grand_mean))
            .sum::<f64>()
            / N as f64;

        // Inconsistency ratio.
        let total_energy = gradient_energy + self.curl_energy;
        self.inconsistency_ratio = if total_energy > 1e-12 {
            self.curl_energy / total_energy
        } else {
            0.0
        };

        // State classification.
        self.state = if self.count < WARMUP {
            HodgeState::Calibrating
        } else if self.inconsistency_ratio >= INCOHERENT_THRESHOLD {
            HodgeState::Incoherent
        } else if self.inconsistency_ratio >= INCONSISTENT_THRESHOLD {
            HodgeState::Inconsistent
        } else {
            HodgeState::Coherent
        };
    }

    pub fn state(&self) -> HodgeState {
        self.state
    }

    pub fn inconsistency_ratio(&self) -> f64 {
        self.inconsistency_ratio
    }

    pub fn curl_energy(&self) -> f64 {
        self.curl_energy
    }

    pub fn summary(&self) -> HodgeSummary {
        HodgeSummary {
            state: self.state,
            inconsistency_ratio: self.inconsistency_ratio,
            curl_energy: self.curl_energy,
            observations: self.count,
        }
    }
}

impl Default for HodgeDecompositionMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let m = HodgeDecompositionMonitor::new();
        assert_eq!(m.state(), HodgeState::Calibrating);
    }

    #[test]
    fn constant_inputs_yield_coherent() {
        let mut m = HodgeDecompositionMonitor::new();
        // All controllers at same value → all differences = 0 → no cycles.
        for _ in 0..300 {
            m.observe_and_update(&[1u8; N]);
        }
        assert_eq!(
            m.state(),
            HodgeState::Coherent,
            "Constant inputs should be coherent, ratio={}",
            m.inconsistency_ratio()
        );
    }

    #[test]
    fn consistent_ordering_is_coherent() {
        let mut m = HodgeDecompositionMonitor::new();
        // Controllers have a strict linear ordering: 0 < 1 < 2 < ...
        // This is perfectly consistent (zero curl).
        let mut sev = [0u8; N];
        for (i, s) in sev.iter_mut().enumerate() {
            *s = (i % 4) as u8;
        }
        for _ in 0..500 {
            m.observe_and_update(&sev);
        }
        assert_eq!(
            m.state(),
            HodgeState::Coherent,
            "Consistent ordering should be coherent, ratio={}",
            m.inconsistency_ratio()
        );
    }

    #[test]
    fn curl_energy_is_nonnegative() {
        let mut m = HodgeDecompositionMonitor::new();
        for i in 0u32..200 {
            let val = (i % 4) as u8;
            m.observe_and_update(&[val; N]);
        }
        assert!(
            m.curl_energy() >= 0.0,
            "Curl energy must be non-negative: {}",
            m.curl_energy()
        );
    }

    #[test]
    fn inconsistency_ratio_bounded() {
        let mut m = HodgeDecompositionMonitor::new();
        for i in 0u32..500 {
            let mut sev = [0u8; N];
            for (j, s) in sev.iter_mut().enumerate() {
                *s = (((i as usize + j * 3) ^ (j * 7)) % 4) as u8;
            }
            m.observe_and_update(&sev);
        }
        assert!(
            m.inconsistency_ratio() >= 0.0 && m.inconsistency_ratio() <= 1.0,
            "Ratio should be in [0,1]: {}",
            m.inconsistency_ratio()
        );
    }

    #[test]
    fn recovery_to_coherent() {
        let mut m = HodgeDecompositionMonitor::new();
        // Feed chaotic inputs.
        for i in 0u32..200 {
            let mut sev = [0u8; N];
            for (j, s) in sev.iter_mut().enumerate() {
                *s = (((i as usize).wrapping_mul(7) ^ j.wrapping_mul(13)) % 4) as u8;
            }
            m.observe_and_update(&sev);
        }
        // Now feed consistent inputs for a long time.
        for _ in 0..1000 {
            m.observe_and_update(&[2u8; N]);
        }
        assert_eq!(
            m.state(),
            HodgeState::Coherent,
            "Should recover to Coherent after stabilization, ratio={}",
            m.inconsistency_ratio()
        );
    }

    #[test]
    fn summary_consistent() {
        let mut m = HodgeDecompositionMonitor::new();
        for _ in 0..100 {
            m.observe_and_update(&[1u8; N]);
        }
        let s = m.summary();
        assert_eq!(s.state, m.state());
        assert!((s.curl_energy - m.curl_energy()).abs() < 1e-12);
        assert_eq!(s.observations, 100);
    }
}
