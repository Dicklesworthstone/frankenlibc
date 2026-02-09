//! # Persistent Homology Anomaly Detector
//!
//! Computes 0-dimensional persistent homology of validation cost point clouds
//! to detect **topological anomalies** — structurally novel failure patterns
//! that spectral and statistical methods cannot capture.
//!
//! ## Mathematical Foundation
//!
//! Given a point cloud P ⊂ ℝ⁴ of validation observations, the
//! **Vietoris-Rips filtration** builds a nested family of simplicial complexes:
//!
//! ```text
//! VR(P, ε₁) ⊆ VR(P, ε₂) ⊆ …   for ε₁ ≤ ε₂
//! ```
//!
//! An edge (p, q) exists in VR(P, ε) when d(p, q) ≤ ε.
//!
//! The **0th persistent homology** H₀ tracks connected components:
//! - At ε = 0: every point is its own component (β₀ = n).
//! - As ε grows, components merge via union operations.
//! - Each merge produces a (birth, death) pair in the **persistence diagram**.
//! - The longest-lived component (born at 0, dies at ∞) is the "essential" feature.
//!
//! ## Topological Anomaly Detection
//!
//! The persistence diagram is a stable topological summary: small perturbations
//! in the point cloud cause small changes in the diagram (stability theorem).
//! But when the workload enters a *structurally* new regime:
//!
//! - **Fragmentation**: data splits into clusters → new long-lived persistence pairs.
//! - **Collapse**: data converges → persistence pairs die earlier.
//! - **Topology change**: new holes or voids appear → qualitative diagram shift.
//!
//! These structural changes are invisible to spectral methods (which only see
//! eigenvalue statistics) and to CUSUM/Pareto controllers (which only track
//! scalar summaries). Persistent homology sees the *shape* of the data.
//!
//! ## Connection to Math Item #23
//!
//! Persistent-homology topology-shift diagnostics for anomaly class detection.
//!
//! ## Runtime Budget
//!
//! For n = 24 points in ℝ⁴:
//! - Pairwise distances: n(n-1)/2 = 276 pairs.
//! - Sort edges: O(276 log 276) ≈ 2200 comparisons.
//! - Union-Find merges: 276 operations at O(α(n)) each.
//! - Total: ~3000 operations per recompute. Negligible.

/// Point cloud size for persistence computation.
const PERSIST_CLOUD: usize = 24;

/// Observation dimension.
const PERSIST_DIM: usize = 4;

/// Minimum persistence to count as "significant" (fraction of diameter).
const SIGNIFICANCE_FRACTION: f64 = 0.15;

/// EWMA rate for baseline tracking.
const BASELINE_ALPHA: f64 = 0.05;

/// Number of windows to average before baseline is ready.
const BASELINE_WINDOWS: u64 = 4;

/// Relative change threshold for topological anomaly detection.
const TOPO_ANOMALY_THRESHOLD: f64 = 0.5;

/// A birth-death pair in the 0-dimensional persistence diagram.
#[derive(Debug, Clone, Copy)]
pub struct PersistencePair {
    /// Scale at which this connected component was born (always 0 for H₀).
    pub birth: f64,
    /// Scale at which this component merged into an older one.
    pub death: f64,
}

impl PersistencePair {
    /// Lifetime of this topological feature.
    pub fn persistence(&self) -> f64 {
        self.death - self.birth
    }
}

/// Summary statistics of a persistence diagram.
#[derive(Debug, Clone, Copy)]
pub struct PersistenceSummary {
    /// Number of persistence pairs (= n-1 for n points in H₀).
    pub pair_count: usize,
    /// Total persistence: Σ (death - birth).
    pub total_persistence: f64,
    /// Number of significant persistence pairs (persistence > threshold × diameter).
    pub significant_features: usize,
    /// Persistence entropy: -Σ pᵢ log(pᵢ) where pᵢ = persistenceᵢ / total.
    pub persistence_entropy: f64,
    /// Maximum single persistence value.
    pub max_persistence: f64,
}

/// Topological state of the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologicalState {
    /// Still calibrating baseline topology.
    Calibrating,
    /// Normal topological regime.
    Normal,
    /// Topological anomaly detected — structural change in data shape.
    Anomalous,
}

/// Union-Find (disjoint set) for connected component tracking.
struct UnionFind {
    parent: [usize; PERSIST_CLOUD],
    rank: [u8; PERSIST_CLOUD],
}

impl UnionFind {
    fn new(_n: usize) -> Self {
        let mut parent = [0usize; PERSIST_CLOUD];
        for (i, p) in parent.iter_mut().enumerate() {
            *p = i;
        }
        Self {
            parent,
            rank: [0; PERSIST_CLOUD],
        }
    }

    fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            self.parent[x] = self.parent[self.parent[x]]; // path halving
            x = self.parent[x];
        }
        x
    }

    fn union(&mut self, x: usize, y: usize) -> bool {
        let rx = self.find(x);
        let ry = self.find(y);
        if rx == ry {
            return false;
        }
        if self.rank[rx] < self.rank[ry] {
            self.parent[rx] = ry;
        } else if self.rank[rx] > self.rank[ry] {
            self.parent[ry] = rx;
        } else {
            self.parent[ry] = rx;
            self.rank[rx] += 1;
        }
        true
    }
}

/// Weighted edge for the Vietoris-Rips filtration.
#[derive(Clone, Copy)]
struct Edge {
    dist: f64,
    i: u16,
    j: u16,
}

/// Compute 0-dimensional persistent homology of a point cloud.
///
/// Returns (birth=0, death=merge_distance) pairs for each component merge.
fn compute_persistence_h0(points: &[[f64; PERSIST_DIM]]) -> Vec<PersistencePair> {
    let n = points.len();
    if n < 2 {
        return vec![];
    }

    // Compute all pairwise distances.
    let mut edges = Vec::with_capacity(n * (n - 1) / 2);
    for i in 0..n {
        for j in (i + 1)..n {
            edges.push(Edge {
                dist: euclidean_dist(&points[i], &points[j]),
                i: i as u16,
                j: j as u16,
            });
        }
    }

    // Sort edges by distance (Kruskal-style for minimum spanning forest).
    edges.sort_by(|a, b| {
        a.dist
            .partial_cmp(&b.dist)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Process edges: each successful union kills a connected component.
    let mut uf = UnionFind::new(n);
    let mut pairs = Vec::with_capacity(n - 1);
    for edge in &edges {
        if uf.union(edge.i as usize, edge.j as usize) {
            pairs.push(PersistencePair {
                birth: 0.0,
                death: edge.dist,
            });
        }
    }

    pairs
}

fn euclidean_dist(a: &[f64; PERSIST_DIM], b: &[f64; PERSIST_DIM]) -> f64 {
    let mut sum = 0.0f64;
    for i in 0..PERSIST_DIM {
        let d = a[i] - b[i];
        sum += d * d;
    }
    sum.sqrt()
}

fn summarize(pairs: &[PersistencePair], diameter: f64) -> PersistenceSummary {
    if pairs.is_empty() {
        return PersistenceSummary {
            pair_count: 0,
            total_persistence: 0.0,
            significant_features: 0,
            persistence_entropy: 0.0,
            max_persistence: 0.0,
        };
    }

    let threshold = diameter * SIGNIFICANCE_FRACTION;
    let mut total = 0.0f64;
    let mut max_p = 0.0f64;
    let mut significant = 0usize;

    for pair in pairs {
        let p = pair.persistence();
        total += p;
        max_p = max_p.max(p);
        if p > threshold {
            significant += 1;
        }
    }

    // Persistence entropy: -Σ (pᵢ/total) · ln(pᵢ/total).
    let entropy = if total > 1e-12 {
        let mut h = 0.0f64;
        for pair in pairs {
            let frac = pair.persistence() / total;
            if frac > 1e-15 {
                h -= frac * frac.ln();
            }
        }
        h
    } else {
        0.0
    };

    PersistenceSummary {
        pair_count: pairs.len(),
        total_persistence: total,
        significant_features: significant,
        persistence_entropy: entropy,
        max_persistence: max_p,
    }
}

/// The persistent homology anomaly detector.
pub struct PersistenceDetector {
    /// Circular buffer of observations.
    window: [[f64; PERSIST_DIM]; PERSIST_CLOUD],
    /// Write position.
    write_pos: usize,
    /// Number of observations recorded (capped at PERSIST_CLOUD).
    count: usize,
    /// Baseline persistence entropy.
    baseline_entropy: f64,
    /// Baseline total persistence.
    baseline_total: f64,
    /// Whether baseline is established.
    baseline_ready: bool,
    /// Number of windows used to build baseline.
    baseline_windows: u64,
    /// Current topological state.
    state: TopologicalState,
    /// Total anomalies detected.
    anomaly_count: u64,
    /// Last computed summary.
    last_summary: Option<PersistenceSummary>,
}

impl PersistenceDetector {
    /// Creates a new persistence detector.
    pub fn new() -> Self {
        Self {
            window: [[0.0; PERSIST_DIM]; PERSIST_CLOUD],
            write_pos: 0,
            count: 0,
            baseline_entropy: 0.0,
            baseline_total: 0.0,
            baseline_ready: false,
            baseline_windows: 0,
            state: TopologicalState::Calibrating,
            anomaly_count: 0,
            last_summary: None,
        }
    }

    /// Record a 4D observation vector.
    pub fn observe(&mut self, values: [f64; PERSIST_DIM]) {
        self.window[self.write_pos] = values;
        self.write_pos = (self.write_pos + 1) % PERSIST_CLOUD;
        if self.count < PERSIST_CLOUD {
            self.count += 1;
        }

        // Recompute when the cloud is full and we've wrapped around.
        if self.count >= PERSIST_CLOUD && self.write_pos == 0 {
            self.recompute();
        }
    }

    /// Current topological state.
    pub fn state(&self) -> TopologicalState {
        self.state
    }

    /// Total anomaly detections.
    pub fn anomaly_count(&self) -> u64 {
        self.anomaly_count
    }

    /// Last computed persistence summary.
    pub fn last_summary(&self) -> PersistenceSummary {
        self.last_summary.unwrap_or(PersistenceSummary {
            pair_count: 0,
            total_persistence: 0.0,
            significant_features: 0,
            persistence_entropy: 0.0,
            max_persistence: 0.0,
        })
    }

    fn recompute(&mut self) {
        // Extract point cloud (already in order, no need to sort).
        let points: Vec<[f64; PERSIST_DIM]> = (0..self.count).map(|i| self.window[i]).collect();

        // Compute diameter for normalization.
        let mut diameter = 0.0f64;
        for i in 0..points.len() {
            for j in (i + 1)..points.len() {
                diameter = diameter.max(euclidean_dist(&points[i], &points[j]));
            }
        }

        let pairs = compute_persistence_h0(&points);
        let summary = summarize(&pairs, diameter);
        self.last_summary = Some(summary);

        if !self.baseline_ready {
            let alpha = 1.0 / (self.baseline_windows as f64 + 1.0);
            self.baseline_entropy =
                (1.0 - alpha) * self.baseline_entropy + alpha * summary.persistence_entropy;
            self.baseline_total =
                (1.0 - alpha) * self.baseline_total + alpha * summary.total_persistence;
            self.baseline_windows += 1;
            self.baseline_ready = self.baseline_windows >= BASELINE_WINDOWS;
            self.state = TopologicalState::Calibrating;
            return;
        }

        // Detect topological anomaly: significant change in persistence entropy
        // or total persistence relative to baseline.
        let entropy_change = if self.baseline_entropy > 1e-12 {
            (summary.persistence_entropy - self.baseline_entropy).abs() / self.baseline_entropy
        } else if summary.persistence_entropy > 1e-12 {
            1.0
        } else {
            0.0
        };

        let total_change = if self.baseline_total > 1e-12 {
            (summary.total_persistence - self.baseline_total).abs() / self.baseline_total
        } else if summary.total_persistence > 1e-12 {
            1.0
        } else {
            0.0
        };

        let is_anomalous =
            entropy_change > TOPO_ANOMALY_THRESHOLD || total_change > TOPO_ANOMALY_THRESHOLD;

        if is_anomalous {
            self.state = TopologicalState::Anomalous;
            self.anomaly_count += 1;
        } else {
            self.state = TopologicalState::Normal;
            // Slow baseline adaptation.
            self.baseline_entropy = (1.0 - BASELINE_ALPHA) * self.baseline_entropy
                + BASELINE_ALPHA * summary.persistence_entropy;
            self.baseline_total = (1.0 - BASELINE_ALPHA) * self.baseline_total
                + BASELINE_ALPHA * summary.total_persistence;
        }
    }
}

impl Default for PersistenceDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cloud_has_no_pairs() {
        let pairs = compute_persistence_h0(&[]);
        assert!(pairs.is_empty());
    }

    #[test]
    fn two_points_one_pair() {
        let points = [[0.0, 0.0, 0.0, 0.0], [1.0, 0.0, 0.0, 0.0]];
        let pairs = compute_persistence_h0(&points);
        assert_eq!(pairs.len(), 1);
        assert!(
            (pairs[0].death - 1.0).abs() < 1e-10,
            "death = {}",
            pairs[0].death
        );
    }

    #[test]
    fn n_points_n_minus_1_pairs() {
        // n points always produce exactly n-1 merge events in H₀.
        let mut points = [[0.0f64; PERSIST_DIM]; 10];
        for (i, p) in points.iter_mut().enumerate() {
            p[0] = i as f64;
        }
        let pairs = compute_persistence_h0(&points);
        assert_eq!(pairs.len(), 9);
    }

    #[test]
    fn collinear_points_monotonic_death() {
        // Points equally spaced on a line: deaths should be monotonically increasing.
        let mut points = [[0.0f64; PERSIST_DIM]; 8];
        for (i, p) in points.iter_mut().enumerate() {
            p[0] = i as f64 * 10.0;
        }
        let pairs = compute_persistence_h0(&points);
        for i in 1..pairs.len() {
            assert!(
                pairs[i].death >= pairs[i - 1].death - 1e-10,
                "death[{}]={} < death[{}]={}",
                i,
                pairs[i].death,
                i - 1,
                pairs[i - 1].death
            );
        }
    }

    #[test]
    fn two_clusters_one_significant_gap() {
        // Cluster A: points near (0,0,0,0)
        // Cluster B: points near (100,0,0,0)
        // There should be one very significant persistence pair (the inter-cluster merge).
        let mut points = [[0.0f64; PERSIST_DIM]; 8];
        // Cluster A
        for (i, p) in points[..4].iter_mut().enumerate() {
            p[0] = i as f64 * 0.1;
        }
        // Cluster B
        for (i, p) in points[4..8].iter_mut().enumerate() {
            p[0] = 100.0 + i as f64 * 0.1;
        }
        let pairs = compute_persistence_h0(&points);
        let diameter = 100.3; // approximate
        let summary = summarize(&pairs, diameter);
        // The inter-cluster merge has persistence ≈ 100, which is >> 15% of diameter.
        assert!(
            summary.significant_features >= 1,
            "expected at least 1 significant feature, got {}",
            summary.significant_features
        );
        assert!(
            summary.max_persistence > 90.0,
            "max persistence {} should reflect inter-cluster gap",
            summary.max_persistence
        );
    }

    #[test]
    fn persistence_entropy_nonnegative() {
        let points: Vec<[f64; PERSIST_DIM]> = (0..6)
            .map(|i| {
                let x = i as f64;
                [x, x * 0.5, x * 0.3, x * 0.1]
            })
            .collect();
        let pairs = compute_persistence_h0(&points);
        let diameter = euclidean_dist(&points[0], &points[5]);
        let summary = summarize(&pairs, diameter);
        assert!(
            summary.persistence_entropy >= 0.0,
            "entropy = {}",
            summary.persistence_entropy
        );
    }

    #[test]
    fn union_find_correctness() {
        let mut uf = UnionFind::new(5);
        assert!(uf.union(0, 1));
        assert!(uf.union(2, 3));
        assert!(!uf.union(0, 1)); // already connected
        assert!(uf.union(1, 2)); // connects {0,1} with {2,3}
        assert!(!uf.union(0, 3)); // already connected through 1-2
        assert_eq!(uf.find(0), uf.find(3)); // same component
        assert_ne!(uf.find(0), uf.find(4)); // 4 is still separate
    }

    #[test]
    fn new_detector_is_calibrating() {
        let det = PersistenceDetector::new();
        assert_eq!(det.state(), TopologicalState::Calibrating);
        assert_eq!(det.anomaly_count(), 0);
    }

    #[test]
    fn stable_data_reaches_normal() {
        let mut det = PersistenceDetector::new();
        // Feed several windows of stable data.
        for epoch in 0..8 {
            for i in 0..PERSIST_CLOUD {
                let t = (epoch * PERSIST_CLOUD + i) as f64 * 0.1;
                det.observe([t.sin(), (t * 1.3).cos(), (t * 0.7).sin(), (t * 2.0).cos()]);
            }
        }
        assert_ne!(det.state(), TopologicalState::Calibrating);
    }

    #[test]
    fn detects_topology_change() {
        let mut det = PersistenceDetector::new();
        // Phase 1: smooth, continuous data.
        for epoch in 0..8 {
            for i in 0..PERSIST_CLOUD {
                let t = (epoch * PERSIST_CLOUD + i) as f64 * 0.05;
                det.observe([t.sin(), t.cos(), (t * 0.5).sin(), (t * 0.5).cos()]);
            }
        }
        // Phase 2: bimodal — half the points at (100,0,0,0), half at (-100,0,0,0).
        for epoch in 0..4 {
            for i in 0..PERSIST_CLOUD {
                let v = if i < PERSIST_CLOUD / 2 { 100.0 } else { -100.0 };
                let jitter = (epoch * PERSIST_CLOUD + i) as f64 * 0.001;
                det.observe([v + jitter, jitter, jitter, jitter]);
            }
        }
        assert!(
            det.anomaly_count() > 0 || det.state() == TopologicalState::Anomalous,
            "expected topological anomaly, got {:?} with count {}",
            det.state(),
            det.anomaly_count(),
        );
    }
}
