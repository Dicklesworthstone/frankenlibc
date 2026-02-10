//! Runtime robust signal fusion controller.
//!
//! Learns a compact trust weighting over advanced runtime monitors and emits a
//! fused risk bonus. This avoids naive additive overcounting while still
//! escalating coherent multi-signal anomalies quickly.

use crate::config::SafetyLevel;

pub const SIGNALS: usize = 46;
const ETA: f64 = 0.14;
const UNIFORM_MIX: f64 = 0.02;
const MAX_BONUS_PPM: u32 = 280_000;

/// Summary for telemetry snapshots.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FusionSummary {
    pub bonus_ppm: u32,
    pub entropy_milli: u32,
    pub drift_ppm: u32,
    pub dominant_signal: u8,
}

/// Online robust fusion state.
pub struct KernelFusionController {
    weights: [f64; SIGNALS],
    bonus_ppm: u32,
    entropy_milli: u32,
    drift_ppm: u32,
    dominant_signal: u8,
}

impl KernelFusionController {
    #[must_use]
    pub fn new() -> Self {
        let w = 1.0 / SIGNALS as f64;
        Self {
            weights: [w; SIGNALS],
            bonus_ppm: 0,
            entropy_milli: 0,
            drift_ppm: 0,
            dominant_signal: 0,
        }
    }

    /// Observe latest per-signal severities and update fused bonus.
    ///
    /// `severity` values are expected in range 0..=4.
    #[must_use]
    pub fn observe(
        &mut self,
        severity: [u8; SIGNALS],
        adverse: bool,
        mode: SafetyLevel,
    ) -> FusionSummary {
        let prev = self.weights;
        let mut normalized = [0.0; SIGNALS];
        for (dst, &src) in normalized.iter_mut().zip(severity.iter()) {
            *dst = f64::from(src.min(4)) / 4.0;
        }

        // Exponentiated-gradient update:
        // - adverse outcome rewards active signals,
        // - non-adverse outcome penalizes active signals.
        for (i, w) in self.weights.iter_mut().enumerate() {
            let s = normalized[i];
            let loss = if adverse {
                // Active signals should be trusted more when failure is observed.
                1.0 - s
            } else {
                // Active signals should be discounted on clean outcomes.
                0.2 + 0.8 * s
            };
            *w *= (-ETA * loss).exp();
        }

        renormalize(&mut self.weights);
        mix_uniform(&mut self.weights, UNIFORM_MIX);

        let score = dot(&self.weights, &normalized);
        let scale = match mode {
            SafetyLevel::Strict => 220_000.0,
            SafetyLevel::Hardened => 320_000.0,
            SafetyLevel::Off => 80_000.0,
        };

        let drift = l1_distance(&prev, &self.weights);
        let mut bonus = (score * scale) as u32;
        if adverse {
            bonus = bonus.saturating_add((drift * 90_000.0) as u32);
        }
        self.bonus_ppm = bonus.min(MAX_BONUS_PPM);
        self.drift_ppm = (drift.clamp(0.0, 1.0) * 1_000_000.0) as u32;
        self.entropy_milli = (entropy(self.weights).clamp(0.0, 1.0) * 1000.0) as u32;
        self.dominant_signal = argmax(&self.weights) as u8;

        self.summary()
    }

    #[must_use]
    pub const fn bonus_ppm(&self) -> u32 {
        self.bonus_ppm
    }

    #[must_use]
    pub fn summary(&self) -> FusionSummary {
        FusionSummary {
            bonus_ppm: self.bonus_ppm,
            entropy_milli: self.entropy_milli,
            drift_ppm: self.drift_ppm,
            dominant_signal: self.dominant_signal,
        }
    }
}

impl Default for KernelFusionController {
    fn default() -> Self {
        Self::new()
    }
}

fn dot(a: &[f64; SIGNALS], b: &[f64; SIGNALS]) -> f64 {
    let mut s = 0.0;
    for i in 0..SIGNALS {
        s += a[i] * b[i];
    }
    s
}

fn renormalize(w: &mut [f64; SIGNALS]) {
    let mut sum = 0.0;
    for &v in w.iter() {
        sum += v.max(0.0);
    }
    if sum <= 1e-12 {
        let u = 1.0 / SIGNALS as f64;
        for v in w.iter_mut() {
            *v = u;
        }
        return;
    }
    for v in w.iter_mut() {
        *v = v.max(0.0) / sum;
    }
}

fn mix_uniform(w: &mut [f64; SIGNALS], rho: f64) {
    let u = 1.0 / SIGNALS as f64;
    for v in w.iter_mut() {
        *v = (1.0 - rho) * *v + rho * u;
    }
    renormalize(w);
}

fn l1_distance(a: &[f64; SIGNALS], b: &[f64; SIGNALS]) -> f64 {
    let mut s = 0.0;
    for i in 0..SIGNALS {
        s += (a[i] - b[i]).abs();
    }
    (s * 0.5).clamp(0.0, 1.0)
}

fn entropy(w: [f64; SIGNALS]) -> f64 {
    let mut h = 0.0;
    for p in w {
        if p > 1e-12 {
            h -= p * p.ln();
        }
    }
    let h_max = (SIGNALS as f64).ln();
    if h_max <= 1e-12 {
        return 0.0;
    }
    (h / h_max).clamp(0.0, 1.0)
}

fn argmax(values: &[f64; SIGNALS]) -> usize {
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
    fn bonus_is_bounded() {
        let mut f = KernelFusionController::new();
        let sev = [4; SIGNALS];
        for _ in 0..128 {
            let s = f.observe(sev, true, SafetyLevel::Hardened);
            assert!(s.bonus_ppm <= MAX_BONUS_PPM);
        }
    }

    #[test]
    fn entropy_in_unit_interval() {
        let mut f = KernelFusionController::new();
        let mut sev = [0; SIGNALS];
        sev[3] = 4;
        for _ in 0..64 {
            let _ = f.observe(sev, true, SafetyLevel::Strict);
        }
        let s = f.summary();
        assert!(s.entropy_milli <= 1000);
    }

    #[test]
    fn concentrated_signal_becomes_dominant() {
        let mut f = KernelFusionController::new();
        let mut sev = [0; SIGNALS];
        sev[7] = 4;
        for _ in 0..200 {
            let _ = f.observe(sev, true, SafetyLevel::Strict);
        }
        assert_eq!(f.summary().dominant_signal, 7);
    }

    #[test]
    fn clean_traffic_reduces_bonus() {
        let mut f = KernelFusionController::new();
        let mut sev = [0; SIGNALS];
        sev[0] = 4;
        for _ in 0..64 {
            let _ = f.observe(sev, true, SafetyLevel::Hardened);
        }
        let high = f.bonus_ppm();
        for _ in 0..128 {
            let _ = f.observe(sev, false, SafetyLevel::Hardened);
        }
        let low = f.bonus_ppm();
        assert!(low < high);
    }
}
