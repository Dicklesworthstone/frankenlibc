//! Delta-debugging minimizer for conformance fixture cases.
//!
//! Given a failing [`FixtureSet`], the minimizer produces the smallest subset
//! of cases (and, within each case, the smallest input) that still reproduces
//! the failure.  This is a classic ddmin implementation adapted for the
//! fixture-based verification pipeline.

use crate::fixtures::{FixtureCase, FixtureSet};

/// Outcome of running a test predicate on a candidate fixture set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The failure reproduces with this subset.
    Fail,
    /// The failure does NOT reproduce.
    Pass,
    /// The test could not be evaluated (e.g. empty input).
    Unresolved,
}

/// A test predicate: given a set of fixture cases, returns whether the failure
/// reproduces.
pub trait TestPredicate {
    fn test(&self, cases: &[FixtureCase]) -> Outcome;
}

/// Function-based predicate wrapper.
pub struct FnPredicate<F: Fn(&[FixtureCase]) -> Outcome>(pub F);

impl<F: Fn(&[FixtureCase]) -> Outcome> TestPredicate for FnPredicate<F> {
    fn test(&self, cases: &[FixtureCase]) -> Outcome {
        (self.0)(cases)
    }
}

/// Result of minimization.
#[derive(Debug, Clone)]
pub struct MinimizeResult {
    /// The minimal set of cases that reproduce the failure.
    pub cases: Vec<FixtureCase>,
    /// Number of predicate evaluations performed.
    pub evaluations: usize,
    /// Original case count.
    pub original_count: usize,
}

/// Classic ddmin: find a 1-minimal subset of `cases` that still triggers `Fail`.
///
/// Algorithm (Zeller & Hildebrandt, 2002):
/// 1. Split cases into `n` partitions (start with n=2).
/// 2. Try each partition alone: if one fails, recurse on it.
/// 3. Try each complement: if one fails, recurse on it.
/// 4. Otherwise double n and repeat (finer partitions).
/// 5. Stop when n >= len (each partition has ≤1 element = 1-minimal).
pub fn ddmin(cases: &[FixtureCase], predicate: &dyn TestPredicate) -> MinimizeResult {
    let original_count = cases.len();
    let mut evals = 0usize;

    if cases.is_empty() {
        return MinimizeResult {
            cases: vec![],
            evaluations: 0,
            original_count: 0,
        };
    }

    // Verify the full set actually fails
    evals += 1;
    if predicate.test(cases) != Outcome::Fail {
        return MinimizeResult {
            cases: cases.to_vec(),
            evaluations: evals,
            original_count,
        };
    }

    let mut current = cases.to_vec();
    let mut n = 2usize;

    loop {
        let len = current.len();
        if n > len {
            break;
        }

        let chunk_size = len.div_ceil(n);
        let num_chunks = n;
        let mut found = false;

        // Try each partition
        for i in 0..num_chunks {
            let start = i * chunk_size;
            let end = (start + chunk_size).min(len);
            if start >= len {
                break;
            }
            let partition: Vec<FixtureCase> = current[start..end].to_vec();
            evals += 1;
            if predicate.test(&partition) == Outcome::Fail {
                current = partition;
                n = 2;
                found = true;
                break;
            }
        }

        if found {
            continue;
        }

        // Try each complement
        for i in 0..num_chunks {
            let start = i * chunk_size;
            let end = (start + chunk_size).min(len);
            if start >= len {
                break;
            }
            let complement: Vec<FixtureCase> = current[..start]
                .iter()
                .chain(current[end..].iter())
                .cloned()
                .collect();
            if complement.is_empty() {
                continue;
            }
            evals += 1;
            if predicate.test(&complement) == Outcome::Fail {
                current = complement;
                n = n.saturating_sub(1).max(2);
                found = true;
                break;
            }
        }

        if !found {
            if n >= len {
                break;
            }
            n = (n * 2).min(len);
        }
    }

    MinimizeResult {
        cases: current,
        evaluations: evals,
        original_count,
    }
}

/// Minimize a full [`FixtureSet`], returning a new set with only the minimal
/// failing cases.
pub fn minimize_fixture_set(
    set: &FixtureSet,
    predicate: &dyn TestPredicate,
) -> (FixtureSet, MinimizeResult) {
    let result = ddmin(&set.cases, predicate);
    let minimized_set = FixtureSet {
        version: set.version.clone(),
        family: set.family.clone(),
        captured_at: set.captured_at.clone(),
        cases: result.cases.clone(),
    };
    (minimized_set, result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_case(name: &str) -> FixtureCase {
        FixtureCase {
            name: name.into(),
            function: "test".into(),
            spec_section: "test".into(),
            inputs: json!({}),
            expected_output: "ok".into(),
            expected_errno: 0,
            mode: "strict".into(),
        }
    }

    #[test]
    fn ddmin_empty_input() {
        let pred = FnPredicate(|_: &[FixtureCase]| Outcome::Fail);
        let result = ddmin(&[], &pred);
        assert!(result.cases.is_empty());
        assert_eq!(result.evaluations, 0);
    }

    #[test]
    fn ddmin_single_failing_case() {
        let cases = vec![make_case("a")];
        let pred = FnPredicate(|c: &[FixtureCase]| {
            if c.iter().any(|x| x.name == "a") {
                Outcome::Fail
            } else {
                Outcome::Pass
            }
        });
        let result = ddmin(&cases, &pred);
        assert_eq!(result.cases.len(), 1);
        assert_eq!(result.cases[0].name, "a");
    }

    #[test]
    fn ddmin_isolates_single_failure_from_many() {
        // Only case "c" causes the failure
        let cases: Vec<_> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(|n| make_case(n))
            .collect();
        let pred = FnPredicate(|c: &[FixtureCase]| {
            if c.iter().any(|x| x.name == "c") {
                Outcome::Fail
            } else {
                Outcome::Pass
            }
        });
        let result = ddmin(&cases, &pred);
        assert_eq!(result.cases.len(), 1);
        assert_eq!(result.cases[0].name, "c");
        assert_eq!(result.original_count, 5);
    }

    #[test]
    fn ddmin_isolates_pair_interaction() {
        // Failure requires both "b" AND "d" present
        let cases: Vec<_> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(|n| make_case(n))
            .collect();
        let pred = FnPredicate(|c: &[FixtureCase]| {
            let has_b = c.iter().any(|x| x.name == "b");
            let has_d = c.iter().any(|x| x.name == "d");
            if has_b && has_d {
                Outcome::Fail
            } else {
                Outcome::Pass
            }
        });
        let result = ddmin(&cases, &pred);
        assert_eq!(result.cases.len(), 2);
        let names: Vec<&str> = result.cases.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"b"));
        assert!(names.contains(&"d"));
    }

    #[test]
    fn ddmin_full_set_passes_returns_original() {
        let cases = vec![make_case("a"), make_case("b")];
        let pred = FnPredicate(|_: &[FixtureCase]| Outcome::Pass);
        let result = ddmin(&cases, &pred);
        // If full set doesn't fail, return it unchanged
        assert_eq!(result.cases.len(), 2);
    }

    #[test]
    fn ddmin_all_cases_needed() {
        // Failure requires all 3 cases
        let cases = vec![make_case("a"), make_case("b"), make_case("c")];
        let pred = FnPredicate(|c: &[FixtureCase]| {
            if c.len() == 3 {
                Outcome::Fail
            } else {
                Outcome::Pass
            }
        });
        let result = ddmin(&cases, &pred);
        assert_eq!(result.cases.len(), 3);
    }

    #[test]
    fn ddmin_tracks_evaluation_count() {
        let cases: Vec<_> = (0..8).map(|i| make_case(&format!("case{}", i))).collect();
        let pred = FnPredicate(|c: &[FixtureCase]| {
            if c.iter().any(|x| x.name == "case5") {
                Outcome::Fail
            } else {
                Outcome::Pass
            }
        });
        let result = ddmin(&cases, &pred);
        assert_eq!(result.cases.len(), 1);
        assert!(result.evaluations > 0);
        // Should be efficient — log(n) evaluations for single-fault isolation
        assert!(result.evaluations < 20);
    }

    #[test]
    fn minimize_fixture_set_preserves_metadata() {
        let set = FixtureSet {
            version: "v1".into(),
            family: "string/ops".into(),
            captured_at: "2026-01-01T00:00:00Z".into(),
            cases: vec![make_case("a"), make_case("b"), make_case("c")],
        };
        let pred = FnPredicate(|c: &[FixtureCase]| {
            if c.iter().any(|x| x.name == "b") {
                Outcome::Fail
            } else {
                Outcome::Pass
            }
        });
        let (minimized, result) = minimize_fixture_set(&set, &pred);
        assert_eq!(minimized.version, "v1");
        assert_eq!(minimized.family, "string/ops");
        assert_eq!(minimized.captured_at, "2026-01-01T00:00:00Z");
        assert_eq!(minimized.cases.len(), 1);
        assert_eq!(minimized.cases[0].name, "b");
        assert_eq!(result.original_count, 3);
    }

    #[test]
    fn ddmin_large_set_single_fault() {
        let cases: Vec<_> = (0..100).map(|i| make_case(&format!("c{}", i))).collect();
        let pred = FnPredicate(|c: &[FixtureCase]| {
            if c.iter().any(|x| x.name == "c73") {
                Outcome::Fail
            } else {
                Outcome::Pass
            }
        });
        let result = ddmin(&cases, &pred);
        assert_eq!(result.cases.len(), 1);
        assert_eq!(result.cases[0].name, "c73");
        // ddmin should be efficient
        assert!(
            result.evaluations < 30,
            "evaluations: {}",
            result.evaluations
        );
    }
}
