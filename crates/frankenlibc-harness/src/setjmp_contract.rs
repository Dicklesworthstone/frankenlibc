//! Validation helpers for setjmp-family semantics contract artifacts.
//!
//! This module provides deterministic parsing and intrinsic checks for
//! `tests/conformance/setjmp_semantics_contract.v1.json`.

use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Debug, Deserialize)]
pub struct SetjmpSemanticsContract {
    pub schema_version: String,
    pub bead: String,
    pub symbols: SymbolPlan,
    pub abi_semantics_matrix: Vec<SemanticsRow>,
    pub signal_mask_contract: SignalMaskContract,
    pub support_matrix_caveats: SupportMatrixCaveats,
    pub parity_checks: ParityChecks,
    pub summary: ContractSummary,
}

#[derive(Debug, Deserialize)]
pub struct SymbolPlan {
    pub phase1_deferred: Vec<String>,
    pub phase2_target: Vec<String>,
    pub support_matrix_visible_now: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SemanticsRow {
    pub symbol: String,
    pub strict_semantics: String,
    pub hardened_semantics: String,
    pub signal_mask_semantics: String,
    pub support_matrix_status: String,
}

#[derive(Debug, Deserialize)]
pub struct SignalMaskContract {
    pub pairing_rules: Vec<String>,
    pub phase1_enforcement: String,
}

#[derive(Debug, Deserialize)]
pub struct SupportMatrixCaveats {
    pub user_visible_notes: Vec<String>,
    pub waiver_policy_symbols: Vec<String>,
    pub owner_bead: String,
    pub expires_utc: String,
}

#[derive(Debug, Deserialize)]
pub struct ParityChecks {
    pub required_gate: String,
    pub required_test: String,
    pub required_logs: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ContractSummary {
    pub total_symbols: usize,
    pub deferred_symbols: usize,
    pub phase2_target_symbols: usize,
    pub required_signal_mask_rules: usize,
}

pub fn parse_contract_str(json: &str) -> Result<SetjmpSemanticsContract, String> {
    serde_json::from_str(json).map_err(|err| format!("invalid setjmp semantics contract: {err}"))
}

impl SetjmpSemanticsContract {
    /// Validate shape and internal consistency independent of external files.
    pub fn validate_intrinsic(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.schema_version != "v1" {
            errors.push(format!(
                "schema_version must be v1, got {}",
                self.schema_version
            ));
        }
        if self.bead != "bd-2xp3" {
            errors.push(format!("bead must be bd-2xp3, got {}", self.bead));
        }

        let deferred = to_set(
            &self.symbols.phase1_deferred,
            "symbols.phase1_deferred",
            &mut errors,
        );
        let phase2 = to_set(
            &self.symbols.phase2_target,
            "symbols.phase2_target",
            &mut errors,
        );

        for required in [
            "setjmp",
            "longjmp",
            "_setjmp",
            "_longjmp",
            "sigsetjmp",
            "siglongjmp",
        ] {
            if !deferred.contains(required) {
                errors.push(format!("missing required deferred symbol {required}"));
            }
        }

        let matrix_symbols = to_set(
            &self
                .abi_semantics_matrix
                .iter()
                .map(|row| row.symbol.clone())
                .collect::<Vec<_>>(),
            "abi_semantics_matrix.symbol",
            &mut errors,
        );

        if matrix_symbols != deferred {
            let missing = deferred
                .difference(&matrix_symbols)
                .cloned()
                .collect::<Vec<_>>();
            let extra = matrix_symbols
                .difference(&deferred)
                .cloned()
                .collect::<Vec<_>>();
            errors.push(format!(
                "abi_semantics_matrix symbol coverage mismatch missing={missing:?} extra={extra:?}"
            ));
        }

        for row in &self.abi_semantics_matrix {
            if row.strict_semantics.trim().is_empty() {
                errors.push(format!("row {} strict_semantics is empty", row.symbol));
            }
            if row.hardened_semantics.trim().is_empty() {
                errors.push(format!("row {} hardened_semantics is empty", row.symbol));
            }
            if row.signal_mask_semantics.trim().is_empty() {
                errors.push(format!("row {} signal_mask_semantics is empty", row.symbol));
            }
            if row.support_matrix_status != "DeferredNotExported" {
                errors.push(format!(
                    "row {} support_matrix_status must be DeferredNotExported",
                    row.symbol
                ));
            }
        }

        if self.signal_mask_contract.pairing_rules.is_empty() {
            errors.push("signal_mask_contract.pairing_rules must be non-empty".to_string());
        }
        if self
            .signal_mask_contract
            .phase1_enforcement
            .trim()
            .is_empty()
        {
            errors.push("signal_mask_contract.phase1_enforcement must be non-empty".to_string());
        }

        if self.support_matrix_caveats.user_visible_notes.is_empty() {
            errors.push("support_matrix_caveats.user_visible_notes must be non-empty".to_string());
        }
        if self
            .support_matrix_caveats
            .waiver_policy_symbols
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != self.support_matrix_caveats.waiver_policy_symbols.len()
        {
            errors.push("support_matrix_caveats.waiver_policy_symbols has duplicates".to_string());
        }
        if self.support_matrix_caveats.owner_bead.trim().is_empty() {
            errors.push("support_matrix_caveats.owner_bead must be non-empty".to_string());
        }
        if self.support_matrix_caveats.expires_utc.trim().is_empty() {
            errors.push("support_matrix_caveats.expires_utc must be non-empty".to_string());
        }

        if self.parity_checks.required_gate.trim().is_empty() {
            errors.push("parity_checks.required_gate must be non-empty".to_string());
        }
        if self.parity_checks.required_test.trim().is_empty() {
            errors.push("parity_checks.required_test must be non-empty".to_string());
        }
        if self.parity_checks.required_logs.is_empty() {
            errors.push("parity_checks.required_logs must be non-empty".to_string());
        }

        if self.summary.total_symbols != deferred.len() {
            errors.push(format!(
                "summary.total_symbols mismatch: expected {}, got {}",
                deferred.len(),
                self.summary.total_symbols
            ));
        }
        if self.summary.deferred_symbols != deferred.len() {
            errors.push(format!(
                "summary.deferred_symbols mismatch: expected {}, got {}",
                deferred.len(),
                self.summary.deferred_symbols
            ));
        }
        if self.summary.phase2_target_symbols != phase2.len() {
            errors.push(format!(
                "summary.phase2_target_symbols mismatch: expected {}, got {}",
                phase2.len(),
                self.summary.phase2_target_symbols
            ));
        }
        if self.summary.required_signal_mask_rules != self.signal_mask_contract.pairing_rules.len()
        {
            errors.push(format!(
                "summary.required_signal_mask_rules mismatch: expected {}, got {}",
                self.signal_mask_contract.pairing_rules.len(),
                self.summary.required_signal_mask_rules
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate contract alignment against support matrix symbol visibility.
    pub fn validate_support_alignment(
        &self,
        support_symbols: &BTreeSet<String>,
    ) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        for symbol in &self.symbols.phase1_deferred {
            if support_symbols.contains(symbol) {
                errors.push(format!(
                    "deferred symbol {symbol} unexpectedly present in support matrix"
                ));
            }
        }
        for symbol in &self.symbols.support_matrix_visible_now {
            if !support_symbols.contains(symbol) {
                errors.push(format!(
                    "support_matrix_visible_now symbol {symbol} missing from support matrix"
                ));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

fn to_set(values: &[String], field: &str, errors: &mut Vec<String>) -> BTreeSet<String> {
    if values.is_empty() {
        errors.push(format!("{field} must be non-empty"));
    }
    let mut set = BTreeSet::new();
    for value in values {
        if value.trim().is_empty() {
            errors.push(format!("{field} contains empty symbol"));
            continue;
        }
        if !set.insert(value.clone()) {
            errors.push(format!("{field} contains duplicate symbol {value}"));
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::{SetjmpSemanticsContract, parse_contract_str};
    use std::collections::BTreeSet;

    fn sample_contract_json() -> String {
        r#"{
  "schema_version": "v1",
  "bead": "bd-2xp3",
  "symbols": {
    "phase1_deferred": ["setjmp","longjmp","_setjmp","_longjmp","sigsetjmp","siglongjmp"],
    "phase2_target": ["setjmp","longjmp","sigsetjmp","siglongjmp"],
    "support_matrix_visible_now": []
  },
  "abi_semantics_matrix": [
    {"symbol":"setjmp","strict_semantics":"a","hardened_semantics":"b","signal_mask_semantics":"c","support_matrix_status":"DeferredNotExported"},
    {"symbol":"longjmp","strict_semantics":"a","hardened_semantics":"b","signal_mask_semantics":"c","support_matrix_status":"DeferredNotExported"},
    {"symbol":"_setjmp","strict_semantics":"a","hardened_semantics":"b","signal_mask_semantics":"c","support_matrix_status":"DeferredNotExported"},
    {"symbol":"_longjmp","strict_semantics":"a","hardened_semantics":"b","signal_mask_semantics":"c","support_matrix_status":"DeferredNotExported"},
    {"symbol":"sigsetjmp","strict_semantics":"a","hardened_semantics":"b","signal_mask_semantics":"c","support_matrix_status":"DeferredNotExported"},
    {"symbol":"siglongjmp","strict_semantics":"a","hardened_semantics":"b","signal_mask_semantics":"c","support_matrix_status":"DeferredNotExported"}
  ],
  "signal_mask_contract": {
    "pairing_rules": ["r1","r2","r3","r4"],
    "phase1_enforcement": "enforced"
  },
  "support_matrix_caveats": {
    "user_visible_notes": ["note"],
    "waiver_policy_symbols": ["setjmp","longjmp"],
    "owner_bead": "bd-2ry",
    "expires_utc": "2026-06-30T00:00:00Z"
  },
  "parity_checks": {
    "required_gate": "scripts/check_setjmp_semantics_contract.sh",
    "required_test": "cargo test",
    "required_logs": ["a","b"]
  },
  "summary": {
    "total_symbols": 6,
    "deferred_symbols": 6,
    "phase2_target_symbols": 4,
    "required_signal_mask_rules": 4
  }
}"#
            .to_string()
    }

    fn parse_sample() -> SetjmpSemanticsContract {
        parse_contract_str(&sample_contract_json()).expect("sample JSON should parse")
    }

    #[test]
    fn parses_and_validates_minimal_contract() {
        let contract = parse_sample();
        contract
            .validate_intrinsic()
            .expect("intrinsic validation should pass");

        let support_symbols: BTreeSet<String> =
            ["malloc", "free"].into_iter().map(str::to_string).collect();
        contract
            .validate_support_alignment(&support_symbols)
            .expect("support alignment should pass for absent deferred symbols");
    }

    #[test]
    fn duplicate_deferred_symbol_is_rejected() {
        let mut contract = parse_sample();
        contract.symbols.phase1_deferred.push("setjmp".to_string());
        let err = contract
            .validate_intrinsic()
            .expect_err("duplicate deferred symbol should fail validation")
            .join("\n");
        assert!(
            err.contains("symbols.phase1_deferred contains duplicate symbol setjmp"),
            "unexpected error output: {err}"
        );
    }

    #[test]
    fn support_alignment_rejects_exported_deferred_symbol() {
        let contract = parse_sample();
        let support_symbols: BTreeSet<String> = ["malloc", "setjmp"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let err = contract
            .validate_support_alignment(&support_symbols)
            .expect_err("exported deferred symbol should fail support alignment")
            .join("\n");
        assert!(
            err.contains("deferred symbol setjmp unexpectedly present in support matrix"),
            "unexpected error output: {err}"
        );
    }
}
