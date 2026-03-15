//! Canonical local identifier wrappers for membrane evidence.

use std::fmt;

/// Fallback schema version for membrane-local evidence payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SchemaVersion {
    major: u16,
    minor: u16,
}

impl SchemaVersion {
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Canonical schema version for membrane-emitted evidence rows.
pub const MEMBRANE_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0);

/// Local fallback wrapper for canonical decision identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct DecisionId(u64);

impl DecisionId {
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn is_assigned(self) -> bool {
        self.0 != 0
    }

    #[must_use]
    pub fn scoped_trace_id(self, scope: &'static str) -> TraceId {
        if self.is_assigned() {
            TraceId::new(format!("{scope}::{:016x}", self.0))
        } else {
            TraceId::empty()
        }
    }
}

impl fmt::Display for DecisionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Local fallback wrapper for canonical policy identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PolicyId(u32);

impl PolicyId {
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn is_assigned(self) -> bool {
        self.0 != 0
    }
}

impl fmt::Display for PolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Local fallback wrapper for canonical trace identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TraceId(String);

impl TraceId {
    #[must_use]
    pub fn new(raw: String) -> Self {
        Self(raw)
    }

    #[must_use]
    pub fn empty() -> Self {
        Self(String::new())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::{DecisionId, MEMBRANE_SCHEMA_VERSION, PolicyId};

    #[test]
    fn scoped_trace_ids_use_canonical_separator_and_hex_width() {
        let trace_id = DecisionId::from_raw(0x2a).scoped_trace_id("membrane::heal");
        assert_eq!(trace_id.as_str(), "membrane::heal::000000000000002a");
    }

    #[test]
    fn zero_decision_id_does_not_emit_trace_id() {
        let trace_id = DecisionId::from_raw(0).scoped_trace_id("membrane::heal");
        assert!(trace_id.is_empty());
    }

    #[test]
    fn policy_id_wrapper_preserves_assignment_status() {
        assert!(!PolicyId::from_raw(0).is_assigned());
        assert!(PolicyId::from_raw(7).is_assigned());
    }

    #[test]
    fn membrane_schema_version_is_stable() {
        assert_eq!(MEMBRANE_SCHEMA_VERSION.major(), 1);
        assert_eq!(MEMBRANE_SCHEMA_VERSION.minor(), 0);
        assert_eq!(MEMBRANE_SCHEMA_VERSION.to_string(), "1.0");
    }
}
