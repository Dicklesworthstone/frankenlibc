//! Runtime mode configuration.
//!
//! The runtime mode is set via the `GLIBC_RUST_MODE` environment variable:
//! - `strict` (default): ABI-compatible behavior with POSIX-correct errno/return
//!   semantics. The membrane validates but does NOT silently rewrite operations.
//!   Invalid operations produce the same errors a conformant libc would.
//! - `hardened`: TSM repair mode. The membrane validates AND applies deterministic
//!   healing for invalid/unsafe patterns (clamp, truncate, quarantine, safe-default).
//!   This is opt-in behavior that deviates from strict POSIX where safety requires it.
//! - `off`: No validation. Pure passthrough for benchmarking baseline only.

use std::sync::OnceLock;

/// Runtime operating mode for the membrane.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SafetyLevel {
    /// Strict ABI-compatible behavior. POSIX-correct errno/return semantics.
    /// Membrane validates pointers but does not silently rewrite operations.
    /// Invalid operations produce correct error returns, not silent repairs.
    #[default]
    Strict,
    /// Hardened mode. TSM applies deterministic healing for unsafe patterns.
    /// Opt-in behavior that prioritizes safety over strict POSIX conformance
    /// when the two conflict (e.g., clamping a buffer overflow vs segfault).
    Hardened,
    /// No validation. Pure passthrough for benchmarking baseline.
    Off,
}

impl SafetyLevel {
    /// Parse from string (case-insensitive).
    #[must_use]
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "strict" | "default" | "abi" => Self::Strict,
            "hardened" | "repair" | "tsm" | "full" => Self::Hardened,
            "off" | "none" | "disabled" => Self::Off,
            _ => Self::Strict,
        }
    }

    /// Returns true if the membrane should apply healing actions.
    #[must_use]
    pub const fn heals_enabled(self) -> bool {
        matches!(self, Self::Hardened)
    }

    /// Returns true if validation is active.
    #[must_use]
    pub const fn validation_enabled(self) -> bool {
        !matches!(self, Self::Off)
    }
}

static GLOBAL_LEVEL: OnceLock<SafetyLevel> = OnceLock::new();

fn parse_runtime_mode_env(raw: &str) -> SafetyLevel {
    match raw.to_ascii_lowercase().as_str() {
        "strict" | "default" | "abi" => SafetyLevel::Strict,
        "hardened" | "repair" | "tsm" | "full" => SafetyLevel::Hardened,
        // Runtime contract is strict|hardened only. Keep benchmark-only `Off`
        // reachable via direct API use in tests/bench code, not env parsing.
        _ => SafetyLevel::Strict,
    }
}

/// Get the configured safety level (reads env var on first call, caches thereafter).
#[must_use]
pub fn safety_level() -> SafetyLevel {
    *GLOBAL_LEVEL.get_or_init(|| {
        std::env::var("GLIBC_RUST_MODE")
            .map(|v| parse_runtime_mode_env(&v))
            .unwrap_or_default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_safety_levels() {
        assert_eq!(SafetyLevel::from_str_loose("strict"), SafetyLevel::Strict);
        assert_eq!(SafetyLevel::from_str_loose("STRICT"), SafetyLevel::Strict);
        assert_eq!(SafetyLevel::from_str_loose("default"), SafetyLevel::Strict);
        assert_eq!(SafetyLevel::from_str_loose("abi"), SafetyLevel::Strict);
        assert_eq!(
            SafetyLevel::from_str_loose("hardened"),
            SafetyLevel::Hardened
        );
        assert_eq!(SafetyLevel::from_str_loose("repair"), SafetyLevel::Hardened);
        assert_eq!(SafetyLevel::from_str_loose("tsm"), SafetyLevel::Hardened);
        assert_eq!(SafetyLevel::from_str_loose("off"), SafetyLevel::Off);
        assert_eq!(SafetyLevel::from_str_loose("none"), SafetyLevel::Off);
        assert_eq!(SafetyLevel::from_str_loose("bogus"), SafetyLevel::Strict);
    }

    #[test]
    fn runtime_mode_parser_is_strict_or_hardened_only() {
        assert_eq!(parse_runtime_mode_env("strict"), SafetyLevel::Strict);
        assert_eq!(parse_runtime_mode_env("hardened"), SafetyLevel::Hardened);
        assert_eq!(parse_runtime_mode_env("repair"), SafetyLevel::Hardened);
        assert_eq!(parse_runtime_mode_env("off"), SafetyLevel::Strict);
        assert_eq!(parse_runtime_mode_env("none"), SafetyLevel::Strict);
        assert_eq!(parse_runtime_mode_env("bogus"), SafetyLevel::Strict);
    }

    #[test]
    fn default_is_strict() {
        assert_eq!(SafetyLevel::default(), SafetyLevel::Strict);
    }

    #[test]
    fn healing_only_in_hardened() {
        assert!(!SafetyLevel::Strict.heals_enabled());
        assert!(SafetyLevel::Hardened.heals_enabled());
        assert!(!SafetyLevel::Off.heals_enabled());
    }

    #[test]
    fn validation_except_off() {
        assert!(SafetyLevel::Strict.validation_enabled());
        assert!(SafetyLevel::Hardened.validation_enabled());
        assert!(!SafetyLevel::Off.validation_enabled());
    }
}
