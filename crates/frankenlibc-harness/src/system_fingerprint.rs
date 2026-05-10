//! System environment fingerprint helper (bd-6epxt).
//!
//! Produces a stable string derived deterministically from
//! `/proc/cpuinfo`, `/proc/sys/kernel/osrelease`, and the host arch.
//! Used by live runners (bd-juvqm.3, bd-8b70o) to anchor the
//! `environment_fingerprint` field on LiveMeasurementRow so two
//! measurements can be compared only when the runs share an
//! environment.
//!
//! Format: `<os>-<arch>-<cpus>cpu-<kernel_release>`, e.g.
//!         `linux-x86_64-64cpu-6.1.0-25-amd64`.
//!
//! `FRANKENLIBC_ENV_FINGERPRINT` env override short-circuits to a
//! custom string for CI environments where a pinned fingerprint is
//! required.

use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentFingerprintComponents {
    pub os: String,
    pub arch: String,
    pub cpus: u32,
    pub kernel_release: String,
}

impl EnvironmentFingerprintComponents {
    pub fn render(&self) -> String {
        format!(
            "{}-{}-{}cpu-{}",
            self.os, self.arch, self.cpus, self.kernel_release
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvFingerprintError {
    InvalidFormat,
    EmptyComponent(&'static str),
    InvalidCpuCount(String),
}

impl core::fmt::Display for EnvFingerprintError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EnvFingerprintError::InvalidFormat => f.write_str(
                "fingerprint must be `<os>-<arch>-<cpus>cpu-<kernel_release>` (4 segments separated by `-`, with the third ending in `cpu`)",
            ),
            EnvFingerprintError::EmptyComponent(c) => write!(f, "empty component {c}"),
            EnvFingerprintError::InvalidCpuCount(s) => write!(f, "invalid cpu count {s:?}"),
        }
    }
}

impl std::error::Error for EnvFingerprintError {}

/// Build a [`EnvironmentFingerprintComponents`] from the running
/// host. Reads `/proc/cpuinfo` for the CPU count and
/// `/proc/sys/kernel/osrelease` for the kernel release.
pub fn detect_components() -> EnvironmentFingerprintComponents {
    let os = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(windows) {
        "windows"
    } else {
        "other"
    }
    .to_string();
    let arch = std::env::consts::ARCH.to_string();
    let cpus = read_cpu_count();
    let kernel_release = read_kernel_release();
    EnvironmentFingerprintComponents {
        os,
        arch,
        cpus,
        kernel_release,
    }
}

fn read_cpu_count() -> u32 {
    if let Ok(text) = std::fs::read_to_string("/proc/cpuinfo") {
        let processors = text.lines().filter(|l| l.starts_with("processor")).count() as u32;
        if processors > 0 {
            return processors;
        }
    }
    std::thread::available_parallelism()
        .map(|n| u32::try_from(n.get()).unwrap_or(0))
        .unwrap_or(0)
}

fn read_kernel_release() -> String {
    let osrelease = Path::new("/proc/sys/kernel/osrelease");
    if osrelease.exists()
        && let Ok(text) = std::fs::read_to_string(osrelease)
    {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "unknown".to_string()
}

/// Compute the environment fingerprint, honoring the
/// `FRANKENLIBC_ENV_FINGERPRINT` override.
pub fn environment_fingerprint() -> String {
    if let Ok(custom) = std::env::var("FRANKENLIBC_ENV_FINGERPRINT") {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    detect_components().render()
}

/// Build a fingerprint string from explicit components (the public
/// way to render a fingerprint for tests).
pub fn from_components(c: &EnvironmentFingerprintComponents) -> String {
    c.render()
}

/// Parse a fingerprint string back into its components. Fails closed
/// on malformed input.
pub fn validate_environment_fingerprint(
    fingerprint: &str,
) -> Result<EnvironmentFingerprintComponents, EnvFingerprintError> {
    let parts: Vec<&str> = fingerprint.split('-').collect();
    // We need at least 4 parts: os, arch, <cpus>cpu, kernel_release...
    if parts.len() < 4 {
        return Err(EnvFingerprintError::InvalidFormat);
    }
    let os = parts[0];
    let arch = parts[1];
    let cpus_segment = parts[2];
    if !cpus_segment.ends_with("cpu") {
        return Err(EnvFingerprintError::InvalidFormat);
    }
    let cpus_str = &cpus_segment[..cpus_segment.len() - 3];
    if os.is_empty() {
        return Err(EnvFingerprintError::EmptyComponent("os"));
    }
    if arch.is_empty() {
        return Err(EnvFingerprintError::EmptyComponent("arch"));
    }
    if cpus_str.is_empty() {
        return Err(EnvFingerprintError::EmptyComponent("cpus"));
    }
    let cpus: u32 = cpus_str
        .parse()
        .map_err(|_| EnvFingerprintError::InvalidCpuCount(cpus_str.to_string()))?;
    // Everything after the third segment is kernel_release (which can
    // contain `-`, e.g. `6.1.0-25-amd64`).
    let kernel_release = parts[3..].join("-");
    if kernel_release.is_empty() {
        return Err(EnvFingerprintError::EmptyComponent("kernel_release"));
    }
    Ok(EnvironmentFingerprintComponents {
        os: os.to_string(),
        arch: arch.to_string(),
        cpus,
        kernel_release,
    })
}

/// Stable list of every error variant the validator can produce.
pub const ENV_FINGERPRINT_ERROR_KINDS: &[&str] =
    &["invalid_format", "empty_component", "invalid_cpu_count"];

#[cfg(test)]
mod tests {
    use super::*;

    fn synth() -> EnvironmentFingerprintComponents {
        EnvironmentFingerprintComponents {
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            cpus: 64,
            kernel_release: "6.1.0-25-amd64".to_string(),
        }
    }

    #[test]
    fn render_round_trip_preserves_components() {
        let c = synth();
        let s = c.render();
        let parsed = validate_environment_fingerprint(&s).unwrap();
        assert_eq!(parsed, c);
    }

    #[test]
    fn from_components_matches_render() {
        let c = synth();
        assert_eq!(from_components(&c), c.render());
    }

    #[test]
    fn validate_rejects_too_few_segments() {
        assert!(matches!(
            validate_environment_fingerprint("linux-x86_64"),
            Err(EnvFingerprintError::InvalidFormat)
        ));
    }

    #[test]
    fn validate_rejects_missing_cpu_suffix() {
        assert!(matches!(
            validate_environment_fingerprint("linux-x86_64-64-6.1"),
            Err(EnvFingerprintError::InvalidFormat)
        ));
    }

    #[test]
    fn validate_rejects_non_numeric_cpu_count() {
        assert!(matches!(
            validate_environment_fingerprint("linux-x86_64-NaNcpu-6.1"),
            Err(EnvFingerprintError::InvalidCpuCount(_))
        ));
    }

    #[test]
    fn validate_rejects_empty_kernel_release() {
        assert!(matches!(
            validate_environment_fingerprint("linux-x86_64-64cpu-"),
            Err(EnvFingerprintError::InvalidFormat)
                | Err(EnvFingerprintError::EmptyComponent("kernel_release"))
        ));
    }

    #[test]
    fn detect_components_returns_non_empty_fields_on_linux() {
        if !cfg!(target_os = "linux") {
            return;
        }
        let c = detect_components();
        assert_eq!(c.os, "linux");
        assert!(!c.arch.is_empty());
        // cpus may be 0 if /proc/cpuinfo is unreadable AND
        // available_parallelism fails — extremely unlikely on a
        // normal CI host. We only assert the renderer round-trips.
        let s = c.render();
        let parsed = validate_environment_fingerprint(&s).unwrap();
        assert_eq!(parsed, c);
    }

    #[test]
    fn environment_fingerprint_renders_a_round_trippable_string() {
        // Don't mutate process env in tests (parallel-test races).
        // Just call the API and assert it round-trips OR honors an
        // existing override.
        let s = environment_fingerprint();
        let parsed = validate_environment_fingerprint(&s);
        if std::env::var("FRANKENLIBC_ENV_FINGERPRINT").is_err() {
            // No override → round-trip must succeed.
            parsed.unwrap();
        }
        // With an override we don't enforce the format.
    }

    #[test]
    fn kernel_release_can_contain_internal_dashes() {
        let s = "linux-x86_64-32cpu-6.1.0-25-amd64-rt";
        let parsed = validate_environment_fingerprint(s).unwrap();
        assert_eq!(parsed.kernel_release, "6.1.0-25-amd64-rt");
    }
}
