//! CPU/OS-validated native-loader glibc-hwcaps selection.
//!
//! The x86-64 psABI levels are cumulative. In particular, advertising AVX or
//! AVX-512 in CPUID is insufficient without the corresponding XCR0 state.
//! Unknown architectures and directory names retain the baseline search path.
//! No host-loader resolution, environment lookup, or optional-ISA instruction
//! is needed to classify a capability. This is not a GLIBC_TUNABLES parser.

use std::sync::OnceLock;

#[cfg(any(target_arch = "x86_64", test))]
const V2_ECX: u32 = (1 << 0) | (1 << 9) | (1 << 13) | (1 << 19) | (1 << 20) | (1 << 23);
#[cfg(any(target_arch = "x86_64", test))]
const V3_ECX: u32 = (1 << 12) | (1 << 22) | (1 << 26) | (1 << 27) | (1 << 28) | (1 << 29);
#[cfg(any(target_arch = "x86_64", test))]
const V3_EBX7: u32 = (1 << 3) | (1 << 5) | (1 << 8);
#[cfg(any(target_arch = "x86_64", test))]
const V4_EBX7: u32 = (1 << 16) | (1 << 17) | (1 << 28) | (1 << 30) | (1 << 31);
const NAMES: &[&str] = &["x86-64-v4", "x86-64-v3", "x86-64-v2"];

#[cfg(any(target_arch = "x86_64", test))]
#[derive(Clone, Copy, Debug, Default)]
struct X86Features {
    ecx1: u32,
    ebx7: u32,
    extended_ecx: u32,
    xcr0: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Capabilities {
    // Zero means no architecture-specific support; one is x86-64 baseline.
    x86_level: u8,
}

impl Capabilities {
    #[cfg(any(target_arch = "x86_64", test))]
    fn from_x86(features: X86Features) -> Self {
        let has = |value: u32, mask: u32| value & mask == mask;
        let mut level = 1;
        if has(features.ecx1, V2_ECX) && has(features.extended_ecx, 1) {
            level = 2;
            if has(features.ecx1, V3_ECX)
                && has(features.ebx7, V3_EBX7)
                && has(features.extended_ecx, 1 << 5)
                && has(features.xcr0, 0x6)
            {
                level = 3;
                if has(features.ebx7, V4_EBX7) && has(features.xcr0, 0xe6) {
                    level = 4;
                }
            }
        }
        Self { x86_level: level }
    }

    pub(crate) fn detect() -> Self {
        static CAPABILITIES: OnceLock<Capabilities> = OnceLock::new();
        *CAPABILITIES.get_or_init(detect)
    }

    /// Highest priority first; the baseline directory is appended by callers.
    pub(crate) fn names(self) -> &'static [&'static str] {
        match self.x86_level {
            2 => &NAMES[2..],
            3 => &NAMES[1..],
            4 => NAMES,
            _ => &[],
        }
    }

    /// Cache ISA fields encode a zero-based level INDEX, not a bit mask.
    /// Reject unknown levels before doing any arithmetic or shift with them.
    pub(crate) fn rank(self, name: &[u8], isa_index: u32) -> Option<usize> {
        if isa_index >= u32::from(self.x86_level) {
            return None;
        }
        NAMES
            .iter()
            .position(|candidate| candidate.as_bytes() == name && self.names().contains(candidate))
    }

    #[cfg(test)]
    pub(crate) fn for_x86_level(level: u8) -> Self {
        assert!((1..=4).contains(&level));
        Self { x86_level: level }
    }
}

#[cfg(target_arch = "x86_64")]
fn detect() -> Capabilities {
    use core::arch::x86_64::__cpuid_count;

    // SAFETY: CPUID is available on x86-64. Check maximum leaves before
    // querying feature leaves, rather than accepting unspecified leaf data.
    let basic_max = unsafe { __cpuid_count(0, 0) }.eax;
    let extended_max = unsafe { __cpuid_count(0x8000_0000, 0) }.eax;
    let mut features = X86Features::default();
    if basic_max >= 1 {
        features.ecx1 = unsafe { __cpuid_count(1, 0) }.ecx;
    }
    if basic_max >= 7 {
        features.ebx7 = unsafe { __cpuid_count(7, 0) }.ebx;
    }
    if extended_max >= 0x8000_0001 {
        features.extended_ecx = unsafe { __cpuid_count(0x8000_0001, 0) }.ecx;
    }
    if features.ecx1 & ((1 << 26) | (1 << 27)) == ((1 << 26) | (1 << 27)) {
        let xcr0: u32;
        // SAFETY: XSAVE and OSXSAVE were both checked. XGETBV(0) is legal
        // here; do not execute it at all when the OS has not enabled XSAVE.
        unsafe {
            core::arch::asm!(
                "xgetbv",
                in("ecx") 0u32,
                out("eax") xcr0,
                out("edx") _,
                options(nomem, nostack, preserves_flags),
            );
        }
        features.xcr0 = xcr0;
    }
    Capabilities::from_x86(features)
}

#[cfg(not(target_arch = "x86_64"))]
fn detect() -> Capabilities {
    // An unknown hwcaps name must never be interpreted as permission to run
    // an ISA extension. Add each architecture with its own OS-state checks.
    Capabilities::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_features() -> X86Features {
        X86Features {
            ecx1: V2_ECX | V3_ECX,
            ebx7: V3_EBX7 | V4_EBX7,
            extended_ecx: 1 | (1 << 5),
            xcr0: 0xe6,
        }
    }

    #[test]
    fn capabilities_are_cumulative_and_priority_ordered() {
        assert!(Capabilities::default().names().is_empty());
        assert!(
            Capabilities::from_x86(X86Features::default())
                .names()
                .is_empty()
        );
        assert_eq!(Capabilities::from_x86(all_features()).names(), NAMES);
        for level in 1..=4 {
            let caps = Capabilities::for_x86_level(level);
            assert_eq!(caps.names().len(), usize::from(level - 1));
            for (index, name) in NAMES.iter().enumerate() {
                let supported = (4 - index) <= usize::from(level);
                assert_eq!(caps.rank(name.as_bytes(), 0).is_some(), supported);
            }
        }
    }

    #[test]
    fn every_v2_feature_is_required_even_when_avx512_is_advertised() {
        for bit in 0..32 {
            if V2_ECX & (1 << bit) != 0 {
                let mut features = all_features();
                features.ecx1 &= !(1 << bit);
                assert_eq!(Capabilities::from_x86(features).x86_level, 1, "bit {bit}");
            }
        }
        let mut features = all_features();
        features.extended_ecx &= !1;
        assert_eq!(Capabilities::from_x86(features).x86_level, 1);
    }

    #[test]
    fn every_v3_feature_and_xmm_ymm_state_is_required() {
        for bit in 0..32 {
            for (register, mask) in [(0, V3_ECX), (1, V3_EBX7), (2, 1 << 5), (3, 0x6)] {
                if mask & (1 << bit) == 0 {
                    continue;
                }
                let mut features = all_features();
                let value = match register {
                    0 => &mut features.ecx1,
                    1 => &mut features.ebx7,
                    2 => &mut features.extended_ecx,
                    _ => &mut features.xcr0,
                };
                *value &= !(1 << bit);
                assert_eq!(
                    Capabilities::from_x86(features).x86_level,
                    2,
                    "register {register}, bit {bit}"
                );
            }
        }
    }

    #[test]
    fn every_v4_feature_and_opmask_zmm_state_is_required() {
        for bit in 0..32 {
            for (register, mask) in [(0, V4_EBX7), (1, 0xe0)] {
                if mask & (1 << bit) == 0 {
                    continue;
                }
                let mut features = all_features();
                let value = if register == 0 {
                    &mut features.ebx7
                } else {
                    &mut features.xcr0
                };
                *value &= !(1 << bit);
                assert_eq!(
                    Capabilities::from_x86(features).x86_level,
                    3,
                    "register {register}, bit {bit}"
                );
            }
        }
    }

    #[test]
    fn names_and_isa_indices_must_both_be_supported() {
        let caps = Capabilities::for_x86_level(3);
        assert_eq!(caps.rank(b"x86-64-v2", 0), Some(2));
        assert_eq!(caps.rank(b"x86-64-v3", 2), Some(1));
        for name in [
            b"x86-64-v4".as_slice(),
            b"x86-64-v9",
            b"../x86-64-v3",
            b"X86-64-v3",
        ] {
            assert_eq!(caps.rank(name, 0), None);
        }
        for isa_index in [3, 4, 31, 32, 1023, u32::MAX] {
            assert_eq!(caps.rank(b"x86-64-v2", isa_index), None);
        }
    }
}
