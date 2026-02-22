//! SipHash-based allocation fingerprints and trailing canaries.
//!
//! Every membrane-managed allocation gets:
//! - A 20-byte fingerprint header: `[u64 hash | u32 generation | u64 size]`
//! - An 8-byte trailing canary (known pattern derived from the hash)
//!
//! The fingerprint provides:
//! - Allocation integrity verification (P(undetected corruption) <= 2^-64)
//! - Generation tracking for temporal safety
//! - Size metadata for bounds checking (supports allocations >4GiB)

/// Size of the fingerprint header prepended to allocations.
pub const FINGERPRINT_SIZE: usize = 20;

/// Size of the trailing canary appended to allocations.
pub const CANARY_SIZE: usize = 8;

/// Total overhead per allocation (header + canary).
pub const TOTAL_OVERHEAD: usize = FINGERPRINT_SIZE + CANARY_SIZE;

/// Allocation fingerprint stored as a header before the user-visible pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct AllocationFingerprint {
    /// SipHash-2-4 of (base_address, size, generation, secret).
    pub hash: u64,
    /// Generation counter for temporal safety.
    pub generation: u32,
    /// Allocation size in bytes (user-requested, not including overhead).
    pub size: u64,
}

impl AllocationFingerprint {
    /// Compute a fingerprint for the given allocation parameters.
    #[must_use]
    pub fn compute(base_addr: usize, size: u64, generation: u32) -> Self {
        let hash = sip_hash_2_4(base_addr, size, generation);
        Self {
            hash,
            generation,
            size,
        }
    }

    /// Verify that this fingerprint matches the expected values.
    #[must_use]
    pub fn verify(&self, base_addr: usize) -> bool {
        let expected_hash = sip_hash_2_4(base_addr, self.size, self.generation);
        self.hash == expected_hash
    }

    /// Serialize fingerprint to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; FINGERPRINT_SIZE] {
        let mut buf = [0u8; FINGERPRINT_SIZE];
        buf[0..8].copy_from_slice(&self.hash.to_le_bytes());
        buf[8..12].copy_from_slice(&self.generation.to_le_bytes());
        buf[12..20].copy_from_slice(&self.size.to_le_bytes());
        buf
    }

    /// Deserialize fingerprint from bytes.
    #[must_use]
    pub fn from_bytes(buf: &[u8; FINGERPRINT_SIZE]) -> Self {
        let hash = u64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);
        let generation = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let size = u64::from_le_bytes([
            buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19],
        ]);
        Self {
            hash,
            generation,
            size,
        }
    }

    /// Derive the canary value from the fingerprint hash.
    #[must_use]
    pub fn canary(&self) -> Canary {
        Canary::from_hash(self.hash)
    }
}

/// 8-byte trailing canary for buffer overflow detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Canary {
    /// The canary bytes derived from the allocation hash.
    pub value: [u8; CANARY_SIZE],
}

impl Canary {
    /// Derive canary from a fingerprint hash.
    #[must_use]
    pub fn from_hash(hash: u64) -> Self {
        // XOR-fold and bit-rotate to create a distinct pattern
        let folded = hash ^ hash.rotate_left(32) ^ 0xDEAD_BEEF_CAFE_BABEu64;
        Self {
            value: folded.to_le_bytes(),
        }
    }

    /// Serialize to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CANARY_SIZE] {
        self.value
    }

    /// Check if a byte slice matches this canary.
    #[must_use]
    pub fn verify(&self, bytes: &[u8; CANARY_SIZE]) -> bool {
        self.value == *bytes
    }
}

use std::sync::atomic::{AtomicU64, Ordering};

static SIP_KEY_0: AtomicU64 = AtomicU64::new(0);
static SIP_KEY_1: AtomicU64 = AtomicU64::new(0);

fn init_keys() -> (u64, u64) {
    let mut k0 = SIP_KEY_0.load(Ordering::Relaxed);
    let mut k1 = SIP_KEY_1.load(Ordering::Relaxed);
    if k0 == 0 || k1 == 0 {
        // Fallback PRNG seeded by ASLR and time (or similar).
        // Since we are in a libc interposition, avoid complex std::time calls if possible.
        let aslr = init_keys as usize as u64;
        let mut r0 = aslr ^ 0x0706_0504_0302_0100;
        let mut r1 = aslr ^ 0x0F0E_0D0C_0B0A_0908;
        
        #[cfg(target_os = "linux")]
        {
            let mut buf = [0u8; 16];
            // SYS_getrandom = 318 on x86_64
            let res = unsafe { libc::syscall(318, buf.as_mut_ptr(), buf.len(), 0) };
            if res == 16 {
                r0 = u64::from_le_bytes(buf[0..8].try_into().unwrap());
                r1 = u64::from_le_bytes(buf[8..16].try_into().unwrap());
            }
        }
        
        // Ensure non-zero keys
        if r0 == 0 { r0 = 1; }
        if r1 == 0 { r1 = 1; }
        
        let _ = SIP_KEY_0.compare_exchange(0, r0, Ordering::Relaxed, Ordering::Relaxed);
        let _ = SIP_KEY_1.compare_exchange(0, r1, Ordering::Relaxed, Ordering::Relaxed);
        
        k0 = SIP_KEY_0.load(Ordering::Relaxed);
        k1 = SIP_KEY_1.load(Ordering::Relaxed);
    }
    (k0, k1)
}

/// SipHash-2-4 implementation (simplified).
///
/// Uses a runtime-initialized secret key for collision resistance
/// and allocation integrity.
fn sip_hash_2_4(addr: usize, size: u64, generation: u32) -> u64 {
    let (k0, k1) = init_keys();

    let mut v0: u64 = k0 ^ 0x736f_6d65_7073_6575;
    let mut v1: u64 = k1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2: u64 = k0 ^ 0x6c79_6765_6e65_7261;
    let mut v3: u64 = k1 ^ 0x7465_6462_7974_6573;

    // Pack inputs into a 192-bit message (3 words)
    let m0 = addr as u64;
    let m1 = size;
    let m2 = generation as u64;

    // Process m0
    v3 ^= m0;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= m0;

    // Process m1
    v3 ^= m1;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= m1;

    // Process m2
    v3 ^= m2;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= m2;

    // Finalization
    v2 ^= 0xFF;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);

    v0 ^ v1 ^ v2 ^ v3
}

#[inline(always)]
fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_roundtrip() {
        let fp = AllocationFingerprint::compute(0x1000, 256, 1);
        let bytes = fp.to_bytes();
        let fp2 = AllocationFingerprint::from_bytes(&bytes);
        assert_eq!(fp, fp2);
    }

    #[test]
    fn fingerprint_verify_passes_for_correct_addr() {
        let fp = AllocationFingerprint::compute(0x2000, 512, 3);
        assert!(fp.verify(0x2000));
    }

    #[test]
    fn fingerprint_verify_fails_for_wrong_addr() {
        let fp = AllocationFingerprint::compute(0x2000, 512, 3);
        assert!(!fp.verify(0x3000));
    }

    #[test]
    fn canary_roundtrip() {
        let fp = AllocationFingerprint::compute(0x4000, 128, 1);
        let canary = fp.canary();
        let bytes = canary.to_bytes();
        assert!(canary.verify(&bytes));
    }

    #[test]
    fn canary_detects_corruption() {
        let fp = AllocationFingerprint::compute(0x4000, 128, 1);
        let canary = fp.canary();
        let mut corrupted = canary.to_bytes();
        corrupted[3] ^= 0xFF;
        assert!(!canary.verify(&corrupted));
    }

    #[test]
    fn different_params_produce_different_fingerprints() {
        let fp1 = AllocationFingerprint::compute(0x1000, 256, 1);
        let fp2 = AllocationFingerprint::compute(0x1000, 256, 2);
        let fp3 = AllocationFingerprint::compute(0x2000, 256, 1);
        assert_ne!(fp1.hash, fp2.hash);
        assert_ne!(fp1.hash, fp3.hash);
    }
}
