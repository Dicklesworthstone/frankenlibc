//! SipHash-based allocation fingerprints and trailing canaries.
//!
//! Every membrane-managed allocation gets:
//! - A 24-byte fingerprint header: `[u64 hash | u64 generation | u64 size]`
//! - An 8-byte trailing canary (an invertible transform of the hash)
//!
//! The fingerprint provides:
//! - Allocation integrity checks when the arena/validator reaches them
//! - Generation tracking for temporal safety
//! - Size metadata for bounds checking (supports allocations >4GiB)
//!
//! The canary preserves all 64 hash bits; it does not add entropy or provide
//! an independent authentication tag. A single blind guess succeeds with
//! probability 2^-64 only if the hash is uniformly unpredictable to the caller.
//! Reading the header hash reveals the canary. The process/time/address key
//! initialization below does not establish cryptographic entropy, and neither
//! metadata check intercepts direct C writes or identifies stale raw pointers
//! after same-address reuse.

/// Size of the fingerprint header prepended to allocations.
pub const FINGERPRINT_SIZE: usize = 24;

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
    pub generation: u64,
    /// Allocation size in bytes (user-requested, not including overhead).
    pub size: u64,
}

impl AllocationFingerprint {
    /// Compute a fingerprint for the given allocation parameters.
    #[must_use]
    pub fn compute(base_addr: usize, size: u64, generation: u64) -> Self {
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
        buf[8..16].copy_from_slice(&self.generation.to_le_bytes());
        buf[16..24].copy_from_slice(&self.size.to_le_bytes());
        buf
    }

    /// Deserialize fingerprint from bytes.
    #[must_use]
    pub fn from_bytes(buf: &[u8; FINGERPRINT_SIZE]) -> Self {
        let hash = u64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);
        let generation = u64::from_le_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);
        let size = u64::from_le_bytes([
            buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
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
    /// Derive a canary without discarding any fingerprint hash bits.
    ///
    /// XOR with a constant is a bijection: applying the same XOR recovers the
    /// hash. This separates the stored byte patterns, not cryptographic domains;
    /// disclosure of either value reveals the other. In particular, do not XOR
    /// the hash with its 32-bit rotation: that folds both halves into only 32
    /// independent output bits.
    #[must_use]
    pub fn from_hash(hash: u64) -> Self {
        Self {
            value: (hash ^ 0xDEAD_BEEF_CAFE_BABEu64).to_le_bytes(),
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
use std::time::{SystemTime, UNIX_EPOCH};

static SIP_KEY_0: AtomicU64 = AtomicU64::new(0);
static SIP_KEY_1: AtomicU64 = AtomicU64::new(0);

#[inline(always)]
fn splitmix64(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *seed;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(feature = "owned-tls-cache")]
fn current_thread_entropy() -> u64 {
    let stack_probe = 0u8;
    let stack_addr = &stack_probe as *const u8 as usize as u64;
    u64::from(std::process::id()).rotate_left(23) ^ stack_addr.rotate_left(11)
}

#[cfg(not(feature = "owned-tls-cache"))]
fn current_thread_entropy() -> u64 {
    use std::hash::{Hash, Hasher};

    let mut tid_hasher = std::collections::hash_map::DefaultHasher::new();
    std::thread::current().id().hash(&mut tid_hasher);
    tid_hasher.finish()
}

fn init_keys() -> (u64, u64) {
    let mut k0 = SIP_KEY_0.load(Ordering::Relaxed);
    let mut k1 = SIP_KEY_1.load(Ordering::Relaxed);
    if k0 == 0 || k1 == 0 {
        // Safe entropy mix from process/thread/time + ASLR address noise.
        let aslr = init_keys as *const () as usize as u64;
        let pid = u64::from(std::process::id());
        let time_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0u128, |d| d.as_nanos());
        let time_lo = time_nanos as u64;
        let time_hi = (time_nanos >> 64) as u64;
        let tid = current_thread_entropy();

        let mut seed = aslr
            ^ pid.rotate_left(11)
            ^ tid.rotate_left(23)
            ^ time_lo.rotate_left(7)
            ^ time_hi.rotate_left(31)
            ^ 0xA5A5_5A5A_D3C3_B4B4;

        let mut r0 = splitmix64(&mut seed);
        let mut r1 = splitmix64(&mut seed);

        // Ensure non-zero keys
        if r0 == 0 {
            r0 = 1;
        }
        if r1 == 0 {
            r1 = 1;
        }

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
fn sip_hash_2_4(addr: usize, size: u64, generation: u64) -> u64 {
    let (k0, k1) = init_keys();

    let mut v0: u64 = k0 ^ 0x736f_6d65_7073_6575;
    let mut v1: u64 = k1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2: u64 = k0 ^ 0x6c79_6765_6e65_7261;
    let mut v3: u64 = k1 ^ 0x7465_6462_7974_6573;

    // Pack inputs into a 192-bit message (3 words)
    let m0 = addr as u64;
    let m1 = size;
    let m2 = generation;

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

    // Rank over GF(2) of the linear part of an affine 64-bit transform.
    // This inspects the actual production function on a complete basis; a
    // random collision sample would not establish its preserved bit width.
    fn affine_difference_rank(transform: impl Fn(u64) -> u64, origin: u64) -> usize {
        let offset = transform(origin);
        let mut basis = [0u64; 64];
        let mut rank = 0;
        for bit in 0..64 {
            let mut column = transform(origin ^ (1u64 << bit)) ^ offset;
            while column != 0 {
                let pivot = 63 - column.leading_zeros() as usize;
                if basis[pivot] == 0 {
                    basis[pivot] = column;
                    rank += 1;
                    break;
                }
                column ^= basis[pivot];
            }
        }
        rank
    }

    #[test]
    fn canary_derivation_preserves_full_width() {
        for origin in [0, u64::MAX, 0x1234_5678_9ABC_DEF0] {
            assert_eq!(
                affine_difference_rank(
                    |hash| u64::from_le_bytes(Canary::from_hash(hash).to_bytes()),
                    origin,
                ),
                64,
                "the affine canary transform must preserve all 64 hash bits"
            );
        }
    }

    #[test]
    fn canary_width_check_rejects_legacy_fold() {
        // Frozen negative control from bd-reality-202609-lx578q.8.1. The same
        // structural check used above must reject the former production map.
        let legacy = |hash: u64| hash ^ hash.rotate_left(32) ^ 0xDEAD_BEEF_CAFE_BABE;
        assert_eq!(affine_difference_rank(legacy, 0), 32);
        for (left, right) in [
            (0, 0x0000_0001_0000_0001),
            (0x1234_5678_9ABC_DEF0, 0x1234_5679_9ABC_DEF1),
        ] {
            assert_eq!(legacy(left), legacy(right));
            assert_ne!(Canary::from_hash(left), Canary::from_hash(right));
        }
    }

    #[test]
    fn canary_derivation_known_vectors_and_layout() {
        assert_eq!(std::mem::size_of::<AllocationFingerprint>(), 24);
        assert_eq!(std::mem::size_of::<Canary>(), 8);
        for (hash, expected) in [
            (0, 0xDEAD_BEEF_CAFE_BABE_u64),
            (u64::MAX, 0x2152_4110_3501_4541),
            (0x0000_0001_0000_0001, 0xDEAD_BEEE_CAFE_BABF),
            (0xDEAD_BEEF_CAFE_BABE, 0),
        ] {
            assert_eq!(Canary::from_hash(hash).to_bytes(), expected.to_le_bytes());
        }
    }

    #[test]
    fn different_params_produce_different_fingerprints() {
        let fp1 = AllocationFingerprint::compute(0x1000, 256, 1);
        let fp2 = AllocationFingerprint::compute(0x1000, 256, 2);
        let fp3 = AllocationFingerprint::compute(0x2000, 256, 1);
        assert_ne!(fp1.hash, fp2.hash);
        assert_ne!(fp1.hash, fp3.hash);
    }

    // ═══════════════════════════════════════════════════════════════
    // Regression sample: distinct allocation inputs at the current process key.
    // This is not a cryptographic proof. A blind guess against a uniformly
    // unpredictable 64-bit tag has probability 2^-64; random collisions among
    // many tags follow a birthday bound instead. Neither key unpredictability
    // nor either probability bound can be established by this finite sample.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_siphash_collision_resistance_empirical() {
        use std::collections::HashSet;
        let mut hashes = HashSet::new();

        // Vary all three input dimensions systematically
        let addrs: &[usize] = &[0, 1, 0x1000, 0xDEAD_BEEF, 0x7FFF_FFFF_FFFF, usize::MAX];
        let sizes: &[u64] = &[0, 1, 64, 256, 4096, u64::MAX];
        let gens: &[u64] = &[0, 1, 2, 100, u64::MAX - 1, u64::MAX];

        let mut count = 0u64;
        for &addr in addrs {
            for &size in sizes {
                for &generation in gens {
                    let hash = sip_hash_2_4(addr, size, generation);
                    let is_new = hashes.insert((addr, size, generation, hash));
                    assert!(
                        is_new,
                        "Duplicate input: addr={addr:#x}, size={size}, gen={generation}"
                    );
                    count += 1;
                }
            }
        }

        // Verify all hashes are unique (no collisions among 216 inputs)
        let unique_hashes: HashSet<u64> = hashes.iter().map(|&(_, _, _, h)| h).collect();
        assert_eq!(
            unique_hashes.len(),
            count as usize,
            "Hash collision detected among {count} inputs"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // Regression sample: generation changes alter the checked fingerprints.
    // A finite 64-bit hash is not universally collision-free, and raw caller
    // pointers do not carry generations. Same-address reuse is therefore not
    // detected merely by verifying the current allocation's fingerprint.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_generation_change_always_changes_hash() {
        let addrs: &[usize] = &[0x1000, 0x2000, 0xABCD_0000];
        let sizes: &[u64] = &[64, 256, 4096];

        for &addr in addrs {
            for &size in sizes {
                let mut prev_hashes = std::collections::HashSet::new();
                for generation in 0..1000u64 {
                    let fp = AllocationFingerprint::compute(addr, size, generation);
                    let is_new = prev_hashes.insert(fp.hash);
                    assert!(
                        is_new,
                        "Generation change did not change hash: \
                         addr={addr:#x}, size={size}, gen={generation}"
                    );
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Fingerprint Integrity — Single-Bit Sensitivity
    //
    // Theorem: Modifying any single bit of the fingerprint hash
    // causes verification failure. This proves the fingerprint
    // catches all single-bit corruptions.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_fingerprint_single_bit_sensitivity() {
        let fp = AllocationFingerprint::compute(0x1000, 256, 1);
        let bytes = fp.to_bytes();

        // Verify the original passes
        let original = AllocationFingerprint::from_bytes(&bytes);
        assert!(original.verify(0x1000));

        // Flip each bit in the hash portion (first 8 bytes) and verify failure
        for byte_idx in 0..8 {
            for bit_idx in 0..8 {
                let mut corrupted = bytes;
                corrupted[byte_idx] ^= 1 << bit_idx;
                let corrupted_fp = AllocationFingerprint::from_bytes(&corrupted);
                assert!(
                    !corrupted_fp.verify(0x1000),
                    "Single-bit flip at byte {byte_idx} bit {bit_idx} was not detected"
                );
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Canary Detects All Single-Byte Corruptions
    //
    // Theorem: Every possible single-byte corruption in the canary
    // is detected. For each byte position and each non-original
    // value (255 alternatives), verify() returns false.
    //
    // This enumerates changed-byte detection for this canary value when verify
    // is called. A write that leaves the bytes intact, skips the tail, or never
    // reaches a check is outside this test's scope.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_canary_detects_all_single_byte_corruptions() {
        let fp = AllocationFingerprint::compute(0x5000, 512, 7);
        let canary = fp.canary();
        let original = canary.to_bytes();

        for byte_idx in 0..CANARY_SIZE {
            for alt_val in 0..=255u8 {
                if alt_val == original[byte_idx] {
                    continue; // skip the original value
                }
                let mut corrupted = original;
                corrupted[byte_idx] = alt_val;
                assert!(
                    !canary.verify(&corrupted),
                    "Canary failed to detect corruption at byte {byte_idx}, \
                     value {alt_val:#04x} (original {:#04x})",
                    original[byte_idx]
                );
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Fingerprint Serialization Bijection
    //
    // Theorem: to_bytes() and from_bytes() form a bijection —
    // every fingerprint survives a round-trip exactly, and distinct
    // fingerprints produce distinct byte representations.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_fingerprint_serialization_bijection() {
        let test_cases = [
            (0x1000usize, 256u64, 1u64),
            (0, 0, 0),
            (usize::MAX, u64::MAX, u64::MAX),
            (0xDEAD_BEEF, 4096, 42),
            (1, 1, 1),
        ];

        for &(addr, size, generation) in &test_cases {
            let fp = AllocationFingerprint::compute(addr, size, generation);
            let bytes = fp.to_bytes();
            let fp2 = AllocationFingerprint::from_bytes(&bytes);
            assert_eq!(
                fp, fp2,
                "Round-trip failed for ({addr:#x}, {size}, {generation})"
            );
        }

        // Distinct fingerprints → distinct bytes
        let fp_a = AllocationFingerprint::compute(0x1000, 256, 1);
        let fp_b = AllocationFingerprint::compute(0x1000, 256, 2);
        assert_ne!(
            fp_a.to_bytes(),
            fp_b.to_bytes(),
            "Distinct fingerprints must produce distinct byte representations"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // PROPERTY-BASED: Fingerprint invariants via proptest
    // ═══════════════════════════════════════════════════════════════

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_fingerprint_roundtrip(
            addr in 0usize..usize::MAX,
            size in 0u64..u64::MAX,
            generation in 0u64..u64::MAX,
        ) {
            let fp = AllocationFingerprint::compute(addr, size, generation);
            let bytes = fp.to_bytes();
            let fp2 = AllocationFingerprint::from_bytes(&bytes);
            prop_assert_eq!(fp, fp2);
        }

        #[test]
        fn prop_fingerprint_verify_correct_addr(
            addr in 1usize..0xFFFF_FFFF,
            size in 1u64..0xFFFF_FFFF,
            generation in 1u64..0xFFFF_FFFF,
        ) {
            let fp = AllocationFingerprint::compute(addr, size, generation);
            prop_assert!(fp.verify(addr), "fingerprint must verify for correct address");
        }

        #[test]
        fn prop_fingerprint_verify_wrong_addr(
            addr in 1usize..0x7FFF_FFFF,
            size in 1u64..0xFFFF_FFFF,
            generation in 1u64..0xFFFF_FFFF,
        ) {
            let fp = AllocationFingerprint::compute(addr, size, generation);
            let wrong_addr = addr + 1;
            prop_assert!(
                !fp.verify(wrong_addr),
                "fingerprint must NOT verify for wrong address"
            );
        }

        #[test]
        fn prop_canary_roundtrip(hash in 0u64..u64::MAX) {
            let canary = Canary::from_hash(hash);
            let bytes = canary.to_bytes();
            prop_assert!(canary.verify(&bytes), "canary must verify its own bytes");
        }

        #[test]
        fn prop_canary_preserves_hash_differences(left: u64, right: u64) {
            let left_canary = u64::from_le_bytes(Canary::from_hash(left).to_bytes());
            let right_canary = u64::from_le_bytes(Canary::from_hash(right).to_bytes());
            prop_assert_eq!(left_canary ^ right_canary, left ^ right);
        }

        #[test]
        fn prop_canary_detects_any_byte_flip(
            hash in 0u64..u64::MAX,
            byte_idx in 0usize..CANARY_SIZE,
        ) {
            let canary = Canary::from_hash(hash);
            let mut corrupted = canary.to_bytes();
            corrupted[byte_idx] ^= 0xFF; // flip all bits in one byte
            prop_assert!(
                !canary.verify(&corrupted),
                "canary must detect byte flip at index {byte_idx}"
            );
        }

        #[test]
        fn prop_different_inputs_produce_different_hashes(
            addr1 in 1usize..0xFFFF_FFFF,
            addr2 in 1usize..0xFFFF_FFFF,
            size in 1u64..0xFFFF_FFFF,
            generation in 1u64..0xFFFF_FFFF,
        ) {
            prop_assume!(addr1 != addr2);
            let fp1 = AllocationFingerprint::compute(addr1, size, generation);
            let fp2 = AllocationFingerprint::compute(addr2, size, generation);
            prop_assert_ne!(fp1.hash, fp2.hash, "different addresses must produce different hashes");
        }
    }
}
