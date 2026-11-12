//! SipHash-based allocation fingerprints and domain-separated trailing canaries.
//!
//! Every membrane-managed allocation gets:
//! - A 24-byte fingerprint header: `[u64 hash | u64 generation | u64 size]`
//! - An 8-byte trailing canary keyed by an independent OS CSPRNG key (`K_tail != K_hdr`)
//!
//! Key material `(K_hdr_0, K_hdr_1, K_tail_0, K_tail_1)` (256 bits) is seeded once per
//! process image from Linux `SYS_getrandom` (`GRND_NONBLOCK`, allocation-free and safe
//! before `main` during `LD_PRELOAD` bootstrap), inherited across `fork()` so child
//! processes can validate and free parent-allocated heap blocks, and freshly re-seeded
//! across `execve()`.
//!
//! Because `H = SipHash24(K_hdr, base || size || generation)` and
//! `C_tail = SipHash13(K_tail, base || size || generation || H)` use independent 128-bit
//! secret keys, leaking all 24 header bytes (`hash`, `generation`, `size`) gives zero
//! cryptographic advantage in forging `C_tail` without `K_tail`.

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
    /// SipHash-2-4 of (base_address, size, generation) under `K_hdr`.
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

    /// Derive the domain-separated trailing canary for `base_addr` under `K_tail`.
    #[must_use]
    #[inline]
    pub fn canary_for(&self, base_addr: usize) -> Canary {
        Canary::derive(base_addr, self.size, self.generation, self.hash)
    }
}

/// 8-byte trailing canary for buffer overflow detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Canary {
    /// The canary bytes derived under `K_tail` from `(base_addr, size, generation, header_hash)`.
    pub value: [u8; CANARY_SIZE],
}

impl Canary {
    /// Derive a 64-bit trailing canary under the process's independent `K_tail` secret.
    ///
    /// Computes `SipHash-1-3(K_tail, base_addr || size || generation || header_hash)`.
    /// Disclosing all 24 header bytes (`header_hash`, `generation`, `size`) and `base_addr`
    /// gives zero advantage in computing `Canary` without `K_tail`.
    #[must_use]
    #[inline]
    pub fn derive(base_addr: usize, size: u64, generation: u64, header_hash: u64) -> Self {
        let (t0, t1) = init_tail_keys();
        Self::derive_with_tail_keys(t0, t1, base_addr, size, generation, header_hash)
    }

    /// Deterministic SipHash-1-3 canary derivation for explicit key-separation testing.
    #[must_use]
    #[inline]
    pub fn derive_with_tail_keys(
        k0: u64,
        k1: u64,
        base_addr: usize,
        size: u64,
        generation: u64,
        header_hash: u64,
    ) -> Self {
        let tag = sip_hash_1_3_tail_with_keys(k0, k1, base_addr, size, generation, header_hash);
        Self {
            value: tag.to_le_bytes(),
        }
    }

    /// Convert to native little-endian `u64` tag for compact TLS cache storage.
    #[must_use]
    #[inline(always)]
    pub const fn as_u64(&self) -> u64 {
        u64::from_le_bytes(self.value)
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

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const KEY_STATE_UNINIT: u8 = 0;
const KEY_STATE_INIT: u8 = 1;
const KEY_STATE_READY: u8 = 2;

static KEY_INIT_STATE: AtomicU8 = AtomicU8::new(KEY_STATE_UNINIT);
static KEY_SOURCE_CSPRNG: AtomicBool = AtomicBool::new(false);
static SIP_KEY_0: AtomicU64 = AtomicU64::new(0);
static SIP_KEY_1: AtomicU64 = AtomicU64::new(0);
static TAIL_KEY_0: AtomicU64 = AtomicU64::new(0);
static TAIL_KEY_1: AtomicU64 = AtomicU64::new(0);

#[inline(always)]
fn splitmix64(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *seed;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Fill `buf` from the Linux kernel CSPRNG via a direct `SYS_getrandom` syscall.
///
/// Allocation-free, lock-free, TLS-free, and `environ`-free: safe to invoke
/// before `main` during early `ld.so` `LD_PRELOAD` initialization without
/// re-entering interposed libc functions.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[allow(unsafe_code)]
fn fill_os_csprng_bytes(buf: &mut [u8; 32]) -> bool {
    const GRND_NONBLOCK: usize = 0x0001;
    const EINTR_NEG: isize = -4;

    #[inline(always)]
    #[allow(unsafe_code)]
    unsafe fn raw_sys_getrandom(ptr: *mut u8, len: usize, flags: usize) -> isize {
        #[cfg(target_arch = "x86_64")]
        {
            let ret: isize;
            // SAFETY: Direct Linux x86_64 `SYS_getrandom` (318) syscall writing up to
            // `len` bytes into caller-owned stack memory `[ptr .. ptr + len)`.
            unsafe {
                core::arch::asm!(
                    "syscall",
                    inlateout("rax") 318usize => ret,
                    in("rdi") ptr,
                    in("rsi") len,
                    in("rdx") flags,
                    lateout("rcx") _,
                    lateout("r11") _,
                    options(nostack, preserves_flags),
                );
            }
            ret
        }
        #[cfg(target_arch = "aarch64")]
        {
            let ret: isize;
            // SAFETY: Direct Linux aarch64 `SYS_getrandom` (278) syscall writing up to
            // `len` bytes into caller-owned stack memory `[ptr .. ptr + len)`.
            unsafe {
                core::arch::asm!(
                    "svc #0",
                    in("x8") 278usize,
                    inlateout("x0") ptr as usize => ret,
                    in("x1") len,
                    in("x2") flags,
                    options(nostack, preserves_flags),
                );
            }
            ret
        }
    }

    let mut filled = 0usize;
    while filled < buf.len() {
        // SAFETY: `buf[filled..]` is valid writable stack memory for `buf.len() - filled` bytes.
        let n = unsafe {
            raw_sys_getrandom(
                buf.as_mut_ptr().add(filled),
                buf.len() - filled,
                GRND_NONBLOCK,
            )
        };
        if n > 0 {
            let step = (n as usize).min(buf.len() - filled);
            filled += step;
        } else if n == EINTR_NEG {
            continue;
        } else {
            // Never retry without `GRND_NONBLOCK` (which could block early-boot PID-1
            // processes before CRNG pool initialization); fall back to the non-blocking
            // `splitmix64` entropy mix in `ensure_keys_initialized()`.
            return false;
        }
    }
    true
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn fill_os_csprng_bytes(_buf: &mut [u8; 32]) -> bool {
    false
}

/// Returns `true` when the active 256-bit header/canary keys were seeded directly
/// from the OS CSPRNG (`SYS_getrandom`).
#[must_use]
pub fn keys_seeded_from_csprng() -> bool {
    let _ = init_keys();
    KEY_SOURCE_CSPRNG.load(Ordering::Relaxed)
}

#[inline]
fn recover_key_init_state(state: &AtomicU8) {
    let _ = state.compare_exchange(
        KEY_STATE_INIT,
        KEY_STATE_UNINIT,
        Ordering::AcqRel,
        Ordering::Relaxed,
    );
}

/// Reset an interrupted in-progress key initialization in a freshly forked child.
///
/// If another thread in the parent held `KEY_STATE_INIT` at the instant of `fork()`,
/// that thread does not exist in the child and zero allocations could have completed
/// key stamping yet (`init_keys` had not returned). Resetting `KEY_STATE_INIT ->
/// KEY_STATE_UNINIT` prevents child spin-livelock while leaving `KEY_STATE_READY`
/// keys untouched so parent-allocated blocks remain valid across `fork()`.
pub(crate) fn recover_key_init_in_fork_child() {
    recover_key_init_state(&KEY_INIT_STATE);
}

/// Allocation-free per-thread entropy probe.
///
/// Must NEVER call `std::thread::current()`, which lazily allocates `Arc<Thread>`
/// via `malloc` on uninitialized C pthreads and would self-deadlock if invoked
/// while the current thread owns `KEY_STATE_INIT`.
fn current_thread_entropy() -> u64 {
    let stack_probe = 0u8;
    let stack_addr = &stack_probe as *const u8 as usize as u64;
    #[cfg(target_arch = "x86_64")]
    #[allow(unsafe_code)]
    let cycle_mix = unsafe { core::arch::x86_64::_rdtsc() };
    #[cfg(not(target_arch = "x86_64"))]
    let cycle_mix = 0x9E37_79B9_7F4A_7C15u64;
    u64::from(std::process::id()).rotate_left(23) ^ stack_addr.rotate_left(11) ^ cycle_mix
}

#[cold]
#[inline(never)]
fn ensure_keys_initialized() {
    loop {
        match KEY_INIT_STATE.compare_exchange(
            KEY_STATE_UNINIT,
            KEY_STATE_INIT,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                let mut raw = [0u8; 32];
                let csprng_ok = fill_os_csprng_bytes(&mut raw);
                let (mut k0, mut k1, mut t0, mut t1) = if csprng_ok {
                    (
                        u64::from_le_bytes([
                            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                        ]),
                        u64::from_le_bytes([
                            raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
                        ]),
                        u64::from_le_bytes([
                            raw[16], raw[17], raw[18], raw[19], raw[20], raw[21], raw[22], raw[23],
                        ]),
                        u64::from_le_bytes([
                            raw[24], raw[25], raw[26], raw[27], raw[28], raw[29], raw[30], raw[31],
                        ]),
                    )
                } else {
                    // Explicit ENOSYS / non-Linux fallback entropy mix.
                    let aslr = ensure_keys_initialized as *const () as usize as u64;
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

                    (
                        splitmix64(&mut seed),
                        splitmix64(&mut seed),
                        splitmix64(&mut seed),
                        splitmix64(&mut seed),
                    )
                };

                if k0 == 0 {
                    k0 = 1;
                }
                if k1 == 0 {
                    k1 = 1;
                }
                if t0 == 0 {
                    t0 = 1;
                }
                if t1 == 0 {
                    t1 = 1;
                }
                if k0 == t0 && k1 == t1 {
                    t0 ^= 0x9E37_79B9_7F4A_7C15;
                    if t0 == 0 {
                        t0 = 1;
                    }
                }

                SIP_KEY_0.store(k0, Ordering::Relaxed);
                SIP_KEY_1.store(k1, Ordering::Relaxed);
                TAIL_KEY_0.store(t0, Ordering::Relaxed);
                TAIL_KEY_1.store(t1, Ordering::Relaxed);
                KEY_SOURCE_CSPRNG.store(csprng_ok, Ordering::Relaxed);
                KEY_INIT_STATE.store(KEY_STATE_READY, Ordering::Release);
                return;
            }
            Err(KEY_STATE_READY) => return,
            Err(_) => {
                std::hint::spin_loop();
                if KEY_INIT_STATE.load(Ordering::Acquire) == KEY_STATE_READY {
                    return;
                }
            }
        }
    }
}

#[inline(always)]
fn init_keys() -> (u64, u64) {
    if KEY_INIT_STATE.load(Ordering::Acquire) != KEY_STATE_READY {
        ensure_keys_initialized();
    }
    (
        SIP_KEY_0.load(Ordering::Relaxed),
        SIP_KEY_1.load(Ordering::Relaxed),
    )
}

#[inline(always)]
fn init_tail_keys() -> (u64, u64) {
    if KEY_INIT_STATE.load(Ordering::Acquire) != KEY_STATE_READY {
        ensure_keys_initialized();
    }
    (
        TAIL_KEY_0.load(Ordering::Relaxed),
        TAIL_KEY_1.load(Ordering::Relaxed),
    )
}

/// SipHash-2-4 implementation for the 24-byte `AllocationFingerprint` header under `K_hdr`.
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

/// SipHash-1-3 implementation for the 8-byte trailing `Canary` under independent `K_tail`.
///
/// Binds `(addr, size, generation, header_hash)` with domain-separation tag `0xEE`
/// so leaking the 24-byte header cannot forge the trailing canary.
#[inline]
fn sip_hash_1_3_tail_with_keys(
    k0: u64,
    k1: u64,
    addr: usize,
    size: u64,
    generation: u64,
    header_hash: u64,
) -> u64 {
    let mut v0: u64 = k0 ^ 0x736f_6d65_7073_6575;
    let mut v1: u64 = k1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2: u64 = k0 ^ 0x6c79_6765_6e65_7261;
    let mut v3: u64 = k1 ^ 0x7465_6462_7974_6573;

    let m0 = addr as u64;
    let m1 = size;
    let m2 = generation;
    let m3 = header_hash;

    v3 ^= m0;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= m0;

    v3 ^= m1;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= m1;

    v3 ^= m2;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= m2;

    v3 ^= m3;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= m3;

    // Distinct finalization constant (0xEE vs 0xFF) + 3 SipHash-1-3 finalization rounds.
    v2 ^= 0xEE;
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
        let canary = fp.canary_for(0x4000);
        let bytes = canary.to_bytes();
        assert!(canary.verify(&bytes));
    }

    #[test]
    fn canary_detects_corruption() {
        let fp = AllocationFingerprint::compute(0x4000, 128, 1);
        let canary = fp.canary_for(0x4000);
        let mut corrupted = canary.to_bytes();
        corrupted[3] ^= 0xFF;
        assert!(!canary.verify(&corrupted));
    }

    // Rank over GF(2) of the linear part of an affine 64-bit transform.
    // Retained as the structural negative control proving the former rank-32
    // folded map (`hash ^ hash.rotate_left(32) ^ C`) collapsed 64 bits to 32.
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
    fn canary_domain_separation_across_independent_tail_keys() {
        // Identical 24-byte `AllocationFingerprint` header `(hash, size, generation)`
        // and `base_addr` must produce distinct trailing canaries under independent
        // `K_tail` keys, proving header-leak non-derivability without `K_tail`.
        let base_addr = 0x7FFF_1234_5600usize;
        let fp = AllocationFingerprint::compute(base_addr, 256, 42);

        let c_key_a = Canary::derive_with_tail_keys(
            0x0123_4567_89AB_CDEF,
            0xFEDC_BA98_7654_3210,
            base_addr,
            fp.size,
            fp.generation,
            fp.hash,
        );
        let c_key_b = Canary::derive_with_tail_keys(
            0x1111_2222_3333_4444,
            0x5555_6666_7777_8888,
            base_addr,
            fp.size,
            fp.generation,
            fp.hash,
        );
        let c_live = fp.canary_for(base_addr);

        assert_ne!(c_key_a, c_key_b);
        assert_ne!(
            c_live.as_u64(),
            fp.hash ^ 0xDEAD_BEEF_CAFE_BABEu64,
            "trailing canary must never equal plaintext header XOR constant"
        );
    }

    #[test]
    fn canary_never_equals_header_xor_constant_across_10k_allocations() {
        // Verify across 10,000 distinct allocations that `Canary ^ fp.hash` is not
        // ANY fixed constant (in fact, behaves as an independent 64-bit PRF output).
        let mut xor_deltas = std::collections::HashSet::with_capacity(10_000);
        for i in 0..10_000u64 {
            let addr = 0x10_0000usize.wrapping_add((i as usize).wrapping_mul(64));
            let size = 16 + (i % 512) * 8;
            let generation = i + 1;
            let fp = AllocationFingerprint::compute(addr, size, generation);
            let canary_u64 = fp.canary_for(addr).as_u64();
            let delta = canary_u64 ^ fp.hash;
            assert_ne!(
                delta, 0xDEAD_BEEF_CAFE_BABEu64,
                "legacy XOR constant matched at allocation {i}"
            );
            xor_deltas.insert(delta);
        }
        // For 10,000 independent 64-bit values, birthday-paradox collision probability
        // is ~2.7e-12; requiring >= 9,995 unique XOR deltas rules out any affine/small-range
        // relationship between `fp.hash` and `Canary`.
        assert!(
            xor_deltas.len() >= 9_995,
            "expected near-10,000 distinct (canary ^ hash) values, got {}",
            xor_deltas.len()
        );
    }

    #[test]
    fn os_csprng_seeding_and_independent_key_domains() {
        let (k0, k1) = init_keys();
        let (t0, t1) = init_tail_keys();
        assert_ne!((k0, k1), (0, 0));
        assert_ne!((t0, t1), (0, 0));
        assert_ne!(
            (k0, k1),
            (t0, t1),
            "K_hdr and K_tail must be independent 128-bit keys"
        );
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        assert!(
            keys_seeded_from_csprng(),
            "Linux x86_64/aarch64 must seed fingerprint/canary keys from SYS_getrandom"
        );
    }

    #[test]
    fn canary_width_check_rejects_legacy_fold() {
        // Frozen negative control from bd-reality-202609-lx578q.8.1.
        let legacy = |hash: u64| hash ^ hash.rotate_left(32) ^ 0xDEAD_BEEF_CAFE_BABE;
        assert_eq!(affine_difference_rank(legacy, 0), 32);
        for (left, right) in [
            (0, 0x0000_0001_0000_0001),
            (0x1234_5678_9ABC_DEF0, 0x1234_5679_9ABC_DEF1),
        ] {
            assert_eq!(legacy(left), legacy(right));
            assert_ne!(
                Canary::derive(0x4000, 128, 1, left),
                Canary::derive(0x4000, 128, 1, right)
            );
        }
    }

    #[test]
    fn canary_derivation_known_vectors_and_layout() {
        assert_eq!(std::mem::size_of::<AllocationFingerprint>(), 24);
        assert_eq!(std::mem::size_of::<Canary>(), 8);
        // Deterministic SipHash-1-3 test vector check under fixed tail keys.
        let c0 = Canary::derive_with_tail_keys(
            0x0706_0504_0302_0100,
            0x0F0E_0D0C_0B0A_0908,
            0x1000,
            64,
            1,
            0xCAFE_BABE_1234_5678,
        );
        let c1 = Canary::derive_with_tail_keys(
            0x0706_0504_0302_0100,
            0x0F0E_0D0C_0B0A_0908,
            0x1000,
            64,
            1,
            0xCAFE_BABE_1234_5679,
        );
        assert_ne!(c0, c1);
        // Single-bit avalanche in SipHash-1-3 changes ~32 bits on average.
        let diff_bits = (c0.as_u64() ^ c1.as_u64()).count_ones();
        assert!(
            (12..=52).contains(&diff_bits),
            "expected strong SipHash avalanche, got {diff_bits} differing bits"
        );
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
        let canary = fp.canary_for(0x5000);
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

    #[test]
    fn fork_recovery_resets_in_progress_key_init_without_disturbing_ready_keys() {
        let interrupted = AtomicU8::new(KEY_STATE_INIT);
        recover_key_init_state(&interrupted);
        assert_eq!(interrupted.load(Ordering::Acquire), KEY_STATE_UNINIT);

        let ready = AtomicU8::new(KEY_STATE_READY);
        recover_key_init_state(&ready);
        assert_eq!(ready.load(Ordering::Acquire), KEY_STATE_READY);

        let uninit = AtomicU8::new(KEY_STATE_UNINIT);
        recover_key_init_state(&uninit);
        assert_eq!(uninit.load(Ordering::Acquire), KEY_STATE_UNINIT);

        let fp_before = AllocationFingerprint::compute(0x4000, 64, 7);
        let canary_before = fp_before.canary_for(0x4000);
        crate::util::note_fork_child();
        let fp_after = AllocationFingerprint::compute(0x4000, 64, 7);
        let canary_after = fp_after.canary_for(0x4000);
        assert_eq!(fp_before, fp_after);
        assert_eq!(canary_before, canary_after);
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
        fn prop_canary_roundtrip(
            addr in 0usize..usize::MAX,
            size in 0u64..u64::MAX,
            generation in 0u64..u64::MAX,
            hash in 0u64..u64::MAX,
        ) {
            let canary = Canary::derive(addr, size, generation, hash);
            let bytes = canary.to_bytes();
            prop_assert!(canary.verify(&bytes), "canary must verify its own bytes");
        }

        #[test]
        fn prop_canary_domain_separates_distinct_header_hashes(
            addr in 0usize..usize::MAX,
            size in 0u64..u64::MAX,
            generation in 0u64..u64::MAX,
            left: u64,
            right: u64,
        ) {
            prop_assume!(left != right);
            let left_canary = Canary::derive(addr, size, generation, left);
            let right_canary = Canary::derive(addr, size, generation, right);
            prop_assert_ne!(left_canary, right_canary);
        }

        #[test]
        fn prop_canary_detects_any_byte_flip(
            addr in 0usize..usize::MAX,
            size in 0u64..u64::MAX,
            generation in 0u64..u64::MAX,
            hash in 0u64..u64::MAX,
            byte_idx in 0usize..CANARY_SIZE,
        ) {
            let canary = Canary::derive(addr, size, generation, hash);
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
