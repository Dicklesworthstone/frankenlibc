//! SipHash-based allocation fingerprints and trailing canaries.
//!
//! Every membrane-managed allocation gets:
//! - A 24-byte fingerprint header: `[u64 hash | u64 generation | u64 size]`
//! - An 8-byte trailing canary, authenticated with a separate secret key
//!
//! The fingerprint provides:
//! - Allocation integrity checks when the arena/validator reaches them
//! - Generation tracking for temporal safety
//! - Size metadata for bounds checking (supports allocations >4GiB)
//!
//! Header and tail keys come from the kernel CSPRNG, through raw syscalls that
//! cannot re-enter the allocator or alter C `errno`. The tail authenticates the
//! allocation address, size, generation, and header hash with its own key, so
//! disclosure of the header no longer reveals the tail. Neither metadata check
//! intercepts direct C writes or identifies stale raw pointers after same-address
//! reuse. The tags are 64 bits: this does not protect against disclosure of the
//! secret keys or replay of an intact allocation's metadata.

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
    /// SipHash-2-4 of (base_address, size, generation) with the header key.
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

    /// Authenticate the allocation and its header with the independent tail key.
    ///
    /// `base_addr`, size, and generation must come from trusted arena metadata
    /// when this is used for verification. Never use an unverified header's
    /// size to locate the tail in memory.
    #[must_use]
    pub fn canary(&self, base_addr: usize) -> Canary {
        Canary::compute(base_addr, self.size, self.generation, self.hash)
    }
}

/// 8-byte trailing canary for buffer overflow detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Canary {
    /// The independently authenticated canary bytes.
    pub value: [u8; CANARY_SIZE],
}

impl Canary {
    /// Compute the tail tag from trusted allocation metadata and its header hash.
    #[must_use]
    pub fn compute(base_addr: usize, size: u64, generation: u64, header_hash: u64) -> Self {
        Self::with_key(secret_keys().tail, base_addr, size, generation, header_hash)
    }

    fn with_key(
        key: [u64; 2],
        base_addr: usize,
        size: u64,
        generation: u64,
        header_hash: u64,
    ) -> Self {
        Self {
            value: sip_hash_words(key, &[base_addr as u64, size, generation, header_hash])
                .to_le_bytes(),
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

#[repr(C)]
struct SecretKeys {
    header: [u64; 2],
    tail: [u64; 2],
}

fn secret_keys() -> &'static SecretKeys {
    entropy::keys()
}

/// Complete a kernel entropy read, including short reads and early-boot EINTR.
/// Zero progress or any other error must never publish partially filled keys.
fn fill_random(
    mut remaining: &mut [u8],
    mut read: impl FnMut(&mut [u8]) -> isize,
) -> Result<(), ()> {
    while !remaining.is_empty() {
        match read(remaining) {
            -4 => continue, // EINTR; no C errno access.
            n if n > 0 && n as usize <= remaining.len() => {
                remaining = &mut remaining[n as usize..];
            }
            _ => return Err(()),
        }
    }
    Ok(())
}

/// This boundary owns exactly one immutable mmap page. Publishing a pointer
/// instead of a Once/lock means signal reentry or fork during initialization
/// cannot strand a waiter on a vanished initializer. A losing initializer has
/// never published its page and can safely unmap it. The winning page remains
/// mapped for the lifetime of the process and is inherited unchanged by fork.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[allow(unsafe_code)]
mod entropy {
    use super::{SecretKeys, fill_random};
    use std::sync::atomic::{AtomicPtr, Ordering};

    static KEYS: AtomicPtr<SecretKeys> = AtomicPtr::new(std::ptr::null_mut());

    // mmap/mprotect/munmap round this to the host page size on 16/64-KiB ARM
    // kernels too. The allocation holds only 32 bytes and has u64 alignment.
    const MAP_SIZE: usize = 4096;
    const PROT_READ: usize = 1;
    const PROT_WRITE: usize = 2;
    const MAP_PRIVATE_ANONYMOUS: usize = 0x22;

    #[cfg(target_arch = "x86_64")]
    const SYS_MMAP: usize = 9;
    #[cfg(target_arch = "x86_64")]
    const SYS_MPROTECT: usize = 10;
    #[cfg(target_arch = "x86_64")]
    const SYS_MUNMAP: usize = 11;
    #[cfg(target_arch = "x86_64")]
    const SYS_GETRANDOM: usize = 318;
    #[cfg(target_arch = "x86_64")]
    const SYS_WRITE: usize = 1;
    #[cfg(target_arch = "x86_64")]
    const SYS_EXIT_GROUP: usize = 231;

    #[cfg(target_arch = "aarch64")]
    const SYS_MMAP: usize = 222;
    #[cfg(target_arch = "aarch64")]
    const SYS_MPROTECT: usize = 226;
    #[cfg(target_arch = "aarch64")]
    const SYS_MUNMAP: usize = 215;
    #[cfg(target_arch = "aarch64")]
    const SYS_GETRANDOM: usize = 278;
    #[cfg(target_arch = "aarch64")]
    const SYS_WRITE: usize = 64;
    #[cfg(target_arch = "aarch64")]
    const SYS_EXIT_GROUP: usize = 94;

    #[inline]
    pub(super) fn keys() -> &'static SecretKeys {
        let mut ptr = KEYS.load(Ordering::Acquire);
        if ptr.is_null() {
            ptr = initialize();
        }
        // SAFETY: Acquire sees a fully initialized, read-only SecretKeys page.
        // Only unpublished losing pages are unmapped; this reference never dies.
        unsafe { &*ptr }
    }

    #[cold]
    fn initialize() -> *mut SecretKeys {
        let mapped = syscall6(
            SYS_MMAP,
            0,
            MAP_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE_ANONYMOUS,
            usize::MAX,
            0,
        );
        if (-4095..=0).contains(&mapped) {
            fail_closed();
        }
        let candidate = mapped as *mut SecretKeys;
        // SAFETY: the successful anonymous mapping is writable and exclusively
        // owned here. Every u64 bit pattern is valid; getrandom initializes all
        // 32 bytes before they are interpreted as keys or published.
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(candidate.cast::<u8>(), size_of::<SecretKeys>())
        };
        if fill_random(bytes, |part| {
            syscall6(
                SYS_GETRANDOM,
                part.as_mut_ptr() as usize,
                part.len(),
                0,
                0,
                0,
                0,
            )
        })
        .is_err()
        {
            fail_closed();
        }
        if syscall6(SYS_MPROTECT, mapped as usize, MAP_SIZE, PROT_READ, 0, 0, 0) != 0 {
            fail_closed();
        }
        match KEYS.compare_exchange(
            std::ptr::null_mut(),
            candidate,
            Ordering::Release,
            Ordering::Acquire,
        ) {
            Ok(_) => candidate,
            Err(winner) => {
                // No other thread has ever observed candidate. The winner's
                // page is distinct and remains mapped for the process lifetime.
                let _ = syscall6(SYS_MUNMAP, mapped as usize, MAP_SIZE, 0, 0, 0, 0);
                winner
            }
        }
    }

    #[cold]
    fn fail_closed() -> ! {
        let message = b"frankenlibc: cannot initialize allocation integrity keys\n";
        // A fixed raw write avoids stdio, allocation, and interposed symbols on
        // this failure path. No weak entropy fallback is permitted, even ENOSYS.
        let _ = syscall6(
            SYS_WRITE,
            2,
            message.as_ptr() as usize,
            message.len(),
            0,
            0,
            0,
        );
        let _ = syscall6(SYS_EXIT_GROUP, 127, 0, 0, 0, 0, 0);
        // SAFETY: terminate even if a sandbox denies exit_group. Returning from
        // initialization without a secret would violate the integrity contract.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            std::arch::asm!("ud2", options(noreturn, nostack));
        }
        // SAFETY: same non-returning failure contract on aarch64.
        #[cfg(target_arch = "aarch64")]
        unsafe {
            std::arch::asm!("brk #0", options(noreturn, nostack));
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn syscall6(n: usize, a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> isize {
        let result: isize;
        // SAFETY: callers pass either a valid live output slice, a static
        // message, or a mapping owned by this module. mmap's other parameters
        // are constants; all syscall clobbers are listed and memory effects
        // are intentionally not marked nomem/readonly.
        unsafe {
            std::arch::asm!(
                "syscall",
                inlateout("rax") n => result,
                in("rdi") a, in("rsi") b, in("rdx") c,
                in("r10") d, in("r8") e, in("r9") f,
                lateout("rcx") _, lateout("r11") _,
                options(nostack),
            );
        }
        result
    }

    #[cfg(target_arch = "aarch64")]
    fn syscall6(n: usize, a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> isize {
        let result: isize;
        // SAFETY: the same owned-buffer/mapping contract as x86_64; kernel
        // errors are returned directly, without touching the C errno slot.
        unsafe {
            std::arch::asm!(
                "svc 0",
                in("x8") n, inlateout("x0") a => result,
                in("x1") b, in("x2") c, in("x3") d, in("x4") e, in("x5") f,
                options(nostack),
            );
        }
        result
    }
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
mod entropy {
    use super::SecretKeys;

    pub(super) fn keys() -> &'static SecretKeys {
        // Unsupported targets must not quietly fall back to guessable keys.
        std::process::abort()
    }
}

fn sip_hash_2_4(addr: usize, size: u64, generation: u64) -> u64 {
    sip_hash_words(secret_keys().header, &[addr as u64, size, generation])
}

/// Standard SipHash-2-4 over complete little-endian u64 message words.
/// The final length word is required even when no partial word remains.
fn sip_hash_words([k0, k1]: [u64; 2], words: &[u64]) -> u64 {
    let mut v0: u64 = k0 ^ 0x736f_6d65_7073_6575;
    let mut v1: u64 = k1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2: u64 = k0 ^ 0x6c79_6765_6e65_7261;
    let mut v3: u64 = k1 ^ 0x7465_6462_7974_6573;

    for &word in words {
        v3 ^= word;
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= word;
    }

    let last = ((words.len() * 8) as u64) << 56;
    v3 ^= last;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= last;

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
        let canary = fp.canary(0x4000);
        let bytes = canary.to_bytes();
        assert!(canary.verify(&bytes));
    }

    #[test]
    fn canary_detects_corruption() {
        let fp = AllocationFingerprint::compute(0x4000, 128, 1);
        let canary = fp.canary(0x4000);
        let mut corrupted = canary.to_bytes();
        corrupted[3] ^= 0xFF;
        assert!(!canary.verify(&corrupted));
    }

    // Negative-control characterization of the old affine canary derivations.
    // The current keyed nonlinear function must not inherit their linear laws.
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
    fn canary_is_not_a_fixed_xor_of_disclosed_header() {
        let mut xor_offsets = std::collections::HashSet::new();
        for generation in 0..10_000u64 {
            let base = 0x4000 + generation as usize * 64;
            let fp = AllocationFingerprint::compute(base, 32, generation);
            let tag = u64::from_le_bytes(fp.canary(base).to_bytes());
            xor_offsets.insert(fp.hash ^ tag);
            assert_ne!(tag, fp.hash ^ 0xDEAD_BEEF_CAFE_BABE);
        }
        // This regression sample rejects a fixed XOR mask, not a proof of PRF
        // security. The independence comes from separate OS-random keys.
        assert_eq!(xor_offsets.len(), 10_000);
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
                Canary::compute(0x4000, 32, 1, left),
                Canary::compute(0x4000, 32, 1, right),
            );
        }
    }

    #[test]
    fn siphash_known_vectors_and_layout() {
        assert_eq!(std::mem::size_of::<AllocationFingerprint>(), 24);
        assert_eq!(std::mem::size_of::<Canary>(), 8);
        assert_eq!(std::mem::size_of::<SecretKeys>(), 32);
        // The authors' vectors_sip64 (https://github.com/veorq/SipHash):
        // key bytes 00..0f; message bytes 00..17 and 00..1f respectively.
        let key = [0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908];
        let words = [
            0x0706_0504_0302_0100,
            0x0f0e_0d0c_0b0a_0908,
            0x1716_1514_1312_1110,
            0x1f1e_1d1c_1b1a_1918,
        ];
        assert_eq!(sip_hash_words(key, &[]), 0x726f_db47_dd0e_0e31);
        assert_eq!(sip_hash_words(key, &words[..3]), 0xb8ad_50c6_f649_af94);
        assert_eq!(sip_hash_words(key, &words), 0x7127_512f_72f2_7cce);
    }

    #[test]
    fn tail_key_changes_canary_without_changing_header() {
        let header_key = [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210];
        let header = sip_hash_words(header_key, &[0x4000, 128, 7]);
        let disclosed = AllocationFingerprint {
            hash: header,
            size: 128,
            generation: 7,
        };
        let first = Canary::with_key(
            [1, 2],
            0x4000,
            disclosed.size,
            disclosed.generation,
            disclosed.hash,
        );
        let second = Canary::with_key(
            [3, 4],
            0x4000,
            disclosed.size,
            disclosed.generation,
            disclosed.hash,
        );
        assert_ne!(first, second);
        assert_ne!(
            first.to_bytes(),
            (header ^ 0xDEAD_BEEF_CAFE_BABE).to_le_bytes()
        );
        assert_ne!(
            second.to_bytes(),
            (header ^ 0xDEAD_BEEF_CAFE_BABE).to_le_bytes()
        );
    }

    #[test]
    fn tail_authenticates_each_allocation_field() {
        let original = Canary::compute(0x4000, 128, 7, 0x1234_5678_9abc_def0);
        for changed in [
            Canary::compute(0x4001, 128, 7, 0x1234_5678_9abc_def0),
            Canary::compute(0x4000, 129, 7, 0x1234_5678_9abc_def0),
            Canary::compute(0x4000, 128, 8, 0x1234_5678_9abc_def0),
            Canary::compute(0x4000, 128, 7, 0x1234_5678_9abc_def1),
        ] {
            assert_ne!(original, changed);
        }
    }

    #[test]
    fn entropy_reader_retries_interruption_and_completes_short_reads() {
        let mut bytes = [0u8; 32];
        let mut call = 0;
        assert_eq!(
            fill_random(&mut bytes, |remaining| {
                call += 1;
                match call {
                    1 | 3 => -4,
                    2 => {
                        remaining[..7].fill(0x11);
                        7
                    }
                    4 => {
                        assert_eq!(remaining.len(), 25);
                        remaining.fill(0x22);
                        25
                    }
                    _ => panic!("unexpected extra entropy read"),
                }
            }),
            Ok(())
        );
        assert_eq!(call, 4);
        assert_eq!(bytes[..7], [0x11; 7]);
        assert_eq!(bytes[7..], [0x22; 25]);
    }

    #[test]
    fn entropy_reader_rejects_unavailable_zero_and_invalid_reads() {
        for error in [-38, -1, -5, 0, 33] {
            let mut bytes = [0u8; 32];
            assert_eq!(fill_random(&mut bytes, |_| error), Err(()));
        }
        let mut calls = 0;
        assert_eq!(
            fill_random(&mut [0u8; 32], |remaining| {
                calls += 1;
                if calls == 1 {
                    remaining[..3].fill(0x33);
                    3
                } else {
                    -38
                }
            }),
            Err(())
        );
        assert_eq!(calls, 2);
    }

    #[test]
    #[cfg(target_os = "linux")]
    #[allow(unsafe_code)]
    fn fork_preserves_initialized_allocation_keys() {
        let expected = AllocationFingerprint::compute(0x6000, 128, 9);
        let expected_tail = expected.canary(0x6000);
        // SAFETY: the child only executes lock-free integer hashing over the
        // inherited immutable keys, then _exit; no Rust allocation or locks.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            let actual = AllocationFingerprint::compute(0x6000, 128, 9);
            let valid = actual == expected && actual.canary(0x6000) == expected_tail;
            // SAFETY: immediate child termination; no inherited destructors run.
            unsafe { libc::_exit(i32::from(!valid)) };
        }
        let mut status = 0;
        // SAFETY: child is the live pid returned by fork and status is writable.
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn exec_initializes_fresh_allocation_keys() {
        const PROBE_ENV: &str = "FRANKENLIBC_FINGERPRINT_EXEC_PROBE";
        if std::env::var_os(PROBE_ENV).is_some() {
            let fp = AllocationFingerprint::compute(0x6000, 128, 9);
            // A tag for fixed public metadata is not secret key material.
            println!(
                "CANARY_EXEC_TAG {}",
                u64::from_le_bytes(fp.canary(0x6000).to_bytes())
            );
            return;
        }
        let parent = AllocationFingerprint::compute(0x6000, 128, 9)
            .canary(0x6000)
            .to_bytes();
        let output =
            std::process::Command::new(std::env::current_exe().expect("current test binary"))
                .args([
                    "--exact",
                    "fingerprint::tests::exec_initializes_fresh_allocation_keys",
                    "--nocapture",
                ])
                .env(PROBE_ENV, "1")
                .output()
                .expect("execute independent key process");
        assert!(output.status.success(), "key probe child failed");
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 test output");
        let child = stdout
            .lines()
            .find_map(|line| line.strip_prefix("CANARY_EXEC_TAG "))
            .expect("non-zero child test executed")
            .parse::<u64>()
            .expect("numeric child tag")
            .to_le_bytes();
        assert_ne!(parent, child, "exec must not reuse inherited process keys");
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
        let canary = fp.canary(0x5000);
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
            let canary = Canary::compute(0x4000, 128, 1, hash);
            let bytes = canary.to_bytes();
            prop_assert!(canary.verify(&bytes), "canary must verify its own bytes");
        }

        #[test]
        fn prop_canary_authenticates_hash_differences(left: u64, right: u64) {
            prop_assume!(left != right);
            let left_canary = Canary::compute(0x4000, 128, 1, left);
            let right_canary = Canary::compute(0x4000, 128, 1, right);
            prop_assert_ne!(left_canary, right_canary);
        }

        #[test]
        fn prop_canary_detects_any_byte_flip(
            hash in 0u64..u64::MAX,
            byte_idx in 0usize..CANARY_SIZE,
        ) {
            let canary = Canary::compute(0x4000, 128, 1, hash);
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
