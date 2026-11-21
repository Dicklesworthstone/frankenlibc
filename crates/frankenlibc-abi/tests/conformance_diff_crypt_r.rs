#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-libcrypt (libxcrypt) crypt_r oracle

//! Differential gate for crypt_r (bd-c1gtzh) — the reentrant crypt had no
//! differential gate. crypt_r writes into the caller's struct crypt_data and
//! returns a pointer into it. Like crypt, the host (libxcrypt) never returns
//! NULL: unsupported/invalid settings yield the "*0"/"*1" failure token. fl's
//! crypt_r delegates to crypt (fixed in bd-r9ihvq), so it should match. Each
//! impl uses its own large data buffer (covering struct crypt_data on either
//! libc). Compares the result strings for failure tokens and a supported
//! scheme. No mocks.

use std::ffi::{CStr, CString, c_char, c_int, c_void};

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: std::ffi::c_int) -> *mut std::ffi::c_void;
    fn dlsym(handle: *mut std::ffi::c_void, symbol: *const c_char) -> *mut std::ffi::c_void;
    fn dlvsym(handle: *mut c_void, symbol: *const c_char, version: *const c_char) -> *mut c_void;
}

type CryptRFn =
    unsafe extern "C" fn(*const c_char, *const c_char, *mut std::ffi::c_void) -> *mut c_char;

/// Resolve host libxcrypt's `crypt_r` at RUNTIME.
///
/// This target used a bare `extern "C" { fn crypt_r(..) }` and did not link:
///   rust-lld: error: undefined symbol: crypt_r
/// Nothing pulled in libcrypt, so the whole gate was DARK on the fleet — silent,
/// not green.
///
/// Linking `-lcrypt` would not have been the right fix either. fl exports its
/// own `crypt_r` under `#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]`,
/// so in a RELEASE build a bare extern resolves to FL'S OWN SYMBOL and the
/// "host" arm would silently compare fl against itself — a gate that can only
/// pass. dlopen/dlsym against libcrypt.so.1 is the only way to get a real
/// oracle, and it also sidesteps the missing libcrypt.so dev symlink on the
/// workers. Same approach as conformance_diff_crypt_failure_token.
fn host_crypt_r() -> CryptRFn {
    static F: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let addr = *F.get_or_init(|| {
        const RTLD_NOW: std::ffi::c_int = 2;
        // SAFETY: constant, NUL-terminated library and symbol names.
        let h = unsafe { dlopen(c"libcrypt.so.1".as_ptr(), RTLD_NOW) };
        assert!(!h.is_null(), "dlopen libcrypt.so.1 failed");
        let p = unsafe { dlsym(h, c"crypt_r".as_ptr()) };
        assert!(!p.is_null(), "dlsym crypt_r failed");
        p as usize
    });
    // SAFETY: dlsym returned a non-null pointer to crypt_r, whose signature is
    // fixed by the libxcrypt ABI.
    unsafe { std::mem::transmute::<usize, CryptRFn>(addr) }
}

/// Same call shape as the old extern, so call sites are unchanged.
unsafe fn crypt_r(
    key: *const c_char,
    salt: *const c_char,
    data: *mut std::ffi::c_void,
) -> *mut c_char {
    unsafe { host_crypt_r()(key, salt, data) }
}

// Generous buffer: glibc's struct crypt_data is ~128 KiB; libxcrypt's is small.
// 256 KiB safely covers either as the crypt_r data argument.
const DATA_SIZE: usize = 256 * 1024;

fn host(key: &str, salt: &str) -> Option<String> {
    let k = CString::new(key).unwrap();
    let s = CString::new(salt).unwrap();
    let mut data = vec![0u8; DATA_SIZE];
    let p = unsafe {
        crypt_r(
            k.as_ptr(),
            s.as_ptr(),
            data.as_mut_ptr() as *mut std::ffi::c_void,
        )
    };
    if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}
fn fl(key: &str, salt: &str) -> Option<String> {
    let k = CString::new(key).unwrap();
    let s = CString::new(salt).unwrap();
    let mut data = vec![0u8; DATA_SIZE];
    let p = unsafe {
        frankenlibc_abi::unistd_abi::crypt_r(
            k.as_ptr(),
            s.as_ptr(),
            data.as_mut_ptr() as *mut std::ffi::c_void,
        )
    };
    if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}

#[test]
fn crypt_r_failure_token_matches_host() {
    for salt in ["$z$badscheme", "!", "", "*0", "*1"] {
        let h = host("password", salt);
        let f = fl("password", salt);
        assert!(h.is_some(), "host crypt_r(pw, {salt:?}) unexpectedly NULL");
        let ht = h.unwrap();
        assert!(
            ht.starts_with('*'),
            "host crypt_r token for {salt:?} = {ht:?}"
        );
        assert_eq!(
            f,
            Some(ht.clone()),
            "crypt_r(pw, {salt:?}): fl={f:?} host={ht:?}"
        );
    }
}

#[test]
fn crypt_r_supported_scheme_matches_host() {
    let salt = "$6$saltsalt$";
    let f = fl("password", salt).expect("fl crypt_r should hash $6$");
    assert!(
        f.starts_with(salt) && !f.starts_with('*'),
        "fl crypt_r({salt:?})={f:?}"
    );
    assert_eq!(
        Some(&f),
        host("password", salt).as_ref(),
        "fl vs host crypt_r hash for {salt:?}"
    );
}

// The legacy DES block entrypoints share the caller-owned crypt_data surface
// with crypt_r. Resolve their live compatibility symbols rather than binding
// an extern that could silently resolve to FrankenLibC itself in release mode.
type SetkeyFn = unsafe extern "C" fn(*const c_char);
type EncryptFn = unsafe extern "C" fn(*mut c_char, c_int);
type SetkeyRFn = unsafe extern "C" fn(*const c_char, *mut c_void);
type EncryptRFn = unsafe extern "C" fn(*mut c_char, c_int, *mut c_void);

static DES_GLOBAL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn host_des_functions() -> (SetkeyFn, EncryptFn, SetkeyRFn, EncryptRFn) {
    static ADDRESSES: std::sync::OnceLock<[usize; 4]> = std::sync::OnceLock::new();
    let addresses = ADDRESSES.get_or_init(|| {
        // SAFETY: all library, symbol, and version names are static C strings.
        let handle = unsafe { dlopen(c"libcrypt.so.1".as_ptr(), libc::RTLD_NOW) };
        assert!(!handle.is_null(), "DES oracle requires libcrypt.so.1");
        let symbols = [c"setkey", c"encrypt", c"setkey_r", c"encrypt_r"];
        let candidate = [
            frankenlibc_abi::unistd_abi::setkey as *const () as usize,
            frankenlibc_abi::unistd_abi::encrypt as *const () as usize,
            frankenlibc_abi::unistd_abi::setkey_r as *const () as usize,
            frankenlibc_abi::unistd_abi::encrypt_r as *const () as usize,
        ];
        std::array::from_fn(|index| {
            // SAFETY: handle stays loaded and each symbol is NUL-terminated.
            let mut symbol = unsafe { dlsym(handle, symbols[index].as_ptr()) };
            for version in [c"GLIBC_2.2.5", c"GLIBC_2.17", c"GLIBC_2.0", c"XCRYPT_2.0"] {
                if !symbol.is_null() {
                    break;
                }
                // SAFETY: the handle is live; symbol and version are C strings.
                symbol = unsafe { dlvsym(handle, symbols[index].as_ptr(), version.as_ptr()) };
            }
            assert!(!symbol.is_null(), "missing DES oracle {:?}", symbols[index]);
            assert_ne!(
                symbol as usize, candidate[index],
                "oracle resolved to candidate"
            );
            symbol as usize
        })
    });
    // SAFETY: each address was resolved for the corresponding fixed C ABI;
    // the library handle is deliberately retained for the process lifetime.
    unsafe {
        (
            std::mem::transmute::<usize, SetkeyFn>(addresses[0]),
            std::mem::transmute::<usize, EncryptFn>(addresses[1]),
            std::mem::transmute::<usize, SetkeyRFn>(addresses[2]),
            std::mem::transmute::<usize, EncryptRFn>(addresses[3]),
        )
    }
}

fn des_bits(value: u64) -> [c_char; 64] {
    std::array::from_fn(|index| ((value >> (63 - index)) & 1) as c_char)
}

fn des_word(bits: &[c_char]) -> u64 {
    assert_eq!(bits.len(), 64);
    bits.iter().fold(0, |value, &bit| {
        assert!(bit == 0 || bit == 1, "DES output must remain a bit vector");
        (value << 1) | bit as u64
    })
}

#[test]
fn des_block_known_answer_and_reverse_preserve_errno_and_bounds() {
    let _guard = DES_GLOBAL_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let key = des_bits(0x1334_5779_9bbc_dff1);
    let plaintext = 0x0123_4567_89ab_cdef;
    let ciphertext = 0x85e8_1354_0f0a_b405;
    let mut block = [0x5a as c_char; 66];
    block[1..65].copy_from_slice(&des_bits(plaintext));
    // SAFETY: each key/block has 64 readable/writable bit bytes. The extra
    // bytes around block are canaries, outside the API's writable extent.
    unsafe {
        frankenlibc_abi::errno_abi::set_abi_errno(libc::E2BIG);
        frankenlibc_abi::unistd_abi::setkey(key.as_ptr());
        frankenlibc_abi::unistd_abi::encrypt(block.as_mut_ptr().add(1), 0);
        assert_eq!(*frankenlibc_abi::errno_abi::__errno_location(), libc::E2BIG);
    }
    assert_eq!(des_word(&block[1..65]), ciphertext, "FIPS DES known answer");
    assert_eq!((block[0], block[65]), (0x5a, 0x5a));
    // SAFETY: the same 64-byte block remains readable and writable.
    unsafe { frankenlibc_abi::unistd_abi::encrypt(block.as_mut_ptr().add(1), 1) };
    assert_eq!(des_word(&block[1..65]), plaintext);
    assert_eq!((block[0], block[65]), (0x5a, 0x5a));
    let inherited_key_result = std::thread::spawn(move || {
        let mut block = des_bits(plaintext);
        // SAFETY: the global key was installed before starting this thread;
        // the block is a writable 64-byte bit vector.
        unsafe { frankenlibc_abi::unistd_abi::encrypt(block.as_mut_ptr(), 0) };
        des_word(&block)
    })
    .join()
    .unwrap();
    assert_eq!(
        inherited_key_result, ciphertext,
        "setkey state is process-global"
    );
}

#[test]
fn des_block_and_reentrant_paths_match_live_libcrypt() {
    let _guard = DES_GLOBAL_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let (host_setkey, host_encrypt, host_setkey_r, host_encrypt_r) = host_des_functions();
    let mut host_data = vec![0u8; DATA_SIZE];
    let mut candidate_data = vec![0u8; DATA_SIZE];
    let mut seed = 0x831c_a539_6f72_40bdu64;
    for case in 0..96 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let key = des_bits(seed);
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let input = des_bits(seed);
        // All nonzero direction flags decrypt on the GNU compatibility ABI.
        for direction in [0, 1, -1, 2] {
            let mut expected = input;
            let mut expected_r = input;
            let mut actual = input;
            let mut actual_r = input;
            // SAFETY: vectors have 64 bit bytes and each independent data
            // allocation exceeds the largest documented crypt_data layout.
            unsafe {
                host_setkey(key.as_ptr());
                host_encrypt(expected.as_mut_ptr(), direction);
                host_setkey_r(key.as_ptr(), host_data.as_mut_ptr().cast());
                host_encrypt_r(
                    expected_r.as_mut_ptr(),
                    direction,
                    host_data.as_mut_ptr().cast(),
                );
                frankenlibc_abi::unistd_abi::setkey(key.as_ptr());
                frankenlibc_abi::unistd_abi::encrypt(actual.as_mut_ptr(), direction);
                frankenlibc_abi::unistd_abi::setkey_r(
                    key.as_ptr(),
                    candidate_data.as_mut_ptr().cast(),
                );
                frankenlibc_abi::unistd_abi::encrypt_r(
                    actual_r.as_mut_ptr(),
                    direction,
                    candidate_data.as_mut_ptr().cast(),
                );
            }
            assert_eq!(expected_r, expected, "host global/reentrant case {case}");
            assert_eq!(
                actual, expected,
                "global case {case}, direction {direction}"
            );
            assert_eq!(
                actual_r, expected,
                "reentrant case {case}, direction {direction}"
            );
        }
    }
}

#[test]
fn des_reentrant_contexts_copy_rekey_and_ignore_key_parity() {
    let _guard = DES_GLOBAL_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let first_key = des_bits(0x1334_5779_9bbc_dff1);
    let parity_key = des_bits(0x1334_5779_9bbc_dff1 ^ 0x0101_0101_0101_0101);
    let zero_key = des_bits(0);
    let mut first = vec![0u8; DATA_SIZE];
    let mut second = vec![0u8; DATA_SIZE];
    // SAFETY: independent caller-owned context buffers and fixed-size keys.
    unsafe {
        frankenlibc_abi::errno_abi::set_abi_errno(libc::E2BIG);
        frankenlibc_abi::unistd_abi::setkey_r(first_key.as_ptr(), first.as_mut_ptr().cast());
        frankenlibc_abi::unistd_abi::setkey_r(zero_key.as_ptr(), second.as_mut_ptr().cast());
        assert_eq!(*frankenlibc_abi::errno_abi::__errno_location(), libc::E2BIG);
        frankenlibc_abi::unistd_abi::setkey(zero_key.as_ptr());
    }
    let mut copied = first.clone();
    // crypt_r publishes into crypt_data.output. Its unrelated password-hash
    // result must not overwrite an initialized DES key in private workspace.
    // SAFETY: both strings are terminated; first is a full crypt_data buffer.
    let hash = unsafe {
        frankenlibc_abi::unistd_abi::crypt_r(
            c"password".as_ptr(),
            c"$6$rounds=1000$salt$".as_ptr(),
            first.as_mut_ptr().cast(),
        )
    };
    assert!(!hash.is_null());
    // SAFETY: crypt_r returned its terminated result in the live first buffer.
    assert!(
        unsafe { CStr::from_ptr(hash) }
            .to_bytes()
            .starts_with(b"$6$")
    );
    for data in [&mut first, &mut copied] {
        let mut block = des_bits(0x0123_4567_89ab_cdef);
        // SAFETY: each context owns its initialized state and block has 64 bytes.
        unsafe {
            frankenlibc_abi::errno_abi::set_abi_errno(libc::E2BIG);
            frankenlibc_abi::unistd_abi::encrypt_r(block.as_mut_ptr(), 0, data.as_mut_ptr().cast());
            assert_eq!(*frankenlibc_abi::errno_abi::__errno_location(), libc::E2BIG);
        }
        assert_eq!(
            des_word(&block),
            0x85e8_1354_0f0a_b405,
            "context owns its key"
        );
    }
    let mut zero_block = des_bits(0);
    // SAFETY: second is initialized and all key/block vectors have 64 bytes.
    unsafe {
        frankenlibc_abi::unistd_abi::encrypt_r(
            zero_block.as_mut_ptr(),
            0,
            second.as_mut_ptr().cast(),
        );
        frankenlibc_abi::unistd_abi::setkey_r(parity_key.as_ptr(), second.as_mut_ptr().cast());
    }
    assert_eq!(des_word(&zero_block), 0x8ca6_4de9_c1b1_23a7);
    let mut block = des_bits(0x0123_4567_89ab_cdef);
    // SAFETY: the same context was rekeyed and the new block is fully writable.
    unsafe {
        frankenlibc_abi::unistd_abi::encrypt_r(block.as_mut_ptr(), 0, second.as_mut_ptr().cast());
    }
    assert_eq!(
        des_word(&block),
        0x85e8_1354_0f0a_b405,
        "key parity is ignored"
    );
    let workers: Vec<_> = [first, copied, second]
        .into_iter()
        .map(|mut data| {
            std::thread::spawn(move || {
                for _ in 0..16 {
                    let mut block = des_bits(0x0123_4567_89ab_cdef);
                    // SAFETY: each thread exclusively owns its copied context
                    // and its writable 64-byte block.
                    unsafe {
                        frankenlibc_abi::unistd_abi::encrypt_r(
                            block.as_mut_ptr(),
                            0,
                            data.as_mut_ptr().cast(),
                        );
                    }
                    assert_eq!(des_word(&block), 0x85e8_1354_0f0a_b405);
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn des_rejects_invalid_state_and_inputs_without_partial_output() {
    let _guard = DES_GLOBAL_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let key = des_bits(0x1334_5779_9bbc_dff1);
    let mut data = vec![0u8; DATA_SIZE];
    let mut block = des_bits(0x0123_4567_89ab_cdef);
    let original = block;
    // SAFETY: all extents are valid and initialized; the API explicitly rejects
    // a zeroed context until its matching setkey_r installs a key.
    unsafe {
        frankenlibc_abi::errno_abi::set_abi_errno(0);
        frankenlibc_abi::unistd_abi::encrypt_r(block.as_mut_ptr(), 0, data.as_mut_ptr().cast());
        assert_eq!(
            *frankenlibc_abi::errno_abi::__errno_location(),
            libc::EINVAL
        );
        assert_eq!(
            block, original,
            "uninitialized context cannot fabricate a result"
        );
        frankenlibc_abi::unistd_abi::setkey_r(key.as_ptr(), data.as_mut_ptr().cast());
    }
    let valid_state = data.clone();
    let mut bad_key = key;
    bad_key[27] = 2;
    // SAFETY: all non-null extents remain valid. Malformed bit values and null
    // pointers exercise the candidate's documented checked rejection policy.
    unsafe {
        frankenlibc_abi::errno_abi::set_abi_errno(0);
        frankenlibc_abi::unistd_abi::setkey_r(bad_key.as_ptr(), data.as_mut_ptr().cast());
        assert_eq!(
            *frankenlibc_abi::errno_abi::__errno_location(),
            libc::EINVAL
        );
        assert_eq!(
            data, valid_state,
            "rejected key must preserve the previous key"
        );
        block[37] = 2;
        let invalid_input = block;
        frankenlibc_abi::errno_abi::set_abi_errno(0);
        frankenlibc_abi::unistd_abi::encrypt_r(block.as_mut_ptr(), 0, data.as_mut_ptr().cast());
        assert_eq!(
            *frankenlibc_abi::errno_abi::__errno_location(),
            libc::EINVAL
        );
        assert_eq!(block, invalid_input, "rejected block must remain untouched");
        frankenlibc_abi::errno_abi::set_abi_errno(0);
        frankenlibc_abi::unistd_abi::setkey_r(key.as_ptr(), std::ptr::null_mut());
        assert_eq!(
            *frankenlibc_abi::errno_abi::__errno_location(),
            libc::EINVAL
        );
        frankenlibc_abi::errno_abi::set_abi_errno(0);
        frankenlibc_abi::unistd_abi::encrypt_r(std::ptr::null_mut(), 0, data.as_mut_ptr().cast());
        assert_eq!(
            *frankenlibc_abi::errno_abi::__errno_location(),
            libc::EINVAL
        );
    }
}
