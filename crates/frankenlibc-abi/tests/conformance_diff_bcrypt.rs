#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live libxcrypt oracle via dlopen/dlsym

//! bcrypt (`$2a$`/`$2b$`/`$2y$`) against live libxcrypt.
//!
//! fl could not hash the bcrypt family at all before bd-c6ykz1: `crypt()` fell
//! through to the host-delegation arm, and on any host where `libcrypt.so.1` is
//! not `dlsym`-able it returned the two-character failure token instead. Since
//! bcrypt is one of the schemes real `/etc/shadow` entries use, that made those
//! passwords silently unverifiable rather than loudly unsupported.
//!
//! ## Why the oracle is `dlopen`ed rather than declared
//!
//! fl exports `crypt` itself. A link-time `extern "C" { fn crypt(..) }` here is
//! exactly the at-risk shape bd-v0388t measured: the arm could be satisfied by
//! something in this binary and the gate would compare fl against itself. The
//! shared `dlsym_oracle` helper cannot be used either — its `handles()` covers
//! `libc`/`libm`/`libresolv` and says so in its own failure message, listing
//! `libcrypt` as a case that needs its own handle. So this file opens
//! `libcrypt.so.1` directly and asserts the resolved address is NOT fl's.
//!
//! ## Vectors
//!
//! Every expectation below was probed from live libxcrypt on this host, not
//! copied from a document. Three of them (`U*U`, `U*U*`, `U*U*U`) coincide with
//! the published OpenBSD vectors, which is a useful independent check that the
//! host's libxcrypt is behaving canonically rather than that this file agrees
//! with itself.

use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::OnceLock;

type CryptFn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_char;

/// Resolve `crypt` from libxcrypt, refusing to hand back fl's own definition.
fn host_crypt() -> Option<CryptFn> {
    static H: OnceLock<Option<usize>> = OnceLock::new();
    *H.get_or_init(|| {
        // SAFETY: dlopen/dlsym with NUL-terminated names; the handle is
        // intentionally leaked for the process lifetime.
        unsafe {
            let mut handle = std::ptr::null_mut::<c_void>();
            for name in [c"libcrypt.so.1", c"libcrypt.so.2", c"libcrypt.so"] {
                handle = libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
                if !handle.is_null() {
                    break;
                }
            }
            if handle.is_null() {
                return None;
            }
            let sym = libc::dlsym(handle, c"crypt".as_ptr());
            if sym.is_null() {
                return None;
            }
            let fl = frankenlibc_abi::unistd_abi::crypt as *const () as usize;
            assert_ne!(
                sym as usize, fl,
                "the resolved libxcrypt crypt IS fl's own definition — this gate \
                 would compare fl against itself and pass unconditionally \
                 (bd-v0388t)"
            );
            Some(sym as usize)
        }
    })
    .map(|addr| {
        // SAFETY: the address came from dlsym on libcrypt's `crypt`, whose C
        // signature is `char *crypt(const char *, const char *)`.
        unsafe { std::mem::transmute::<usize, CryptFn>(addr) }
    })
}

fn fl_crypt(key: &CStr, setting: &CStr) -> String {
    // SAFETY: both pointers are NUL-terminated and live for the call.
    let out = unsafe { frankenlibc_abi::unistd_abi::crypt(key.as_ptr(), setting.as_ptr()) };
    assert!(!out.is_null(), "fl crypt must never return NULL (libxcrypt contract)");
    // SAFETY: non-null and NUL-terminated by the same contract.
    unsafe { CStr::from_ptr(out) }.to_string_lossy().into_owned()
}

/// `(password, setting, expected)` — all probed from live libxcrypt.
const VECTORS: &[(&str, &str, &str)] = &[
    ("", "$2b$04$abcdefghijklmnopqrstuu",
     "$2b$04$abcdefghijklmnopqrstuubyCG3zY1GIXMyxfivm.ClDiInHzxjiq"),
    ("a", "$2b$04$abcdefghijklmnopqrstuu",
     "$2b$04$abcdefghijklmnopqrstuuMFdJu9yVgmagVAIC24fOZkaFqd3s9JC"),
    ("password", "$2b$05$.OGB/.SE/ueHAeqKBO2NC.",
     "$2b$05$.OGB/.SE/ueHAeqKBO2NC.l.rLVibUznFAk1jsn2/OhryTtvR79Iu"),
    ("password", "$2a$05$.OGB/.SE/ueHAeqKBO2NC.",
     "$2a$05$.OGB/.SE/ueHAeqKBO2NC.l.rLVibUznFAk1jsn2/OhryTtvR79Iu"),
    ("password", "$2y$05$.OGB/.SE/ueHAeqKBO2NC.",
     "$2y$05$.OGB/.SE/ueHAeqKBO2NC.l.rLVibUznFAk1jsn2/OhryTtvR79Iu"),
    ("abcdefghijklmnopqrstuvwxyz", "$2b$06$.OGB/.SE/ueHAeqKBO2NC.",
     "$2b$06$.OGB/.SE/ueHAeqKBO2NC..Cy/8oNnM3M8.rTlCMRXVi3Fs.jck9."),
    ("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2b$04$abcdefghijklmnopqrstuu",
     "$2b$04$abcdefghijklmnopqrstuuGspVVDvTz38hS7RBjIMQOom7jxHAiA."),
    // 80 bytes: past bcrypt's 72-byte cap, so the tail must be discarded.
    ("01234567890123456789012345678901234567890123456789012345678901234567890123456789",
     "$2b$04$abcdefghijklmnopqrstuu",
     "$2b$04$abcdefghijklmnopqrstuum2G75IXDN/xsgbNa/hCiPSKyIHQd70S"),
    // The published OpenBSD triple.
    ("U*U", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.",
     "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"),
    ("U*U*", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.",
     "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK"),
    ("U*U*U", "$2a$05$XXXXXXXXXXXXXXXXXXXXXO",
     "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a"),
];

#[test]
fn bcrypt_matches_live_libxcrypt() {
    let Some(host) = host_crypt() else {
        panic!("libxcrypt unavailable; this gate cannot run without its oracle");
    };

    let mut divergences = Vec::new();
    for (password, setting, pinned) in VECTORS {
        let key = CString::new(*password).expect("password has no NUL");
        let salt = CString::new(*setting).expect("setting has no NUL");

        // SAFETY: both pointers are NUL-terminated and live for the call.
        let host_out = unsafe { host(key.as_ptr(), salt.as_ptr()) };
        assert!(!host_out.is_null(), "host crypt returned NULL for {setting}");
        // SAFETY: non-null and NUL-terminated.
        let host_str = unsafe { CStr::from_ptr(host_out) }.to_string_lossy().into_owned();

        // The pin catches a host whose libxcrypt has itself changed, which
        // would otherwise let fl and a drifted oracle agree on a wrong answer.
        assert_eq!(
            host_str, *pinned,
            "host libxcrypt no longer produces the recorded vector for {setting}"
        );

        let fl_str = fl_crypt(&key, &salt);
        if fl_str != host_str {
            divergences.push(format!(
                "  {setting} + {password:?}\n    fl    = {fl_str}\n    glibc = {host_str}"
            ));
        }
    }
    assert!(
        divergences.is_empty(),
        "bcrypt divergences from live libxcrypt:\n{}",
        divergences.join("\n")
    );
}

/// A rejected setting must produce libxcrypt's failure token, never NULL and
/// never a plausible-looking hash.
#[test]
fn bcrypt_rejects_bad_settings_like_libxcrypt() {
    let Some(host) = host_crypt() else {
        panic!("libxcrypt unavailable; this gate cannot run without its oracle");
    };
    // Cost below the minimum, cost above the maximum, truncated salt, and a
    // variant letter bcrypt does not define.
    for setting in [
        "$2b$03$abcdefghijklmnopqrstuu",
        "$2b$32$abcdefghijklmnopqrstuu",
        "$2b$05$tooshort",
        "$2z$05$abcdefghijklmnopqrstuu",
    ] {
        let key = CString::new("password").unwrap();
        let salt = CString::new(setting).unwrap();
        // SAFETY: NUL-terminated, live for the call.
        let host_out = unsafe { host(key.as_ptr(), salt.as_ptr()) };
        // SAFETY: libxcrypt never returns NULL here.
        let host_str = unsafe { CStr::from_ptr(host_out) }.to_string_lossy().into_owned();
        let fl_str = fl_crypt(&key, &salt);
        assert_eq!(fl_str, host_str, "rejected setting {setting}");
    }
}
