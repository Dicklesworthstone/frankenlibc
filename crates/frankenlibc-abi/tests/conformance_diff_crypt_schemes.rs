#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live libxcrypt oracle via dlopen/dlsym

//! The crypt(3) schemes fl gained under bd-c6ykz1, against live libxcrypt:
//! bcrypt (`$2a$`/`$2b$`/`$2y$`), scrypt (`$7$`), and `crypt_gensalt` for both.
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
    assert!(
        !out.is_null(),
        "fl crypt must never return NULL (libxcrypt contract)"
    );
    // SAFETY: non-null and NUL-terminated by the same contract.
    unsafe { CStr::from_ptr(out) }
        .to_string_lossy()
        .into_owned()
}

/// `(password, setting, expected)` — all probed from live libxcrypt.
const VECTORS: &[(&str, &str, &str)] = &[
    (
        "",
        "$2b$04$abcdefghijklmnopqrstuu",
        "$2b$04$abcdefghijklmnopqrstuubyCG3zY1GIXMyxfivm.ClDiInHzxjiq",
    ),
    (
        "a",
        "$2b$04$abcdefghijklmnopqrstuu",
        "$2b$04$abcdefghijklmnopqrstuuMFdJu9yVgmagVAIC24fOZkaFqd3s9JC",
    ),
    (
        "password",
        "$2b$05$.OGB/.SE/ueHAeqKBO2NC.",
        "$2b$05$.OGB/.SE/ueHAeqKBO2NC.l.rLVibUznFAk1jsn2/OhryTtvR79Iu",
    ),
    (
        "password",
        "$2a$05$.OGB/.SE/ueHAeqKBO2NC.",
        "$2a$05$.OGB/.SE/ueHAeqKBO2NC.l.rLVibUznFAk1jsn2/OhryTtvR79Iu",
    ),
    (
        "password",
        "$2y$05$.OGB/.SE/ueHAeqKBO2NC.",
        "$2y$05$.OGB/.SE/ueHAeqKBO2NC.l.rLVibUznFAk1jsn2/OhryTtvR79Iu",
    ),
    (
        "abcdefghijklmnopqrstuvwxyz",
        "$2b$06$.OGB/.SE/ueHAeqKBO2NC.",
        "$2b$06$.OGB/.SE/ueHAeqKBO2NC..Cy/8oNnM3M8.rTlCMRXVi3Fs.jck9.",
    ),
    (
        "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
        "$2b$04$abcdefghijklmnopqrstuu",
        "$2b$04$abcdefghijklmnopqrstuuGspVVDvTz38hS7RBjIMQOom7jxHAiA.",
    ),
    // 80 bytes: past bcrypt's 72-byte cap, so the tail must be discarded.
    (
        "01234567890123456789012345678901234567890123456789012345678901234567890123456789",
        "$2b$04$abcdefghijklmnopqrstuu",
        "$2b$04$abcdefghijklmnopqrstuum2G75IXDN/xsgbNa/hCiPSKyIHQd70S",
    ),
    // The published OpenBSD triple.
    (
        "U*U",
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.",
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
    ),
    (
        "U*U*",
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.",
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK",
    ),
    (
        "U*U*U",
        "$2a$05$XXXXXXXXXXXXXXXXXXXXXO",
        "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a",
    ),
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
        assert!(
            !host_out.is_null(),
            "host crypt returned NULL for {setting}"
        );
        // SAFETY: non-null and NUL-terminated.
        let host_str = unsafe { CStr::from_ptr(host_out) }
            .to_string_lossy()
            .into_owned();

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
        let host_str = unsafe { CStr::from_ptr(host_out) }
            .to_string_lossy()
            .into_owned();
        let fl_str = fl_crypt(&key, &salt);
        assert_eq!(fl_str, host_str, "rejected setting {setting}");
    }
}

// ---------------------------------------------------------------------------
// crypt_gensalt
// ---------------------------------------------------------------------------

type GensaltFn = unsafe extern "C" fn(*const c_char, u64, *const c_char, i32) -> *mut c_char;

fn host_gensalt() -> Option<GensaltFn> {
    static H: OnceLock<Option<usize>> = OnceLock::new();
    *H.get_or_init(|| {
        // SAFETY: dlopen/dlsym with NUL-terminated names.
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
            let sym = libc::dlsym(handle, c"crypt_gensalt".as_ptr());
            if sym.is_null() {
                return None;
            }
            let fl = frankenlibc_abi::unistd_abi::crypt_gensalt as *const () as usize;
            assert_ne!(sym as usize, fl, "resolved gensalt IS fl's own (bd-v0388t)");
            Some(sym as usize)
        }
    })
    .map(|addr| {
        // SAFETY: `char *crypt_gensalt(const char *, unsigned long, const char *, int)`.
        unsafe { std::mem::transmute::<usize, GensaltFn>(addr) }
    })
}

/// 64 bytes of fixed "entropy" — the probes that produced the expectations
/// below used exactly these, so the comparison is deterministic.
fn entropy() -> Vec<c_char> {
    (1..=64u8).map(|b| b as c_char).collect()
}

/// `(prefix, count, nrbytes, expected)`. `None` means libxcrypt REFUSES the
/// request; fl must refuse it too rather than inventing a weaker setting.
const GENSALT_VECTORS: &[(&str, u64, i32, Option<&str>)] = &[
    ("$2b$", 0, 16, Some("$2b$05$.OGB/.SE/ueHAeqKBO2NC.")),
    ("$2b$", 4, 16, Some("$2b$04$.OGB/.SE/ueHAeqKBO2NC.")),
    ("$2b$", 31, 16, Some("$2b$31$.OGB/.SE/ueHAeqKBO2NC.")),
    ("$2b$", 3, 16, None),
    ("$2b$", 32, 16, None),
    ("$2a$", 0, 16, Some("$2a$05$.OGB/.SE/ueHAeqKBO2NC.")),
    ("$2y$", 0, 16, Some("$2y$05$.OGB/.SE/ueHAeqKBO2NC.")),
    ("$7$", 0, 16, Some("$7$CU..../..../6k.2IU/5UE08g.1Bsk1E.")),
    (
        "$7$",
        0,
        32,
        Some("$7$CU..../..../6k.2IU/5UE08g.1Bsk1E2V2HEF3KQ/4Ncl4QoV5T.0"),
    ),
    // count 1..=5 are REFUSED for $7$ even though 0 and 6+ are accepted. My
    // first implementation applied N_log2 = count + 7 uniformly and would have
    // produced a setting here; probing the host is what caught it.
    ("$7$", 1, 16, None),
    // Below 16 bytes of entropy libxcrypt refuses rather than padding.
    ("$7$", 0, 8, None),
    // The pre-existing schemes must not have moved.
    ("$6$", 0, 16, Some("$6$/6k.2IU/5UE08g.1")),
    ("$1$", 0, 16, Some("$1$/6k.2IU/")),
    // ---- traditional DES ----
    // An EMPTY prefix means DES, not the strongest scheme. fl answered
    // "$6$" here, so a caller expecting two characters got nineteen.
    ("", 0, 16, Some("/0")),
    // The two characters are one per entropy BYTE, low six bits -- not the
    // three-byte little-endian packing every other scheme uses, which would
    // emit "/6" from this same entropy.
    ("", 0, 2, Some("/0")),
    // No tunable cost: any non-zero count is refused, not ignored.
    ("", 1, 16, None),
    // Fewer than two entropy bytes is refused rather than padded.
    ("", 0, 1, None),
    // A prefix whose first two bytes are base-64 digits also selects DES...
    ("ab", 0, 16, Some("/0")),
    // ...and ONLY those two are examined. `crypt` refuses "ab:" as a setting
    // while gensalt accepts it as a prefix -- two different checks in one
    // library, measured separately rather than assumed to agree.
    ("ab:", 0, 16, Some("/0")),
    ("a", 0, 16, None),
    ("!!", 0, 16, None),
    // ---- BSDI extended DES ----
    ("_", 0, 16, Some("_J9../6k.")),
    // THE COUNT IS FORCED ODD. count 2 emits 3 (`1...` little-endian), and
    // 724 and 725 both emit 725. An implementation that passed the count
    // through would produce a setting the host never generates.
    ("_", 2, 16, Some("_1.../6k.")),
    ("_", 724, 16, Some("_J9../6k.")),
    ("_", 725, 16, Some("_J9../6k.")),
    // Four salt characters come from three entropy bytes, so two is refused.
    ("_", 0, 2, None),
    ("_", 0, 3, Some("_J9../6k.")),
    // ---- NTHASH ----
    // The setting IS the prefix: no salt, no cost, and nothing drawn from the
    // entropy -- which is why nrbytes 0 still succeeds.
    ("$3$", 0, 16, Some("$3$")),
    ("$3$", 0, 0, Some("$3$")),
];

#[test]
fn gensalt_matches_live_libxcrypt() {
    let Some(host) = host_gensalt() else {
        panic!("libxcrypt unavailable; this gate cannot run without its oracle");
    };
    let bytes = entropy();

    let mut divergences = Vec::new();
    for (prefix, count, nrbytes, expected) in GENSALT_VECTORS {
        let pfx = CString::new(*prefix).expect("prefix has no NUL");

        // SAFETY: `pfx` is NUL-terminated; `bytes` holds at least `nrbytes`.
        let host_ptr = unsafe { host(pfx.as_ptr(), *count, bytes.as_ptr(), *nrbytes) };
        let host_out = if host_ptr.is_null() {
            None
        } else {
            // SAFETY: non-null and NUL-terminated.
            Some(
                unsafe { CStr::from_ptr(host_ptr) }
                    .to_string_lossy()
                    .into_owned(),
            )
        };
        assert_eq!(
            host_out.as_deref(),
            *expected,
            "host libxcrypt no longer produces the recorded setting for              {prefix} count={count} nrbytes={nrbytes}"
        );

        // SAFETY: same arguments, fl's entry point.
        let fl_ptr = unsafe {
            frankenlibc_abi::unistd_abi::crypt_gensalt(
                pfx.as_ptr(),
                *count,
                bytes.as_ptr(),
                *nrbytes,
            )
        };
        let fl_out = if fl_ptr.is_null() {
            None
        } else {
            // SAFETY: non-null and NUL-terminated.
            Some(
                unsafe { CStr::from_ptr(fl_ptr) }
                    .to_string_lossy()
                    .into_owned(),
            )
        };

        if fl_out != host_out {
            divergences.push(format!(
                "  {prefix} count={count} nrbytes={nrbytes}\n    fl    = {fl_out:?}\n    glibc = {host_out:?}"
            ));
        }
    }
    assert!(
        divergences.is_empty(),
        "crypt_gensalt divergences from live libxcrypt:\n{}",
        divergences.join("\n")
    );
}

/// A generated setting must be one fl can then HASH. This is the property that
/// makes the capability usable rather than merely present: `passwd` calls
/// gensalt and feeds the result straight to crypt.
#[test]
fn generated_settings_round_trip_through_crypt() {
    let Some(host) = host_crypt() else {
        panic!("libxcrypt unavailable; this gate cannot run without its oracle");
    };
    let bytes = entropy();

    // $7$ at its default cost is deliberately expensive (N=2^14, r=32), so the
    // round trip uses bcrypt at the minimum cost. The $7$ hash path is covered
    // by the core vectors, which use cheap parameters.
    for prefix in ["$2b$", "$2a$", "$2y$"] {
        let pfx = CString::new(prefix).unwrap();
        // SAFETY: NUL-terminated prefix, 64 bytes of entropy.
        let setting_ptr = unsafe {
            frankenlibc_abi::unistd_abi::crypt_gensalt(pfx.as_ptr(), 4, bytes.as_ptr(), 16)
        };
        assert!(!setting_ptr.is_null(), "fl gensalt refused {prefix}");
        // SAFETY: non-null and NUL-terminated.
        let setting = unsafe { CStr::from_ptr(setting_ptr) }.to_owned();

        let key = CString::new("password").unwrap();
        let fl_hash = fl_crypt(&key, &setting);
        // SAFETY: both NUL-terminated and live for the call.
        let host_ptr = unsafe { host(key.as_ptr(), setting.as_ptr()) };
        // SAFETY: libxcrypt never returns NULL here.
        let host_hash = unsafe { CStr::from_ptr(host_ptr) }
            .to_string_lossy()
            .into_owned();

        assert_eq!(fl_hash, host_hash, "round trip for {prefix}");
        assert!(
            fl_hash.starts_with(prefix),
            "the hash must carry the setting it was made from: {fl_hash}"
        );
    }

    // The three schemes added alongside DES round-trip too, and they are cheap
    // enough to run at their DEFAULT cost: 25 rounds, 725 rounds, and one MD4.
    // This is the property that makes a capability usable rather than merely
    // present -- `passwd` calls gensalt and feeds the result straight to crypt,
    // so a setting fl can generate but not hash would be worse than no setting.
    for (prefix, nrbytes) in [("", 16), ("_", 16), ("$3$", 16)] {
        let pfx = CString::new(prefix).unwrap();
        // SAFETY: NUL-terminated prefix, 64 bytes of entropy.
        let setting_ptr = unsafe {
            frankenlibc_abi::unistd_abi::crypt_gensalt(pfx.as_ptr(), 0, bytes.as_ptr(), nrbytes)
        };
        assert!(
            !setting_ptr.is_null(),
            "fl gensalt refused {prefix:?}, so the scheme cannot be created"
        );
        // SAFETY: non-null and NUL-terminated.
        let setting = unsafe { CStr::from_ptr(setting_ptr) }.to_owned();

        let key = CString::new("password").unwrap();
        let fl_hash = fl_crypt(&key, &setting);
        // SAFETY: both NUL-terminated and live for the call.
        let host_ptr = unsafe { host(key.as_ptr(), setting.as_ptr()) };
        // SAFETY: libxcrypt never returns NULL here.
        let host_hash = unsafe { CStr::from_ptr(host_ptr) }
            .to_string_lossy()
            .into_owned();

        assert_eq!(fl_hash, host_hash, "round trip for {prefix:?}");
        assert_ne!(
            fl_hash, "*0",
            "fl generated a setting for {prefix:?} that it then refused to hash"
        );
    }
}

// ---------------------------------------------------------------------------
// NTHASH ($3$)
// ---------------------------------------------------------------------------
//
// Lives here rather than in conformance_diff_crypt_des.rs because it shares
// nothing with DES but the dispatcher: it is unsalted, uniterated MD4 over the
// byte-widened password. It joins this file because the libxcrypt oracle is
// already open here.

/// `(password, expected)` — probed from live libxcrypt with the setting `$3$`.
const NTHASH_VECTORS: &[(&[u8], &str)] = &[
    (b"", "$3$$31d6cfe0d16ae931b73c59d7e0c089c0"),
    (b"a", "$3$$186cb09181e2c2ecaac768c47c729904"),
    (b"password", "$3$$8846f7eaee8fb117ad06bdd830b7586c"),
    (b"The quick brown fox", "$3$$b9894503d51bf4dfc6f4192d1666800a"),
    // NOT UTF-8 decoded: these two bytes widen to c3 00 a9 00.
    (b"\xc3\xa9", "$3$$08eb94a3771213775172fc988504a4c1"),
    // Long enough that the widened message spans several MD4 blocks.
    (
        b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "$3$$c16e1f599bba2bab447a15fa2ca8aabb",
    ),
];

#[test]
fn nthash_matches_live_libxcrypt() {
    let Some(host) = host_crypt() else {
        panic!("libcrypt.so.1 did not resolve `crypt`; this gate cannot run vacuously");
    };
    for (password, expected) in NTHASH_VECTORS {
        let key = CString::new(*password).expect("no interior NUL");
        let setting = CString::new("$3$").expect("no interior NUL");
        // SAFETY: resolved libxcrypt `crypt`, two NUL-terminated pointers.
        let host_out = unsafe { host(key.as_ptr(), setting.as_ptr()) };
        assert!(!host_out.is_null(), "host crypt returned NULL");
        // SAFETY: NUL-terminated static storage.
        let host_hash = unsafe { CStr::from_ptr(host_out) }
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            host_hash, *expected,
            "the pinned vector for {password:?} no longer matches live libxcrypt"
        );
        assert_eq!(
            fl_crypt(&key, &setting),
            *expected,
            "fl NTHASH diverges for {password:?}"
        );
    }
}

/// The salt is parsed and thrown away, and the output must carry an EMPTY salt
/// whatever was supplied. This is not cosmetic: `strcmp(crypt(pw, stored),
/// stored)` is the standard authentication test, so echoing the salt back would
/// fail a correct password against an existing `$3$abc$…` record.
#[test]
fn nthash_ignores_the_salt_and_never_echoes_it() {
    let Some(host) = host_crypt() else {
        panic!("no libxcrypt oracle");
    };
    let key = CString::new("password").expect("no interior NUL");
    let reference = "$3$$8846f7eaee8fb117ad06bdd830b7586c";
    for setting in ["$3$", "$3$$", "$3$abc$", "$3$xyzzy$more", "$3$$$$"] {
        let setting = CString::new(setting).expect("no interior NUL");
        // SAFETY: as above.
        let host_out = unsafe { host(key.as_ptr(), setting.as_ptr()) };
        // SAFETY: as above.
        let host_hash = unsafe { CStr::from_ptr(host_out) }
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            host_hash, reference,
            "host no longer ignores the salt for {setting:?}"
        );
        assert_eq!(
            fl_crypt(&key, &setting),
            reference,
            "fl must ignore the salt and emit an empty one for {setting:?}"
        );
    }
}

#[test]
fn nthash_rejects_bad_settings_like_libxcrypt() {
    let Some(host) = host_crypt() else {
        panic!("no libxcrypt oracle");
    };
    let key = CString::new("password").expect("no interior NUL");
    for setting in [
        &b"$3"[..],
        b"$3$!",
        b"$3$*",
        b"$3$:",
        b"$3$;",
        b"$3$\\",
        b"$3$ ",
        b"$3$\x01",
        b"$3$\x7f",
        b"$3$\xff",
    ] {
        let setting = CString::new(setting).expect("no interior NUL");
        // SAFETY: as above.
        let host_out = unsafe { host(key.as_ptr(), setting.as_ptr()) };
        // SAFETY: as above.
        let host_hash = unsafe { CStr::from_ptr(host_out) }
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            host_hash, "*0",
            "host no longer rejects {setting:?}; the pinned expectation is stale"
        );
        assert_eq!(
            fl_crypt(&key, &setting),
            "*0",
            "fl must refuse {setting:?} rather than hash it"
        );
    }
}
