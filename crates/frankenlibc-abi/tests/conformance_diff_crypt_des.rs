#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live libxcrypt oracle via dlopen/dlsym

//! Traditional DES `crypt(3)` — the two-character-salt scheme — against live
//! libxcrypt.
//!
//! ## Why this scheme was unhashable, and why that was not obvious
//!
//! Before this gate, `unistd_abi`'s dispatch documented the scheme as "2-char
//! salt — Traditional DES (returns error; DES is obsolete)" and had no arm for
//! it: every such setting fell through to host delegation, which yields the
//! two-character failure token on any host where `libcrypt.so.1` is not
//! `dlsym`-able. The premise was wrong twice over. The incumbent still
//! implements DES — `crypt("password", "ab")` answers `abJnggxhB/yWI` on glibc
//! 2.42 — and "obsolete" is not the same as "absent": an `/etc/shadow` written
//! before the MD5 era still holds these hashes, and a login path that cannot
//! verify one does not fail loudly, it fails as *wrong password*.
//!
//! This is the fourth arm of the same hole bcrypt and `$7$` closed under
//! bd-c6ykz1, and it is the one whose bead recorded the family as "blocked on a
//! missing local oracle". That premise did not survive a probe: `crypt` is
//! absent from `libc.so.6` on glibc 2.42 — it moved to `libcrypt.so.1`, which
//! has it, along with DES and yescrypt.
//!
//! ## Why the oracle is `dlopen`ed rather than declared
//!
//! fl exports `crypt` itself, so a link-time `extern "C" { fn crypt(..) }` is
//! the at-risk shape bd-v0388t measured: the arm could be satisfied inside this
//! binary and the gate would compare fl against itself and pass
//! unconditionally. The shared `dlsym_oracle` helper covers `libc`/`libm`/
//! `libresolv` and names `libcrypt` as a case needing its own handle, so this
//! file opens `libcrypt.so.1` directly and asserts the resolved address is not
//! fl's own.
//!
//! ## What the vectors cover
//!
//! Every expectation was probed from live libxcrypt on this host. The three
//! groups test three genuinely different rules:
//!
//!   * `HASH_VECTORS` — the cipher itself, over salts spanning the whole
//!     base-64 alphabet and passwords spanning empty, short, exactly eight
//!     bytes, over-length and high-bit.
//!   * `TRAILING_ACCEPTED` — settings longer than two characters. These hash
//!     identically to their two-character prefix, so the assertion is equality
//!     with the `"ab"` answer, not merely non-rejection.
//!   * `REJECTED` — the acceptance rule, which is the part most likely to be
//!     got wrong by writing the obvious code. The salt characters must be
//!     base-64 digits, but the bytes after them are held to a WEAKER standard:
//!     printable ASCII minus `!`, `*`, `:`, `;` and `\`. So `ab$` is accepted
//!     and `ab:` is refused. Those five are the characters that would corrupt
//!     or forge a shadow-file record, and a "base-64 throughout" check — the
//!     natural first guess — gets `ab$` wrong in the unsafe direction.
//!
//! Deliberately NOT covered: `_`-prefixed BSDI extended DES and `$3$` NTHASH,
//! which the same libxcrypt also hashes and fl still delegates for. Asserting
//! them here would make this gate red for a gap it is not about.

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

fn cstring(bytes: &[u8]) -> CString {
    CString::new(bytes).expect("no interior NUL in any vector")
}

fn fl_crypt(key: &[u8], setting: &[u8]) -> String {
    let (key, setting) = (cstring(key), cstring(setting));
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

fn host_hash(key: &[u8], setting: &[u8]) -> Option<String> {
    let host = host_crypt()?;
    let (key, setting) = (cstring(key), cstring(setting));
    // SAFETY: resolved libxcrypt `crypt`, called with two NUL-terminated
    // pointers that outlive the call.
    let out = unsafe { host(key.as_ptr(), setting.as_ptr()) };
    if out.is_null() {
        return None;
    }
    // SAFETY: libxcrypt returns a NUL-terminated string in static storage.
    Some(
        unsafe { CStr::from_ptr(out) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// `(password, setting, expected)` — probed from live libxcrypt.
const HASH_VECTORS: &[(&[u8], &[u8], &str)] = &[
    (b"", b"ab", "abmF1QH4PEr.E"),
    (b"a", b"ab", "abxxB7HlIeckU"),
    (b"ab", b"ab", "abAwh7.RciMzE"),
    (b"abc", b"ab", "abFZSxKKdq5s6"),
    (b"password", b"ab", "abJnggxhB/yWI"),
    (b"password", b"zz", "zzXUHfURnGg8I"),
    (b"password", b"..", "..UZoIyj/Hy/c"),
    (b"password", b"//", "//TIk/siaNpyQ"),
    (b"password", b"ZZ", "ZZKRwXSu3tt8s"),
    (b"password", b"99", "99ryZiYJu/1JE"),
    (b"password", b"A.", "A.xewbx2DpQ8I"),
    (b"password", b".9", ".9jqBP29IK9ok"),
    (b"password", b"z/", "z/LfhO4s2PAws"),
    (b"password", b"0Z", "0ZnHNZp9Qgm5g"),
    (b"hello world", b"Xy", "Xyy7mbARqDoBw"),
    (b"P@ssw0rd!", b"q3", "q3tLi/vTNkRWg"),
    (b"~!@#$%^&*()", b"Tt", "Tt4CYAODkGp3U"),
    (b"\x7f\x01", b"ab", "ab64nD8d1KgAQ"),
    (b"ZZZZZZZZ", b"ab", "abISxwCBjeqvc"),
    (b"aaaaaaaaaaaaaaaa", b"ab", "abBUNZY4cR2mg"),
    (b"The quick brown fox", b"j9", "j9yWGoad56NCQ"),
    (b"nosuchuser", b"..", "..sp2gotcbraE"),
];

/// The eight-byte key cap: these three passwords share their first eight bytes
/// and MUST produce the same hash. This is a real property of the scheme, not
/// an artefact — it is why DES crypt cannot distinguish long passphrases.
const TRUNCATION_GROUP: (&[&[u8]], &[u8], &str) = (
    &[b"12345678", b"123456789", b"12345678X"],
    b"aB",
    "aB75dxyE/c05M",
);

/// Settings longer than two characters. All hash to the `"ab"` answer.
const TRAILING_ACCEPTED: &[&[u8]] = &[
    b"ab$",
    b"ab_",
    b"ab-",
    b"ab~",
    b"ab.",
    b"abcdefghij",
    b"ab$$$$",
    b"ab\"#%&'()+,<=>?@[]^`{|}",
];

/// Settings libxcrypt refuses, answering the failure token with EINVAL.
const REJECTED: &[&[u8]] = &[
    b"", b"a", b".", b"!!", b"a!", b"!a", b"ab:", b"ab;", b"ab*", b"ab!", b"ab\\", b"ab ", b"a:b",
    b"ab\x7f", b"ab\x01", b":ab", b"*ab", b"_ab", b"ab\xff",
];

/// The pinned expectations must still be what the host says. If libxcrypt on
/// this machine disagrees with the table, every other arm here is comparing fl
/// against a stale transcript, so this runs first and says so plainly.
#[test]
fn pinned_vectors_still_match_the_live_host() {
    let Some(_) = host_crypt() else {
        panic!("libcrypt.so.1 did not resolve `crypt`; this gate cannot run vacuously");
    };
    for (key, setting, expected) in HASH_VECTORS {
        assert_eq!(
            host_hash(key, setting).as_deref(),
            Some(*expected),
            "the pinned vector for key={key:?} setting={setting:?} no longer matches live \
             libxcrypt — re-probe the table before trusting any other arm in this file"
        );
    }
}

#[test]
fn des_hashes_match_the_host() {
    assert!(host_crypt().is_some(), "no libxcrypt oracle");
    for (key, setting, expected) in HASH_VECTORS {
        assert_eq!(
            fl_crypt(key, setting),
            *expected,
            "fl DES hash diverges for key={key:?} setting={setting:?}"
        );
    }
}

#[test]
fn key_is_capped_at_eight_bytes() {
    let (keys, setting, expected) = TRUNCATION_GROUP;
    for key in keys {
        assert_eq!(
            host_hash(key, setting).as_deref(),
            Some(expected),
            "host disagrees with the pinned truncation expectation for {key:?}"
        );
        assert_eq!(
            fl_crypt(key, setting),
            expected,
            "fl must discard everything past the eighth key byte ({key:?})"
        );
    }
}

#[test]
fn trailing_bytes_are_validated_then_discarded() {
    assert!(host_crypt().is_some(), "no libxcrypt oracle");
    let two_char = fl_crypt(b"password", b"ab");
    for setting in TRAILING_ACCEPTED {
        assert_eq!(
            host_hash(b"password", setting).as_deref(),
            Some(two_char.as_str()),
            "host no longer folds {setting:?} onto its two-character prefix"
        );
        assert_eq!(
            fl_crypt(b"password", setting),
            two_char,
            "fl must accept {setting:?} and hash it as its two-character prefix — a \
             base-64-throughout check would wrongly reject this"
        );
    }
}

#[test]
fn invalid_settings_produce_the_failure_token() {
    assert!(host_crypt().is_some(), "no libxcrypt oracle");
    for setting in REJECTED {
        let host = host_hash(b"password", setting);
        assert_eq!(
            host.as_deref(),
            Some("*0"),
            "host no longer rejects {setting:?}; the pinned expectation is stale"
        );
        assert_eq!(
            fl_crypt(b"password", setting),
            "*0",
            "fl must refuse {setting:?} rather than hash it"
        );
    }
}

/// The whole salt alphabet, not a sample: all 4096 two-character settings.
/// A permutation table transcribed with one digit wrong typically survives a
/// handful of vectors and fails here.
#[test]
fn every_salt_pair_matches_the_host() {
    assert!(host_crypt().is_some(), "no libxcrypt oracle");
    const A64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut checked = 0usize;
    for &first in A64 {
        for &second in A64 {
            let setting = [first, second];
            let host = host_hash(b"password", &setting).expect("host answered NULL");
            assert_eq!(
                fl_crypt(b"password", &setting),
                host,
                "fl diverges on salt {:?}",
                std::str::from_utf8(&setting).unwrap_or("<non-utf8>")
            );
            checked += 1;
        }
    }
    // A zero here would mean the loop never ran and the test passed vacuously.
    assert_eq!(checked, 4096, "the salt sweep did not cover the alphabet");
}
