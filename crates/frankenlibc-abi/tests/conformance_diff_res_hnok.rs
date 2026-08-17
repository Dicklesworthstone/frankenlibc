#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-differential calls through dlsym

//! `res_hnok` must accept and reject exactly what glibc does (bd-ie6tg7).
//!
//! ## Why a differential and not a specification
//!
//! `res_hnok` is a hostname validator, and its real contract is a pile of
//! historical quirks rather than a rule anyone would write down twice. Probed on
//! host glibc 2.42:
//!
//! ```text
//! ""            -> 1   (the EMPTY name is valid)
//! "."           -> 1
//! ".host"       -> 0   but "host."      -> 1
//! "-lead.com"   -> 0   but "trail-.com" -> 1
//! "a..b"        -> 0
//! "under_score.com" -> 1     "_sip._tcp.example.com" -> 1
//! 63-char label -> 1   64-char label -> 0
//! ```
//!
//! An empty string being VALID, and a trailing hyphen being accepted where a
//! leading one is not, are the kind of asymmetries a hand-written expectation
//! gets wrong in the same direction as the implementation. So every case below
//! is answered by the host, and fl is only ever compared against it.
//!
//! The cases are chosen to separate plausible implementations: someone writing
//! this from RFC 1035 would reject the empty name, reject the underscore, and
//! reject the trailing hyphen — three ways to be defensibly wrong and
//! ABI-incompatible.

use std::ffi::{CStr, CString, c_char, c_int};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_addr_optional;

type Hnok = unsafe extern "C" fn(*const c_char) -> c_int;

#[test]
fn res_hnok_matches_the_host_on_every_quirk() {
    let fl = frankenlibc_abi::glibc_internal_abi::res_hnok as Hnok;
    // `host_addr_optional` asserts the resolved address is NOT fl's own, so a
    // collapsed oracle fails loudly rather than comparing fl with itself.
    let Some(addr) = (unsafe { host_addr_optional(c"res_hnok", fl as *const ()) }) else {
        panic!("host glibc does not export res_hnok; this gate needs an oracle");
    };
    // SAFETY: the resolved symbol has `res_hnok`'s C signature.
    let glibc: Hnok = unsafe { std::mem::transmute(addr) };

    let long_label = "a".repeat(63);
    let too_long_label = "a".repeat(64);
    let long_name = format!("{}.{}.{}.{}", "b".repeat(60), "c".repeat(60), "d".repeat(60), "e".repeat(60));
    let over_255 = format!("{}.{}.{}.{}.{}", "f".repeat(60), "g".repeat(60), "h".repeat(60), "i".repeat(60), "j".repeat(60));

    let cases: Vec<String> = vec![
        // Ordinary
        "example.com".into(),
        "a".into(),
        "a.b".into(),
        "a-b.c-d".into(),
        "3com.com".into(),
        "UPPER.COM".into(),
        "1.2.3.4".into(),
        // The quirks a from-spec implementation gets wrong
        "".into(),
        ".".into(),
        "host.".into(),
        ".host".into(),
        "-lead.com".into(),
        "trail-.com".into(),
        "under_score.com".into(),
        "_sip._tcp.example.com".into(),
        // Structure
        "a..b".into(),
        "..".into(),
        "a.".into(),
        // Characters that must be rejected
        "a b.com".into(),
        "a*b.com".into(),
        "a\\b.com".into(),
        "a\tb.com".into(),
        "a\u{7f}b.com".into(),
        "a!b.com".into(),
        "a/b.com".into(),
        // Position-sensitive characters, one per label position. These are the
        // rows that separate the classes: a backslash may START or sit INSIDE a
        // label but may not END one, while a hyphen is the mirror image.
        "\\ab.com".into(),
        "a\\b.com".into(),
        "ab\\.com".into(),
        "_ab.com".into(),
        "a_b.com".into(),
        "ab_.com".into(),
        "-ab.com".into(),
        "a-b.com".into(),
        "ab-.com".into(),
        "_".into(),
        "\\".into(),
        "-".into(),
        // Lengths
        format!("{long_label}.com"),
        format!("{too_long_label}.com"),
        long_name,
        over_255,
        // The total-length boundary, measured at 253/254.
        "x".repeat(253),
        "x".repeat(254),
        format!("{}.{}", "y".repeat(63), "z".repeat(189)),
        format!("{}.{}", "y".repeat(63), "z".repeat(190)),
    ];

    let mut divergences: Vec<String> = Vec::new();
    let mut compared = 0usize;
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    for case in &cases {
        let c = CString::new(case.as_str()).expect("case has no interior NUL");
        // SAFETY: both take one NUL-terminated string and read no further.
        let (want, got) = unsafe { (glibc(c.as_ptr()), fl(c.as_ptr())) };
        let shown: String = case.chars().take(28).collect();
        if got != want {
            divergences.push(format!(
                "res_hnok({shown:?}{}) -> fl {got}, host {want}",
                if case.chars().count() > 28 { "..." } else { "" }
            ));
        }
        if want != 0 {
            accepted += 1;
        } else {
            rejected += 1;
        }
        compared += 1;
    }

    // Assert the positive facts. A table the host accepted (or rejected)
    // uniformly would be satisfied by `return 1;` (or `return 0;`), so the gate
    // must see both answers to mean anything.
    assert_eq!(compared, cases.len(), "the loop skipped cases");
    assert!(
        accepted >= 5 && rejected >= 5,
        "host accepted {accepted} and rejected {rejected}; this gate cannot \
         distinguish a real validator from a constant without both"
    );
    for d in &divergences {
        println!("  {d}");
    }
    println!("compared {compared} res_hnok cases: {accepted} accepted, {rejected} rejected");
    assert!(
        divergences.is_empty(),
        "{} of {compared} cases diverge from the host",
        divergences.len()
    );
}
