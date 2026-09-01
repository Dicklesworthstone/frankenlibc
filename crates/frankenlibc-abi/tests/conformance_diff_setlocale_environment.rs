#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live glibc setlocale oracle + a re-exec'd child

//! `setlocale(LC_ALL, "")` against live glibc, across ENVIRONMENTS.
//!
//! ## Why this needs subprocesses
//!
//! The empty locale name means "adopt the environment", so the behaviour under
//! test is a function of `LC_ALL`/`LC_CTYPE`/`LANG` at process start. glibc
//! caches its answer, and a test that mutated `environ` in-process would be
//! asking a libc that had already made up its mind. So each row re-execs this
//! binary with a controlled environment and compares the two answers there.
//!
//! `env_clear()` matters: inheriting the harness's own locale variables would
//! make the "nothing set" row untestable, and that row is the one fl got wrong.
//!
//! ## What was wrong (bd-9t8wzq)
//!
//! fl mapped the empty name straight to UTF-8 and never looked at the
//! environment. glibc reads `LC_ALL`, then the category's own variable, then
//! `LANG`, then falls back to `"C"`. So a program calling `setlocale(LC_ALL,
//! "")` with nothing set got `"C"` from glibc and a UTF-8 locale from fl -- the
//! ordinary environment, not an exotic one.
//!
//! That is the same defect b5aef5e3a fixed for the STARTUP locale (bd-1kxrmz),
//! surviving at an entry point that commit did not touch.
//!
//! ## What is compared, and what is not
//!
//! The CODESET, not the locale name. fl models two charsets and names them `C`
//! and `C.UTF-8`, so it cannot echo `en_US.UTF-8` back; asserting the name would
//! pin a limitation rather than the contract. `nl_langinfo(CODESET)` is the
//! thing programs actually branch on, and it is exactly what was wrong.

use std::ffi::{CStr, CString, c_char, c_int};
use std::process::Command;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_fn;

type SetlocaleFn = unsafe extern "C" fn(c_int, *const c_char) -> *mut c_char;
type NlLanginfoFn = unsafe extern "C" fn(c_int) -> *mut c_char;

const HELPER_VAR: &str = "FRANKENLIBC_SETLOCALE_ENV_HELPER";

fn host_setlocale() -> SetlocaleFn {
    // SAFETY: `char *setlocale(int, const char *)`; fl's own export is passed so
    // a collapsed oracle aborts rather than comparing fl with itself (bd-v0388t).
    unsafe {
        host_fn(
            c"setlocale",
            frankenlibc_abi::locale_abi::setlocale as *const (),
        )
    }
}

fn host_nl_langinfo() -> NlLanginfoFn {
    // SAFETY: `char *nl_langinfo(nl_item)`.
    unsafe {
        host_fn(
            c"nl_langinfo",
            frankenlibc_abi::locale_abi::nl_langinfo as *const (),
        )
    }
}

fn text(p: *const c_char) -> String {
    if p.is_null() {
        return String::from("(NULL)");
    }
    // SAFETY: both libcs return NUL-terminated static storage.
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

/// The child: adopt the environment in BOTH libcs and print each result.
fn helper_body() {
    let empty = CString::new("").expect("no interior NUL");

    // SAFETY: NUL-terminated locale name; CODESET is a valid nl_item.
    let (host_returned, host_codeset, fl_returned, fl_codeset) = unsafe {
        let host_returned = !host_setlocale()(libc::LC_ALL, empty.as_ptr()).is_null();
        let host = text(host_nl_langinfo()(libc::CODESET));
        let fl_returned =
            !frankenlibc_abi::locale_abi::setlocale(libc::LC_ALL, empty.as_ptr()).is_null();
        let fl = text(frankenlibc_abi::locale_abi::nl_langinfo(libc::CODESET));
        (host_returned, host, fl_returned, fl)
    };
    println!("HOST_RETURNED={host_returned}");
    println!("HOST={host_codeset}");
    println!("FL_RETURNED={fl_returned}");
    println!("FL={fl_codeset}");
}

#[derive(Debug)]
struct LocaleOutcome {
    returned: bool,
    codeset: String,
}

/// Re-exec this binary with exactly `vars` set, and return both libc outcomes.
fn locale_outcomes_under(vars: &[(&str, &str)]) -> (LocaleOutcome, LocaleOutcome) {
    let mut cmd = Command::new(std::env::current_exe().expect("current test binary path"));
    cmd.env_clear().env(HELPER_VAR, "1");
    for (k, v) in vars {
        cmd.env(k, v);
    }
    let out = cmd
        .args(["--exact", "setlocale_environment_helper", "--nocapture"])
        .output()
        .expect("run setlocale environment helper");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let field = |tag: &str| -> String {
        stdout
            .lines()
            .find_map(|l| l.strip_prefix(tag))
            .unwrap_or_else(|| {
                panic!("helper printed no {tag} line for {vars:?}:\nstdout={stdout}")
            })
            .to_string()
    };
    let parse_returned = |tag| match field(tag).as_str() {
        "true" => true,
        "false" => false,
        other => panic!("helper returned invalid boolean {other:?} for {tag}"),
    };
    (
        LocaleOutcome {
            returned: parse_returned("HOST_RETURNED="),
            codeset: field("HOST="),
        },
        LocaleOutcome {
            returned: parse_returned("FL_RETURNED="),
            codeset: field("FL="),
        },
    )
}

#[test]
fn setlocale_environment_helper() {
    if std::env::var(HELPER_VAR).is_ok() {
        helper_body();
    }
}

/// The environment decides the codeset, and fl must agree with glibc on every
/// row -- including the empty environment, which is the one fl got wrong.
#[test]
fn setlocale_empty_name_follows_the_environment() {
    if std::env::var(HELPER_VAR).is_ok() {
        return; // the child runs only its own arm
    }

    let rows: &[(&str, &[(&str, &str)])] = &[
        ("nothing set", &[]),
        ("LANG=C", &[("LANG", "C")]),
        ("LANG=C.UTF-8", &[("LANG", "C.UTF-8")]),
        ("LC_ALL=C.UTF-8", &[("LC_ALL", "C.UTF-8")]),
        ("LC_CTYPE=C.UTF-8", &[("LC_CTYPE", "C.UTF-8")]),
        // LC_ALL outranks both LANG and the category variable.
        (
            "LC_ALL=C beats LANG=C.UTF-8",
            &[("LC_ALL", "C"), ("LANG", "C.UTF-8")],
        ),
        // The category variable outranks LANG.
        (
            "LC_CTYPE=C beats LANG=C.UTF-8",
            &[("LC_CTYPE", "C"), ("LANG", "C.UTF-8")],
        ),
        // Set-but-empty does not count as set, so LANG still decides.
        (
            "LC_ALL empty falls through to LANG",
            &[("LC_ALL", ""), ("LANG", "C.UTF-8")],
        ),
        // This name is installed on some workers and absent on others. The
        // differential covers both legitimate host outcomes.
        ("LANG=en_US.UTF-8", &[("LANG", "en_US.UTF-8")]),
    ];

    let mut divergences = Vec::new();
    for (label, vars) in rows {
        let (host, fl) = locale_outcomes_under(vars);
        if host.returned != fl.returned || host.codeset != fl.codeset {
            divergences.push(format!(
                "  {label}: glibc returned={} CODESET={} fl returned={} CODESET={}",
                host.returned, host.codeset, fl.returned, fl.codeset
            ));
        }
    }
    assert!(
        divergences.is_empty(),
        "setlocale(LC_ALL, \"\") disagrees with live glibc:\n{}",
        divergences.join("\n")
    );
}

/// The probe must be able to observe a DIFFERENCE, or agreement proves nothing.
///
/// If the harness could not vary the child's environment -- `env_clear` not
/// taking, or the helper never running -- every row would report the same
/// codeset and the test above would pass while testing nothing.
#[test]
fn the_environment_actually_reaches_the_child() {
    if std::env::var(HELPER_VAR).is_ok() {
        return;
    }
    let (ascii_host, _) = locale_outcomes_under(&[("LANG", "C")]);
    let (utf8_host, _) = locale_outcomes_under(&[("LANG", "C.UTF-8")]);
    assert_ne!(
        ascii_host.codeset, utf8_host.codeset,
        "glibc reported the same codeset for LANG=C and LANG=C.UTF-8 — the child \
         is not seeing the environment we set, so this gate cannot prove anything"
    );
    assert_eq!(
        ascii_host.codeset, "ANSI_X3.4-1968",
        "glibc's C-locale codeset on this host"
    );
    assert_eq!(
        utf8_host.codeset, "UTF-8",
        "glibc's C.UTF-8 codeset on this host"
    );
}

/// A missing environment locale is a failing selection, not an ASCII success.
///
/// The old implementation passed this test by accepting its UTF-8 suffix and
/// mutating the active codec. The name is deliberately impossible to install
/// accidentally, while the host result remains the independent oracle.
#[test]
fn setlocale_empty_name_rejects_an_uninstalled_environment_locale() {
    if std::env::var(HELPER_VAR).is_ok() {
        return;
    }
    let (host, fl) = locale_outcomes_under(&[("LANG", "frankenlibc.definitely_missing.UTF-8")]);
    assert!(
        !host.returned,
        "host unexpectedly installed the reserved test locale"
    );
    assert_eq!(
        host.returned, fl.returned,
        "setlocale return value for missing LANG"
    );
    assert_eq!(host.codeset, fl.codeset, "CODESET after missing LANG");
}
