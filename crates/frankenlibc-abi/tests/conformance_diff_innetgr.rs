#![cfg(target_os = "linux")]

//! Live-glibc differential gate for `innetgr` against a synthetic `/etc/netgroup`.

use std::ffi::{CString, c_char, c_int, c_void};
use std::fs::File;
use std::process::{Command, Stdio};

type InnetgrFn =
    unsafe extern "C" fn(*const c_char, *const c_char, *const c_char, *const c_char) -> c_int;

fn host_innetgr() -> InnetgrFn {
    // SAFETY: libc.so.6 is the incumbent oracle, deliberately isolated from the
    // ABI crate's exported `innetgr` symbol.
    unsafe {
        let handle = libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
        assert!(!handle.is_null(), "dlopen libc.so.6");
        let symbol = libc::dlsym(handle, c"innetgr".as_ptr());
        assert!(!symbol.is_null(), "dlsym innetgr");
        std::mem::transmute::<*mut c_void, InnetgrFn>(symbol)
    }
}

fn call_innetgr(
    function: InnetgrFn,
    group: &str,
    host: Option<&str>,
    user: Option<&str>,
    domain: Option<&str>,
) -> c_int {
    let group = CString::new(group).expect("group is a C string");
    let host = host.map(|value| CString::new(value).expect("host is a C string"));
    let user = user.map(|value| CString::new(value).expect("user is a C string"));
    let domain = domain.map(|value| CString::new(value).expect("domain is a C string"));
    // SAFETY: every non-null pointer comes from a CString that remains live for
    // the complete call; null is the specified innetgr wildcard argument.
    unsafe {
        function(
            group.as_ptr(),
            host.as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            user.as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            domain
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
        )
    }
}

#[test]
fn innetgr_matches_glibc_with_synthetic_netgroup() {
    if std::env::var_os("FRANKENLIBC_INNETGR_BWRAP_CHILD").is_none() {
        let fixture = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/innetgr_synthetic.netgroup"
        );
        let fixture_file = File::open(fixture).expect("open innetgr fixture");
        let output = Command::new("bwrap")
            .args([
                "--dev-bind",
                "/",
                "/",
                "--tmpfs",
                "/etc",
                "--file",
                "0",
                "/etc/netgroup",
                std::env::current_exe()
                    .expect("current test binary path")
                    .to_str()
                    .expect("UTF-8 test path"),
                "--exact",
                "innetgr_matches_glibc_with_synthetic_netgroup",
                "--nocapture",
                "--test-threads",
                "1",
            ])
            .stdin(Stdio::from(fixture_file))
            .env("FRANKENLIBC_INNETGR_BWRAP_CHILD", "1")
            .output()
            .expect("launch bwrap innetgr oracle child");
        assert!(
            output.status.success(),
            "innetgr bwrap oracle child failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        return;
    }

    let host = host_innetgr();
    let fl: InnetgrFn = frankenlibc_abi::glibc_internal_abi::innetgr;
    let cases = [
        (
            "direct",
            "team",
            Some("build"),
            Some("alice"),
            Some("example.com"),
        ),
        (
            "nested",
            "team",
            Some("build"),
            Some("bob"),
            Some("example.com"),
        ),
        (
            "empty_host_wildcard",
            "team",
            Some("anything"),
            Some("ops"),
            Some("anything"),
        ),
        (
            "null_host",
            "team",
            None,
            Some("alice"),
            Some("example.com"),
        ),
        (
            "null_user",
            "team",
            Some("build"),
            None,
            Some("example.com"),
        ),
        ("null_domain", "team", Some("build"), Some("alice"), None),
        (
            "host_case_insensitive",
            "team",
            Some("BUILD"),
            Some("alice"),
            Some("example.com"),
        ),
        (
            "user_case_insensitive",
            "team",
            Some("build"),
            Some("ALICE"),
            Some("example.com"),
        ),
        (
            "domain_case_insensitive",
            "team",
            Some("build"),
            Some("alice"),
            Some("EXAMPLE.COM"),
        ),
        (
            "group_case",
            "casegroup",
            Some("CaseHost"),
            Some("CaseUser"),
            Some("CaseDomain"),
        ),
        (
            "missing_group",
            "missing",
            Some("build"),
            Some("alice"),
            Some("example.com"),
        ),
    ];
    for (name, group, host_arg, user_arg, domain_arg) in cases {
        let host_result = call_innetgr(host, group, host_arg, user_arg, domain_arg);
        let fl_result = call_innetgr(fl, group, host_arg, user_arg, domain_arg);
        assert_eq!(fl_result, host_result, "{name}: group={group}");
    }
}

// ---------------------------------------------------------------------------
// THE BACKEND ARM (bd-4dipf6).
//
// The arm above builds its oracle environment with `--tmpfs /etc`, which also
// removes `/etc/nsswitch.conf` — and nsswitch.conf is what SELECTS the netgroup
// backend. That configuration exists on no deployed host, and it is the one in
// which fl and glibc happen to agree, so the gate above could not see this.
//
// Measured on glibc 2.42 with one synthetic /etc/netgroup, varying only the
// nsswitch line: `netgroup: nis` (the STOCK Debian/Ubuntu line, no `files`)
// answers 0 while `netgroup: files`, a missing line, and a missing file all
// answer 1. fl read /etc/netgroup unconditionally and answered 1 in every case,
// so on a default host carrying an /etc/netgroup it reported membership where
// glibc reported none — fail-OPEN in an access-control predicate.
//
// This arm binds a REAL /etc (a copy of the host's, with the netgroup file and
// one rewritten nsswitch line) so the deployed configuration is the one under
// test.
// ---------------------------------------------------------------------------

/// One row: the `netgroup:` source list to write, and what both libraries must
/// then answer for a member that IS in the file.
const BACKEND_ROWS: &[(&str, &str, c_int)] = &[
    ("stock_nis_denies", "netgroup:       nis", 0),
    ("files_admits", "netgroup:       files", 1),
    ("files_second_still_admits", "netgroup:       nis files", 1),
    ("no_netgroup_line_defaults_to_files", "", 1),
];

#[test]
fn innetgr_honours_the_nsswitch_backend_like_glibc() {
    if std::env::var_os("FRANKENLIBC_INNETGR_NSS_CHILD").is_some() {
        // Child: one row, selected by env, inside the bound /etc.
        let expected: c_int = std::env::var("FRANKENLIBC_INNETGR_NSS_EXPECT")
            .expect("expectation")
            .parse()
            .expect("numeric expectation");
        let host = host_innetgr();
        let fl: InnetgrFn = frankenlibc_abi::glibc_internal_abi::innetgr;
        let h = call_innetgr(
            host,
            "team",
            Some("build"),
            Some("alice"),
            Some("example.com"),
        );
        let f = call_innetgr(
            fl,
            "team",
            Some("build"),
            Some("alice"),
            Some("example.com"),
        );
        assert_eq!(
            h, expected,
            "the live glibc oracle changed: this row's expectation is read from it"
        );
        assert_eq!(f, h, "fl disagrees with glibc under this nsswitch backend");
        return;
    }

    for (name, nsswitch_line, expected) in BACKEND_ROWS {
        let dir =
            std::env::temp_dir().join(format!("fl-innetgr-nss-{}-{}", std::process::id(), name));
        let etc = dir.join("etc");
        std::fs::create_dir_all(&etc).expect("scratch etc");
        // A real /etc, so nsswitch.conf, ld.so.conf and the rest are present.
        for entry in std::fs::read_dir("/etc").expect("read /etc").flatten() {
            let from = entry.path();
            let to = etc.join(entry.file_name());
            if from.is_file() && std::fs::copy(&from, &to).is_err() {
                // Unreadable /etc entries (root-only keys) are irrelevant here.
                continue;
            }
        }
        std::fs::write(
            etc.join("netgroup"),
            "team (build,alice,example.com) (,ops,) child\nchild (ci,,example.com) (build,bob,example.com)\n",
        )
        .expect("write netgroup");
        let base = std::fs::read_to_string("/etc/nsswitch.conf").unwrap_or_default();
        let mut kept: Vec<&str> = base
            .lines()
            .filter(|l| !l.trim_start().starts_with("netgroup:"))
            .collect();
        if !nsswitch_line.is_empty() {
            kept.push(nsswitch_line);
        }
        std::fs::write(etc.join("nsswitch.conf"), kept.join("\n") + "\n")
            .expect("write nsswitch.conf");

        let output = Command::new("bwrap")
            .args([
                "--dev-bind",
                "/",
                "/",
                "--bind",
                etc.to_str().expect("utf-8 etc path"),
                "/etc",
                std::env::current_exe()
                    .expect("current test binary path")
                    .to_str()
                    .expect("UTF-8 test path"),
                "--exact",
                "innetgr_honours_the_nsswitch_backend_like_glibc",
                "--nocapture",
                "--test-threads",
                "1",
            ])
            .env("FRANKENLIBC_INNETGR_NSS_CHILD", "1")
            .env("FRANKENLIBC_INNETGR_NSS_EXPECT", expected.to_string())
            .output()
            .expect("launch bwrap nsswitch child");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            output.status.success(),
            "nsswitch backend row {name} failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}
