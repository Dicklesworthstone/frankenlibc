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
