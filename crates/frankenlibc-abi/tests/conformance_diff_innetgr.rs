#![cfg(target_os = "linux")]

//! Live-glibc differential gate for netgroup policy and iteration.

use std::ffi::{CStr, CString, c_char, c_int};
use std::fs::File;
use std::io::Write;
use std::process::{Command, Stdio};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type InnetgrFn =
    unsafe extern "C" fn(*const c_char, *const c_char, *const c_char, *const c_char) -> c_int;

fn host_innetgr() -> InnetgrFn {
    // SAFETY: the signature matches innetgr; the shared resolver verifies that
    // the host address differs from the candidate's definition.
    unsafe {
        dlsym_oracle::host_fn(
            c"innetgr",
            frankenlibc_abi::glibc_internal_abi::innetgr as *const (),
        )
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
            .env_remove("FRANKENLIBC_NSSWITCH_CONF")
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
        if name == "direct" {
            assert_eq!(
                host_result, 1,
                "missing nsswitch file must reach native files"
            );
        }
        assert_eq!(fl_result, host_result, "{name}: group={group}");
    }
    // Both positive and negative expectations are fixed by the independent GNU
    // oracle. In particular, later duplicate definitions must not grant a
    // member that the first definition omitted, even when the first is empty.
    for (group, query_host, expected) in [
        ("continued_triples", "build", 1),
        ("continued_children", "build", 1),
        ("continued_children", "first", 1),
        ("continued_inside", "bu", 1),
        ("continued_inside", "build", 0),
        ("continued_field_start", "build", 1),
        ("continuation_owner", "build", 1),
        ("continued_hidden", "build", 0),
        ("dup_first", "first", 1),
        ("dup_first", "build", 0),
        ("dup_empty", "build", 0),
        ("dup_parent", "first", 1),
        ("dup_parent", "build", 0),
        ("continued_cycle", "build", 1),
        ("continued_cycle", "first", 1),
        ("comment_hidden", "build", 0),
        ("indented", "build", 0),
        ("literal#name", "build", 1),
        ("literal", "build", 0),
        ("inline_hash", "build", 1),
        ("hash_glued", "build", 0),
        ("comment_chain", "build", 1),
        ("blank_ends", "build", 0),
    ] {
        let arguments = (Some(query_host), Some("alice"), Some("example.com"));
        let host_result = call_innetgr(host, group, arguments.0, arguments.1, arguments.2);
        let fl_result = call_innetgr(fl, group, arguments.0, arguments.1, arguments.2);
        assert_eq!(
            host_result, expected,
            "GNU record {group}: host={query_host}"
        );
        assert_eq!(
            fl_result, host_result,
            "native record {group}: host={query_host}"
        );
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
// This arm binds a minimal private /etc containing only the synthetic netgroup
// and the selected nsswitch policy. It does not inherit other host databases.
// ---------------------------------------------------------------------------

/// One row: the `netgroup:` source list to write, and what both libraries must
/// then answer for a member that IS in the file.
const BACKEND_ROWS: &[(&str, &str, c_int, Option<c_int>)] = &[
    ("stock_nis_denies", "netgroup:       nis", 0, Some(0)),
    ("files_admits", "netgroup:       files", 1, Some(1)),
    (
        "files_second_still_admits",
        "netgroup:       nis files",
        1,
        Some(1),
    ),
    ("no_netgroup_line_defaults_to_files", "", 1, Some(1)),
    (
        "unavailable_stops_before_files",
        "netgroup: franken_missing [UNAVAIL=return] files",
        0,
        Some(0),
    ),
    (
        "unavailable_continues_to_files",
        "netgroup: franken_missing [UNAVAIL=continue] files",
        1,
        Some(1),
    ),
    (
        "negated_success_stops",
        "netgroup: franken_missing [!SUCCESS=return] files",
        0,
        Some(0),
    ),
    (
        "negated_unavailable_continues",
        "netgroup: franken_missing [!UNAVAIL=return] files",
        1,
        Some(1),
    ),
    (
        "notfound_action_does_not_stop_unavailable",
        "netgroup: franken_missing [NOTFOUND=return] files",
        1,
        Some(1),
    ),
    (
        "mixed_case_action_stops",
        "netgroup: franken_missing [uNaVaIl=ReTuRn] files",
        0,
        Some(0),
    ),
    (
        "service_names_are_case_sensitive",
        "netgroup: FILES",
        0,
        Some(0),
    ),
    (
        "compat_is_not_netgroup_files",
        "netgroup: compat [UNAVAIL=return] files",
        0,
        Some(0),
    ),
    ("empty_source_list_denies", "netgroup:", 0, Some(0)),
    (
        "files_success_continues_to_files",
        "netgroup: files [SUCCESS=continue] files",
        1,
        Some(1),
    ),
    // GNU innetgr stops at the first known group despite SUCCESS=continue.
    // GNU setnetgrent aborts for this unavailable-following-source combination
    // (getnetgrent_r.c:103, data != NULL); only membership is compared on this
    // row. The enumeration continue policy is tested with two available files
    // sources above and with observable source callbacks in core::nss tests.
    (
        "membership_stops_at_known_group",
        "netgroup: files [SUCCESS=continue] franken_missing",
        1,
        None,
    ),
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
        for group in ["team", "empty", "missing"] {
            let h = call_innetgr(
                host,
                group,
                Some("build"),
                Some("absent"),
                Some("example.com"),
            );
            let f = call_innetgr(
                fl,
                group,
                Some("build"),
                Some("absent"),
                Some("example.com"),
            );
            assert_eq!(h, 0, "GNU negative control for {group}");
            assert_eq!(f, h, "nonmember or missing group {group}");
        }
        if let Ok(expected) = std::env::var("FRANKENLIBC_INNETGR_NSS_SET_EXPECT") {
            let expected: c_int = expected.parse().expect("numeric setnetgrent expectation");
            for (name, api) in netgroup_providers() {
                // SAFETY: group strings are static, and each provider owns its
                // own iterator; every reset is paired with its own end hook.
                unsafe {
                    assert_eq!((api.set)(c"team".as_ptr()), expected, "{name}: set team");
                    (api.end)();
                    assert_eq!((api.set)(c"empty".as_ptr()), expected, "{name}: set empty");
                    (api.end)();
                    assert_eq!((api.set)(c"missing".as_ptr()), 0, "{name}: missing group");
                    (api.end)();
                }
            }
        }
        return;
    }

    for (name, nsswitch_line, expected, set_expected) in BACKEND_ROWS {
        let dir =
            std::env::temp_dir().join(format!("fl-innetgr-nss-{}-{}", std::process::id(), name));
        let etc = dir.join("etc");
        std::fs::create_dir_all(&etc).expect("scratch etc");
        std::fs::write(
            etc.join("netgroup"),
            "team (build,alice,example.com) (,ops,) child\nchild (ci,,example.com) (build,bob,example.com)\nempty\n",
        )
        .expect("write netgroup");
        // The absent-netgroup-line row still has a readable configuration,
        // independently of the absent-file case in the first test.
        std::fs::write(
            etc.join("nsswitch.conf"),
            format!("passwd: files\n{nsswitch_line}\n"),
        )
        .expect("write nsswitch.conf");

        let mut command = Command::new("bwrap");
        command
            .args([
                "--dev-bind",
                "/",
                "/",
                "--ro-bind",
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
            .env_remove("FRANKENLIBC_INNETGR_NSS_SET_EXPECT")
            .env_remove("FRANKENLIBC_NSSWITCH_CONF");
        if let Some(set_expected) = set_expected {
            command.env(
                "FRANKENLIBC_INNETGR_NSS_SET_EXPECT",
                set_expected.to_string(),
            );
        }
        let output = command.output().expect("launch bwrap nsswitch child");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            output.status.success(),
            "nsswitch backend row {name} failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

type SetNetgroupFn = unsafe extern "C" fn(*const c_char) -> c_int;
type GetNetgroupFn =
    unsafe extern "C" fn(*mut *mut c_char, *mut *mut c_char, *mut *mut c_char) -> c_int;
type GetNetgroupReentrantFn = unsafe extern "C" fn(
    *mut *mut c_char,
    *mut *mut c_char,
    *mut *mut c_char,
    *mut c_char,
    usize,
) -> c_int;
type EndNetgroupFn = unsafe extern "C" fn();
type ErrnoFn = unsafe extern "C" fn() -> *mut c_int;

#[derive(Clone, Copy)]
struct NetgroupApi {
    set: SetNetgroupFn,
    get: GetNetgroupFn,
    get_r: GetNetgroupReentrantFn,
    end: EndNetgroupFn,
    errno: ErrnoFn,
}

fn netgroup_providers() -> [(&'static str, NetgroupApi); 2] {
    use frankenlibc_abi::{errno_abi, unistd_abi as fl};
    let candidate = NetgroupApi {
        set: fl::setnetgrent,
        get: fl::getnetgrent,
        get_r: fl::getnetgrent_r,
        end: fl::endnetgrent,
        errno: errno_abi::__errno_location,
    };
    // SAFETY: every function pointer has the public C declaration's signature;
    // every host symbol, including its errno slot, is checked for independence.
    let host = unsafe {
        NetgroupApi {
            set: dlsym_oracle::host_fn(c"setnetgrent", fl::setnetgrent as *const ()),
            get: dlsym_oracle::host_fn(c"getnetgrent", fl::getnetgrent as *const ()),
            get_r: dlsym_oracle::host_fn(c"getnetgrent_r", fl::getnetgrent_r as *const ()),
            end: dlsym_oracle::host_fn(c"endnetgrent", fl::endnetgrent as *const ()),
            errno: dlsym_oracle::host_fn(
                c"__errno_location",
                errno_abi::__errno_location as *const (),
            ),
        }
    };
    [("GNU", host), ("native", candidate)]
}

type Fields = [Option<Vec<u8>>; 3];

fn fields(host: &[u8], user: &[u8], domain: &[u8]) -> Fields {
    [host, user, domain].map(|field| (!field.is_empty()).then(|| field.to_vec()))
}

fn read_entry(api: NetgroupApi, size: Option<usize>) -> (c_int, c_int, Fields) {
    let untouched = c"untouched".as_ptr().cast_mut();
    let mut host = untouched;
    let mut user = untouched;
    let mut domain = untouched;
    let mut buffer = vec![0xa5u8; size.unwrap_or(0).max(1)];
    // SAFETY: output slots and caller buffer are live. A zero-length buffer has
    // a non-null pointer, and failed calls must leave all output slots alone.
    let (result, error) = unsafe {
        *(api.errno)() = 0;
        let result = match size {
            Some(size) => (api.get_r)(
                &mut host,
                &mut user,
                &mut domain,
                buffer.as_mut_ptr().cast(),
                size,
            ),
            None => (api.get)(&mut host, &mut user, &mut domain),
        };
        (result, *(api.errno)())
    };
    assert!(matches!(result, 0 | 1));
    if result == 0 {
        assert_eq!(
            [host, user, domain],
            [untouched; 3],
            "failed read published fields"
        );
        return (result, error, [None, None, None]);
    }
    let values = [host, user, domain].map(|value| {
        if value.is_null() {
            None
        } else {
            // SAFETY: a successful call returned a NUL-terminated field in
            // the still-live caller buffer or the provider's current buffer.
            Some(unsafe { CStr::from_ptr(value) }.to_bytes().to_vec())
        }
    });
    (result, error, values)
}

#[test]
fn netgroup_iteration_and_buffer_retries_match_glibc() {
    if std::env::var_os("FRANKENLIBC_NETGROUP_ITER_CHILD").is_none() {
        let mut fixture = String::from(include_str!("fixtures/innetgr_synthetic.netgroup"));
        fixture.push_str("empty\nwild (,,)\nplain (build,alice,example.com)\n");
        for (index, fields) in [
            ["h".repeat(1500), "alice".into(), "example.com".into()],
            ["build".into(), "u".repeat(1500), "example.com".into()],
            ["build".into(), "alice".into(), "d".repeat(1500)],
        ]
        .into_iter()
        .enumerate()
        {
            fixture.push_str(&format!(
                "long{index} ({},{},{}) (later,bob,example.com)\n",
                fields[0], fields[1], fields[2]
            ));
        }
        fixture.push_str(&format!(
            "buffer_exact_capacity ({},alice,example.com)\n",
            "e".repeat(1005)
        ));
        let mut child = Command::new("bwrap")
            .args([
                "--dev-bind",
                "/",
                "/",
                "--tmpfs",
                "/etc",
                "--file",
                "0",
                "/etc/netgroup",
            ])
            .arg(std::env::current_exe().expect("current test binary"))
            .args([
                "--exact",
                "netgroup_iteration_and_buffer_retries_match_glibc",
                "--nocapture",
                "--test-threads",
                "1",
            ])
            .env("FRANKENLIBC_NETGROUP_ITER_CHILD", "1")
            .env_remove("FRANKENLIBC_NSSWITCH_CONF")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("launch isolated netgroup iterator child");
        child
            .stdin
            .take()
            .expect("fixture input")
            .write_all(fixture.as_bytes())
            .expect("write fixture");
        let output = child.wait_with_output().expect("wait for iterator child");
        assert!(
            output.status.success(),
            "netgroup iterator child failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
            "iterator child must execute its test"
        );
        return;
    }

    let exhausted = (0, 0, [None, None, None]);
    let too_small = (0, libc::ERANGE, [None, None, None]);
    for (name, api) in netgroup_providers() {
        // SAFETY: all group names remain live throughout each call; provider
        // state is reset before use and released through its matching end hook.
        unsafe {
            assert_eq!(
                (api.set)(c"empty".as_ptr()),
                1,
                "{name}: empty group exists"
            );
            assert_eq!(read_entry(api, Some(24)), exhausted, "{name}: empty group");
            assert_eq!((api.set)(c"plain".as_ptr()), 1, "{name}");
            assert_eq!((api.set)(c"missing".as_ptr()), 0, "{name}: absent group");
            assert_eq!(
                read_entry(api, Some(24)),
                exhausted,
                "{name}: failed reset clears old entries"
            );

            assert_eq!((api.set)(c"plain".as_ptr()), 1, "{name}");
            for size in [0, 1, 23] {
                assert_eq!(
                    read_entry(api, Some(size)),
                    too_small,
                    "{name}: short buffer {size}"
                );
            }
            assert_eq!(
                read_entry(api, Some(24)),
                (1, 0, fields(b"build", b"alice", b"example.com")),
                "{name}: exact buffer retries same record"
            );
            assert_eq!(read_entry(api, Some(24)), exhausted, "{name}");

            assert_eq!((api.set)(c"wild".as_ptr()), 1, "{name}");
            assert_eq!(
                read_entry(api, Some(2)),
                too_small,
                "{name}: wildcard NUL capacity"
            );
            assert_eq!(
                read_entry(api, Some(3)),
                (1, 0, [None, None, None]),
                "{name}: actual wildcard fields"
            );

            assert_eq!((api.set)(c"team".as_ptr()), 1, "{name}");
            for expected in [
                fields(b"build", b"alice", b"example.com"),
                fields(b"", b"ops", b""),
                fields(b"ci", b"", b"example.com"),
                fields(b"build", b"bob", b"example.com"),
            ] {
                assert_eq!(
                    read_entry(api, None),
                    (1, 0, expected),
                    "{name}: nested enumeration"
                );
            }
            assert_eq!(read_entry(api, None), exhausted, "{name}");
            (api.end)();
            assert_eq!(read_entry(api, None), exhausted, "{name}: end resets state");

            let first = || fields(b"first", b"alice", b"example.com");
            let build = || fields(b"build", b"alice", b"example.com");
            for (group, found, entries) in [
                ("continued_triples", 1, vec![first(), build()]),
                ("continued_children", 1, vec![build(), first()]),
                (
                    "continued_inside",
                    1,
                    vec![fields(b"bu", b"alice", b"example.com")],
                ),
                ("continued_field_start", 1, vec![build()]),
                ("continuation_owner", 1, vec![first(), build()]),
                ("continued_hidden", 0, vec![]),
                ("dup_first", 1, vec![first()]),
                ("dup_empty", 1, vec![]),
                ("dup_parent", 1, vec![first()]),
                ("continued_cycle", 1, vec![build(), first()]),
                ("comment_hidden", 0, vec![]),
                ("indented", 0, vec![]),
                ("literal#name", 1, vec![build()]),
                ("literal", 0, vec![]),
                ("inline_hash", 1, vec![first(), build()]),
                ("hash_glued", 1, vec![first()]),
                ("comment_chain", 1, vec![first(), build()]),
                ("blank_ends", 1, vec![first()]),
            ] {
                let group_name = CString::new(group).expect("logical record group");
                assert_eq!((api.set)(group_name.as_ptr()), found, "{name}: set {group}");
                for (index, expected) in entries.into_iter().enumerate() {
                    // Exercise both APIs against the same provider-owned
                    // iterator, including continuation and duplicate records.
                    let size = if index % 2 == 0 { None } else { Some(128) };
                    assert_eq!(
                        read_entry(api, size),
                        (1, 0, expected),
                        "{name}: {group} entry {index}"
                    );
                }
                assert_eq!(
                    read_entry(api, Some(128)),
                    exhausted,
                    "{name}: end of {group}"
                );
                (api.end)();
            }

            let expected = [vec![b'e'; 1005], b"alice".to_vec(), b"example.com".to_vec()];
            assert_eq!((api.set)(c"buffer_exact_capacity".as_ptr()), 1, "{name}");
            assert_eq!(
                read_entry(api, None),
                (1, 0, expected.map(Some)),
                "{name}: complete 1024-byte record"
            );

            for (index, expected) in [
                [vec![b'h'; 1500], b"alice".to_vec(), b"example.com".to_vec()],
                [b"build".to_vec(), vec![b'u'; 1500], b"example.com".to_vec()],
                [b"build".to_vec(), b"alice".to_vec(), vec![b'd'; 1500]],
            ]
            .into_iter()
            .enumerate()
            {
                let group = CString::new(format!("long{index}")).expect("group name");
                let needed = expected.iter().map(Vec::len).sum::<usize>() + 3;
                assert_eq!((api.set)(group.as_ptr()), 1, "{name}");
                for _ in 0..2 {
                    assert_eq!(
                        read_entry(api, None),
                        too_small,
                        "{name}: long field must not become a wildcard"
                    );
                }
                assert_eq!(
                    read_entry(api, Some(needed - 1)),
                    too_small,
                    "{name}: retry still needs complete record"
                );
                assert_eq!(
                    read_entry(api, Some(needed)),
                    (1, 0, expected.map(Some)),
                    "{name}: reentrant retry recovers original fields"
                );
                assert_eq!(
                    read_entry(api, None),
                    (1, 0, fields(b"later", b"bob", b"example.com")),
                    "{name}: next record follows recovered entry"
                );
                assert_eq!(read_entry(api, None), exhausted, "{name}");
                (api.end)();
            }
        }
    }
}
