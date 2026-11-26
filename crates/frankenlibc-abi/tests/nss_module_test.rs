#![cfg(target_os = "linux")]

//! NSS service modules (`libnss_<service>.so.2`) behind the passwd, group,
//! shadow, initgroups, hosts and netgroup databases.
//!
//! fl used to answer these databases from /etc/passwd and /etc/group alone,
//! so any user or group provided by sss, systemd, ldap, winbind, ... did not
//! exist under fl. The test module (`tests/integration/
//! fixture_nss_module_lib.c`, built as `libnss_fltest.so.2` and, without
//! `initgroups_dyn`, `libnss_fltestnoig.so.2`) uses only the public module
//! ABI, exactly like those modules.
//!
//! Two gates:
//! - `module_sources_answer_through_fl`: fl alone, configured through its
//!   `FRANKENLIBC_NSSWITCH_CONF` / `_PASSWD_PATH` / `_GROUP_PATH` overrides,
//!   against a transcript measured from glibc 2.39 for the same files.
//! - `module_sources_match_host_glibc`: fl and host glibc side by side in a
//!   private /etc (bwrap, or a root mount namespace), over configurations
//!   covering source order, status actions, group merge and the initgroups
//!   rules. It fails, rather than passes vacuously, when no sandbox exists.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;

const CHILD_ENV: &str = "FRANKENLIBC_NSS_MODULE_CHILD";

#[allow(clippy::type_complexity)]
struct Api {
    getpwnam: unsafe extern "C" fn(*const c_char) -> *mut libc::passwd,
    getpwuid: unsafe extern "C" fn(libc::uid_t) -> *mut libc::passwd,
    getgrnam: unsafe extern "C" fn(*const c_char) -> *mut libc::group,
    getgrgid: unsafe extern "C" fn(libc::gid_t) -> *mut libc::group,
    getspnam: unsafe fn(*const c_char) -> Option<(Vec<u8>, Vec<u8>, i64)>,
    getpwnam_r: unsafe extern "C" fn(
        *const c_char,
        *mut libc::passwd,
        *mut c_char,
        usize,
        *mut *mut libc::passwd,
    ) -> c_int,
    getgrnam_r: unsafe extern "C" fn(
        *const c_char,
        *mut libc::group,
        *mut c_char,
        usize,
        *mut *mut libc::group,
    ) -> c_int,
    getgrouplist:
        unsafe extern "C" fn(*const c_char, libc::gid_t, *mut libc::gid_t, *mut c_int) -> c_int,
    setpwent: unsafe extern "C" fn(),
    getpwent: unsafe extern "C" fn() -> *mut libc::passwd,
    endpwent: unsafe extern "C" fn(),
    setgrent: unsafe extern "C" fn(),
    getgrent: unsafe extern "C" fn() -> *mut libc::group,
    endgrent: unsafe extern "C" fn(),
}

unsafe fn fl_getspnam(name: *const c_char) -> Option<(Vec<u8>, Vec<u8>, i64)> {
    let sp = unsafe { frankenlibc_abi::pwd_abi::getspnam(name) }.cast::<libc::spwd>();
    unsafe { spwd_fields(sp) }
}

unsafe fn host_getspnam(name: *const c_char) -> Option<(Vec<u8>, Vec<u8>, i64)> {
    unsafe { spwd_fields(libc::getspnam(name)) }
}

unsafe fn spwd_fields(sp: *mut libc::spwd) -> Option<(Vec<u8>, Vec<u8>, i64)> {
    if sp.is_null() {
        return None;
    }
    let sp = unsafe { &*sp };
    Some((
        unsafe { cstr(sp.sp_namp) },
        unsafe { cstr(sp.sp_pwdp) },
        sp.sp_lstchg,
    ))
}

fn fl_api() -> Api {
    use frankenlibc_abi::grp_abi as g;
    use frankenlibc_abi::pwd_abi as p;
    Api {
        getpwnam: p::getpwnam,
        getpwuid: p::getpwuid,
        getgrnam: g::getgrnam,
        getgrgid: g::getgrgid,
        getspnam: fl_getspnam,
        getpwnam_r: p::getpwnam_r,
        getgrnam_r: g::getgrnam_r,
        getgrouplist: frankenlibc_abi::unistd_abi::getgrouplist,
        setpwent: p::setpwent,
        getpwent: p::getpwent,
        endpwent: p::endpwent,
        setgrent: g::setgrent,
        getgrent: g::getgrent,
        endgrent: g::endgrent,
    }
}

fn host_api() -> Api {
    Api {
        getpwnam: libc::getpwnam,
        getpwuid: libc::getpwuid,
        getgrnam: libc::getgrnam,
        getgrgid: libc::getgrgid,
        getspnam: host_getspnam,
        getpwnam_r: libc::getpwnam_r,
        getgrnam_r: libc::getgrnam_r,
        getgrouplist: libc::getgrouplist,
        setpwent: libc::setpwent,
        getpwent: libc::getpwent,
        endpwent: libc::endpwent,
        setgrent: libc::setgrent,
        getgrent: libc::getgrent,
        endgrent: libc::endgrent,
    }
}

unsafe fn cstr(p: *const c_char) -> Vec<u8> {
    if p.is_null() {
        b"(null)".to_vec()
    } else {
        unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()
    }
}

fn s(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

unsafe fn pw_line(pw: *mut libc::passwd) -> String {
    if pw.is_null() {
        return "NULL".into();
    }
    let pw = unsafe { &*pw };
    unsafe {
        format!(
            "{}:{}:{}:{}:{}:{}:{}",
            s(&cstr(pw.pw_name)),
            s(&cstr(pw.pw_passwd)),
            pw.pw_uid,
            pw.pw_gid,
            s(&cstr(pw.pw_gecos)),
            s(&cstr(pw.pw_dir)),
            s(&cstr(pw.pw_shell))
        )
    }
}

unsafe fn gr_line(gr: *mut libc::group) -> String {
    if gr.is_null() {
        return "NULL".into();
    }
    let gr = unsafe { &*gr };
    let mut members = Vec::new();
    let mut i = 0;
    while !gr.gr_mem.is_null() && !unsafe { *gr.gr_mem.add(i) }.is_null() {
        members.push(s(&unsafe { cstr(*gr.gr_mem.add(i)) }));
        i += 1;
    }
    unsafe {
        format!(
            "{}:{}:{}:{}",
            s(&cstr(gr.gr_name)),
            s(&cstr(gr.gr_passwd)),
            gr.gr_gid,
            members.join(",")
        )
    }
}

/// Everything one libc answers for the test module's users and groups.
fn transcript(api: &Api) -> String {
    let mut out = String::new();
    let c = |v: &str| CString::new(v).unwrap();
    unsafe {
        for name in ["fltest1", "root", "alice", "fl_nosuch"] {
            writeln!(
                out,
                "getpwnam {name}: {}",
                pw_line((api.getpwnam)(c(name).as_ptr()))
            )
            .unwrap();
        }
        for uid in [4202, 0, 1000, 77777] {
            writeln!(out, "getpwuid {uid}: {}", pw_line((api.getpwuid)(uid))).unwrap();
        }
        for name in ["fltestgrp", "fltestgrp2", "root", "wheel", "fl_nosuch"] {
            writeln!(
                out,
                "getgrnam {name}: {}",
                gr_line((api.getgrnam)(c(name).as_ptr()))
            )
            .unwrap();
        }
        for gid in [4303, 0, 10, 77777] {
            writeln!(out, "getgrgid {gid}: {}", gr_line((api.getgrgid)(gid))).unwrap();
        }
        for name in ["fltest2", "fl_nosuch"] {
            let sp = (api.getspnam)(c(name).as_ptr())
                .map(|(n, p, l)| format!("{}:{}:{l}", s(&n), s(&p)));
            writeln!(out, "getspnam {name}: {}", sp.as_deref().unwrap_or("NULL")).unwrap();
        }
        for (name, len) in [("fltest1", 8usize), ("fltest1", 1024), ("fl_nosuch", 1024)] {
            let mut pw: libc::passwd = std::mem::zeroed();
            let mut res: *mut libc::passwd = std::ptr::null_mut();
            let mut buf = vec![0 as c_char; len];
            let rc = (api.getpwnam_r)(c(name).as_ptr(), &mut pw, buf.as_mut_ptr(), len, &mut res);
            writeln!(out, "getpwnam_r {name} {len}: rc={rc} {}", pw_line(res)).unwrap();
        }
        for (name, len) in [
            ("fltestmany", 16usize),
            ("fltestmany", 1024),
            ("root", 1024),
        ] {
            let mut gr: libc::group = std::mem::zeroed();
            let mut res: *mut libc::group = std::ptr::null_mut();
            let mut buf = vec![0 as c_char; len];
            let rc = (api.getgrnam_r)(c(name).as_ptr(), &mut gr, buf.as_mut_ptr(), len, &mut res);
            writeln!(out, "getgrnam_r {name} {len}: rc={rc} {}", gr_line(res)).unwrap();
        }
        for (user, base) in [("fltest1", 4301), ("fltest2", 4302), ("alice", 1000)] {
            let mut groups = [0 as libc::gid_t; 32];
            let mut n: c_int = 32;
            let rc = (api.getgrouplist)(c(user).as_ptr(), base, groups.as_mut_ptr(), &mut n);
            let list: Vec<String> = groups[..n.max(0) as usize]
                .iter()
                .map(|g| g.to_string())
                .collect();
            writeln!(out, "getgrouplist {user}: rc={rc} [{}]", list.join(" ")).unwrap();
            let mut n: c_int = 0;
            let rc = (api.getgrouplist)(c(user).as_ptr(), base, std::ptr::null_mut(), &mut n);
            writeln!(out, "getgrouplist {user} size query: rc={rc} n={n}").unwrap();
        }
        (api.setpwent)();
        let mut names = Vec::new();
        loop {
            let pw = (api.getpwent)();
            if pw.is_null() {
                break;
            }
            names.push(s(&cstr((*pw).pw_name)));
        }
        (api.endpwent)();
        writeln!(out, "getpwent: {}", names.join(" ")).unwrap();
        (api.setgrent)();
        let mut groups = Vec::new();
        loop {
            let gr = (api.getgrent)();
            if gr.is_null() {
                break;
            }
            groups.push(gr_line(gr));
        }
        (api.endgrent)();
        writeln!(out, "getgrent: {}", groups.join(" | ")).unwrap();
    }
    out
}

const PASSWD: &str =
    "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/sh\n";
const GROUP: &str =
    "root:x:0:alice\nwheel:x:10:fltest1\nfltestgrp:zz:4301:bob\nfltestmany:x:4303:fltest1\n";

fn repo_root() -> PathBuf {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "frankenlibc-nss-module-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// Keep the provider's alignment deterministic in separate GNU/candidate processes.
#[repr(align(16))]
struct AccountCallerBuffer([u8; 4160]);

fn account_reentrant_transcript(host: bool) -> String {
    use frankenlibc_abi::{grp_abi as group, pwd_abi as passwd};

    let mut transcript = String::new();
    for capacity in [
        0, 16, 23, 43, 44, 51, 52, 55, 56, 59, 63, 64, 87, 88, 94, 95, 96, 128, 4095, 4096,
    ] {
        for offset in [0, 1] {
            for operation in ["pwnam", "pwuid", "grnam", "grgid", "spnam"] {
                let mut storage = AccountCallerBuffer([0xa5; 4160]);
                let start = 16 + offset;
                // SAFETY: every call receives capacity writable bytes and valid
                // output/result objects. The surrounding bytes are canaries.
                let (rc, error, value) = unsafe {
                    let buffer = storage.0.as_mut_ptr().add(start).cast::<c_char>();
                    let errno = if host {
                        libc::__errno_location()
                    } else {
                        frankenlibc_abi::errno_abi::__errno_location()
                    };
                    *errno = 619;
                    match operation {
                        "pwnam" | "pwuid" => {
                            let mut entry: libc::passwd = std::mem::zeroed();
                            let mut result = &mut entry as *mut libc::passwd;
                            let rc = match (host, operation) {
                                (true, "pwnam") => libc::getpwnam_r(
                                    c"fltest1".as_ptr(),
                                    &mut entry,
                                    buffer,
                                    capacity,
                                    &mut result,
                                ),
                                (false, "pwnam") => passwd::getpwnam_r(
                                    c"fltest1".as_ptr(),
                                    &mut entry,
                                    buffer,
                                    capacity,
                                    &mut result,
                                ),
                                (true, _) => libc::getpwuid_r(
                                    4201,
                                    &mut entry,
                                    buffer,
                                    capacity,
                                    &mut result,
                                ),
                                (false, _) => passwd::getpwuid_r(
                                    4201,
                                    &mut entry,
                                    buffer,
                                    capacity,
                                    &mut result,
                                ),
                            };
                            let error = *errno;
                            assert!(result.is_null() || (rc == 0 && std::ptr::eq(result, &entry)));
                            (rc, error, pw_line(result))
                        }
                        "grnam" | "grgid" => {
                            let mut entry: libc::group = std::mem::zeroed();
                            let mut result = &mut entry as *mut libc::group;
                            let rc = match (host, operation) {
                                (true, "grnam") => libc::getgrnam_r(
                                    c"fltestgrp".as_ptr(),
                                    &mut entry,
                                    buffer,
                                    capacity,
                                    &mut result,
                                ),
                                (false, "grnam") => group::getgrnam_r(
                                    c"fltestgrp".as_ptr(),
                                    &mut entry,
                                    buffer,
                                    capacity,
                                    &mut result,
                                ),
                                (true, _) => libc::getgrgid_r(
                                    4301,
                                    &mut entry,
                                    buffer,
                                    capacity,
                                    &mut result,
                                ),
                                (false, _) => group::getgrgid_r(
                                    4301,
                                    &mut entry,
                                    buffer,
                                    capacity,
                                    &mut result,
                                ),
                            };
                            let error = *errno;
                            assert!(result.is_null() || (rc == 0 && std::ptr::eq(result, &entry)));
                            (rc, error, gr_line(result))
                        }
                        _ => {
                            let mut entry: libc::spwd = std::mem::zeroed();
                            let mut result = &mut entry as *mut libc::spwd;
                            let rc = if host {
                                libc::getspnam_r(
                                    c"fltest1".as_ptr(),
                                    &mut entry,
                                    buffer,
                                    capacity,
                                    &mut result,
                                )
                            } else {
                                passwd::getspnam_r(
                                    c"fltest1".as_ptr(),
                                    std::ptr::from_mut(&mut entry).cast(),
                                    buffer,
                                    capacity,
                                    std::ptr::from_mut(&mut result).cast(),
                                )
                            };
                            let error = *errno;
                            assert!(result.is_null() || (rc == 0 && std::ptr::eq(result, &entry)));
                            (rc, error, format!("{:?}", spwd_fields(result)))
                        }
                    }
                };
                assert!(storage.0[..start].iter().all(|byte| *byte == 0xa5));
                assert!(
                    storage.0[start + capacity..]
                        .iter()
                        .all(|byte| *byte == 0xa5)
                );
                writeln!(
                    transcript,
                    "{operation}/{capacity}/{offset}={rc}:{error}:{value}"
                )
                .unwrap();
            }
        }
    }
    // Only nonreentrant calls own growable scratch. Do not compare their
    // internal retry count, which is not part of the public libc contract.
    unsafe {
        std::env::remove_var("FLTEST_TRACE");
        std::env::remove_var("FLTEST_ACCOUNT_ERRNO");
    }
    let api = if host { host_api() } else { fl_api() };
    unsafe {
        writeln!(
            transcript,
            "static-pw={}",
            pw_line((api.getpwnam)(c"fltest1".as_ptr()))
        )
        .unwrap();
        writeln!(
            transcript,
            "static-gr={}",
            gr_line((api.getgrnam)(c"fltestgrp".as_ptr()))
        )
        .unwrap();
        writeln!(
            transcript,
            "static-sp={:?}",
            (api.getspnam)(c"fltest1".as_ptr())
        )
        .unwrap();
    }
    transcript
}

/// A module may require more scratch than its result occupies. A caller's
/// ERANGE must be terminal even with TRYAGAIN=continue, and successful module
/// layouts must not be repacked into a larger representation.
#[test]
fn accounts_reentrant_module_buffers_match_glibc() {
    const TEST: &str = "accounts_reentrant_module_buffers_match_glibc";
    if std::env::var_os(CHILD_ENV).is_some() {
        let host = std::env::var("FLTEST_ACCOUNT_PROVIDER").unwrap() == "host";
        if host {
            unsafe extern "C" {
                fn __nss_configure_lookup(database: *const c_char, sources: *const c_char)
                -> c_int;
            }
            let accounts = CString::new(std::env::var("FLTEST_ACCOUNT_SOURCES").unwrap()).unwrap();
            let groups = CString::new(std::env::var("FLTEST_GROUP_SOURCES").unwrap()).unwrap();
            for (database, sources) in [
                (c"passwd", &accounts),
                (c"shadow", &accounts),
                (c"group", &groups),
            ] {
                assert_eq!(
                    unsafe { __nss_configure_lookup(database.as_ptr(), sources.as_ptr()) },
                    0
                );
            }
        }
        unsafe { libc::alarm(15) };
        let transcript = account_reentrant_transcript(host);
        unsafe { libc::alarm(0) };
        println!("ACCOUNT_BUFFER_BEGIN\n{transcript}ACCOUNT_BUFFER_END");
        return;
    }
    let dir = scratch_dir("account-reentrant-buffers");
    build_modules(&dir);
    let cases = [
        ("fltest", "fltest", false, false),
        ("fltest", "fltest", true, false),
        (
            "fltest [TRYAGAIN=continue] fltestnoig",
            "fltest [TRYAGAIN=continue] fltestnoig",
            true,
            false,
        ),
        (
            "fltest [TRYAGAIN=return] fltestnoig",
            "fltest [TRYAGAIN=return] fltestnoig",
            true,
            false,
        ),
        (
            "fltest [SUCCESS=continue] fltestnoig",
            "fltest [SUCCESS=continue] fltestnoig",
            false,
            false,
        ),
        ("fltest", "fltest [SUCCESS=merge] fltestnoig", false, false),
        ("fltest", "fltest [SUCCESS=merge] flmissing", false, false),
        ("fltest fltestnoig", "fltest fltestnoig", false, true),
    ];
    let mut compared = 0;
    for (index, (accounts, groups, scratch, errno_probe)) in cases.into_iter().enumerate() {
        let mut oracle = None;
        for (provider, mode) in [("host", "strict"), ("fl", "strict"), ("fl", "hardened")] {
            let label = format!("account-buffers-{index}-{provider}-{mode}");
            let config = format!("passwd: {accounts}\nshadow: {accounts}\ngroup: {groups}\n");
            let mut child = host_module_child(TEST, &dir, &config, &label);
            child
                .env("FLTEST_ACCOUNT_PROVIDER", provider)
                .env("FLTEST_ACCOUNT_SOURCES", accounts)
                .env("FLTEST_GROUP_SOURCES", groups)
                .env("FLTEST_TRACE", "1")
                .env("FRANKENLIBC_MODE", mode);
            child.env("FLTEST_ACCOUNT_ERRNO", if errno_probe { "1" } else { "0" });
            if scratch {
                child.env("FLTEST_ACCOUNT_SCRATCH", "fltest");
            } else {
                child.env_remove("FLTEST_ACCOUNT_SCRATCH");
            }
            let result = run_child(child, &label);
            let stdout = std::str::from_utf8(&result.stdout).unwrap();
            let transcript = stdout
                .split_once("ACCOUNT_BUFFER_BEGIN\n")
                .and_then(|(_, rest)| rest.split_once("ACCOUNT_BUFFER_END"))
                .map(|(text, _)| text)
                .expect("account buffer transcript")
                .to_owned();
            assert_eq!(transcript.lines().count(), 203);
            let trace = String::from_utf8_lossy(&result.stderr)
                .lines()
                .filter(|line| line.starts_with("fltest:") || line.starts_with("fltestnoig:"))
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if scratch {
                assert!(transcript.contains(&format!(
                    "pwnam/128/0={}:{}:NULL",
                    libc::ERANGE,
                    libc::ERANGE
                )));
                assert!(transcript.contains("pwnam/4096/0=0:"));
                assert!(transcript.contains("static-pw=fltest1:x:4201:4301:"));
            }
            if let Some(expected) = &oracle {
                assert_eq!(
                    &(transcript, trace),
                    expected,
                    "{label}: accounts={accounts}, groups={groups}"
                );
                compared += 1;
            } else {
                oracle = Some((transcript, trace));
            }
        }
    }
    assert_eq!(compared, 16);
    eprintln!("account buffers: {compared} GNU/candidate comparisons, all five reentrant lookups");
}

unsafe fn account_enumeration_value(database: &str, result: *mut c_void) -> Option<String> {
    if result.is_null() {
        return None;
    }
    Some(unsafe {
        match database {
            "passwd" => pw_line(result.cast()),
            "group" => gr_line(result.cast()),
            "shadow" => {
                let (name, password, changed) = spwd_fields(result.cast()).unwrap();
                format!("{}:{}:{changed}", s(&name), s(&password))
            }
            _ => unreachable!(),
        }
    })
}

fn account_enumeration_read(
    host: bool,
    database: &str,
    capacity: Option<usize>,
    offset: usize,
) -> (c_int, c_int, Option<String>) {
    use frankenlibc_abi::{grp_abi as group, pwd_abi as passwd};

    let mut storage = AccountCallerBuffer([0xa5; 4160]);
    let start = 16 + offset;
    // Nonreentrant growth may invoke get repeatedly. Suppress only those
    // private get traces; source-transition set/end callbacks remain visible.
    if capacity.is_none() {
        unsafe { std::env::set_var("FLTEST_ACCOUNT_ENUM_PRIVATE", "1") };
    }
    let (rc, error, value) = unsafe {
        let errno = if host {
            libc::__errno_location()
        } else {
            frankenlibc_abi::errno_abi::__errno_location()
        };
        let mut pw: libc::passwd = std::mem::zeroed();
        let mut gr: libc::group = std::mem::zeroed();
        let mut sp: libc::spwd = std::mem::zeroed();
        let output: *mut c_void = match database {
            "passwd" => (&raw mut pw).cast(),
            "group" => (&raw mut gr).cast(),
            "shadow" => (&raw mut sp).cast(),
            _ => unreachable!(),
        };
        let mut result = output;
        *errno = 619;
        let rc = if let Some(capacity) = capacity {
            let buffer = storage.0.as_mut_ptr().add(start).cast::<c_char>();
            match (host, database) {
                (true, "passwd") => libc::getpwent_r(output.cast(), buffer, capacity, (&raw mut result).cast()),
                (false, "passwd") => passwd::getpwent_r(output.cast(), buffer, capacity, (&raw mut result).cast()),
                (true, "group") => libc::getgrent_r(output.cast(), buffer, capacity, (&raw mut result).cast()),
                (false, "group") => group::getgrent_r(output.cast(), buffer, capacity, (&raw mut result).cast()),
                (true, "shadow") => libc::getspent_r(output.cast(), buffer, capacity, (&raw mut result).cast()),
                (false, "shadow") => passwd::getspent_r(output, buffer, capacity, &mut result),
                _ => unreachable!(),
            }
        } else {
            result = match (host, database) {
                (true, "passwd") => libc::getpwent().cast(),
                (false, "passwd") => passwd::getpwent().cast(),
                (true, "group") => libc::getgrent().cast(),
                (false, "group") => group::getgrent().cast(),
                (true, "shadow") => libc::getspent().cast(),
                (false, "shadow") => passwd::getspent(),
                _ => unreachable!(),
            };
            if result.is_null() { -1 } else { 0 }
        };
        let error = *errno;
        if capacity.is_some() {
            assert!(result.is_null() || (rc == 0 && result == output));
        }
        let value = account_enumeration_value(database, result);
        (rc, error, value)
    };
    if let Some(capacity) = capacity {
        assert!(storage.0[..start].iter().all(|byte| *byte == 0xa5));
        assert!(storage.0[start + capacity..].iter().all(|byte| *byte == 0xa5));
    } else {
        unsafe { std::env::remove_var("FLTEST_ACCOUNT_ENUM_PRIVATE") };
    }
    (rc, error, value)
}

fn account_enumeration_lifecycle(host: bool, database: &str, rewind: bool) -> c_int {
    use frankenlibc_abi::{grp_abi as group, pwd_abi as passwd};
    unsafe {
        let errno = if host { libc::__errno_location() } else {
            frankenlibc_abi::errno_abi::__errno_location()
        };
        *errno = 619;
        match (host, database, rewind) {
            (true, "passwd", true) => libc::setpwent(),
            (false, "passwd", true) => passwd::setpwent(),
            (true, "passwd", false) => libc::endpwent(),
            (false, "passwd", false) => passwd::endpwent(),
            (true, "group", true) => libc::setgrent(),
            (false, "group", true) => group::setgrent(),
            (true, "group", false) => libc::endgrent(),
            (false, "group", false) => group::endgrent(),
            (true, "shadow", true) => libc::setspent(),
            (false, "shadow", true) => passwd::setspent(),
            (true, "shadow", false) => libc::endspent(),
            (false, "shadow", false) => passwd::endspent(),
            _ => unreachable!(),
        }
        *errno
    }
}

fn account_enumeration_transcript(host: bool, database: &str) -> String {
    let mut output = String::new();
    writeln!(output, "fresh-end {}", account_enumeration_lifecycle(host, database, false)).unwrap();
    for capacity in [0, 1, 8] {
        writeln!(output, "implicit {capacity} {:?}", account_enumeration_read(host, database, Some(capacity), 1)).unwrap();
    }
    writeln!(output, "static-after-range {:?}", account_enumeration_read(host, database, None, 0)).unwrap();
    for (index, capacity) in [64, 4095, 4096].into_iter().enumerate() {
        writeln!(output, "mixed {capacity} {:?}", account_enumeration_read(host, database, Some(capacity), index % 2)).unwrap();
    }
    for index in 0..16 {
        let value = account_enumeration_read(host, database, Some(4096), index % 2);
        let done = value.2.is_none();
        writeln!(output, "drain {index} {value:?}").unwrap();
        if done { break; }
    }
    writeln!(output, "repeat-eof {:?}", account_enumeration_read(host, database, Some(4096), 0)).unwrap();
    writeln!(output, "set {}", account_enumeration_lifecycle(host, database, true)).unwrap();
    writeln!(output, "rewind-small {:?}", account_enumeration_read(host, database, Some(1), 0)).unwrap();
    writeln!(output, "rewind-retry {:?}", account_enumeration_read(host, database, Some(4096), 1)).unwrap();
    writeln!(output, "static-next {:?}", account_enumeration_read(host, database, None, 0)).unwrap();
    writeln!(output, "end {}", account_enumeration_lifecycle(host, database, false)).unwrap();
    writeln!(output, "end-again {}", account_enumeration_lifecycle(host, database, false)).unwrap();
    writeln!(output, "after-end {:?}", account_enumeration_read(host, database, Some(4096), 1)).unwrap();
    writeln!(output, "final-end {}", account_enumeration_lifecycle(host, database, false)).unwrap();
    output
}

/// Public account enumeration must expose the provider's real ERANGE, retain
/// its row for retry, and share traversal between _r and nonreentrant callers.
#[test]
fn accounts_enumeration_matches_glibc_module_policy() {
    const TEST: &str = "accounts_enumeration_matches_glibc_module_policy";
    if std::env::var_os(CHILD_ENV).is_some() {
        let host = std::env::var("FLTEST_ACCOUNT_PROVIDER").unwrap() == "host";
        let database = std::env::var("FLTEST_ACCOUNT_DATABASE").unwrap();
        if host {
            unsafe extern "C" {
                fn __nss_configure_lookup(database: *const c_char, sources: *const c_char) -> c_int;
            }
            let name = CString::new(database.as_str()).unwrap();
            let sources = CString::new(std::env::var("FLTEST_ACCOUNT_SOURCES").unwrap()).unwrap();
            assert_eq!(unsafe { __nss_configure_lookup(name.as_ptr(), sources.as_ptr()) }, 0);
        }
        unsafe { libc::alarm(15) };
        let transcript = account_enumeration_transcript(host, &database);
        unsafe { libc::alarm(0) };
        println!("ACCOUNT_ENUM_BEGIN\n{transcript}ACCOUNT_ENUM_END");
        return;
    }

    let dir = scratch_dir("account-enumeration");
    build_modules(&dir);
    let module = Command::new("cc")
        .args(["-O2", "-fPIC", "-shared", "-DSERVICE=flaccountgetonly",
            "-DNO_ACCOUNT_SET", "-DNO_ACCOUNT_END"])
        .arg(repo_root().join("tests/integration/fixture_nss_module_lib.c"))
        .arg("-o").arg(dir.join("libnss_flaccountgetonly.so.2"))
        .output().expect("build get-only account module");
    assert!(module.status.success(), "account module build failed: {}",
        String::from_utf8_lossy(&module.stderr));
    let cases = [
        ("fltest", "normal", false),
        ("fltest fltestnoig", "normal", false),
        ("fltest [SUCCESS=continue] fltestnoig", "normal", false),
        ("fltest [TRYAGAIN=continue] fltestnoig", "normal", true),
        ("fltest [TRYAGAIN=return] fltestnoig", "normal", true),
        ("fltest [UNAVAIL=return] fltestnoig", "get-unavail", false),
        ("fltest [UNAVAIL=continue] fltestnoig", "get-unavail", false),
        ("fltest [TRYAGAIN=return] fltestnoig", "get-again", false),
        ("fltest [TRYAGAIN=continue] fltestnoig", "get-again", false),
        ("fltest [TRYAGAIN=return] fltestnoig", "get-quiet-again", false),
        ("fltest [NOTFOUND=return] fltestnoig", "get-notfound", false),
        ("fltest [NOTFOUND=continue] fltestnoig", "get-notfound", false),
        ("fltest fltestnoig", "get-return", false),
        ("fltest [!SUCCESS=continue] fltestnoig", "get-return", false),
        ("fltest fltestnoig", "set-unavail", false),
        ("fltest [UNAVAIL=return] fltestnoig", "set-unavail", false),
        ("fltest [TRYAGAIN=return] fltestnoig", "set-again", false),
        ("fltest [NOTFOUND=return] fltestnoig", "set-notfound", false),
        ("fltest fltestnoig", "set-return", false),
        ("flmissing fltest", "normal", false),
        ("flmissing [UNAVAIL=return] fltestnoig", "normal", false),
        ("flaccountgetonly", "normal", false),
        ("flaccountgetonly fltest", "normal", false),
        ("fltest flaccountgetonly fltestnoig", "normal", false),
    ];
    let mut compared = 0;
    for database in ["passwd", "group", "shadow"] {
        for (index, (sources, scenario, scratch)) in cases.into_iter().enumerate() {
            let mut oracle = None;
            for (provider, mode) in [("host", "strict"), ("fl", "strict"), ("fl", "hardened")] {
                let label = format!("account-enum-{database}-{index}-{provider}-{mode}");
                let mut child = host_module_child(TEST, &dir, &format!("{database}: {sources}\n"), &label);
                child.env("FLTEST_ACCOUNT_PROVIDER", provider)
                    .env("FLTEST_ACCOUNT_DATABASE", database)
                    .env("FLTEST_ACCOUNT_SOURCES", sources)
                    .env("FLTEST_ACCOUNT_ENUM", scenario)
                    .env("FLTEST_TRACE", "1")
                    .env("FRANKENLIBC_MODE", mode)
                    .env_remove("FLTEST_ACCOUNT_ENUM_PRIVATE")
                    .env_remove("FLTEST_ACCOUNT_SCRATCH")
                    .env_remove("FLTEST_ACCOUNT_ERRNO");
                if scratch {
                    child.env("FLTEST_ACCOUNT_ENUM_SCRATCH", "fltest");
                } else {
                    child.env_remove("FLTEST_ACCOUNT_ENUM_SCRATCH");
                }
                let result = run_child(child, &label);
                let stdout = std::str::from_utf8(&result.stdout).unwrap();
                let transcript = stdout.split_once("ACCOUNT_ENUM_BEGIN\n")
                    .and_then(|(_, rest)| rest.split_once("ACCOUNT_ENUM_END"))
                    .map(|(text, _)| text).expect("account enumeration transcript").to_owned();
                assert!(transcript.lines().count() >= 18);
                let trace = String::from_utf8_lossy(&result.stderr).lines()
                    .filter(|line| line.starts_with("fltest:") || line.starts_with("fltestnoig:")
                        || line.starts_with("flaccountgetonly:"))
                    .map(str::to_owned).collect::<Vec<_>>();
                if sources == "fltest" && scenario == "normal" {
                    assert!(transcript.contains("static-after-range (0,"),
                        "{label}: the first record must survive short-buffer retries");
                    assert!(transcript.contains("fltest1") || transcript.contains("fltestgrp"),
                        "{label}: no provider record was observed");
                }
                if let Some(expected) = &oracle {
                    assert_eq!(&(transcript, trace), expected,
                        "{label}: database={database}, sources={sources}, scenario={scenario}");
                    compared += 1;
                } else {
                    oracle = Some((transcript, trace));
                }
            }
        }
    }
    assert_eq!(compared, 144);
    eprintln!("account enumeration: {compared} independent GNU/candidate comparisons");
}

fn account_enumeration_files_read(database: &str, capacity: usize) -> (c_int, Option<String>) {
    use frankenlibc_abi::unistd_abi as nss;

    let mut storage = AccountCallerBuffer([0xa5; 4160]);
    let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut group: libc::group = unsafe { std::mem::zeroed() };
    let mut shadow: libc::spwd = unsafe { std::mem::zeroed() };
    let output: *mut c_void = match database {
        "passwd" => (&raw mut passwd).cast(),
        "group" => (&raw mut group).cast(),
        "shadow" => (&raw mut shadow).cast(),
        _ => unreachable!(),
    };
    // SAFETY: the matching C output and the exact writable buffer are live
    // throughout the direct files callback. Each call has independent storage.
    let (status, value) = unsafe {
        let mut error = 781;
        let errno = frankenlibc_abi::errno_abi::__errno_location();
        *errno = 619;
        let buffer = storage.0.as_mut_ptr().add(17).cast();
        let status = match database {
            "passwd" => nss::_nss_files_getpwent_r(output, buffer, capacity, &mut error),
            "group" => nss::_nss_files_getgrent_r(output, buffer, capacity, &mut error),
            "shadow" => nss::_nss_files_getspent_r(output, buffer, capacity, &mut error),
            _ => unreachable!(),
        };
        let value = if status == 1 {
            assert_eq!((error, *errno), (781, 619));
            account_enumeration_value(database, output)
        } else {
            None
        };
        (status, value)
    };
    assert!(storage.0[..17].iter().all(|byte| *byte == 0xa5));
    assert!(storage.0[17 + capacity..].iter().all(|byte| *byte == 0xa5));
    (status, value)
}

fn account_enumeration_files_rewind(database: &str) {
    use frankenlibc_abi::unistd_abi as nss;
    // SAFETY: these direct providers take only the stayopen flag.
    let status = unsafe {
        match database {
            "passwd" => nss::_nss_files_setpwent(0),
            "group" => nss::_nss_files_setgrent(0),
            "shadow" => nss::_nss_files_setspent(0),
            _ => unreachable!(),
        }
    };
    assert_eq!(status, 1);
}

/// The public iterator and direct files provider must use the same real file
/// cursor. A hidden pending owned record would replay stale data after a direct
/// provider consumes the row following ERANGE.
#[test]
fn accounts_enumeration_shares_files_provider_cursor() {
    const TEST: &str = "accounts_enumeration_shares_files_provider_cursor";
    if std::env::var_os(CHILD_ENV).is_some() {
        unsafe { libc::alarm(15) };
        for database in ["passwd", "group", "shadow"] {
            let assert_public = |expected: &str, capacity| {
                let (rc, _, record) = account_enumeration_read(false, database, capacity, 1);
                assert_eq!(rc, 0, "{database}: {expected}");
                let record = record.expect("public enumeration record");
                assert!(record.starts_with(&format!("{expected}:")), "{database}: {record}");
            };
            let assert_direct = |expected: &str| {
                let (status, record) = account_enumeration_files_read(database, 4096);
                assert_eq!(status, 1, "{database}: {expected}");
                let record = record.expect("direct files enumeration record");
                assert!(record.starts_with(&format!("{expected}:")), "{database}: {record}");
            };
            account_enumeration_lifecycle(false, database, true);
            // The ignored physical line is larger than 128 bytes even though
            // the first returned account fits. Do not consume it privately.
            let small = account_enumeration_read(false, database, Some(128), 1);
            assert_eq!(small, (libc::ERANGE, libc::ERANGE, None), "{database}");
            assert_direct("local_a");
            assert_public("local_b", Some(4096));
            assert_public("local_c", None);

            let (first, second) = if database == "group" {
                ("fltestgrp", "fltestgrp2")
            } else {
                ("fltest1", "fltest2")
            };
            assert_public(first, Some(4096));
            // Rewinding only the files module must not reset public selection
            // once the iterator has advanced to an installed module.
            account_enumeration_files_rewind(database);
            assert_public(second, Some(4096));

            account_enumeration_lifecycle(false, database, false);
            assert_public("local_a", Some(4096));
            assert_direct("local_b");
            account_enumeration_lifecycle(false, database, false);
        }
        unsafe { libc::alarm(0) };
        println!("ACCOUNT_ENUM_FILES_CURSOR_OK");
        return;
    }

    let dir = scratch_dir("account-enumeration-files");
    build_modules(&dir);
    let ignored = format!("#{}\n", "x".repeat(512));
    let mut passwd = ignored.clone();
    let mut group = ignored.clone();
    let mut shadow = ignored;
    for (index, name) in ["local_a", "local_b", "local_c"].into_iter().enumerate() {
        let id = 8100 + index;
        writeln!(passwd, "{name}:x:{id}:{id}:Local:/home/local:/bin/sh").unwrap();
        writeln!(group, "{name}:x:{id}:member").unwrap();
        writeln!(shadow, "{name}:x:20000:0:99999:7:::").unwrap();
    }
    std::fs::write(dir.join("passwd"), passwd).unwrap();
    std::fs::write(dir.join("group"), group).unwrap();
    std::fs::write(dir.join("shadow"), shadow).unwrap();
    for mode in ["strict", "hardened"] {
        let mut child = host_module_child(
            TEST,
            &dir,
            "passwd: files fltest\ngroup: files fltest\nshadow: files fltest\n",
            mode,
        );
        child.env("FRANKENLIBC_MODE", mode)
            .env("FRANKENLIBC_PASSWD_PATH", dir.join("passwd"))
            .env("FRANKENLIBC_GROUP_PATH", dir.join("group"))
            .env("FRANKENLIBC_SHADOW_PATH", dir.join("shadow"))
            .env_remove("FLTEST_ACCOUNT_ENUM")
            .env_remove("FLTEST_ACCOUNT_ENUM_PRIVATE")
            .env_remove("FLTEST_ACCOUNT_ENUM_SCRATCH")
            .env_remove("FLTEST_ACCOUNT_SCRATCH")
            .env_remove("FLTEST_ACCOUNT_ERRNO");
        let output = run_child(child, &format!("account files cursor {mode}"));
        assert!(String::from_utf8_lossy(&output.stdout).contains("ACCOUNT_ENUM_FILES_CURSOR_OK"));
    }
}

fn build_modules(dir: &Path) {
    let source = repo_root().join("tests/integration/fixture_nss_module_lib.c");
    let variants: &[(&str, &[&str])] = &[
        ("fltest", &[]),
        ("fltesthost4", &["-DWITH_HOST4"]),
        (
            "fltesttupleonly",
            &["-DWITH_HOST4", "-DNO_HOST1", "-DNO_HOST2", "-DNO_HOST3"],
        ),
        ("fltestnoig", &["-DNO_INITGROUPS"]),
        ("fltesthost2", &["-DNO_HOST3", "-DNO_HOSTADDR2"]),
        (
            "fltesthostlegacy",
            &["-DNO_HOST3", "-DNO_HOST2", "-DNO_HOSTADDR2"],
        ),
    ];
    for (service, extra) in variants {
        let mut cc = Command::new("cc");
        cc.args(["-O2", "-fPIC", "-shared", &format!("-DSERVICE={service}")]);
        cc.args(*extra);
        let output = cc
            .arg(&source)
            .arg("-o")
            .arg(dir.join(format!("libnss_{service}.so.2")))
            .output()
            .expect("run cc for the test NSS module");
        assert!(
            output.status.success(),
            "building libnss_{service}.so.2 failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn run_child(mut command: Command, label: &str) -> std::process::Output {
    let output = command.output().expect("launch child test process");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{label} child failed:\nstdout={stdout}\nstderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    // libtest prints exactly this for a filter matching nothing; insist the
    // child really ran its one test.
    assert!(
        stdout.contains("1 passed"),
        "{label} child ran no test:\n{stdout}"
    );
    output
}

fn child_test_command(test_name: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("test binary path"));
    command.args(["--exact", test_name, "--nocapture", "--test-threads", "1"]);
    command
}

/// Exercise the production file selectors and their warmed identity caches.
/// AT_SECURE is modeled in an isolated process; this does not claim a
/// privileged kernel-exec test or alter the machine's account databases.
#[cfg(feature = "conformance-testing")]
#[test]
fn secure_startup_ignores_identity_file_overrides() {
    use frankenlibc_abi::{grp_abi as group, pwd_abi as passwd, stdlib_abi as env};

    const TEST: &str = "secure_startup_ignores_identity_file_overrides";
    const CHILD: &str = "FRANKENLIBC_SECURE_IDENTITY_TEST_CHILD";
    const NAME: &str = "FRANKENLIBC_SECURE_IDENTITY_TEST_NAME";
    const MARKER: &str = "secure identity overrides and warmed caches checked";
    if std::env::var_os(CHILD).is_none() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("fl_secure_identity_{}_{stamp}", std::process::id());
        let dir = std::env::temp_dir().join(&name);
        // Retain these private fixture files as failure evidence. No system
        // files are written and no existing directory is removed/reused.
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(
            dir.join("passwd"),
            format!("{name}:x:61234:61235:Fixture:/fixture:/bin/sh\n"),
        )
        .unwrap();
        std::fs::write(dir.join("group"), format!("{name}:x:61235:{name}\n")).unwrap();
        std::fs::write(
            dir.join("shadow"),
            format!("{name}:fixture-password:20000:0:99999:7:::\n"),
        )
        .unwrap();
        std::fs::write(
            dir.join("gshadow"),
            format!("{name}:fixture-password::{name}\n"),
        )
        .unwrap();
        std::fs::write(
            dir.join("nsswitch.conf"),
            "passwd: files\ngroup: files\nshadow: files\ninitgroups: files\n",
        )
        .unwrap();
        for mode in ["strict", "hardened"] {
            let mut command = child_test_command(TEST);
            command
                .env(CHILD, "1")
                .env(NAME, &name)
                .env("FRANKENLIBC_MODE", mode)
                .env("FRANKENLIBC_PASSWD_PATH", dir.join("passwd"))
                .env("FRANKENLIBC_GROUP_PATH", dir.join("group"))
                .env("FRANKENLIBC_SHADOW_PATH", dir.join("shadow"))
                .env("FRANKENLIBC_GSHADOW_PATH", dir.join("gshadow"))
                .env("FRANKENLIBC_NSSWITCH_CONF", dir.join("nsswitch.conf"));
            let output = run_child(command, &format!("secure identity {mode}"));
            assert!(String::from_utf8_lossy(&output.stdout).contains(MARKER));
        }
        return;
    }

    // SAFETY: only this test runs in the child. The timer bounds external NSS
    // modules from the host's real configuration as well as local file I/O.
    unsafe { libc::alarm(30) };
    let name = CString::new(std::env::var(NAME).unwrap()).unwrap();
    // Returning to normal execution between refusals proves the fixture
    // remains reachable and refreshes both positive UID/GID cache entries.
    for secure in [Some(0), Some(1), Some(0), None, Some(0), Some(17), Some(0)] {
        // SAFETY: no other auxv reader runs in this isolated child.
        unsafe { env::set_secure_auxv_for_conformance(secure) };
        let allowed = secure == Some(0);
        for _ in 0..2 {
            // SAFETY: inputs are live NUL-terminated names; each static result
            // is inspected before another call can overwrite its storage.
            unsafe {
                let pw = passwd::getpwnam(name.as_ptr());
                assert_eq!(!pw.is_null(), allowed, "getpwnam: {secure:?}");
                if !pw.is_null() {
                    assert_eq!(cstr((*pw).pw_name), name.as_bytes());
                    assert_eq!((*pw).pw_uid, 61234);
                }
                let pw = passwd::getpwuid(61234);
                assert_eq!(
                    !pw.is_null() && cstr((*pw).pw_name) == name.as_bytes(),
                    allowed,
                    "getpwuid cache: {secure:?}"
                );
                let gr = group::getgrnam(name.as_ptr());
                assert_eq!(!gr.is_null(), allowed, "getgrnam: {secure:?}");
                if !gr.is_null() {
                    assert_eq!(cstr((*gr).gr_name), name.as_bytes());
                    assert_eq!((*gr).gr_gid, 61235);
                }
                let gr = group::getgrgid(61235);
                assert_eq!(
                    !gr.is_null() && cstr((*gr).gr_name) == name.as_bytes(),
                    allowed,
                    "getgrgid cache: {secure:?}"
                );
                assert_eq!(
                    !passwd::getspnam(name.as_ptr()).is_null(),
                    allowed,
                    "getspnam: {secure:?}"
                );
                assert_eq!(
                    !passwd::getsgnam(name.as_ptr()).is_null(),
                    allowed,
                    "getsgnam: {secure:?}"
                );
            }
        }
    }
    unsafe { libc::alarm(0) };
    println!("{MARKER}");
}

/// An attacker-controlled nsswitch file can select loadable service modules,
/// even if the passwd/group file overrides themselves are rejected.
#[cfg(feature = "conformance-testing")]
#[test]
fn secure_startup_ignores_nss_configuration_override() {
    use frankenlibc_abi::{pwd_abi as passwd, stdlib_abi as env};

    const TEST: &str = "secure_startup_ignores_nss_configuration_override";
    const CHILD: &str = "FRANKENLIBC_SECURE_NSS_CONFIG_TEST_CHILD";
    const NAME: &str = "FRANKENLIBC_SECURE_NSS_CONFIG_TEST_NAME";
    const MARKER: &str = "secure NSS configuration and warmed policy checked";
    if std::env::var_os(CHILD).is_none() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "frankenlibc-secure-nss-config-{}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        let config = dir.join("nsswitch.conf");
        // The deliberately absent module stops lookup before files. This
        // tests policy selection without loading any test-supplied DSO.
        std::fs::write(
            &config,
            format!(
                "passwd: flmissing{}x{stamp} [UNAVAIL=return] files\n",
                std::process::id()
            ),
        )
        .unwrap();
        let content = std::fs::read("/etc/passwd").unwrap();
        let name = content
            .split(|&byte| byte == b'\n')
            .find(|line| !line.is_empty() && !matches!(line[0], b'#' | b'+' | b'-'))
            .and_then(|line| line.split(|&byte| byte == b':').next())
            .expect("host has a real files account");
        use std::os::unix::ffi::OsStrExt;
        for mode in ["strict", "hardened"] {
            let mut command = child_test_command(TEST);
            command
                .env(CHILD, "1")
                .env(NAME, std::ffi::OsStr::from_bytes(name))
                .env("FRANKENLIBC_MODE", mode)
                .env("FRANKENLIBC_NSSWITCH_CONF", &config)
                .env_remove("FRANKENLIBC_PASSWD_PATH");
            let output = run_child(command, &format!("secure NSS policy {mode}"));
            assert!(String::from_utf8_lossy(&output.stdout).contains(MARKER));
        }
        return;
    }

    unsafe { libc::alarm(30) };
    let name = CString::new(std::env::var_os(NAME).unwrap().as_encoded_bytes()).unwrap();
    // Host GNU libc ignores FrankenLibC's private override variable. Capture
    // its trusted system-policy answer as an independent comparison oracle.
    let trusted = unsafe { libc::getpwnam(name.as_ptr()) };
    assert!(
        !trusted.is_null(),
        "system NSS resolves its real files account"
    );
    let trusted = unsafe { pw_line(trusted) };
    for secure in [Some(0), Some(1), Some(0), None, Some(0), Some(17), Some(0)] {
        unsafe { env::set_secure_auxv_for_conformance(secure) };
        for _ in 0..2 {
            let value = unsafe { passwd::getpwnam(name.as_ptr()) };
            if secure == Some(0) {
                assert!(
                    value.is_null(),
                    "the ordinary override must select the absent module"
                );
            } else {
                assert!(!value.is_null(), "secure policy cache: {secure:?}");
                assert_eq!(
                    unsafe { pw_line(value) },
                    trusted,
                    "secure policy: {secure:?}"
                );
            }
        }
    }
    unsafe { libc::alarm(0) };
    println!("{MARKER}");
}

// glibc 2.39, same files, `passwd: files fltest` / `group: files
// [SUCCESS=merge] fltest` / `initgroups: files fltestnoig` / `shadow: fltest`.
const EXPECTED_FL_ONLY: &str = "\
getpwnam fltest1: fltest1:x:4201:4301:FL Test One:/home/fltest1:/bin/sh
getpwnam root: root:x:0:0:root:/root:/bin/bash
getpwnam alice: alice:x:1000:1000:Alice:/home/alice:/bin/sh
getpwnam fl_nosuch: NULL
getpwuid 4202: fltest2:*:4202:4302:FL Test Two:/home/fltest2:/bin/false
getpwuid 0: root:x:0:0:root:/root:/bin/bash
getpwuid 1000: alice:x:1000:1000:Alice:/home/alice:/bin/sh
getpwuid 77777: NULL
getgrnam fltestgrp: fltestgrp:zz:4301:bob,fltest1,fltest2
getgrnam fltestgrp2: fltestgrp2::4302:fltest1
getgrnam root: root:x:0:alice,fltest1
getgrnam wheel: wheel:x:10:fltest1
getgrnam fl_nosuch: NULL
getgrgid 4303: fltestmany:x:4303:fltest1,fltest2,nobody,fltest1
getgrgid 0: root:x:0:alice,fltest1
getgrgid 10: wheel:x:10:fltest1
getgrgid 77777: NULL
getspnam fltest2: fltest2:$6$fltest$hash:19002
getspnam fl_nosuch: NULL
getpwnam_r fltest1 8: rc=34 NULL
getpwnam_r fltest1 1024: rc=0 fltest1:x:4201:4301:FL Test One:/home/fltest1:/bin/sh
getpwnam_r fl_nosuch 1024: rc=0 NULL
getgrnam_r fltestmany 16: rc=34 NULL
getgrnam_r fltestmany 1024: rc=0 fltestmany:x:4303:fltest1,fltest2,nobody,fltest1
getgrnam_r root 1024: rc=0 root:x:0:alice,fltest1
getgrouplist fltest1: rc=3 [4301 10 4303]
getgrouplist fltest1 size query: rc=-1 n=3
getgrouplist fltest2: rc=3 [4302 4301 4303]
getgrouplist fltest2 size query: rc=-1 n=3
getgrouplist alice: rc=2 [1000 0]
getgrouplist alice size query: rc=-1 n=2
getpwent: root alice fltest1 fltest2 root
getgrent: root:x:0:alice | wheel:x:10:fltest1 | fltestgrp:zz:4301:bob | fltestmany:x:4303:fltest1 | fltestgrp:x:4301:fltest1,fltest2 | fltestgrp2::4302:fltest1 | fltestmany:x:4303:fltest2,nobody,fltest1 | root:y:0:fltest1
";

#[test]
fn module_sources_answer_through_fl() {
    if std::env::var_os(CHILD_ENV).is_some_and(|v| v == "fl") {
        let got = transcript(&fl_api());
        assert_eq!(got, EXPECTED_FL_ONLY, "fl transcript:\n{got}");
        return;
    }
    let dir = scratch_dir("fl");
    build_modules(&dir);
    std::fs::write(dir.join("passwd"), PASSWD).unwrap();
    std::fs::write(dir.join("group"), GROUP).unwrap();
    std::fs::write(
        dir.join("nsswitch.conf"),
        "passwd: files fltest\ngroup: files [SUCCESS=merge] fltest\n\
         initgroups: files fltestnoig\nshadow: fltest\n",
    )
    .unwrap();
    let mut child = child_test_command("module_sources_answer_through_fl");
    child
        .env(CHILD_ENV, "fl")
        .env("LD_LIBRARY_PATH", &dir)
        .env("FRANKENLIBC_NSSWITCH_CONF", dir.join("nsswitch.conf"))
        .env("FRANKENLIBC_PASSWD_PATH", dir.join("passwd"))
        .env("FRANKENLIBC_GROUP_PATH", dir.join("group"));
    run_child(child, "fl-only");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn runtime_configure_lookup_replaces_concurrent_source_snapshots() {
    use frankenlibc_abi::{errno_abi, glibc_internal_abi, pwd_abi};

    fn configure(line: &CStr) {
        // SAFETY: both arguments are live terminated strings. Successful
        // runtime configuration must preserve the caller's errno.
        unsafe {
            *errno_abi::__errno_location() = 73;
            assert_eq!(
                glibc_internal_abi::__nss_configure_lookup(c"passwd".as_ptr(), line.as_ptr()),
                0
            );
            assert_eq!(*errno_abi::__errno_location(), 73);
        }
    }

    fn lookup() -> bool {
        let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        let mut buffer = [0 as c_char; 1024];
        // SAFETY: caller-owned storage remains live through the reentrant
        // lookup and copying of every returned field. No shared TLS result.
        unsafe {
            let rc = pwd_abi::getpwnam_r(
                c"fltest1".as_ptr(),
                record.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            );
            assert_eq!(rc, 0);
            if result.is_null() {
                return false;
            }
            assert_eq!(result, record.as_mut_ptr());
            let record = &*result;
            assert_eq!(CStr::from_ptr(record.pw_name), c"fltest1");
            assert_eq!((record.pw_uid, record.pw_gid), (4201, 4301));
            assert_eq!(CStr::from_ptr(record.pw_dir), c"/home/fltest1");
            true
        }
    }

    if std::env::var_os(CHILD_ENV).is_some_and(|v| v == "configure-concurrent") {
        assert!(!lookup(), "the configured files backend has no module user");
        configure(c"fltest");
        assert!(
            lookup(),
            "a successful override must actually change lookup"
        );
        // A failed replacement must leave the last complete snapshot live.
        unsafe {
            assert_eq!(
                glibc_internal_abi::__nss_configure_lookup(
                    c"passwd".as_ptr(),
                    c"files [SUCCESS=invalid]".as_ptr(),
                ),
                -1
            );
            assert_eq!(*errno_abi::__errno_location(), libc::EINVAL);
        }
        assert!(lookup());
        let barrier = std::sync::Barrier::new(5);
        std::thread::scope(|scope| {
            let barrier = &barrier;
            for _ in 0..4 {
                scope.spawn(move || {
                    barrier.wait();
                    for _ in 0..128 {
                        // Either complete policy may win this race. A result
                        // may never retain pointers into a retired snapshot.
                        let _ = lookup();
                    }
                });
            }
            barrier.wait();
            for _ in 0..64 {
                configure(c"files");
                configure(c"fltest");
            }
        });
        configure(c"files");
        assert!(!lookup());
        configure(c"fltest");
        assert!(lookup());
        return;
    }
    let dir = scratch_dir("configure-concurrent");
    build_modules(&dir);
    std::fs::write(dir.join("passwd"), PASSWD).unwrap();
    std::fs::write(dir.join("nsswitch.conf"), "passwd: files\n").unwrap();
    for mode in ["strict", "hardened"] {
        let mut child =
            child_test_command("runtime_configure_lookup_replaces_concurrent_source_snapshots");
        child
            .env(CHILD_ENV, "configure-concurrent")
            .env("FRANKENLIBC_MODE", mode)
            .env("LD_LIBRARY_PATH", &dir)
            .env("FRANKENLIBC_NSSWITCH_CONF", dir.join("nsswitch.conf"))
            .env("FRANKENLIBC_PASSWD_PATH", dir.join("passwd"))
            .env_remove("FLTEST_STATUS");
        run_child(child, &format!("runtime-configure {mode}"));
    }
}

#[test]
fn files_identity_providers_bypass_configured_nss_modules() {
    use frankenlibc_abi::unistd_abi as files;

    if let Some(scenario) = std::env::var_os(CHILD_ENV) {
        let api = fl_api();
        let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
        let mut gr: libc::group = unsafe { std::mem::zeroed() };
        let mut buffer = [0 as c_char; 1024];
        let mut err = 717;
        // SAFETY: all input strings are terminated and output buffers are
        // live, writable, and retained while their borrowed fields are read.
        unsafe {
            assert!((api.getpwnam)(c"files-user".as_ptr()).is_null());
            assert!((api.getpwuid)(8301).is_null());
            assert!((api.getgrnam)(c"files-group".as_ptr()).is_null());
            assert!((api.getgrgid)(8401).is_null());
            if scenario == "module" {
                assert!(pw_line((api.getpwnam)(c"fltest1".as_ptr())).starts_with("fltest1:"));
                assert!(gr_line((api.getgrnam)(c"fltestgrp".as_ptr())).starts_with("fltestgrp:"));
            }

            assert_eq!(
                files::_nss_files_getpwnam_r(
                    c"files-user".as_ptr(),
                    (&raw mut pw).cast(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut err,
                ),
                1
            );
            assert_eq!(
                pw_line(&mut pw),
                "files-user:x:8301:8401:Local:/local:/bin/sh"
            );
            assert_eq!(err, 717);
            assert_eq!(
                files::_nss_files_getpwuid_r(
                    8301,
                    (&raw mut pw).cast(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut err,
                ),
                1
            );
            assert_eq!(cstr(pw.pw_name), b"files-user");
            assert_eq!(
                files::_nss_files_getgrnam_r(
                    c"files-group".as_ptr(),
                    (&raw mut gr).cast(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut err,
                ),
                1
            );
            assert_eq!(gr_line(&mut gr), "files-group:x:8401:files-user");
            assert_eq!(err, 717);
            assert_eq!(
                files::_nss_files_getgrgid_r(
                    8401,
                    (&raw mut gr).cast(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut err,
                ),
                1
            );
            assert_eq!(cstr(gr.gr_name), b"files-group");
            assert_eq!(
                files::_nss_files_getpwnam_r(
                    c"fltest1".as_ptr(),
                    (&raw mut pw).cast(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut err,
                ),
                0,
                "a files provider must not expose a record from another module"
            );
            assert_eq!(
                files::_nss_files_getgrnam_r(
                    c"fltestgrp".as_ptr(),
                    (&raw mut gr).cast(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut err,
                ),
                0
            );
            assert_eq!(err, 717);

            assert_eq!(files::_nss_files_setpwent(0), 1);
            for expected in [1, 0] {
                assert_eq!(
                    files::_nss_files_getpwent_r(
                        (&raw mut pw).cast(),
                        buffer.as_mut_ptr(),
                        buffer.len(),
                        &mut err,
                    ),
                    expected
                );
                if expected == 1 {
                    assert_eq!(cstr(pw.pw_name), b"files-user");
                }
            }
            assert_eq!(files::_nss_files_endpwent(), 1);
            assert_eq!(files::_nss_files_setgrent(0), 1);
            for expected in [1, 0] {
                assert_eq!(
                    files::_nss_files_getgrent_r(
                        (&raw mut gr).cast(),
                        buffer.as_mut_ptr(),
                        buffer.len(),
                        &mut err,
                    ),
                    expected
                );
                if expected == 1 {
                    assert_eq!(cstr(gr.gr_name), b"files-group");
                }
            }
            assert_eq!(files::_nss_files_endgrent(), 1);
            assert_eq!(err, 717);
            // Files lifecycle calls must not rewrite the configured public
            // service chain or make its previously unavailable user visible.
            assert!((api.getpwnam)(c"files-user".as_ptr()).is_null());
            assert!((api.getgrnam)(c"files-group".as_ptr()).is_null());
        }
        return;
    }

    let dir = scratch_dir("files-identity");
    build_modules(&dir);
    std::fs::write(
        dir.join("passwd"),
        "files-user:x:8301:8401:Local:/local:/bin/sh\n",
    )
    .unwrap();
    std::fs::write(dir.join("group"), "files-group:x:8401:files-user\n").unwrap();
    for (scenario, services) in [
        ("module", "fltest [NOTFOUND=return]"),
        ("missing", "fltestmissing [UNAVAIL=return] files"),
    ] {
        let config = dir.join(format!("{scenario}.conf"));
        std::fs::write(&config, format!("passwd: {services}\ngroup: {services}\n")).unwrap();
        for mode in ["strict", "hardened"] {
            let mut child =
                child_test_command("files_identity_providers_bypass_configured_nss_modules");
            child
                .env(CHILD_ENV, scenario)
                .env("LD_LIBRARY_PATH", &dir)
                .env("FLTEST_STATUS", "")
                .env("FRANKENLIBC_MODE", mode)
                .env("FRANKENLIBC_NSSWITCH_CONF", &config)
                .env("FRANKENLIBC_PASSWD_PATH", dir.join("passwd"))
                .env("FRANKENLIBC_GROUP_PATH", dir.join("group"));
            run_child(child, &format!("files identity {scenario} {mode}"));
        }
    }
}

/// Configurations for the side-by-side gate: source order, actions, merge,
/// unloadable modules and the initgroups rules.
const DIFF_CONFIGS: &[&str] = &[
    // The configuration EXPECTED_FL_ONLY pins.
    "passwd: files fltest\ngroup: files [SUCCESS=merge] fltest\ninitgroups: files fltestnoig\nshadow: fltest\n",
    "passwd: files fltest\ngroup: files fltest\nshadow: files fltest\n",
    "passwd: fltest files\ngroup: fltest files\n",
    "passwd: fltest [NOTFOUND=return] files\ngroup: files [SUCCESS=merge] fltest\n",
    "passwd: nosuchmod files\ngroup: nosuchmod [UNAVAIL=return] files\n",
    "passwd: files\ngroup: files fltestnoig\n",
    "group: files [SUCCESS=merge] fltest [SUCCESS=merge] files\n",
    "group: files\ninitgroups: files fltest\n",
    "group: files\ninitgroups: files [SUCCESS=continue] fltest\n",
    "group: files fltest\ninitgroups:\n",
    "passwd: files [NOTFOUND=return] fltest\ngroup: files [NOTFOUND=return] fltest\n",
];

/// Launch the child with `files` bound over /etc/<name> for both libcs.
fn sandboxed(files: &[(&str, PathBuf)], test_name: &str) -> Option<Command> {
    let exe = std::env::current_exe().expect("test binary path");
    let test_args = ["--exact", test_name, "--nocapture", "--test-threads", "1"];
    if Command::new("bwrap")
        .args(["--dev-bind", "/", "/", "true"])
        .output()
        .is_ok_and(|o| o.status.success())
    {
        let mut command = Command::new("bwrap");
        command.args(["--dev-bind", "/", "/"]);
        for (name, path) in files {
            command.arg("--bind").arg(path).arg(format!("/etc/{name}"));
        }
        command.arg(&exe).args(test_args);
        return Some(command);
    }
    if Command::new("unshare")
        .args(["-m", "true"])
        .output()
        .is_ok_and(|o| o.status.success())
    {
        let mut script = String::new();
        for (name, path) in files {
            write!(script, "mount --bind '{}' /etc/{name} && ", path.display()).unwrap();
        }
        script.push_str("exec \"$@\"");
        let mut command = Command::new("unshare");
        command
            .args(["-m", "sh", "-c", &script, "sh"])
            .arg(&exe)
            .args(test_args);
        return Some(command);
    }
    None
}

#[test]
fn module_sources_match_host_glibc() {
    if std::env::var_os(CHILD_ENV).is_some_and(|v| v == "diff") {
        // Both libcs read the same bind-mounted /etc files and modules.
        let fl = transcript(&fl_api());
        let host = transcript(&host_api());
        assert_eq!(
            fl,
            host,
            "fl vs glibc for nsswitch.conf:\n{}",
            std::fs::read_to_string("/etc/nsswitch.conf").unwrap_or_default()
        );
        return;
    }
    let dir = scratch_dir("diff");
    build_modules(&dir);
    std::fs::write(dir.join("passwd"), PASSWD).unwrap();
    std::fs::write(dir.join("group"), GROUP).unwrap();
    for (index, config) in DIFF_CONFIGS.iter().enumerate() {
        let conf = dir.join(format!("nsswitch.{index}.conf"));
        std::fs::write(&conf, config).unwrap();
        let files = [
            ("nsswitch.conf", conf),
            ("passwd", dir.join("passwd")),
            ("group", dir.join("group")),
        ];
        let mut child = sandboxed(&files, "module_sources_match_host_glibc").expect(
            "need bwrap or a root mount namespace (unshare -m) to give glibc a private /etc",
        );
        child.env(CHILD_ENV, "diff").env("LD_LIBRARY_PATH", &dir);
        // fl's own path overrides would bypass the bind mounts glibc sees.
        for var in [
            "FRANKENLIBC_NSSWITCH_CONF",
            "FRANKENLIBC_PASSWD_PATH",
            "FRANKENLIBC_GROUP_PATH",
        ] {
            child.env_remove(var);
        }
        run_child(child, &format!("config {index} ({config:?})"));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

const HOSTS: &str = "\
198.51.100.10 files-host shared-host
2001:db8:1::10 files-host shared-host
192.0.2.41 files-reverse
2001:db8::41 files-reverse
";

#[derive(Debug, PartialEq, Eq)]
struct HostAnswer {
    name: Vec<u8>,
    aliases: Vec<Vec<u8>>,
    addresses: Vec<IpAddr>,
}

unsafe fn host_answer(host: *const libc::hostent) -> Option<HostAnswer> {
    if host.is_null() {
        return None;
    }
    let host = unsafe { &*host };
    let mut aliases = Vec::new();
    if !host.h_aliases.is_null() {
        let mut index = 0;
        loop {
            let alias = unsafe { *host.h_aliases.add(index) };
            if alias.is_null() {
                break;
            }
            aliases.push(unsafe { cstr(alias) });
            index += 1;
        }
    }
    let mut addresses = Vec::new();
    if !host.h_addr_list.is_null() {
        let mut index = 0;
        loop {
            let address = unsafe { *host.h_addr_list.add(index) };
            if address.is_null() {
                break;
            }
            addresses.push(match (host.h_addrtype, host.h_length) {
                (libc::AF_INET, 4) => {
                    IpAddr::V4(Ipv4Addr::from(unsafe { address.cast::<[u8; 4]>().read() }))
                }
                (libc::AF_INET6, 16) => {
                    IpAddr::V6(Ipv6Addr::from(unsafe { address.cast::<[u8; 16]>().read() }))
                }
                value => panic!("invalid hostent address shape: {value:?}"),
            });
            index += 1;
        }
    }
    Some(HostAnswer {
        name: unsafe { cstr(host.h_name) },
        aliases,
        addresses,
    })
}

fn named_addresses(name: &str, family: c_int, extra_flags: c_int) -> Result<HostAnswer, c_int> {
    let name = CString::new(name).unwrap();
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = family;
    hints.ai_socktype = libc::SOCK_STREAM;
    hints.ai_flags = libc::AI_CANONNAME | extra_flags;
    let mut head = std::ptr::null_mut();
    let rc = unsafe {
        frankenlibc_abi::resolv_abi::getaddrinfo(name.as_ptr(), std::ptr::null(), &hints, &mut head)
    };
    if rc != 0 {
        assert!(head.is_null());
        return Err(rc);
    }
    assert!(!head.is_null());
    let canonical = unsafe { cstr((*head).ai_canonname) };
    let mut addresses = Vec::new();
    let mut current = head;
    while !current.is_null() {
        let item = unsafe { &*current };
        if current != head {
            assert!(
                item.ai_canonname.is_null(),
                "only the first addrinfo may carry the canonical name"
            );
        }
        addresses.push(match item.ai_family {
            libc::AF_INET => {
                let address = unsafe { &*item.ai_addr.cast::<libc::sockaddr_in>() };
                IpAddr::V4(Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()))
            }
            libc::AF_INET6 => {
                let address = unsafe { &*item.ai_addr.cast::<libc::sockaddr_in6>() };
                IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr))
            }
            value => panic!("invalid addrinfo family: {value}"),
        });
        current = item.ai_next;
    }
    unsafe { frankenlibc_abi::resolv_abi::freeaddrinfo(head) };
    addresses.sort();
    Ok(HostAnswer {
        name: canonical,
        aliases: Vec::new(),
        addresses,
    })
}

fn reverse_name(address: IpAddr) -> Result<Vec<u8>, c_int> {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match address {
        IpAddr::V4(address) => {
            let sa = unsafe {
                &mut *(&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>()
            };
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_addr.s_addr = u32::from_ne_bytes(address.octets());
            std::mem::size_of::<libc::sockaddr_in>()
        }
        IpAddr::V6(address) => {
            let sa = unsafe {
                &mut *(&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
            };
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_addr.s6_addr = address.octets();
            std::mem::size_of::<libc::sockaddr_in6>()
        }
    };
    let mut buffer = [0 as c_char; 512];
    let rc = unsafe {
        frankenlibc_abi::resolv_abi::getnameinfo(
            (&storage as *const libc::sockaddr_storage).cast(),
            len as libc::socklen_t,
            buffer.as_mut_ptr(),
            buffer.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };
    if rc == 0 {
        Ok(unsafe { cstr(buffer.as_ptr()) })
    } else {
        Err(rc)
    }
}

fn host_module_child(test: &str, dir: &Path, config: &str, tag: &str) -> Command {
    let conf = dir.join(format!("hosts-{tag}.conf"));
    std::fs::write(&conf, config).unwrap();
    let mut child = child_test_command(test);
    child
        .env(CHILD_ENV, tag)
        .env("LD_LIBRARY_PATH", dir)
        .env("FRANKENLIBC_NSSWITCH_CONF", conf)
        .env("FRANKENLIBC_HOSTS_PATH", dir.join("hosts"))
        .env_remove("FLTEST_STATUS")
        .env_remove("FLTEST_TRACE");
    child
}

#[derive(Debug, PartialEq, Eq)]
struct ScopedHostAnswer {
    canonical: Vec<u8>,
    addresses: Vec<(IpAddr, u32)>,
}

/// Call each provider directly, preserving scope IDs that a hostent loses.
fn scoped_named_addresses(
    host: bool,
    name: &str,
    family: c_int,
) -> Result<ScopedHostAnswer, c_int> {
    let name = CString::new(name).unwrap();
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = family;
    hints.ai_socktype = libc::SOCK_STREAM;
    hints.ai_flags = libc::AI_CANONNAME;
    let mut head = std::ptr::null_mut();
    // SAFETY: both providers receive a C string, valid hints and an output slot.
    let rc = unsafe {
        if host {
            libc::getaddrinfo(name.as_ptr(), std::ptr::null(), &hints, &mut head)
        } else {
            frankenlibc_abi::resolv_abi::getaddrinfo(
                name.as_ptr(),
                std::ptr::null(),
                &hints,
                &mut head,
            )
        }
    };
    if rc != 0 {
        assert!(
            head.is_null(),
            "failed lookup published a partial addrinfo list"
        );
        return Err(rc);
    }
    assert!(!head.is_null());
    let canonical = unsafe { cstr((*head).ai_canonname) };
    let mut addresses = Vec::new();
    let mut current = head;
    while !current.is_null() {
        assert!(addresses.len() < 16, "cyclic or oversized addrinfo result");
        let item = unsafe { &*current };
        assert!(!item.ai_addr.is_null());
        if current != head {
            assert!(item.ai_canonname.is_null(), "canonical name repeated");
        }
        let address = match item.ai_family {
            libc::AF_INET => {
                assert_eq!(
                    item.ai_addrlen as usize,
                    std::mem::size_of::<libc::sockaddr_in>()
                );
                let address = unsafe { &*item.ai_addr.cast::<libc::sockaddr_in>() };
                assert_eq!(address.sin_family as c_int, libc::AF_INET);
                (
                    IpAddr::V4(Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes())),
                    0,
                )
            }
            libc::AF_INET6 => {
                assert_eq!(
                    item.ai_addrlen as usize,
                    std::mem::size_of::<libc::sockaddr_in6>()
                );
                let address = unsafe { &*item.ai_addr.cast::<libc::sockaddr_in6>() };
                assert_eq!(address.sin6_family as c_int, libc::AF_INET6);
                (
                    IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)),
                    address.sin6_scope_id,
                )
            }
            value => panic!("invalid addrinfo family: {value}"),
        };
        addresses.push(address);
        current = item.ai_next;
    }
    // SAFETY: release with the same provider that allocated the list.
    unsafe {
        if host {
            libc::freeaddrinfo(head);
        } else {
            frankenlibc_abi::resolv_abi::freeaddrinfo(head);
        }
    }
    addresses.sort();
    Ok(ScopedHostAnswer {
        canonical,
        addresses,
    })
}

fn tuple_addresses() -> Vec<(IpAddr, u32)> {
    let mut addresses = vec![
        (Ipv4Addr::new(192, 0, 2, 41).into(), 0),
        ("2001:db8::41".parse().unwrap(), 0),
        ("fe80::41".parse().unwrap(), 7),
        ("fe80::41".parse().unwrap(), 9),
    ];
    addresses.sort();
    addresses
}

fn assert_module_hosts(include_ipv6: bool, has_canonp: bool) {
    let v4: [IpAddr; 2] = [
        Ipv4Addr::new(192, 0, 2, 41).into(),
        Ipv4Addr::new(192, 0, 2, 42).into(),
    ];
    let v6: [IpAddr; 2] = [
        "2001:db8::41".parse().unwrap(),
        "2001:db8::42".parse().unwrap(),
    ];
    for (family, addresses) in [(libc::AF_INET, v4), (libc::AF_INET6, v6)] {
        if family == libc::AF_INET6 && !include_ipv6 {
            assert!(named_addresses("fltest-host", family, 0).is_err());
            continue;
        }
        for name in ["fltest-alias", "fltest-large"] {
            let name_c = CString::new(name).unwrap();
            let answer = unsafe {
                host_answer(
                    frankenlibc_abi::unistd_abi::gethostbyname2(name_c.as_ptr(), family).cast(),
                )
            }
            .expect("module host must be visible through gethostbyname2");
            assert_eq!(answer.name, b"fltest-host.example");
            assert_eq!(answer.addresses, addresses);
            assert_eq!(
                answer.aliases[..2],
                [b"fltest-alias".to_vec(), b"fltest-short".to_vec()]
            );
            if name == "fltest-large" {
                assert_eq!(answer.aliases.len(), 3);
                assert_eq!(answer.aliases[2], vec![b'a'; 3072]);
            } else {
                assert_eq!(answer.aliases.len(), 2);
            }
            let addrinfo = named_addresses(name, family, 0).unwrap();
            assert_eq!(addrinfo.name, b"fltest-host.example");
            assert_eq!(addrinfo.addresses, addresses);

            for len in [8usize, 8192] {
                let mut host: libc::hostent = unsafe { std::mem::zeroed() };
                let mut result = std::ptr::null_mut();
                let mut buffer = vec![0 as c_char; len];
                let mut h_errno = -1;
                let rc = unsafe {
                    frankenlibc_abi::unistd_abi::gethostbyname2_r(
                        name_c.as_ptr(),
                        family,
                        &mut host,
                        buffer.as_mut_ptr(),
                        buffer.len(),
                        &mut result,
                        &mut h_errno,
                    )
                };
                if len == 8 {
                    assert_eq!(rc, libc::ERANGE);
                    assert!(result.is_null());
                } else {
                    assert_eq!(rc, 0);
                    assert_eq!(h_errno, 0);
                    assert_eq!(unsafe { host_answer(result) }.as_ref(), Some(&answer));
                }
            }
        }

        for address in addresses {
            assert_eq!(reverse_name(address).unwrap(), b"fltest-host.example");
            let bytes = match address {
                IpAddr::V4(value) => value.octets().to_vec(),
                IpAddr::V6(value) => value.octets().to_vec(),
            };
            let legacy = unsafe {
                host_answer(
                    frankenlibc_abi::resolv_abi::gethostbyaddr(
                        bytes.as_ptr().cast(),
                        bytes.len() as libc::socklen_t,
                        family,
                    )
                    .cast(),
                )
            }
            .expect("module reverse result");
            assert_eq!(legacy.name, b"fltest-host.example");
            assert_eq!(legacy.addresses, addresses);
            assert_eq!(
                legacy.aliases[..2],
                [b"fltest-alias".to_vec(), b"fltest-short".to_vec()]
            );
            if address == addresses[1] {
                assert_eq!(legacy.aliases.len(), 3);
                assert_eq!(legacy.aliases[2], vec![b'a'; 3072]);
            } else {
                assert_eq!(legacy.aliases.len(), 2);
            }
            for len in [8usize, 8192] {
                let mut host: libc::hostent = unsafe { std::mem::zeroed() };
                let mut result: *mut c_void = std::ptr::null_mut();
                let mut buffer = vec![0 as c_char; len];
                let mut h_errno = -1;
                let rc = unsafe {
                    frankenlibc_abi::inet_abi::gethostbyaddr_r(
                        bytes.as_ptr().cast(),
                        bytes.len() as libc::socklen_t,
                        family,
                        (&mut host as *mut libc::hostent).cast(),
                        buffer.as_mut_ptr(),
                        buffer.len(),
                        &mut result,
                        &mut h_errno,
                    )
                };
                if len == 8 {
                    assert_eq!(rc, libc::ERANGE);
                    assert!(result.is_null());
                } else {
                    assert_eq!(rc, 0);
                    assert_eq!(h_errno, 0);
                    assert_eq!(
                        unsafe { host_answer(result.cast()) }.as_ref(),
                        Some(&legacy)
                    );
                }
            }
        }
    }

    let name = CString::new("fltest-host").unwrap();
    let answer =
        unsafe { host_answer(frankenlibc_abi::resolv_abi::gethostbyname(name.as_ptr()).cast()) }
            .unwrap();
    assert_eq!(answer.name, b"fltest-host.example");
    assert_eq!(answer.addresses, v4);
    let mut host: libc::hostent = unsafe { std::mem::zeroed() };
    let mut result: *mut c_void = std::ptr::null_mut();
    let mut buffer = [0 as c_char; 8192];
    let mut h_errno = -1;
    assert_eq!(
        unsafe {
            frankenlibc_abi::inet_abi::gethostbyname_r(
                name.as_ptr(),
                (&mut host as *mut libc::hostent).cast(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
                &mut h_errno,
            )
        },
        0
    );
    assert_eq!(h_errno, 0);
    assert_eq!(
        unsafe { host_answer(result.cast()) }.as_ref(),
        Some(&answer)
    );

    let mut all = v4.to_vec();
    if include_ipv6 {
        all.extend(v6);
    }
    all.sort();
    assert_eq!(
        named_addresses("fltest-host", libc::AF_UNSPEC, 0)
            .unwrap()
            .addresses,
        all
    );
    let mut mapped: Vec<IpAddr> = v4
        .iter()
        .map(|address| match address {
            IpAddr::V4(value) => IpAddr::V6(value.to_ipv6_mapped()),
            IpAddr::V6(_) => unreachable!(),
        })
        .collect();
    let mapped_address = Ipv4Addr::new(192, 0, 2, 41).to_ipv6_mapped();
    let mapped_bytes = mapped_address.octets();
    let mapped_reverse = unsafe {
        host_answer(
            frankenlibc_abi::resolv_abi::gethostbyaddr(
                mapped_bytes.as_ptr().cast(),
                mapped_bytes.len() as libc::socklen_t,
                libc::AF_INET6,
            )
            .cast(),
        )
    }
    .unwrap();
    assert_eq!(mapped_reverse.name, b"fltest-host.example");
    assert_eq!(mapped_reverse.addresses, mapped);
    assert_eq!(mapped_reverse.aliases, answer.aliases);
    assert_eq!(
        unsafe {
            frankenlibc_abi::inet_abi::gethostbyaddr_r(
                mapped_bytes.as_ptr().cast(),
                mapped_bytes.len() as libc::socklen_t,
                libc::AF_INET6,
                (&mut host as *mut libc::hostent).cast(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
                &mut h_errno,
            )
        },
        0
    );
    assert_eq!(
        unsafe { host_answer(result.cast()) }.as_ref(),
        Some(&mapped_reverse)
    );
    if include_ipv6 {
        mapped.extend(v6);
    }
    mapped.sort();
    assert_eq!(
        named_addresses(
            "fltest-host",
            libc::AF_INET6,
            libc::AI_V4MAPPED | libc::AI_ALL,
        )
        .unwrap()
        .addresses,
        mapped
    );
    assert_eq!(
        named_addresses("fltest-canonical", libc::AF_INET, 0)
            .unwrap()
            .name,
        if has_canonp {
            b"fltest-official.example".to_vec()
        } else {
            b"fltest-host.example".to_vec()
        },
        "getaddrinfo must honor the module's separate canonical-name output"
    );
    let canonical_query = CString::new("fltest-canonical").unwrap();
    assert_eq!(
        unsafe {
            host_answer(frankenlibc_abi::resolv_abi::gethostbyname(canonical_query.as_ptr()).cast())
        }
        .unwrap()
        .name,
        b"fltest-host.example",
        "the hostent name remains independent of the canonical-name extension"
    );
}

#[test]
fn hosts_modules_forward_reverse_and_scratch_growth() {
    if let Ok(service) = std::env::var(CHILD_ENV) {
        assert_module_hosts(service != "fltesthostlegacy", service == "fltest");
        return;
    }
    let dir = scratch_dir("hosts-forward-reverse");
    build_modules(&dir);
    std::fs::write(dir.join("hosts"), HOSTS).unwrap();
    for service in ["fltest", "fltesthost2", "fltesthostlegacy"] {
        let child = host_module_child(
            "hosts_modules_forward_reverse_and_scratch_growth",
            &dir,
            &format!("hosts: {service}\n"),
            service,
        );
        run_child(child, service);
    }
}

fn assert_files_hosts_isolation() {
    for (family, address) in [
        (libc::AF_INET, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 41))),
        (libc::AF_INET6, "2001:db8::41".parse::<IpAddr>().unwrap()),
    ] {
        let mut host: libc::hostent = unsafe { std::mem::zeroed() };
        let mut buffer = [0 as c_char; 8192];
        let mut error = -1;
        let mut h_errno = -1;
        for (name, expected) in [("shared-host", 1), ("fltest-host", 0)] {
            let name = CString::new(name).unwrap();
            let status = unsafe {
                frankenlibc_abi::unistd_abi::_nss_files_gethostbyname2_r(
                    name.as_ptr(),
                    family,
                    (&mut host as *mut libc::hostent).cast(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut error,
                    &mut h_errno,
                )
            };
            assert_eq!(status, expected);
            if status == 1 {
                assert_eq!(unsafe { host_answer(&host) }.unwrap().name, b"files-host");
            }
        }
        let bytes = match address {
            IpAddr::V4(value) => value.octets().to_vec(),
            IpAddr::V6(value) => value.octets().to_vec(),
        };
        assert_eq!(
            unsafe {
                frankenlibc_abi::unistd_abi::_nss_files_gethostbyaddr_r(
                    bytes.as_ptr().cast(),
                    bytes.len() as libc::socklen_t,
                    family,
                    (&mut host as *mut libc::hostent).cast(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut error,
                    &mut h_errno,
                )
            },
            1
        );
        assert_eq!(
            unsafe { host_answer(&host) }.unwrap().name,
            b"files-reverse"
        );
    }
}

fn assert_hosts_policy(expected: &str) {
    let forward = named_addresses("shared-host", libc::AF_INET, 0);
    let reverse = reverse_name(Ipv4Addr::new(192, 0, 2, 41).into());
    let name = CString::new("shared-host").unwrap();
    let legacy =
        unsafe { host_answer(frankenlibc_abi::resolv_abi::gethostbyname(name.as_ptr()).cast()) };
    let mut host: libc::hostent = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let mut buffer = [0 as c_char; 8192];
    let mut h_errno = -1;
    let rc = unsafe {
        frankenlibc_abi::unistd_abi::gethostbyname2_r(
            name.as_ptr(),
            libc::AF_INET6,
            &mut host,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
            &mut h_errno,
        )
    };
    let reverse_address = [192u8, 0, 2, 41];
    let mut reverse_host: libc::hostent = unsafe { std::mem::zeroed() };
    let mut reverse_result: *mut c_void = std::ptr::null_mut();
    let mut reverse_buffer = [0 as c_char; 8192];
    let mut reverse_h_errno = -1;
    let reverse_rc = unsafe {
        frankenlibc_abi::inet_abi::gethostbyaddr_r(
            reverse_address.as_ptr().cast(),
            reverse_address.len() as libc::socklen_t,
            libc::AF_INET,
            (&mut reverse_host as *mut libc::hostent).cast(),
            reverse_buffer.as_mut_ptr(),
            reverse_buffer.len(),
            &mut reverse_result,
            &mut reverse_h_errno,
        )
    };
    match expected {
        "module" => {
            let answer = forward.unwrap();
            assert_eq!(answer.name, b"fltest-host.example");
            assert_eq!(
                answer.addresses,
                vec![
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 41)),
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42)),
                ]
            );
            assert_eq!(reverse.unwrap(), b"fltest-host.example");
            assert_eq!(reverse_rc, 0);
            assert_eq!(
                unsafe { host_answer(reverse_result.cast()) }.unwrap().name,
                b"fltest-host.example"
            );
            assert_eq!(legacy.unwrap().name, b"fltest-host.example");
            assert_eq!(rc, 0);
            assert_eq!(
                unsafe { host_answer(result) }.unwrap().name,
                b"fltest-host.example"
            );
        }
        "files" => {
            let answer = forward.unwrap();
            assert_eq!(answer.name, b"files-host");
            assert_eq!(
                answer.addresses,
                vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))]
            );
            assert_eq!(reverse.unwrap(), b"files-reverse");
            assert_eq!(reverse_rc, 0);
            assert_eq!(
                unsafe { host_answer(reverse_result.cast()) }.unwrap().name,
                b"files-reverse"
            );
            assert_eq!(legacy.unwrap().name, b"files-host");
            assert_eq!(rc, 0);
            assert_eq!(unsafe { host_answer(result) }.unwrap().name, b"files-host");
        }
        "none" | "temporary" => {
            assert!(legacy.is_none());
            assert!(result.is_null());
            assert!(reverse_result.is_null(), "discarded module result leaked");
            if expected == "temporary" {
                assert_eq!(forward, Err(libc::EAI_AGAIN));
                assert_eq!(reverse, Err(libc::EAI_AGAIN));
                assert_eq!(h_errno, 2);
                assert_eq!(reverse_h_errno, 2);
                assert_eq!(rc, libc::EAGAIN, "forward temporary return convention");
                assert_eq!(reverse_rc, 0, "reverse errors are reported through h_errno");
            } else {
                assert!(forward.is_err());
                assert!(reverse.is_err());
            }
        }
        value => panic!("unknown hosts policy result: {value}"),
    }
    assert_files_hosts_isolation();
}

#[test]
fn hosts_modules_policy_order_statuses_and_files_isolation() {
    if std::env::var_os(CHILD_ENV).is_some() {
        assert_hosts_policy(&std::env::var("FLTEST_HOST_EXPECTED").unwrap());
        return;
    }
    let dir = scratch_dir("hosts-policy");
    build_modules(&dir);
    std::fs::write(dir.join("hosts"), HOSTS).unwrap();
    for (index, (config, status, expected)) in [
        ("fltest files", "", "module"),
        ("files fltest", "", "files"),
        ("fltest [SUCCESS=continue] files", "", "files"),
        ("files [SUCCESS=continue] fltest", "", "module"),
        ("fltest [NOTFOUND=return] files", "notfound", "none"),
        ("fltest [NOTFOUND=continue] files", "notfound", "files"),
        ("fltest [TRYAGAIN=return] files", "tryagain", "temporary"),
        ("fltest [TRYAGAIN=continue] files", "tryagain", "files"),
        ("fltest [UNAVAIL=return] files", "unavail", "none"),
        ("fltest [!UNAVAIL=return] files", "unavail", "files"),
        ("fltest [!UNAVAIL=return] files", "notfound", "none"),
        ("fltestmissing files", "", "files"),
        ("fltestmissing [UNAVAIL=return] files", "", "none"),
        ("fltest [SUCCESS=continue] fltestmissing", "", "none"),
    ]
    .iter()
    .enumerate()
    {
        let mut child = host_module_child(
            "hosts_modules_policy_order_statuses_and_files_isolation",
            &dir,
            &format!("hosts: {config}\n"),
            &format!("policy-{index}"),
        );
        child
            .env("FLTEST_STATUS", status)
            .env("FLTEST_HOST_EXPECTED", expected);
        run_child(child, &format!("hosts policy {index}: {config}"));
    }
}

#[test]
fn hosts_modules_tuple_lookup_matches_glibc() {
    if std::env::var_os(CHILD_ENV).is_some() {
        let host = std::env::var("FLTEST_TUPLE_PROVIDER").unwrap() == "host";
        assert_ne!(
            libc::getaddrinfo as *const (),
            frankenlibc_abi::resolv_abi::getaddrinfo as *const (),
            "the host oracle and candidate must be distinct providers"
        );
        if host {
            unsafe extern "C" {
                fn __nss_configure_lookup(database: *const c_char, sources: *const c_char)
                -> c_int;
            }
            let sources = CString::new(std::env::var("FLTEST_TUPLE_SOURCES").unwrap()).unwrap();
            // SAFETY: this child owns its process-local hosts configuration.
            assert_eq!(
                unsafe { __nss_configure_lookup(c"hosts".as_ptr(), sources.as_ptr()) },
                0
            );
        }
        let scenario = std::env::var("FLTEST_TUPLE_SCENARIO").unwrap();
        match scenario.as_str() {
            "tuple" => {
                let expected = ScopedHostAnswer {
                    canonical: b"fltest-tuple.example".to_vec(),
                    addresses: tuple_addresses(),
                };
                for name in ["fltest-tuple", "fltest-tuple-large", "fltest-tuple"] {
                    assert_eq!(
                        scoped_named_addresses(host, name, libc::AF_UNSPEC),
                        Ok(ScopedHostAnswer {
                            canonical: expected.canonical.clone(),
                            addresses: expected.addresses.clone(),
                        }),
                        "provider={host} query={name}"
                    );
                }
            }
            "legacy" | "family" => {
                let family = if scenario == "family" {
                    libc::AF_INET
                } else {
                    libc::AF_UNSPEC
                };
                let mut addresses = vec![
                    (Ipv4Addr::new(192, 0, 2, 41).into(), 0),
                    (Ipv4Addr::new(192, 0, 2, 42).into(), 0),
                ];
                if family == libc::AF_UNSPEC {
                    addresses.push(("2001:db8::41".parse().unwrap(), 0));
                    addresses.push(("2001:db8::42".parse().unwrap(), 0));
                }
                addresses.sort();
                assert_eq!(
                    scoped_named_addresses(host, "fltest-host", family),
                    Ok(ScopedHostAnswer {
                        canonical: b"fltest-host.example".to_vec(),
                        addresses,
                    })
                );
            }
            "notfound" => assert_eq!(
                scoped_named_addresses(host, "fltest-host", libc::AF_UNSPEC),
                Err(libc::EAI_NONAME),
                "a present tuple entry point must not fall back within its module"
            ),
            "temporary" => assert_eq!(
                scoped_named_addresses(host, "fltest-tuple", libc::AF_UNSPEC),
                Err(libc::EAI_AGAIN)
            ),
            other => panic!("unknown tuple scenario: {other}"),
        }
        return;
    }

    let dir = scratch_dir("hosts-tuples");
    build_modules(&dir);
    std::fs::write(dir.join("hosts"), HOSTS).unwrap();
    let cases = [
        ("tuple", "fltesthost4", "tuple", ""),
        ("tuple-only", "fltesttupleonly", "tuple", ""),
        ("legacy", "fltest", "legacy", ""),
        ("family", "fltesthost4", "family", ""),
        ("notfound", "fltesthost4", "notfound", ""),
        (
            "notfound-return",
            "fltesthost4 [NOTFOUND=return] fltest",
            "notfound",
            "",
        ),
        (
            "notfound-continue",
            "fltesthost4 [NOTFOUND=continue] fltest",
            "legacy",
            "",
        ),
        ("temporary", "fltesthost4", "temporary", "tryagain"),
    ];
    for (tag, sources, scenario, status) in cases {
        for (provider, mode) in [("host", "strict"), ("fl", "strict"), ("fl", "hardened")] {
            let label = format!("{tag}-{provider}-{mode}");
            let mut child = host_module_child(
                "hosts_modules_tuple_lookup_matches_glibc",
                &dir,
                &format!("hosts: {sources}\n"),
                &label,
            );
            child
                .env("FLTEST_TUPLE_PROVIDER", provider)
                .env("FLTEST_TUPLE_SOURCES", sources)
                .env("FLTEST_TUPLE_SCENARIO", scenario)
                .env("FLTEST_STATUS", status)
                .env("FLTEST_TRACE", "1")
                .env("FRANKENLIBC_MODE", mode)
                .env(
                    "FLTEST_REQUIRE_TUPLE_HEAD_RESET",
                    if provider == "fl" { "1" } else { "0" },
                )
                .env_remove("FLTEST_TUPLE_SHAPE");
            let output = run_child(child, &label);
            let trace = String::from_utf8_lossy(&output.stderr);
            let has_tuple = sources.starts_with("fltesthost4") || sources == "fltesttupleonly";
            if has_tuple && scenario != "family" {
                assert!(trace.contains(":gethostbyname4_r("), "{label}: {trace}");
                for function in ["gethostbyname3_r", "gethostbyname2_r", "gethostbyname_r"] {
                    assert!(
                        !trace.contains(&format!("fltesthost4:{function}("))
                            && !trace.contains(&format!("fltesttupleonly:{function}(")),
                        "same-module fallback after tuple result: {label}: {trace}"
                    );
                }
            } else {
                assert!(!trace.contains(":gethostbyname4_r("), "{label}: {trace}");
            }
            if scenario == "tuple" {
                assert!(
                    trace.contains(":gethostbyname4_r_ERANGE("),
                    "{label}: {trace}"
                );
            }
            if scenario == "legacy" || scenario == "family" {
                assert!(
                    ["gethostbyname3_r", "gethostbyname2_r", "gethostbyname_r"]
                        .iter()
                        .any(|function| trace.contains(*function)),
                    "missing legacy dispatch: {label}: {trace}"
                );
            }
        }
    }
}

#[test]
fn hosts_modules_tuple_defensive_results() {
    if std::env::var_os(CHILD_ENV).is_some() {
        let shape = std::env::var("FLTEST_TUPLE_SHAPE").unwrap();
        // A regression in cycle handling must fail instead of hanging the suite.
        unsafe { libc::alarm(10) };
        let result = scoped_named_addresses(false, "fltest-tuple", libc::AF_UNSPEC);
        unsafe { libc::alarm(0) };
        if shape == "nameless" {
            assert_eq!(
                result,
                Ok(ScopedHostAnswer {
                    canonical: b"fltest-tuple".to_vec(),
                    addresses: tuple_addresses(),
                })
            );
        } else {
            assert_eq!(result, Err(libc::EAI_FAIL), "malformed tuple list: {shape}");
        }
        return;
    }
    let dir = scratch_dir("hosts-tuple-defensive");
    build_modules(&dir);
    std::fs::write(dir.join("hosts"), HOSTS).unwrap();
    for shape in ["nameless", "empty", "badfamily", "cycle"] {
        for mode in ["strict", "hardened"] {
            let label = format!("{shape}-{mode}");
            let mut child = host_module_child(
                "hosts_modules_tuple_defensive_results",
                &dir,
                "hosts: fltesttupleonly\n",
                &label,
            );
            child
                .env("FLTEST_TUPLE_SHAPE", shape)
                .env("FLTEST_TRACE", "1")
                .env("FRANKENLIBC_MODE", mode);
            let output = run_child(child, &label);
            let trace = String::from_utf8_lossy(&output.stderr);
            assert!(
                trace.contains("fltesttupleonly:gethostbyname4_r("),
                "{label}: {trace}"
            );
            assert!(
                trace.contains(&format!("gethostbyname4_r_shape({shape})")),
                "malformed fixture was not exercised: {label}: {trace}"
            );
            for function in ["gethostbyname3_r", "gethostbyname2_r", "gethostbyname_r"] {
                assert!(!trace.contains(function), "{label}: {trace}");
            }
        }
    }
}

// Netgroup modules have a stateful GNU cursor ABI, including nested group
// records. Compare the public APIs with a separately configured host process;
// no mount namespace, privileges or changes to /etc are required.
#[allow(clippy::type_complexity)]
struct NetgroupApi {
    host: bool,
    set: unsafe extern "C" fn(*const c_char) -> c_int,
    get: unsafe extern "C" fn(*mut *mut c_char, *mut *mut c_char, *mut *mut c_char) -> c_int,
    get_r: unsafe extern "C" fn(
        *mut *mut c_char,
        *mut *mut c_char,
        *mut *mut c_char,
        *mut c_char,
        usize,
    ) -> c_int,
    end: unsafe extern "C" fn(),
    member:
        unsafe extern "C" fn(*const c_char, *const c_char, *const c_char, *const c_char) -> c_int,
}

fn netgroup_api(host: bool) -> NetgroupApi {
    unsafe extern "C" {
        #[link_name = "setnetgrent"]
        fn host_set(name: *const c_char) -> c_int;
        #[link_name = "getnetgrent"]
        fn host_get(h: *mut *mut c_char, u: *mut *mut c_char, d: *mut *mut c_char) -> c_int;
        #[link_name = "getnetgrent_r"]
        fn host_get_r(
            h: *mut *mut c_char,
            u: *mut *mut c_char,
            d: *mut *mut c_char,
            buf: *mut c_char,
            len: usize,
        ) -> c_int;
        #[link_name = "endnetgrent"]
        fn host_end();
        #[link_name = "innetgr"]
        fn host_member(
            group: *const c_char,
            host: *const c_char,
            user: *const c_char,
            domain: *const c_char,
        ) -> c_int;
    }
    use frankenlibc_abi::{glibc_internal_abi as g, unistd_abi as u};
    assert_ne!(host_set as *const (), u::setnetgrent as *const ());
    assert_ne!(host_member as *const (), g::innetgr as *const ());
    if host {
        NetgroupApi {
            host,
            set: host_set,
            get: host_get,
            get_r: host_get_r,
            end: host_end,
            member: host_member,
        }
    } else {
        NetgroupApi {
            host,
            set: u::setnetgrent,
            get: u::getnetgrent,
            get_r: u::getnetgrent_r,
            end: u::endnetgrent,
            member: g::innetgr,
        }
    }
}

unsafe fn netgroup_errno(api: &NetgroupApi) -> *mut c_int {
    if api.host {
        unsafe { libc::__errno_location() }
    } else {
        unsafe { frankenlibc_abi::errno_abi::__errno_location() }
    }
}

type NetgroupFields = [Option<Vec<u8>>; 3];

#[inline(never)]
fn netgroup_clobber_stack() {
    // A returned non-reentrant string must survive the callee's stack frame.
    // In particular, leasing a cursor out of TLS must not lease its buffer.
    let mut scratch = [0xa5u8; 16 * 1024];
    std::hint::black_box(&mut scratch);
}

fn netgroup_read(
    api: &NetgroupApi,
    capacity: Option<usize>,
) -> (c_int, c_int, Option<NetgroupFields>) {
    let mut h = std::ptr::null_mut();
    let mut u = std::ptr::null_mut();
    let mut d = std::ptr::null_mut();
    let mut buffer = vec![0u8; capacity.unwrap_or(0)];
    unsafe {
        *netgroup_errno(api) = 0;
        let rc = if let Some(capacity) = capacity {
            (api.get_r)(&mut h, &mut u, &mut d, buffer.as_mut_ptr().cast(), capacity)
        } else {
            (api.get)(&mut h, &mut u, &mut d)
        };
        let error = *netgroup_errno(api);
        if rc == 1 && capacity.is_none() {
            netgroup_clobber_stack();
        }
        let fields = if rc == 1 {
            Some([h, u, d].map(|p| {
                if p.is_null() {
                    None
                } else {
                    let value = if capacity.is_some() {
                        let start = buffer.as_ptr() as usize;
                        let end = start + buffer.len();
                        assert!(
                            (p as usize) >= start && (p as usize) < end,
                            "getnetgrent_r returned a field outside caller storage"
                        );
                        let remaining = &buffer[p as usize - start..];
                        let length = remaining
                            .iter()
                            .position(|&byte| byte == 0)
                            .expect("netgroup field is terminated inside caller storage");
                        remaining[..length].to_vec()
                    } else {
                        CStr::from_ptr(p).to_bytes().to_vec()
                    };
                    Some(value)
                }
            }))
        } else {
            None
        };
        (rc, error, fields)
    }
}

fn netgroup_print_read(
    out: &mut String,
    label: &str,
    answer: &(c_int, c_int, Option<NetgroupFields>),
) {
    let fields = answer.2.as_ref().map(|fields| {
        fields.each_ref().map(|field| {
            field.as_ref().map(|bytes| {
                if bytes.len() > 128 {
                    assert!(bytes.iter().all(|&byte| byte == b'n'));
                    format!("<{} bytes of n>", bytes.len())
                } else {
                    String::from_utf8(bytes.clone()).unwrap()
                }
            })
        })
    });
    // Successful results may leave errno unchanged. Compare errors only when
    // the public API reports failure, preserving the provider's actual result.
    writeln!(
        out,
        "{label}: rc={} errno={} {fields:?}",
        answer.0,
        if answer.0 == 1 { 0 } else { answer.1 }
    )
    .unwrap();
}

fn netgroup_enumerate(api: &NetgroupApi, out: &mut String) -> usize {
    let mut count = 0;
    loop {
        assert!(count < 32, "nested netgroup cycle did not terminate");
        let answer = netgroup_read(api, Some(8192));
        netgroup_print_read(out, "get_r", &answer);
        if answer.0 != 1 {
            return count;
        }
        count += 1;
    }
}

fn netgroup_membership(api: &NetgroupApi, out: &mut String, name: &CStr) {
    let fields = [
        (Some("fltest-one"), Some("one"), Some("example.test")),
        (Some("fltestnoig-one"), Some("one"), Some("example.test")),
        (Some("anything"), None, None),
        (None, Some(""), None),
        (None, Some("not-empty"), None),
        (None, None, Some("-")),
        (None, None, Some("unmatched-domain")),
        (None, None, None),
    ];
    for (host, user, domain) in fields {
        let values = [host, user, domain].map(|s| s.map(|s| CString::new(s).unwrap()));
        let pointers = values
            .each_ref()
            .map(|s| s.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()));
        let (rc, error) = unsafe {
            *netgroup_errno(api) = 0;
            let rc = (api.member)(name.as_ptr(), pointers[0], pointers[1], pointers[2]);
            (rc, *netgroup_errno(api))
        };
        writeln!(
            out,
            "member {host:?} {user:?} {domain:?}: {rc} errno={}",
            if rc == 0 { error } else { 0 }
        )
        .unwrap();
    }
}

fn netgroup_transcript(api: &NetgroupApi, scenario: &str) -> String {
    let name = CString::new(format!("flnet-{scenario}")).unwrap();
    let mut out = String::new();
    unsafe { (api.end)() };
    let selected = unsafe { (api.set)(name.as_ptr()) };
    writeln!(out, "set {scenario}: {selected}").unwrap();
    if !scenario.starts_with("set-") {
        assert_eq!(selected, 1);
    }
    if selected != 1 {
        // Only enumerate a successfully selected group. A failed SET leaves
        // no valid enumeration contract; still compare its selection outcome,
        // independent membership lookup and explicit END reset.
        netgroup_membership(api, &mut out, &name);
        unsafe { (api.end)() };
        netgroup_print_read(&mut out, "after end", &netgroup_read(api, Some(8192)));
        return out;
    }
    if scenario == "large" {
        assert_eq!(selected, 1);
        for capacity in [None, Some(1), Some(8192), Some(8192)] {
            let answer = netgroup_read(api, capacity);
            netgroup_print_read(&mut out, &format!("get {capacity:?}"), &answer);
            if capacity.is_none() || capacity == Some(1) {
                assert_eq!((answer.0, answer.1), (0, libc::ERANGE));
            }
            if let Some(fields) = answer.2 {
                assert_eq!(fields[0].as_ref().unwrap().len(), 3072);
                assert_eq!(fields[1].as_deref(), Some(b"large-user".as_slice()));
            }
        }
        netgroup_membership(api, &mut out, &name);
    } else if scenario == "scratch" {
        assert_eq!(selected, 1);
        for capacity in [None, Some(2048), Some(4096), Some(8192)] {
            let answer = netgroup_read(api, capacity);
            netgroup_print_read(&mut out, &format!("scratch {capacity:?}"), &answer);
            if capacity.is_none() || capacity == Some(2048) {
                assert_eq!((answer.0, answer.1), (0, libc::ERANGE));
            } else if capacity == Some(4096) {
                assert_eq!(answer.0, 1, "retry must retain the same provider record");
                assert_eq!(
                    answer.2.as_ref().unwrap()[0].as_deref(),
                    Some(b"scratch".as_slice())
                );
            } else {
                assert_eq!(answer.0, 0);
            }
        }
        // GNU membership has its own fixed 1024-byte module buffer, so the
        // provider's scratch requirement must also deny an all-NULL query.
        netgroup_membership(api, &mut out, &name);
    } else if scenario == "null" {
        assert_eq!(selected, 1);
        let answer = netgroup_read(api, Some(3));
        netgroup_print_read(&mut out, "exact buffer", &answer);
        assert_eq!(
            answer.2,
            Some([None, Some(Vec::new()), Some(b"-".to_vec())])
        );
        netgroup_membership(api, &mut out, &name);
    } else if scenario == "retry" {
        assert_eq!(selected, 1);
        for index in 0..4 {
            let answer = netgroup_read(api, Some(8192));
            netgroup_print_read(&mut out, &format!("attempt {index}"), &answer);
        }
        netgroup_membership(api, &mut out, &name);
    } else {
        if matches!(scenario, "basic" | "nested" | "empty" | "cross")
            || scenario.starts_with("get-")
        {
            assert_eq!(selected, 1);
        }
        if scenario == "basic" {
            let short = netgroup_read(api, Some(1));
            assert_eq!((short.0, short.1), (0, libc::ERANGE));
            netgroup_print_read(&mut out, "short", &short);
            for label in ["first nonreentrant", "second nonreentrant"] {
                let answer = netgroup_read(api, None);
                assert_eq!(answer.0, 1);
                netgroup_print_read(&mut out, label, &answer);
            }
        }
        let count = netgroup_enumerate(api, &mut out);
        if scenario == "basic" {
            assert_eq!(
                count, 0,
                "the two non-reentrant reads consumed both records"
            );
        } else if scenario == "empty" {
            assert_eq!(count, 0);
        }
        // Membership has a separate source-selection rule from enumeration.
        // In particular, SUCCESS=continue must not hide an earlier match.
        netgroup_membership(api, &mut out, &name);
    }
    unsafe { (api.end)() };
    // A closed iterator cannot retain a stale provider record.
    netgroup_print_read(&mut out, "after end", &netgroup_read(api, Some(8192)));
    out
}

fn netgroup_extract(output: &std::process::Output) -> &str {
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    stdout
        .split_once("NETGROUP_BEGIN\n")
        .and_then(|(_, rest)| rest.split_once("NETGROUP_END"))
        .map(|(transcript, _)| transcript)
        .expect("child produced a netgroup transcript")
}

#[test]
fn netgroup_modules_match_glibc() {
    if std::env::var_os(CHILD_ENV).is_some() {
        let host = std::env::var("FLTEST_NETGROUP_PROVIDER").unwrap() == "host";
        if host {
            unsafe extern "C" {
                fn __nss_configure_lookup(database: *const c_char, sources: *const c_char)
                -> c_int;
            }
            let sources = CString::new(std::env::var("FLTEST_NETGROUP_SOURCES").unwrap()).unwrap();
            assert_eq!(
                unsafe { __nss_configure_lookup(c"netgroup".as_ptr(), sources.as_ptr()) },
                0
            );
        }
        unsafe { libc::alarm(15) };
        let scenario = std::env::var("FLTEST_NETGROUP_SCENARIO").unwrap();
        let transcript = netgroup_transcript(&netgroup_api(host), &scenario);
        unsafe { libc::alarm(0) };
        println!("NETGROUP_BEGIN\n{transcript}NETGROUP_END");
        return;
    }

    let dir = scratch_dir("netgroups");
    build_modules(&dir);
    let cases = [
        ("basic", "fltest", "basic"),
        ("nested", "fltest", "nested"),
        ("null", "fltest", "null"),
        ("large", "fltest", "large"),
        ("scratch", "fltest", "scratch"),
        ("empty", "fltest", "empty"),
        ("retry", "fltest", "retry"),
        ("get-return", "fltest fltestnoig", "get-return"),
        ("get-notfound", "fltest fltestnoig", "get-notfound"),
        ("get-unavail", "fltest fltestnoig", "get-unavail"),
        ("get-quiet", "fltest fltestnoig", "get-quiet"),
        ("get-again-quiet", "fltest fltestnoig", "get-again-quiet"),
        ("cross", "fltest fltestnoig", "cross"),
        ("cross-stop", "fltest [NOTFOUND=return] fltestnoig", "cross"),
        (
            "success-continue",
            "fltest [SUCCESS=continue] fltestnoig",
            "basic",
        ),
        ("missing-continue", "fltest fltestnoig", "set-notfound"),
        (
            "missing-stop",
            "fltest [NOTFOUND=return] fltestnoig",
            "set-notfound",
        ),
        ("unavail-continue", "fltest fltestnoig", "set-unavail"),
        (
            "unavail-stop",
            "fltest [UNAVAIL=return] fltestnoig",
            "set-unavail",
        ),
        ("again-continue", "fltest fltestnoig", "set-again"),
        (
            "again-stop",
            "fltest [TRYAGAIN=return] fltestnoig",
            "set-again",
        ),
        ("forced-return", "fltest fltestnoig", "set-return"),
        (
            "forced-return-continue",
            "fltest [!SUCCESS=continue] fltestnoig",
            "set-return",
        ),
    ];
    for (tag, sources, scenario) in cases {
        let mut oracle = None;
        for (provider, mode) in [("host", "strict"), ("fl", "strict"), ("fl", "hardened")] {
            let label = format!("netgroup-{tag}-{provider}-{mode}");
            let mut child = host_module_child(
                "netgroup_modules_match_glibc",
                &dir,
                &format!("netgroup: {sources}\n"),
                &label,
            );
            child
                .env("FLTEST_NETGROUP_PROVIDER", provider)
                .env("FLTEST_NETGROUP_SOURCES", sources)
                .env("FLTEST_NETGROUP_SCENARIO", scenario)
                .env("FLTEST_TRACE", "1")
                .env("FRANKENLIBC_MODE", mode);
            let output = run_child(child, &label);
            let transcript = netgroup_extract(&output).to_owned();
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("fltest:setnetgrent("),
                "the configured module was not called: {label}"
            );
            if let Some(oracle) = &oracle {
                assert_eq!(&transcript, oracle, "netgroup oracle mismatch: {label}");
            } else {
                oracle = Some(transcript);
            }
        }
    }
}

static NETGROUP_REENTRY_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

unsafe extern "C" fn netgroup_reentry_callback() -> c_int {
    use frankenlibc_abi::{errno_abi as e, glibc_internal_abi as g, unistd_abi as u};
    NETGROUP_REENTRY_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut h = std::ptr::null_mut();
    let mut user = std::ptr::null_mut();
    let mut d = std::ptr::null_mut();
    let mut buffer = [0 as c_char; 128];
    unsafe {
        *e::__errno_location() = 0;
        if u::setnetgrent(c"flnet-basic".as_ptr()) != 0 || *e::__errno_location() != libc::EDEADLK {
            return 1;
        }
        *e::__errno_location() = 0;
        if u::getnetgrent(&mut h, &mut user, &mut d) != 0 || *e::__errno_location() != libc::EDEADLK
        {
            return 2;
        }
        *e::__errno_location() = 0;
        if u::getnetgrent_r(&mut h, &mut user, &mut d, buffer.as_mut_ptr(), buffer.len()) != 0
            || *e::__errno_location() != libc::EDEADLK
        {
            return 3;
        }
        u::endnetgrent();
        if g::innetgr(
            c"flnet-basic".as_ptr(),
            c"fltest-one".as_ptr(),
            c"one".as_ptr(),
            c"example.test".as_ptr(),
        ) != 1
        {
            return 4;
        }
    }
    0
}

#[test]
fn netgroup_modules_callback_reentry() {
    if std::env::var_os(CHILD_ENV).is_some() {
        unsafe { libc::alarm(10) };
        unsafe {
            let handle = libc::dlopen(c"libnss_fltest.so.2".as_ptr(), libc::RTLD_NOW);
            assert!(!handle.is_null(), "load the same test module as NSS");
            let symbol = libc::dlsym(handle, c"_nss_fltest_set_netgroup_reentry".as_ptr());
            assert!(!symbol.is_null());
            let set_callback: unsafe extern "C" fn(Option<unsafe extern "C" fn() -> c_int>) =
                std::mem::transmute(symbol);
            set_callback(Some(netgroup_reentry_callback));
            let api = netgroup_api(false);
            assert_eq!((api.set)(c"flnet-reentry".as_ptr()), 1);
            let first = netgroup_read(&api, Some(1024));
            assert_eq!(first.0, 1, "callback rejected the reentry contract");
            assert_eq!(
                first.2.unwrap()[0].as_deref(),
                Some(b"fltest-one".as_slice())
            );
            let second = netgroup_read(&api, Some(1024));
            assert_eq!(second.0, 1);
            assert_eq!(
                second.2.unwrap()[0].as_deref(),
                Some(b"fltest-two".as_slice())
            );
            assert_eq!(netgroup_read(&api, Some(1024)).0, 0);
            assert_eq!(
                NETGROUP_REENTRY_CALLS.load(std::sync::atomic::Ordering::Relaxed),
                1
            );
            (api.end)();
            set_callback(None);
            libc::dlclose(handle);
            libc::alarm(0);
        }
        return;
    }

    let dir = scratch_dir("netgroup-reentry");
    build_modules(&dir);
    for mode in ["strict", "hardened"] {
        let mut child = host_module_child(
            "netgroup_modules_callback_reentry",
            &dir,
            "netgroup: fltest\n",
            mode,
        );
        child.env("FRANKENLIBC_MODE", mode);
        run_child(child, &format!("netgroup reentry {mode}"));
    }
}

#[derive(Debug, PartialEq, Eq)]
struct EnumeratedService {
    name: Vec<u8>,
    protocol: Vec<u8>,
    port: u16,
    aliases: Vec<Vec<u8>>,
}

struct ServiceEnumerationApi {
    set: unsafe extern "C" fn(c_int),
    get: unsafe extern "C" fn() -> *mut c_void,
    get_r: unsafe extern "C" fn(*mut c_void, *mut c_char, usize, *mut *mut c_void) -> c_int,
    end: unsafe extern "C" fn(),
    error: unsafe extern "C" fn() -> *mut c_int,
    files_set: unsafe extern "C" fn(c_int) -> c_int,
    files_get: unsafe extern "C" fn(*mut c_void, *mut c_char, usize, *mut c_int) -> c_int,
    files_end: unsafe extern "C" fn() -> c_int,
}

fn service_enumeration_api(host: bool) -> ServiceEnumerationApi {
    unsafe extern "C" {
        #[link_name = "setservent"]
        fn host_set(stayopen: c_int);
        #[link_name = "getservent"]
        fn host_get() -> *mut c_void;
        #[link_name = "getservent_r"]
        fn host_get_r(out: *mut c_void, buf: *mut c_char, len: usize, result: *mut *mut c_void) -> c_int;
        #[link_name = "endservent"]
        fn host_end();
        #[link_name = "_nss_files_setservent"]
        fn host_files_set(stayopen: c_int) -> c_int;
        #[link_name = "_nss_files_getservent_r"]
        fn host_files_get(out: *mut c_void, buf: *mut c_char, len: usize, error: *mut c_int) -> c_int;
        #[link_name = "_nss_files_endservent"]
        fn host_files_end() -> c_int;
    }
    use frankenlibc_abi::{errno_abi as e, unistd_abi as u};
    assert_ne!(host_get as *const (), u::getservent as *const ());
    assert_ne!(host_get_r as *const (), u::getservent_r as *const ());
    if host {
        ServiceEnumerationApi {
            set: host_set, get: host_get, get_r: host_get_r, end: host_end,
            error: libc::__errno_location,
            files_set: host_files_set, files_get: host_files_get, files_end: host_files_end,
        }
    } else {
        ServiceEnumerationApi {
            set: u::setservent, get: u::getservent, get_r: u::getservent_r,
            end: u::endservent, error: e::__errno_location,
            files_set: u::_nss_files_setservent, files_get: u::_nss_files_getservent_r,
            files_end: u::_nss_files_endservent,
        }
    }
}

unsafe fn enumerated_service(
    pointer: *mut c_void,
    bounds: Option<(usize, usize)>,
) -> Option<EnumeratedService> {
    if pointer.is_null() { return None; }
    // SAFETY: the selected API published a complete servent on success.
    let entry = unsafe { &*pointer.cast::<libc::servent>() };
    let string = |pointer: *const c_char| {
        assert!(!pointer.is_null());
        if let Some((start, end)) = bounds {
            let address = pointer as usize;
            assert!((start..end).contains(&address), "service string escaped caller buffer");
            // SAFETY: bound every read before scanning for its terminator.
            let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), end - address) };
            let length = bytes.iter().position(|&byte| byte == 0).expect("unterminated service string");
            bytes[..length].to_vec()
        } else {
            // SAFETY: the non-reentrant API owns terminated output strings.
            unsafe { CStr::from_ptr(pointer) }.to_bytes().to_vec()
        }
    };
    let mut aliases = Vec::new();
    assert!(!entry.s_aliases.is_null());
    for index in 0..4096 {
        let slot = unsafe { entry.s_aliases.add(index) };
        if let Some((start, end)) = bounds {
            assert!((slot as usize) >= start && (slot as usize) + std::mem::size_of::<usize>() <= end);
            assert_eq!((slot as usize) % std::mem::align_of::<usize>(), 0);
        }
        // SAFETY: the caller-buffer case was bounded above; non-reentrant
        // output provides a terminated pointer table by the C API contract.
        let alias = unsafe { *slot };
        if alias.is_null() {
            return Some(EnumeratedService {
                name: string(entry.s_name), protocol: string(entry.s_proto),
                port: u16::from_be(entry.s_port as u16), aliases,
            });
        }
        aliases.push(string(alias));
    }
    panic!("service alias table was not terminated");
}

fn service_enumeration_read(
    api: &ServiceEnumerationApi,
    capacity: Option<usize>,
    offset: usize,
) -> (c_int, c_int, Option<EnumeratedService>) {
    if let Some(capacity) = capacity {
        let mut storage = vec![0x5au8; 16384 + 16];
        assert!(capacity + offset <= storage.len());
        let mut output: libc::servent = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::null_mut();
        let buffer = unsafe { storage.as_mut_ptr().add(offset).cast::<c_char>() };
        unsafe { *(api.error)() = 619 };
        let rc = unsafe { (api.get_r)((&raw mut output).cast(), buffer, capacity, &mut result) };
        let error = unsafe { *(api.error)() };
        assert!(storage[capacity + offset..].iter().all(|&byte| byte == 0x5a));
        if !result.is_null() {
            assert_eq!(result, (&raw mut output).cast());
            assert_eq!(rc, 0);
        }
        let observed = unsafe {
            enumerated_service(result, Some((buffer as usize, buffer as usize + capacity)))
        };
        (rc, error, observed)
    } else {
        unsafe { *(api.error)() = 619 };
        let result = unsafe { (api.get)() };
        let error = unsafe { *(api.error)() };
        (0, error, unsafe { enumerated_service(result, None) })
    }
}

fn service_enumeration_transcript(api: &ServiceEnumerationApi, scenario: &str) -> String {
    let mut output = String::new();
    unsafe { (api.end)() };
    // The first access intentionally has no setservent: GNU calls the first
    // get callback directly, but calls set when traversing to a later source.
    for capacity in [0, 1, 7] {
        writeln!(output, "implicit {capacity} {:?}", service_enumeration_read(api, Some(capacity), 1)).unwrap();
    }
    for index in 0..6 {
        let record = service_enumeration_read(api, Some(8192), index % 2);
        let done = record.2.is_none();
        writeln!(output, "implicit record {index} {record:?}").unwrap();
        if done { break; }
    }
    unsafe { (api.end)(); (api.set)(1) };
    for index in 0..6 {
        let record = service_enumeration_read(api, None, 0);
        let done = record.2.is_none();
        writeln!(output, "owned record {index} {record:?}").unwrap();
        if done { break; }
    }
    unsafe { (api.set)(0) };
    writeln!(output, "rewind {:?}", service_enumeration_read(api, Some(1), 0)).unwrap();
    writeln!(output, "retry {:?}", service_enumeration_read(api, Some(8192), 0)).unwrap();
    unsafe { (api.end)() };

    // Cleanup must reach configured later modules even when enumeration used
    // only the first source, and a repeated end repeats the provider callbacks.
    unsafe { (api.set)(0) };
    writeln!(output, "early end {:?}", service_enumeration_read(api, Some(8192), 0)).unwrap();
    unsafe { (api.end)(); (api.end)() };
    writeln!(output, "after repeated end {:?}", service_enumeration_read(api, Some(8192), 1)).unwrap();
    unsafe { (api.end)() };

    if scenario == "mixed-files" {
        // Public files traversal and direct provider calls must share their
        // position, including a pending short-buffer record.
        unsafe { (api.set)(0) };
        writeln!(output, "mixed first {:?}", service_enumeration_read(api, Some(8192), 0)).unwrap();
        let mut record: libc::servent = unsafe { std::mem::zeroed() };
        let mut storage = [0 as c_char; 8192];
        let mut error = 717;
        unsafe { *(api.error)() = 619 };
        let rc = unsafe {
            (api.files_get)((&raw mut record).cast(), storage.as_mut_ptr(), 1, &mut error)
        };
        writeln!(output, "mixed range {rc} {error} {}", unsafe { *(api.error)() }).unwrap();
        writeln!(output, "mixed retry {:?}", service_enumeration_read(api, Some(8192), 0)).unwrap();
        error = 717;
        unsafe { *(api.error)() = 619 };
        let rc = unsafe {
            (api.files_get)((&raw mut record).cast(), storage.as_mut_ptr(), storage.len(), &mut error)
        };
        let observed = if rc == 1 {
            unsafe {
                enumerated_service(
                    (&raw mut record).cast(),
                    Some((storage.as_ptr() as usize, storage.as_ptr() as usize + storage.len())),
                )
            }
        } else { None };
        writeln!(output, "mixed direct {rc} {error} {observed:?}").unwrap();
        unsafe { (api.files_end)() };
        writeln!(output, "mixed restart {:?}", service_enumeration_read(api, Some(8192), 0)).unwrap();
        unsafe { (api.end)() };
    }
    output
}

#[test]
fn services_enumeration_matches_glibc_module_policy() {
    const TEST: &str = "services_enumeration_matches_glibc_module_policy";
    if std::env::var_os(CHILD_ENV).is_some() {
        let host = std::env::var("FLTEST_SERVICE_PROVIDER").unwrap() == "host";
        if host {
            unsafe extern "C" {
                fn __nss_configure_lookup(database: *const c_char, sources: *const c_char) -> c_int;
            }
            let sources = CString::new(std::env::var("FLTEST_SERVICE_SOURCES").unwrap()).unwrap();
            assert_eq!(unsafe { __nss_configure_lookup(c"services".as_ptr(), sources.as_ptr()) }, 0);
        }
        unsafe { libc::alarm(15) };
        let scenario = std::env::var("FLTEST_SERVICE_ENUM").unwrap();
        let transcript = service_enumeration_transcript(&service_enumeration_api(host), &scenario);
        unsafe { libc::alarm(0) };
        println!("SERVICE_ENUM_BEGIN\n{transcript}SERVICE_ENUM_END");
        return;
    }
    let dir = scratch_dir("service-enumeration");
    build_modules(&dir);
    // This provider deliberately has getservent_r but neither lifecycle
    // callback. Missing symbols must not be treated as callback UNAVAIL.
    let module = Command::new("cc")
        .args(["-O2", "-fPIC", "-shared", "-DSERVICE=fltestgetonly",
            "-DNO_SERVICE_SET", "-DNO_SERVICE_END"])
        .arg(repo_root().join("tests/integration/fixture_nss_module_lib.c"))
        .arg("-o").arg(dir.join("libnss_fltestgetonly.so.2"))
        .output().expect("build get-only service enumeration module");
    assert!(module.status.success(), "get-only module build failed: {}",
        String::from_utf8_lossy(&module.stderr));
    let cases = [
        ("fltest", "normal"),
        ("fltest fltestnoig", "normal"),
        ("fltest [SUCCESS=continue] fltestnoig", "normal"),
        ("fltest [SUCCESS=merge] fltestnoig", "normal"),
        ("fltest [TRYAGAIN=continue] fltestnoig", "normal"),
        ("fltest [NOTFOUND=return] fltestnoig", "normal"),
        ("fltest [SUCCESS=return NOTFOUND=return UNAVAIL=return TRYAGAIN=return] fltestnoig", "normal"),
        ("fltest [UNAVAIL=return] fltestnoig", "get-unavail"),
        ("fltest [UNAVAIL=continue] fltestnoig", "get-unavail"),
        ("fltest [TRYAGAIN=return] fltestnoig", "get-again"),
        ("fltest [TRYAGAIN=continue] fltestnoig", "get-again"),
        ("fltest [TRYAGAIN=return] fltestnoig", "get-quiet-again"),
        ("fltest fltestnoig", "get-return"),
        ("fltest [!SUCCESS=continue] fltestnoig", "get-return"),
        ("fltest fltestnoig", "set-unavail"),
        ("fltest [UNAVAIL=return] fltestnoig", "set-unavail"),
        ("fltest [TRYAGAIN=return] fltestnoig", "set-again"),
        ("fltest [NOTFOUND=return] fltestnoig", "set-notfound"),
        ("fltest fltestnoig", "set-return"),
        ("flmissing fltest", "normal"),
        ("flmissing fltest", "set-unavail"),
        ("flmissing [UNAVAIL=return] files", "normal"),
        ("fltestgetonly", "normal"),
        ("fltestgetonly fltest", "normal"),
        ("fltestgetonly [UNAVAIL=return] fltest", "normal"),
        ("fltest fltestgetonly fltestnoig", "normal"),
        ("fltest flmissing [UNAVAIL=return] fltestnoig", "normal"),
        ("files", "mixed-files"),
    ];
    let mut compared = 0;
    for (index, (sources, scenario)) in cases.into_iter().enumerate() {
        let mut oracle = None;
        for (provider, mode) in [("host", "strict"), ("fl", "strict"), ("fl", "hardened")] {
            let label = format!("service-enum-{index}-{provider}-{mode}");
            let mut child = host_module_child(TEST, &dir, &format!("services: {sources}\n"), &label);
            child.env("FLTEST_SERVICE_PROVIDER", provider)
                .env("FLTEST_SERVICE_SOURCES", sources)
                .env("FLTEST_SERVICE_ENUM", scenario)
                .env("FLTEST_TRACE", "1")
                .env("FRANKENLIBC_MODE", mode);
            let result = run_child(child, &label);
            let stdout = std::str::from_utf8(&result.stdout).unwrap();
            let transcript = stdout.split_once("SERVICE_ENUM_BEGIN\n")
                .and_then(|(_, rest)| rest.split_once("SERVICE_ENUM_END"))
                .map(|(text, _)| text).expect("nonempty enumeration transcript").to_owned();
            assert!(transcript.lines().count() >= 6);
            if sources == "fltest" {
                assert!(transcript.contains("4501") && transcript.contains("4502"),
                    "module's small and large entries must both be observed");
                assert!(String::from_utf8_lossy(&result.stderr).contains("fltest:getservent_r("));
            }
            let cleanup = String::from_utf8_lossy(&result.stderr).lines()
                .filter(|line| line.contains(":endservent("))
                .map(str::to_owned).collect::<Vec<_>>();
            if sources == "fltest fltestnoig" && scenario == "normal" {
                assert!(cleanup.iter().filter(|line| line.contains("fltestnoig:endservent(")).count() >= 4,
                    "early and repeated cleanup must reach the second configured module");
            }
            if let Some(expected) = &oracle {
                assert_eq!(&(transcript, cleanup), expected,
                    "{label}: sources={sources}, scenario={scenario}");
                compared += 1;
            } else { oracle = Some((transcript, cleanup)); }
        }
    }
    assert_eq!(compared, 56);
    eprintln!("services enumeration: {compared} independent GNU/candidate process comparisons");
}


fn service_enumeration_native_isolation(first: &EnumeratedService) {
    use frankenlibc_abi::{pthread_abi, unistd_abi as u};

    unsafe extern "C" fn enumerate(argument: *mut c_void) -> *mut c_void {
        if frankenlibc_core::pthread::thread::current_thread_handle().is_none() {
            return 1usize as *mut c_void;
        }
        // SAFETY: the creator keeps these addresses alive through join. Each
        // native result is inspected before its own state is closed or freed.
        unsafe {
            let creator = &*argument.cast::<[usize; 2]>();
            let first = u::getservent().cast::<libc::servent>();
            if first.is_null() || first as usize == creator[0] {
                return 2usize as *mut c_void;
            }
            if (*first).s_name as usize == creator[1] {
                return 3usize as *mut c_void;
            }
            let name = CStr::from_ptr((*first).s_name).to_bytes();
            if name.len() != 1800 || !name.iter().all(|byte| *byte == b'n') {
                return 4usize as *mut c_void;
            }
            if (*first).s_aliases.is_null() {
                return 5usize as *mut c_void;
            }
            for index in 0..24 {
                if (*(*first).s_aliases.add(index)).is_null() {
                    return 6usize as *mut c_void;
                }
            }
            if !(*(*first).s_aliases.add(24)).is_null() {
                return 7usize as *mut c_void;
            }
            let second = u::getservent().cast::<libc::servent>();
            if second.is_null() || CStr::from_ptr((*second).s_name).to_bytes() != b"second" {
                return 8usize as *mut c_void;
            }
            if !u::getservent().is_null() {
                return 9usize as *mut c_void;
            }
            u::endservent();
        }
        std::ptr::null_mut()
    }

    struct RestoreBackend(bool);
    impl Drop for RestoreBackend {
        fn drop(&mut self) {
            pthread_abi::pthread_threading_restore_for_tests(self.0);
        }
    }

    // Preserve the creator's stable answer while the next files record is
    // pending after ERANGE. Native workers must start their own cursor at zero.
    let api = service_enumeration_api(false);
    unsafe { (api.set)(0) };
    let creator = unsafe { u::getservent().cast::<libc::servent>() };
    assert!(!creator.is_null());
    assert_eq!(unsafe { enumerated_service(creator.cast(), None) }.as_ref(), Some(first));
    let mut addresses = [creator as usize, unsafe { (*creator).s_name } as usize];
    let retry = service_enumeration_read(&api, Some(16), 1);
    assert_eq!((retry.0, retry.1, retry.2), (libc::ERANGE, libc::ERANGE, None));
    let _restore = RestoreBackend(pthread_abi::pthread_threading_swap_force_native_for_tests());
    for _ in 0..3 {
        let mut thread = 0;
        assert_eq!(unsafe {
            pthread_abi::pthread_create(
                &mut thread, std::ptr::null(), Some(enumerate), (&raw mut addresses).cast(),
            )
        }, 0);
        let mut result = std::ptr::null_mut();
        assert_eq!(unsafe { pthread_abi::pthread_join(thread, &mut result) }, 0);
        assert_eq!(result as usize, 0);
        assert_eq!(
            unsafe { enumerated_service(creator.cast(), None) }.as_ref(), Some(first),
            "native enumeration must preserve the creator's published strings and alias table",
        );
    }
    let second = unsafe { u::getservent().cast::<libc::servent>() };
    assert_eq!(second, creator, "creator's answer storage must not migrate");
    assert_eq!(unsafe { CStr::from_ptr((*second).s_name) }.to_bytes(), b"second");
    assert!(unsafe { u::getservent() }.is_null());
    unsafe { u::endservent() };
}

#[test]
fn services_enumeration_files_retry_and_provider_isolation() {
    const TEST: &str = "services_enumeration_files_retry_and_provider_isolation";
    if std::env::var_os(CHILD_ENV).is_some() {
        use frankenlibc_abi::glibc_internal_abi as g;
        unsafe { libc::alarm(30) };
        let api = service_enumeration_api(false);
        let mut raw: libc::servent = unsafe { std::mem::zeroed() };
        let mut storage = vec![0 as c_char; 16384];
        let mut error = 717;
        assert_eq!(unsafe { (api.files_set)(0) }, 1);
        assert_eq!(unsafe {
            (api.files_get)((&raw mut raw).cast(), storage.as_mut_ptr(), storage.len(), &mut error)
        }, 1);
        assert_eq!(unsafe { enumerated_service((&raw mut raw).cast(), None) }.unwrap().name.len(), 1800);
        // A public end before the first public set/get must not close a
        // cursor opened only through the explicit files-provider interface.
        unsafe { (api.end)() };
        assert_eq!(unsafe {
            (api.files_get)((&raw mut raw).cast(), storage.as_mut_ptr(), storage.len(), &mut error)
        }, 1);
        assert_eq!(unsafe { enumerated_service((&raw mut raw).cast(), None) }.unwrap().name, b"second");
        unsafe { (api.files_end)(); (api.set)(0) };
        let module = service_enumeration_read(&api, Some(8192), 0).2.unwrap();
        assert_eq!(module.name, b"fltest-enum-small");
        assert_eq!(unsafe { (api.files_set)(0) }, 1);
        error = 717;
        assert_eq!(unsafe { (api.files_get)((&raw mut raw).cast(), storage.as_mut_ptr(), 1, &mut error) }, -2);
        assert_eq!(error, libc::ERANGE);
        let module = service_enumeration_read(&api, None, 0).2.unwrap();
        assert_eq!(module.name, b"fltest-enum-large");
        assert_eq!(module.aliases[2].len(), 3072);
        error = 717;
        assert_eq!(unsafe {
            (api.files_get)((&raw mut raw).cast(), storage.as_mut_ptr(), storage.len(), &mut error)
        }, 1);
        let first = unsafe { enumerated_service((&raw mut raw).cast(), None) }.unwrap();
        assert_eq!(first.name.len(), 1800);
        assert_eq!(first.aliases.len(), 24);
        assert_eq!(error, 717);
        unsafe { (api.end)() };
        assert_eq!(unsafe { g::__nss_configure_lookup(c"services".as_ptr(), c"files".as_ptr()) }, 0);
        unsafe { (api.set)(0) };
        let small = service_enumeration_read(&api, Some(1), 1);
        assert_eq!((small.0, small.1, small.2), (libc::ERANGE, libc::ERANGE, None));
        assert_eq!(unsafe {
            (api.files_get)((&raw mut raw).cast(), storage.as_mut_ptr(), storage.len(), &mut error)
        }, 1);
        assert_eq!(unsafe { enumerated_service((&raw mut raw).cast(), None) }.unwrap(), first);
        let next = service_enumeration_read(&api, Some(8192), 0).2.unwrap();
        assert_eq!(next.name, b"second");
        assert!(service_enumeration_read(&api, Some(8192), 0).2.is_none());
        unsafe { (api.set)(0) };
        assert_eq!(service_enumeration_read(&api, None, 0).2.unwrap(), first);
        unsafe { (api.end)(); (api.files_end)() };
        service_enumeration_native_isolation(&first);

        // An ERANGE retry belongs to the selected file. Replacing the selected
        // path must discard that old pending record before the next read.
        unsafe { (api.set)(0) };
        let pending = service_enumeration_read(&api, Some(16), 0);
        assert_eq!((pending.0, pending.1, pending.2), (libc::ERANGE, libc::ERANGE, None));
        let replacement = std::env::var_os("FLTEST_SERVICES_REPLACEMENT").unwrap();
        unsafe { std::env::set_var("FRANKENLIBC_SERVICES_PATH", replacement) };
        let changed = service_enumeration_read(&api, Some(8192), 1).2.unwrap();
        assert_eq!(changed.name, b"changed");
        assert_eq!(changed.port, 4503);
        assert_eq!(changed.aliases, vec![b"replacement-alias".to_vec()]);
        assert!(service_enumeration_read(&api, Some(8192), 0).2.is_none());
        unsafe { (api.end)(); (api.files_end)(); libc::alarm(0) };
        return;
    }
    let dir = scratch_dir("service-files-retry");
    build_modules(&dir);
    let path = dir.join("services");
    let aliases = (0..24).map(|index| format!("alias{index}")).collect::<Vec<_>>().join(" ");
    let first = format!("{} 4501/tcp {aliases}\n", "n".repeat(1800));
    std::fs::write(&path, format!("# comment\nbad record\n{first}second 4502/udp alias-last\n")).unwrap();
    let replacement = dir.join("services-replacement");
    std::fs::write(&replacement, "changed 4503/tcp replacement-alias\n").unwrap();
    for mode in ["strict", "hardened"] {
        let mut child = host_module_child(TEST, &dir, "services: fltest\n", mode);
        child.env("FRANKENLIBC_SERVICES_PATH", &path)
            .env("FLTEST_SERVICES_REPLACEMENT", &replacement)
            .env("FRANKENLIBC_MODE", mode);
        run_child(child, &format!("files service enumeration {mode}"));
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ProtocolRecord {
    name: Vec<u8>,
    number: c_int,
    aliases: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug)]
enum ProtocolRequest<'a> {
    Name(&'a CStr),
    Number(c_int),
    Next,
}

struct ProtocolApi {
    name: unsafe extern "C" fn(*const c_char) -> *mut c_void,
    number: unsafe extern "C" fn(c_int) -> *mut c_void,
    name_r: unsafe extern "C" fn(
        *const c_char,
        *mut c_void,
        *mut c_char,
        usize,
        *mut *mut c_void,
    ) -> c_int,
    number_r:
        unsafe extern "C" fn(c_int, *mut c_void, *mut c_char, usize, *mut *mut c_void) -> c_int,
    set: unsafe extern "C" fn(c_int),
    get: unsafe extern "C" fn() -> *mut c_void,
    get_r: unsafe extern "C" fn(*mut c_void, *mut c_char, usize, *mut *mut c_void) -> c_int,
    end: unsafe extern "C" fn(),
    error: unsafe extern "C" fn() -> *mut c_int,
}

fn protocol_api(host: bool) -> ProtocolApi {
    unsafe extern "C" {
        #[link_name = "getprotobyname"]
        fn host_name(name: *const c_char) -> *mut c_void;
        #[link_name = "getprotobynumber"]
        fn host_number(number: c_int) -> *mut c_void;
        #[link_name = "getprotobyname_r"]
        fn host_name_r(
            name: *const c_char,
            out: *mut c_void,
            buf: *mut c_char,
            len: usize,
            result: *mut *mut c_void,
        ) -> c_int;
        #[link_name = "getprotobynumber_r"]
        fn host_number_r(
            number: c_int,
            out: *mut c_void,
            buf: *mut c_char,
            len: usize,
            result: *mut *mut c_void,
        ) -> c_int;
        #[link_name = "setprotoent"]
        fn host_set(stayopen: c_int);
        #[link_name = "getprotoent"]
        fn host_get() -> *mut c_void;
        #[link_name = "getprotoent_r"]
        fn host_get_r(
            out: *mut c_void,
            buf: *mut c_char,
            len: usize,
            result: *mut *mut c_void,
        ) -> c_int;
        #[link_name = "endprotoent"]
        fn host_end();
    }
    use frankenlibc_abi::{errno_abi as e, resolv_abi as r, unistd_abi as u};
    assert_ne!(host_name as *const (), r::getprotobyname as *const ());
    assert_ne!(host_get_r as *const (), u::getprotoent_r as *const ());
    if host {
        ProtocolApi {
            name: host_name,
            number: host_number,
            name_r: host_name_r,
            number_r: host_number_r,
            set: host_set,
            get: host_get,
            get_r: host_get_r,
            end: host_end,
            error: libc::__errno_location,
        }
    } else {
        ProtocolApi {
            name: r::getprotobyname,
            number: r::getprotobynumber,
            name_r: u::getprotobyname_r,
            number_r: u::getprotobynumber_r,
            set: u::setprotoent,
            get: u::getprotoent,
            get_r: u::getprotoent_r,
            end: u::endprotoent,
            error: e::__errno_location,
        }
    }
}

unsafe fn protocol_record(
    pointer: *mut c_void,
    bounds: Option<(usize, usize)>,
) -> Option<ProtocolRecord> {
    if pointer.is_null() {
        return None;
    }
    // SAFETY: a successful API call publishes a complete protoent.
    let entry = unsafe { &*pointer.cast::<libc::protoent>() };
    let string = |pointer: *const c_char| {
        assert!(!pointer.is_null());
        if let Some((start, end)) = bounds {
            let address = pointer as usize;
            assert!(
                (start..end).contains(&address),
                "protocol string escaped caller buffer"
            );
            // SAFETY: the complete remaining range is inside the caller buffer.
            let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), end - address) };
            let len = bytes
                .iter()
                .position(|&byte| byte == 0)
                .expect("unterminated protocol string");
            bytes[..len].to_vec()
        } else {
            // SAFETY: non-reentrant answers own terminated strings.
            unsafe { CStr::from_ptr(pointer) }.to_bytes().to_vec()
        }
    };
    assert!(!entry.p_aliases.is_null());
    let mut aliases = Vec::new();
    for index in 0..4096 {
        let address = (entry.p_aliases as usize)
            .checked_add(index * std::mem::size_of::<usize>())
            .unwrap();
        assert_eq!(address % std::mem::align_of::<usize>(), 0);
        if let Some((start, end)) = bounds {
            assert!(address >= start && address + std::mem::size_of::<usize>() <= end);
        }
        // SAFETY: caller-backed slots were bounded above; owned output follows
        // the API's NULL-terminated alias-array contract.
        let alias = unsafe { *(address as *const *const c_char) };
        if alias.is_null() {
            return Some(ProtocolRecord {
                name: string(entry.p_name),
                number: entry.p_proto,
                aliases,
            });
        }
        aliases.push(string(alias));
    }
    panic!("protocol alias array was not terminated");
}

fn protocol_call(
    api: &ProtocolApi,
    request: ProtocolRequest<'_>,
    capacity: Option<usize>,
    offset: usize,
) -> (c_int, c_int, Option<ProtocolRecord>) {
    if let Some(capacity) = capacity {
        let mut storage = vec![0x5au8; 16384 + 16];
        assert!(offset + capacity <= storage.len());
        let mut output: libc::protoent = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::dangling_mut();
        let buffer = unsafe { storage.as_mut_ptr().add(offset).cast::<c_char>() };
        unsafe { *(api.error)() = 619 };
        // SAFETY: every public API receives complete output objects and a
        // deliberately exact (possibly short or unaligned) buffer range.
        let rc = unsafe {
            match request {
                ProtocolRequest::Name(name) => (api.name_r)(
                    name.as_ptr(),
                    (&raw mut output).cast(),
                    buffer,
                    capacity,
                    &mut result,
                ),
                ProtocolRequest::Number(number) => (api.number_r)(
                    number,
                    (&raw mut output).cast(),
                    buffer,
                    capacity,
                    &mut result,
                ),
                ProtocolRequest::Next => {
                    (api.get_r)((&raw mut output).cast(), buffer, capacity, &mut result)
                }
            }
        };
        let error = unsafe { *(api.error)() };
        assert!(
            storage[..offset]
                .iter()
                .chain(&storage[offset + capacity..])
                .all(|&byte| byte == 0x5a)
        );
        if !result.is_null() {
            assert_eq!(result, (&raw mut output).cast());
            assert_eq!(rc, 0);
        }
        let observed =
            unsafe { protocol_record(result, Some((buffer as usize, buffer as usize + capacity))) };
        (rc, error, observed)
    } else {
        unsafe { *(api.error)() = 619 };
        let result = unsafe {
            match request {
                ProtocolRequest::Name(name) => (api.name)(name.as_ptr()),
                ProtocolRequest::Number(number) => (api.number)(number),
                ProtocolRequest::Next => (api.get)(),
            }
        };
        let error = unsafe { *(api.error)() };
        (0, error, unsafe { protocol_record(result, None) })
    }
}

fn configure_host_protocols() {
    unsafe extern "C" {
        fn __nss_configure_lookup(database: *const c_char, sources: *const c_char) -> c_int;
    }
    let sources = CString::new(std::env::var("FLTEST_PROTOCOL_SOURCES").unwrap()).unwrap();
    assert_eq!(
        unsafe { __nss_configure_lookup(c"protocols".as_ptr(), sources.as_ptr()) },
        0
    );
}

#[test]
fn protocols_lookups_match_glibc_module_policy() {
    const TEST: &str = "protocols_lookups_match_glibc_module_policy";
    if std::env::var_os(CHILD_ENV).is_some() {
        let host = std::env::var("FLTEST_PROTOCOL_PROVIDER").unwrap() == "host";
        if host {
            configure_host_protocols();
        }
        unsafe { libc::alarm(20) };
        let api = protocol_api(host);
        let mut transcript = String::new();
        let sources = std::env::var("FLTEST_PROTOCOL_SOURCES").unwrap();
        let queries = [
            ProtocolRequest::Name(c"tcp"),
            ProtocolRequest::Name(c"TCP"),
            ProtocolRequest::Name(c"fltest-protocol"),
            ProtocolRequest::Name(c"fltest-proto"),
            ProtocolRequest::Name(c"fltest-large-protocol"),
            ProtocolRequest::Name(c"fltest-negative"),
            ProtocolRequest::Name(c"fltest-wide"),
            ProtocolRequest::Name(c"missing-protocol"),
            ProtocolRequest::Name(c"fltest-again"),
            ProtocolRequest::Name(c"fltest-unavail"),
            ProtocolRequest::Name(c"fltest-errno-none"),
            ProtocolRequest::Name(c"fltest-errno-again"),
            ProtocolRequest::Name(c"fltest-errno-unavail"),
            ProtocolRequest::Name(c"fltest-errno-success"),
            ProtocolRequest::Name(c"fltest-errno-written"),
            ProtocolRequest::Number(6),
            ProtocolRequest::Number(14501),
            ProtocolRequest::Number(14502),
            ProtocolRequest::Number(-7),
            ProtocolRequest::Number(70000),
            ProtocolRequest::Number(987654),
        ];
        for query in queries {
            // Exact small-buffer behavior belongs to the selected module.
            // Files keyed lookups retain their existing parsed index: GNU's
            // sequential scan can exhaust a tiny buffer on an unrelated line.
            let module_answer = match query {
                ProtocolRequest::Name(name) => [
                    c"tcp",
                    c"fltest-protocol",
                    c"fltest-proto",
                    c"fltest-large-protocol",
                    c"fltest-negative",
                    c"fltest-wide",
                    c"fltest-errno-success",
                    c"fltest-errno-written",
                ]
                .contains(&name),
                ProtocolRequest::Number(number) => matches!(number, 6 | 14501 | 14502 | -7 | 70000),
                ProtocolRequest::Next => false,
            };
            let mut budgets = Vec::new();
            if sources == "fltest" || (sources.starts_with("fltest ") && module_answer) {
                budgets.extend([(Some(0), 0), (Some(7), 1)]);
            }
            if sources == "fltest" {
                budgets.push((Some(96), 3));
            }
            budgets.extend([(Some(8192), 1), (None, 0)]);
            for (capacity, offset) in budgets {
                writeln!(
                    transcript,
                    "{query:?} {capacity:?}/{offset} {:?}",
                    protocol_call(&api, query, capacity, offset)
                )
                .unwrap();
            }
        }
        println!("PROTOCOL_LOOKUP_BEGIN\n{transcript}PROTOCOL_LOOKUP_END");
        unsafe { libc::alarm(0) };
        return;
    }
    let dir = scratch_dir("protocol-lookups");
    build_modules(&dir);
    let cases = [
        "fltest",
        "files",
        "fltest files",
        "files fltest",
        "fltest [SUCCESS=continue] files",
        "fltest [SUCCESS=merge] files",
        "fltest [NOTFOUND=return] files",
        "fltest [TRYAGAIN=return] files",
        "fltest [TRYAGAIN=continue] files",
        "fltest [UNAVAIL=return] files",
        "flmissing files",
        "flmissing [UNAVAIL=return] files",
        "compat files",
    ];
    let mut compared = 0;
    for (index, sources) in cases.into_iter().enumerate() {
        let mut oracle = None;
        for (provider, mode) in [("host", "strict"), ("fl", "strict"), ("fl", "hardened")] {
            let label = format!("protocol-lookup-{index}-{provider}-{mode}");
            let mut child =
                host_module_child(TEST, &dir, &format!("protocols: {sources}\n"), &label);
            child
                .env("FLTEST_PROTOCOL_PROVIDER", provider)
                .env("FLTEST_PROTOCOL_SOURCES", sources)
                .env("FRANKENLIBC_MODE", mode);
            let output = run_child(child, &label);
            let stdout = std::str::from_utf8(&output.stdout).unwrap();
            let transcript = stdout
                .split_once("PROTOCOL_LOOKUP_BEGIN\n")
                .unwrap()
                .1
                .split_once("PROTOCOL_LOOKUP_END")
                .unwrap()
                .0
                .to_owned();
            assert!((42..=105).contains(&transcript.lines().count()));
            if sources == "fltest" {
                assert!(
                    transcript.contains("number: 14501") && transcript.contains("number: 14502")
                );
                assert!(transcript.contains("number: -7") && transcript.contains("number: 70000"));
            }
            if let Some(expected) = &oracle {
                assert_eq!(&transcript, expected, "{label}: sources={sources}");
                compared += 1;
            } else {
                oracle = Some(transcript);
            }
        }
    }
    assert_eq!(compared, 26);
    eprintln!("protocol lookups: {compared} independent GNU/candidate process comparisons");
}

fn protocol_enumeration_transcript(api: &ProtocolApi) -> String {
    let mut transcript = String::new();
    unsafe { (api.end)() };
    for capacity in [0, 1, 7] {
        writeln!(
            transcript,
            "implicit {capacity} {:?}",
            protocol_call(api, ProtocolRequest::Next, Some(capacity), 1)
        )
        .unwrap();
    }
    for index in 0..6 {
        let answer = protocol_call(api, ProtocolRequest::Next, Some(8192), index % 2);
        let done = answer.2.is_none();
        writeln!(transcript, "implicit {index} {answer:?}").unwrap();
        if done {
            break;
        }
    }
    unsafe {
        (api.end)();
        (api.set)(1)
    };
    for index in 0..6 {
        let answer = protocol_call(api, ProtocolRequest::Next, None, 0);
        let done = answer.2.is_none();
        writeln!(transcript, "owned {index} {answer:?}").unwrap();
        if done {
            break;
        }
    }
    unsafe { (api.set)(0) };
    writeln!(
        transcript,
        "short {:?}",
        protocol_call(api, ProtocolRequest::Next, Some(1), 0)
    )
    .unwrap();
    writeln!(
        transcript,
        "retry {:?}",
        protocol_call(api, ProtocolRequest::Next, Some(8192), 1)
    )
    .unwrap();
    unsafe {
        (api.end)();
        (api.set)(0)
    };
    writeln!(
        transcript,
        "early end {:?}",
        protocol_call(api, ProtocolRequest::Next, Some(8192), 0)
    )
    .unwrap();
    unsafe {
        (api.end)();
        (api.end)()
    };
    writeln!(
        transcript,
        "after end {:?}",
        protocol_call(api, ProtocolRequest::Next, Some(8192), 1)
    )
    .unwrap();
    unsafe { (api.end)() };
    transcript
}

#[test]
fn protocols_enumeration_matches_glibc_module_policy() {
    const TEST: &str = "protocols_enumeration_matches_glibc_module_policy";
    if std::env::var_os(CHILD_ENV).is_some() {
        let host = std::env::var("FLTEST_PROTOCOL_PROVIDER").unwrap() == "host";
        if host {
            configure_host_protocols();
        }
        unsafe { libc::alarm(20) };
        let transcript = protocol_enumeration_transcript(&protocol_api(host));
        println!("PROTOCOL_ENUM_BEGIN\n{transcript}PROTOCOL_ENUM_END");
        unsafe { libc::alarm(0) };
        return;
    }
    let dir = scratch_dir("protocol-enumeration");
    build_modules(&dir);
    let module = Command::new("cc")
        .args([
            "-O2",
            "-fPIC",
            "-shared",
            "-DSERVICE=fltestgetonly",
            "-DNO_PROTOCOL_SET",
            "-DNO_PROTOCOL_END",
        ])
        .arg(repo_root().join("tests/integration/fixture_nss_module_lib.c"))
        .arg("-o")
        .arg(dir.join("libnss_fltestgetonly.so.2"))
        .output()
        .unwrap();
    assert!(
        module.status.success(),
        "{}",
        String::from_utf8_lossy(&module.stderr)
    );
    let cases = [
        ("fltest", "normal"),
        ("fltest fltestnoig", "normal"),
        ("fltest [SUCCESS=continue] fltestnoig", "normal"),
        ("fltest [SUCCESS=merge] fltestnoig", "normal"),
        ("fltest [TRYAGAIN=continue] fltestnoig", "normal"),
        ("fltest [NOTFOUND=return] fltestnoig", "normal"),
        (
            "fltest [SUCCESS=return NOTFOUND=return UNAVAIL=return TRYAGAIN=return] fltestnoig",
            "normal",
        ),
        ("fltest [UNAVAIL=return] fltestnoig", "get-unavail"),
        ("fltest [UNAVAIL=continue] fltestnoig", "get-unavail"),
        ("fltest [TRYAGAIN=return] fltestnoig", "get-again"),
        ("fltest [TRYAGAIN=continue] fltestnoig", "get-again"),
        ("fltest [TRYAGAIN=return] fltestnoig", "get-quiet-again"),
        ("fltest fltestnoig", "get-return"),
        ("fltest [!SUCCESS=continue] fltestnoig", "get-return"),
        ("fltest fltestnoig", "set-unavail"),
        ("fltest [UNAVAIL=return] fltestnoig", "set-unavail"),
        ("fltest [TRYAGAIN=return] fltestnoig", "set-again"),
        ("fltest [NOTFOUND=return] fltestnoig", "set-notfound"),
        ("fltest fltestnoig", "set-return"),
        ("flmissing fltest", "normal"),
        ("flmissing fltest", "set-unavail"),
        ("flmissing [UNAVAIL=return] files", "normal"),
        ("fltestgetonly", "normal"),
        ("fltestgetonly fltest", "normal"),
        ("fltestgetonly [UNAVAIL=return] fltest", "normal"),
        ("fltest fltestgetonly fltestnoig", "normal"),
        ("fltest flmissing [UNAVAIL=return] fltestnoig", "normal"),
        ("files", "normal"),
    ];
    let mut compared = 0;
    for (index, (sources, scenario)) in cases.into_iter().enumerate() {
        let mut oracle = None;
        for (provider, mode) in [("host", "strict"), ("fl", "strict"), ("fl", "hardened")] {
            let label = format!("protocol-enum-{index}-{provider}-{mode}");
            let mut child =
                host_module_child(TEST, &dir, &format!("protocols: {sources}\n"), &label);
            child
                .env("FLTEST_PROTOCOL_PROVIDER", provider)
                .env("FLTEST_PROTOCOL_SOURCES", sources)
                .env("FLTEST_PROTOCOL_ENUM", scenario)
                .env("FLTEST_TRACE", "1")
                .env("FRANKENLIBC_MODE", mode);
            let output = run_child(child, &label);
            let stdout = std::str::from_utf8(&output.stdout).unwrap();
            let transcript = stdout
                .split_once("PROTOCOL_ENUM_BEGIN\n")
                .unwrap()
                .1
                .split_once("PROTOCOL_ENUM_END")
                .unwrap()
                .0
                .to_owned();
            assert!(transcript.lines().count() >= 9);
            let cleanup = String::from_utf8_lossy(&output.stderr)
                .lines()
                .filter(|line| line.contains(":endprotoent("))
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if sources == "fltest" {
                assert!(
                    transcript.contains("number: 14501") && transcript.contains("number: 14502")
                );
            }
            if sources == "fltest fltestnoig" && scenario == "normal" {
                assert!(
                    cleanup
                        .iter()
                        .filter(|line| line.contains("fltestnoig:endprotoent("))
                        .count()
                        >= 4
                );
            }
            if let Some(expected) = &oracle {
                assert_eq!(
                    &(transcript, cleanup),
                    expected,
                    "{label}: {sources}, {scenario}"
                );
                compared += 1;
            } else {
                oracle = Some((transcript, cleanup));
            }
        }
    }
    assert_eq!(compared, 56);
    eprintln!("protocol enumeration: {compared} independent GNU/candidate process comparisons");
}

unsafe extern "C" fn protocol_enumeration_reentry() -> c_int {
    use frankenlibc_abi::{errno_abi as e, resolv_abi as r, unistd_abi as u};
    let mut output: libc::protoent = unsafe { std::mem::zeroed() };
    let mut buffer = [0 as c_char; 1024];
    let mut result = std::ptr::null_mut();
    unsafe {
        u::setprotoent(0);
        if *e::__errno_location() != libc::EDEADLK {
            return 1;
        }
        if !u::getprotoent().is_null() || *e::__errno_location() != libc::EDEADLK {
            return 2;
        }
        if u::getprotoent_r(
            (&raw mut output).cast(),
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        ) != libc::EDEADLK
            || !result.is_null()
        {
            return 3;
        }
        u::endprotoent();
        if *e::__errno_location() != libc::EDEADLK {
            return 4;
        }
        let keyed = r::getprotobyname(c"tcp".as_ptr()).cast::<libc::protoent>();
        if keyed.is_null() || (*keyed).p_proto != 14600 {
            return 5;
        }
    }
    0
}

#[test]
fn protocols_files_retry_provider_isolation_and_reentry() {
    const TEST: &str = "protocols_files_retry_provider_isolation_and_reentry";
    if std::env::var_os(CHILD_ENV).is_some() {
        use frankenlibc_abi::{glibc_internal_abi as g, unistd_abi as u};
        unsafe { libc::alarm(20) };
        let api = protocol_api(false);
        let mut raw: libc::protoent = unsafe { std::mem::zeroed() };
        let mut storage = [0 as c_char; 8192];
        let mut error = 717;
        unsafe {
            assert_eq!(u::_nss_files_setprotoent(0), 1);
            assert_eq!(
                u::_nss_files_getprotoent_r(
                    (&raw mut raw).cast(),
                    storage.as_mut_ptr(),
                    storage.len(),
                    &mut error
                ),
                1
            );
            assert_eq!(raw.p_proto, 14511);
            // A public end before initialization cannot close a private cursor.
            (api.end)();
            assert_eq!(
                u::_nss_files_getprotoent_r(
                    (&raw mut raw).cast(),
                    storage.as_mut_ptr(),
                    storage.len(),
                    &mut error
                ),
                1
            );
            assert_eq!(raw.p_proto, 14512);
            for (name, capacity, status, expected_error) in [
                (c"local-alias", storage.len(), 1, 717),
                (c"missing-protocol", storage.len(), 0, 717),
                (c"local-alias", 1, -2, libc::ERANGE),
            ] {
                error = 717;
                *(api.error)() = 619;
                assert_eq!(
                    u::_nss_files_getprotobyname_r(
                        name.as_ptr(),
                        (&raw mut raw).cast(),
                        storage.as_mut_ptr(),
                        capacity,
                        &mut error,
                    ),
                    status,
                );
                assert_eq!((*(api.error)(), error), (619, expected_error));
                if status == 1 {
                    assert_eq!(raw.p_proto, 6);
                }
            }
            error = 717;
            *(api.error)() = 619;
            assert_eq!(
                u::_nss_files_getprotobynumber_r(
                    6,
                    (&raw mut raw).cast(),
                    storage.as_mut_ptr(),
                    storage.len(),
                    &mut error
                ),
                1
            );
            assert_eq!(CStr::from_ptr(raw.p_name).to_bytes(), b"local-tcp");
            assert_eq!((*(api.error)(), error), (619, 717));
            let path = std::env::var_os("FRANKENLIBC_PROTOCOLS_PATH").unwrap();
            std::env::set_var(
                "FRANKENLIBC_PROTOCOLS_PATH",
                PathBuf::from(&path).with_extension("missing"),
            );
            error = 717;
            *(api.error)() = 619;
            assert_eq!(
                u::_nss_files_getprotobynumber_r(
                    6,
                    (&raw mut raw).cast(),
                    storage.as_mut_ptr(),
                    storage.len(),
                    &mut error,
                ),
                -1,
            );
            assert_eq!((*(api.error)(), error), (619, libc::ENOENT));
            std::env::set_var("FRANKENLIBC_PROTOCOLS_PATH", path);
            (api.set)(0);
        }
        assert_eq!(
            protocol_call(&api, ProtocolRequest::Next, None, 0)
                .2
                .unwrap()
                .number,
            14501
        );
        unsafe {
            u::_nss_files_setprotoent(0);
            assert_eq!(
                u::_nss_files_getprotoent_r(
                    (&raw mut raw).cast(),
                    storage.as_mut_ptr(),
                    1,
                    &mut error
                ),
                -2
            );
            assert_eq!(error, libc::ERANGE);
            u::_nss_files_endprotoent();
        }
        let large = protocol_call(&api, ProtocolRequest::Next, None, 0)
            .2
            .unwrap();
        assert_eq!(large.number, 14502);
        assert_eq!(large.aliases[2], vec![b'p'; 3072]);
        unsafe {
            (api.end)();
            let handle = libc::dlopen(c"libnss_fltest.so.2".as_ptr(), libc::RTLD_NOW);
            assert!(!handle.is_null());
            let symbol = libc::dlsym(handle, c"_nss_fltest_set_protocol_enum_reentry".as_ptr());
            assert!(!symbol.is_null());
            let install: unsafe extern "C" fn(Option<unsafe extern "C" fn() -> c_int>) =
                std::mem::transmute(symbol);
            install(Some(protocol_enumeration_reentry));
            (api.set)(0);
            assert_eq!(
                protocol_call(&api, ProtocolRequest::Next, None, 0)
                    .2
                    .unwrap()
                    .number,
                14501
            );
            assert_eq!(
                protocol_call(&api, ProtocolRequest::Next, None, 0)
                    .2
                    .unwrap()
                    .number,
                14502
            );
            assert!(
                protocol_call(&api, ProtocolRequest::Next, None, 0)
                    .2
                    .is_none()
            );
            (api.end)();
            install(None);
            libc::dlclose(handle);
            assert_eq!(
                g::__nss_configure_lookup(c"protocols".as_ptr(), c"files".as_ptr()),
                0
            );
            (api.set)(0);
        }
        let small = protocol_call(&api, ProtocolRequest::Next, Some(1), 1);
        assert_eq!(
            (small.0, small.1, small.2),
            (libc::ERANGE, libc::ERANGE, None)
        );
        unsafe {
            assert_eq!(
                u::_nss_files_getprotoent_r(
                    (&raw mut raw).cast(),
                    storage.as_mut_ptr(),
                    storage.len(),
                    &mut error
                ),
                1
            );
            let first = protocol_record((&raw mut raw).cast(), None).unwrap();
            assert_eq!(first.name.len(), 1800);
            assert_eq!(first.aliases.len(), 24);
        }
        assert_eq!(
            protocol_call(&api, ProtocolRequest::Next, Some(8192), 1)
                .2
                .unwrap()
                .number,
            14512
        );
        // A different thread owns an independent cursor and published storage.
        std::thread::spawn(|| {
            let api = protocol_api(false);
            let first = protocol_call(&api, ProtocolRequest::Next, None, 0)
                .2
                .unwrap();
            assert_eq!(first.number, 14511);
            unsafe { (api.end)() };
        })
        .join()
        .unwrap();
        assert_eq!(
            protocol_call(&api, ProtocolRequest::Next, Some(8192), 0)
                .2
                .unwrap()
                .number,
            6
        );
        assert!(
            protocol_call(&api, ProtocolRequest::Next, Some(8192), 0)
                .2
                .is_none()
        );
        unsafe { (api.set)(0) };
        assert_eq!(
            protocol_call(&api, ProtocolRequest::Next, Some(7), 0).0,
            libc::ERANGE
        );
        let replacement = std::env::var_os("FLTEST_PROTOCOLS_REPLACEMENT").unwrap();
        unsafe { std::env::set_var("FRANKENLIBC_PROTOCOLS_PATH", replacement) };
        let changed = protocol_call(&api, ProtocolRequest::Next, Some(8192), 1)
            .2
            .unwrap();
        assert_eq!((changed.name, changed.number), (b"changed".to_vec(), 14513));
        unsafe {
            (api.end)();
            u::_nss_files_endprotoent();
            libc::alarm(0)
        };
        return;
    }
    let dir = scratch_dir("protocol-files-retry");
    build_modules(&dir);
    let path = dir.join("protocols");
    let aliases = (0..24)
        .map(|index| format!("alias{index}"))
        .collect::<Vec<_>>()
        .join(" ");
    std::fs::write(&path, format!("# comment\nbad record\n{} 14511 {aliases}\nsecond 14512 last\nlocal-tcp 6 local-alias\n", "n".repeat(1800))).unwrap();
    let replacement = dir.join("protocols-replacement");
    std::fs::write(&replacement, "changed 14513 replacement\n").unwrap();
    for mode in ["strict", "hardened"] {
        let mut child = host_module_child(TEST, &dir, "protocols: fltest\n", mode);
        child
            .env("FRANKENLIBC_PROTOCOLS_PATH", &path)
            .env("FLTEST_PROTOCOLS_REPLACEMENT", &replacement)
            .env("FRANKENLIBC_MODE", mode);
        run_child(
            child,
            &format!("protocol files and callback isolation {mode}"),
        );
    }
}

static SERVICE_ENUM_REENTRY_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

unsafe extern "C" fn service_enumeration_reentry() -> c_int {
    use frankenlibc_abi::{errno_abi as e, resolv_abi as r, unistd_abi as u};
    SERVICE_ENUM_REENTRY_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut output: libc::servent = unsafe { std::mem::zeroed() };
    let mut storage = [0 as c_char; 1024];
    let mut result = std::ptr::null_mut();
    unsafe {
        u::setservent(0);
        if *e::__errno_location() != libc::EDEADLK { return 1; }
        if !u::getservent().is_null() || *e::__errno_location() != libc::EDEADLK { return 2; }
        if u::getservent_r((&raw mut output).cast(), storage.as_mut_ptr(), storage.len(), &mut result)
            != libc::EDEADLK || !result.is_null()
        { return 3; }
        u::endservent();
        if *e::__errno_location() != libc::EDEADLK { return 4; }
        let other = r::getservbyname(c"http".as_ptr(), c"tcp".as_ptr()).cast::<libc::servent>();
        if other.is_null() || CStr::from_ptr((*other).s_name).to_bytes() != b"module-http" { return 5; }
    }
    0
}

#[test]
fn services_enumeration_callback_reentry() {
    const TEST: &str = "services_enumeration_callback_reentry";
    if std::env::var_os(CHILD_ENV).is_some() {
        unsafe {
            libc::alarm(15);
            let handle = libc::dlopen(c"libnss_fltest.so.2".as_ptr(), libc::RTLD_NOW);
            assert!(!handle.is_null());
            let symbol = libc::dlsym(handle, c"_nss_fltest_set_service_enum_reentry".as_ptr());
            assert!(!symbol.is_null());
            let install: unsafe extern "C" fn(Option<unsafe extern "C" fn() -> c_int>) =
                std::mem::transmute(symbol);
            install(Some(service_enumeration_reentry));
            let api = service_enumeration_api(false);
            (api.set)(0);
            assert_eq!(service_enumeration_read(&api, None, 0).2.unwrap().name, b"fltest-enum-small");
            assert_eq!(service_enumeration_read(&api, None, 0).2.unwrap().name, b"fltest-enum-large");
            assert!(service_enumeration_read(&api, None, 0).2.is_none());
            assert_eq!(SERVICE_ENUM_REENTRY_CALLS.load(std::sync::atomic::Ordering::Relaxed), 1);
            (api.end)();
            install(None);
            libc::dlclose(handle);
            libc::alarm(0);
        }
        return;
    }
    let dir = scratch_dir("service-enum-reentry");
    build_modules(&dir);
    for mode in ["strict", "hardened"] {
        let mut child = host_module_child(TEST, &dir, "services: fltest\n", mode);
        child.env("FRANKENLIBC_MODE", mode);
        run_child(child, &format!("service enumeration callback {mode}"));
    }
}

struct HostEnumerationApi {
    set: unsafe extern "C" fn(c_int),
    get: unsafe extern "C" fn() -> *mut c_void,
    get_r: unsafe extern "C" fn(
        *mut c_void,
        *mut c_char,
        usize,
        *mut *mut c_void,
        *mut c_int,
    ) -> c_int,
    end: unsafe extern "C" fn(),
    error: unsafe extern "C" fn() -> *mut c_int,
    host_error: unsafe extern "C" fn() -> *mut c_int,
    files_set: unsafe extern "C" fn(c_int) -> c_int,
    files_get:
        unsafe extern "C" fn(*mut c_void, *mut c_char, usize, *mut c_int, *mut c_int) -> c_int,
    files_end: unsafe extern "C" fn() -> c_int,
}

fn host_enumeration_api(host: bool) -> HostEnumerationApi {
    unsafe extern "C" {
        #[link_name = "sethostent"]
        fn host_set(stayopen: c_int);
        #[link_name = "gethostent"]
        fn host_get() -> *mut c_void;
        #[link_name = "gethostent_r"]
        fn host_get_r(
            out: *mut c_void,
            buf: *mut c_char,
            len: usize,
            result: *mut *mut c_void,
            host_error: *mut c_int,
        ) -> c_int;
        #[link_name = "endhostent"]
        fn host_end();
        #[link_name = "__h_errno_location"]
        fn host_error() -> *mut c_int;
        #[link_name = "_nss_files_sethostent"]
        fn host_files_set(stayopen: c_int) -> c_int;
        #[link_name = "_nss_files_gethostent_r"]
        fn host_files_get(
            out: *mut c_void,
            buf: *mut c_char,
            len: usize,
            error: *mut c_int,
            host_error: *mut c_int,
        ) -> c_int;
        #[link_name = "_nss_files_endhostent"]
        fn host_files_end() -> c_int;
    }
    use frankenlibc_abi::{errno_abi as e, resolv_abi as r, unistd_abi as u};
    assert_ne!(host_get as *const (), u::gethostent as *const ());
    assert_ne!(host_get_r as *const (), u::gethostent_r as *const ());
    if host {
        HostEnumerationApi {
            set: host_set,
            get: host_get,
            get_r: host_get_r,
            end: host_end,
            error: libc::__errno_location,
            host_error,
            files_set: host_files_set,
            files_get: host_files_get,
            files_end: host_files_end,
        }
    } else {
        HostEnumerationApi {
            set: u::sethostent,
            get: u::gethostent,
            get_r: u::gethostent_r,
            end: u::endhostent,
            error: e::__errno_location,
            host_error: r::__h_errno_location,
            files_set: u::_nss_files_sethostent,
            files_get: u::_nss_files_gethostent_r,
            files_end: u::_nss_files_endhostent,
        }
    }
}

unsafe fn enumerated_host(
    pointer: *mut c_void,
    bounds: Option<(usize, usize)>,
) -> Option<HostAnswer> {
    if pointer.is_null() {
        return None;
    }
    // SAFETY: the API published a complete hostent. Check every pointer-table
    // slot, address and string before allowing the shared decoder to read it.
    let entry = unsafe { &*pointer.cast::<libc::hostent>() };
    if let Some((start, end)) = bounds {
        let check = |pointer: *const c_char, length: Option<usize>| {
            let address = pointer as usize;
            assert!(
                (start..end).contains(&address),
                "host data escaped caller buffer"
            );
            if let Some(length) = length {
                assert!(
                    length <= end - address,
                    "host address escaped caller buffer"
                );
            } else {
                // SAFETY: only inspect the checked tail of the caller buffer.
                let bytes =
                    unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), end - address) };
                assert!(bytes.contains(&0), "unterminated host string");
            }
        };
        check(entry.h_name, None);
        assert!(matches!(
            (entry.h_addrtype, entry.h_length),
            (libc::AF_INET, 4) | (libc::AF_INET6, 16)
        ));
        for (table, length) in [
            (entry.h_aliases, None),
            (entry.h_addr_list, Some(entry.h_length as usize)),
        ] {
            let mut terminated = false;
            for index in 0..4096 {
                let address = (table as usize)
                    .checked_add(index * std::mem::size_of::<usize>())
                    .unwrap();
                assert!(
                    address >= start
                        && address <= end
                        && std::mem::size_of::<usize>() <= end - address
                );
                assert_eq!(address % std::mem::align_of::<usize>(), 0);
                // SAFETY: the aligned slot lies wholly inside the supplied buffer.
                let pointer = unsafe { *(address as *const *mut c_char) };
                if pointer.is_null() {
                    terminated = true;
                    break;
                }
                check(pointer, length);
            }
            assert!(terminated, "host pointer table was not terminated");
        }
    }
    // SAFETY: successful non-reentrant output belongs to the API; caller-owned
    // output was checked above, including every terminating pointer and byte.
    unsafe { host_answer(pointer.cast()) }
}

#[derive(Debug, PartialEq, Eq)]
struct HostEnumerationResult {
    status: c_int,
    error: c_int,
    host_error: c_int,
    argument_host_error: c_int,
    answer: Option<HostAnswer>,
}

fn host_enumeration_read(
    api: &HostEnumerationApi,
    capacity: Option<usize>,
    offset: usize,
) -> HostEnumerationResult {
    // GNU enumeration updates the canonical h_errno but leaves the explicit
    // gethostent_r h_errnop argument untouched. Record both independent slots.
    unsafe {
        *(api.error)() = 619;
        *(api.host_error)() = 811;
    }
    let mut argument_host_error = 717;
    let (status, error, host_error, answer) = if let Some(capacity) = capacity {
        let mut storage = vec![0x5au8; 8192 + 16];
        assert!(offset + capacity <= storage.len());
        let buffer = unsafe { storage.as_mut_ptr().add(offset).cast::<c_char>() };
        let mut output: libc::hostent = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::dangling_mut::<c_void>();
        let status = unsafe {
            (api.get_r)(
                (&raw mut output).cast(),
                buffer,
                capacity,
                &mut result,
                &mut argument_host_error,
            )
        };
        let (error, host_error) = unsafe { (*(api.error)(), *(api.host_error)()) };
        assert!(
            storage[..offset]
                .iter()
                .chain(&storage[offset + capacity..])
                .all(|&byte| byte == 0x5a)
        );
        if !result.is_null() {
            assert_eq!(status, 0);
            assert_eq!(result, (&raw mut output).cast());
        }
        let answer =
            unsafe { enumerated_host(result, Some((buffer as usize, buffer as usize + capacity))) };
        (status, error, host_error, answer)
    } else {
        let result = unsafe { (api.get)() };
        let (error, host_error) = unsafe { (*(api.error)(), *(api.host_error)()) };
        (0, error, host_error, unsafe {
            enumerated_host(result, None)
        })
    };
    HostEnumerationResult {
        status,
        error,
        host_error,
        argument_host_error,
        answer,
    }
}

fn host_enumeration_transcript(api: &HostEnumerationApi) -> String {
    let mut transcript = String::new();
    unsafe { (api.end)() };
    for capacity in [0, 1, 7] {
        writeln!(
            transcript,
            "implicit {capacity} {:?}",
            host_enumeration_read(api, Some(capacity), 1)
        )
        .unwrap();
    }
    for index in 0..6 {
        let result = host_enumeration_read(api, Some(8192), index % 2);
        let done = result.answer.is_none();
        writeln!(transcript, "implicit record {index} {result:?}").unwrap();
        if done {
            break;
        }
    }
    unsafe {
        (api.end)();
        (api.set)(1)
    };
    for index in 0..6 {
        let result = host_enumeration_read(api, None, 0);
        let done = result.answer.is_none();
        writeln!(transcript, "owned record {index} {result:?}").unwrap();
        if done {
            break;
        }
    }
    unsafe { (api.set)(0) };
    writeln!(
        transcript,
        "short {:?}",
        host_enumeration_read(api, Some(1), 0)
    )
    .unwrap();
    writeln!(
        transcript,
        "retry {:?}",
        host_enumeration_read(api, Some(8192), 1)
    )
    .unwrap();
    unsafe {
        (api.end)();
        (api.set)(0)
    };
    writeln!(
        transcript,
        "early end {:?}",
        host_enumeration_read(api, Some(8192), 0)
    )
    .unwrap();
    unsafe {
        (api.end)();
        (api.end)()
    };
    writeln!(
        transcript,
        "after end {:?}",
        host_enumeration_read(api, Some(8192), 1)
    )
    .unwrap();
    unsafe { (api.end)() };
    transcript
}

fn configure_host_enumeration(host: bool, sources: &CStr) {
    unsafe extern "C" {
        fn __nss_configure_lookup(database: *const c_char, sources: *const c_char) -> c_int;
    }
    let configure = if host {
        __nss_configure_lookup
    } else {
        frankenlibc_abi::glibc_internal_abi::__nss_configure_lookup
    };
    assert_eq!(unsafe { configure(c"hosts".as_ptr(), sources.as_ptr()) }, 0);
}

fn host_enumeration_scratch(tag: &str) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "frankenlibc-host-enum-{tag}-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir(&path).unwrap();
    path
}

#[test]
fn hosts_enumeration_matches_glibc_module_policy() {
    const TEST: &str = "hosts_enumeration_matches_glibc_module_policy";
    if std::env::var_os(CHILD_ENV).is_some() {
        let host = std::env::var("FLTEST_HOST_PROVIDER").unwrap() == "host";
        let sources = CString::new(std::env::var("FLTEST_HOST_SOURCES").unwrap()).unwrap();
        configure_host_enumeration(host, &sources);
        unsafe { libc::alarm(20) };
        let transcript = host_enumeration_transcript(&host_enumeration_api(host));
        unsafe { libc::alarm(0) };
        println!("HOST_ENUM_BEGIN\n{transcript}HOST_ENUM_END");
        return;
    }
    let dir = host_enumeration_scratch("policy");
    build_modules(&dir);
    let module = Command::new("cc")
        .args([
            "-O2",
            "-fPIC",
            "-shared",
            "-DSERVICE=fltestgetonly",
            "-DNO_HOST_SET",
            "-DNO_HOST_END",
        ])
        .arg(repo_root().join("tests/integration/fixture_nss_module_lib.c"))
        .arg("-o")
        .arg(dir.join("libnss_fltestgetonly.so.2"))
        .output()
        .expect("build get-only hosts enumeration provider");
    assert!(
        module.status.success(),
        "{}",
        String::from_utf8_lossy(&module.stderr)
    );
    let cases = [
        ("fltest", "normal"),
        ("fltest fltestnoig", "normal"),
        ("fltest [SUCCESS=continue] fltestnoig", "normal"),
        ("fltest [SUCCESS=merge] fltestnoig", "normal"),
        ("fltest [TRYAGAIN=continue] fltestnoig", "normal"),
        ("fltest [NOTFOUND=return] fltestnoig", "normal"),
        (
            "fltest [SUCCESS=return NOTFOUND=return UNAVAIL=return TRYAGAIN=return] fltestnoig",
            "normal",
        ),
        ("fltest [UNAVAIL=return] fltestnoig", "get-unavail"),
        ("fltest [UNAVAIL=continue] fltestnoig", "get-unavail"),
        ("fltest [TRYAGAIN=return] fltestnoig", "get-again"),
        ("fltest [TRYAGAIN=continue] fltestnoig", "get-again"),
        ("fltest [TRYAGAIN=return] fltestnoig", "get-quiet-again"),
        ("fltest fltestnoig", "get-notfound"),
        ("fltest [NOTFOUND=return] fltestnoig", "get-notfound"),
        ("fltest fltestnoig", "get-return"),
        ("fltest [!SUCCESS=continue] fltestnoig", "get-return"),
        ("fltest fltestnoig", "set-unavail"),
        ("fltest [UNAVAIL=return] fltestnoig", "set-unavail"),
        ("fltest [TRYAGAIN=return] fltestnoig", "set-again"),
        ("fltest [NOTFOUND=return] fltestnoig", "set-notfound"),
        ("fltest fltestnoig", "set-return"),
        ("flmissing fltest", "normal"),
        ("flmissing", "normal"),
        ("flmissing [UNAVAIL=return] fltest", "normal"),
        ("fltestgetonly", "normal"),
        ("fltestgetonly fltest", "normal"),
        ("fltestgetonly [UNAVAIL=return] fltest", "normal"),
        ("fltest fltestgetonly fltestnoig", "normal"),
        ("fltest flmissing [UNAVAIL=return] fltestnoig", "normal"),
        (
            "fltest [TRYAGAIN=continue] fltestnoig",
            "get-range-internal",
        ),
        ("fltest [TRYAGAIN=continue] fltestnoig", "get-range-again"),
        ("fltest [TRYAGAIN=return] fltestnoig", "get-range-again"),
        ("fltest [TRYAGAIN=return] fltestnoig", "get-nomem-internal"),
        (
            "fltest [TRYAGAIN=continue] fltestnoig",
            "get-nomem-internal",
        ),
        ("fltest [TRYAGAIN=return] fltestnoig", "get-io-internal"),
        ("fltest [TRYAGAIN=continue] fltestnoig", "get-io-internal"),
        ("fltest", "get-success-quiet"),
        ("files", "normal"),
        ("fltest files", "normal"),
    ];
    let mut compared = 0;
    for (index, (sources, scenario)) in cases.into_iter().enumerate() {
        let mut oracle = None;
        for (provider, mode) in [("host", "strict"), ("fl", "strict"), ("fl", "hardened")] {
            let label = format!("host-enum-{index}-{provider}-{mode}");
            let mut child = host_module_child(TEST, &dir, "hosts: files\n", &label);
            child
                .env("FLTEST_HOST_PROVIDER", provider)
                .env("FLTEST_HOST_SOURCES", sources)
                .env("FLTEST_HOST_ENUM", scenario)
                .env("FLTEST_TRACE", "1")
                .env("FRANKENLIBC_MODE", mode)
                .env_remove("FRANKENLIBC_HOSTS_PATH");
            let output = run_child(child, &label);
            let stdout = std::str::from_utf8(&output.stdout).unwrap();
            let transcript = stdout
                .split_once("HOST_ENUM_BEGIN\n")
                .and_then(|(_, rest)| rest.split_once("HOST_ENUM_END"))
                .map(|(text, _)| text)
                .expect("executed hosts enumeration transcript")
                .to_owned();
            assert!(transcript.lines().count() >= 9);
            let lifecycle = String::from_utf8_lossy(&output.stderr)
                .lines()
                .filter(|line| line.contains(":sethostent(") || line.contains(":endhostent("))
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if sources == "fltest" {
                assert!(
                    transcript.contains("192.0.2.41") && transcript.contains("2001:db8::41"),
                    "both complete IPv4 and large IPv6 module records must be observed"
                );
                assert!(String::from_utf8_lossy(&output.stderr).contains("fltest:gethostent_r("));
            }
            if sources == "fltest fltestnoig" && scenario == "normal" {
                assert!(
                    lifecycle
                        .iter()
                        .filter(|line| line.contains("fltestnoig:endhostent("))
                        .count()
                        >= 4,
                    "early and repeated cleanup must reach later configured modules"
                );
            }
            if let Some(expected) = &oracle {
                assert_eq!(
                    &(transcript, lifecycle),
                    expected,
                    "{label}: {sources}, {scenario}"
                );
                compared += 1;
            } else {
                oracle = Some((transcript, lifecycle));
            }
        }
    }
    assert_eq!(compared, 78);
    eprintln!("hosts enumeration: {compared} independent GNU/candidate process comparisons");
}

static HOST_ENUM_REENTRY_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

unsafe extern "C" fn host_enumeration_reentry() -> c_int {
    use frankenlibc_abi::{errno_abi as e, resolv_abi as r, unistd_abi as u};
    HOST_ENUM_REENTRY_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut output: libc::hostent = unsafe { std::mem::zeroed() };
    let mut buffer = [0 as c_char; 1024];
    let mut result = std::ptr::null_mut();
    let mut host_error = 717;
    // SAFETY: the provider invokes this callback while its outer result is
    // leased. Recursive enumeration must fail without entering a second borrow.
    unsafe {
        u::sethostent(0);
        if *e::__errno_location() != libc::EDEADLK {
            return 1;
        }
        if !u::gethostent().is_null() || *e::__errno_location() != libc::EDEADLK {
            return 2;
        }
        if u::gethostent_r(
            (&raw mut output).cast(),
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
            &mut host_error,
        ) != libc::EDEADLK
            || !result.is_null()
        {
            return 3;
        }
        u::endhostent();
        if *e::__errno_location() != libc::EDEADLK {
            return 4;
        }
        let keyed = r::gethostbyname(c"fltest-host".as_ptr()).cast::<libc::hostent>();
        if keyed.is_null() || CStr::from_ptr((*keyed).h_name).to_bytes() != b"fltest-host.example" {
            return 5;
        }
    }
    0
}

#[test]
fn hosts_enumeration_files_retry_provider_isolation_and_reentry() {
    const TEST: &str = "hosts_enumeration_files_retry_provider_isolation_and_reentry";
    if std::env::var_os(CHILD_ENV).is_some() {
        unsafe { libc::alarm(20) };
        let api = host_enumeration_api(false);
        configure_host_enumeration(false, c"fltest");
        let mut entry: libc::hostent = unsafe { std::mem::zeroed() };
        let mut storage = [0 as c_char; 8192];
        let mut error = 619;
        let mut host_error = 717;
        unsafe {
            (api.set)(0);
            assert_eq!((api.files_set)(0), 1);
            assert_eq!(
                (api.files_get)(
                    (&raw mut entry).cast(),
                    storage.as_mut_ptr(),
                    1,
                    &mut error,
                    &mut host_error
                ),
                -2
            );
            assert_eq!(error, libc::ERANGE);
            assert_eq!(host_error, -1);
            assert_eq!(
                (api.files_get)(
                    (&raw mut entry).cast(),
                    storage.as_mut_ptr(),
                    storage.len(),
                    &mut error,
                    &mut host_error
                ),
                1
            );
            assert_eq!(host_answer(&entry).unwrap().name, b"files-first");
        }
        let first = host_enumeration_read(&api, None, 0).answer.unwrap();
        assert_eq!(first.name, b"fltest-host-small");
        unsafe { assert_eq!((api.files_end)(), 1) };
        let second = host_enumeration_read(&api, None, 0).answer.unwrap();
        assert_eq!(second.name, b"fltest-host-large");
        assert_eq!(second.aliases[2], vec![b'a'; 3072]);
        unsafe { (api.end)() };

        configure_host_enumeration(false, c"files");
        unsafe { (api.set)(0) };
        let short = host_enumeration_read(&api, Some(1), 1);
        assert_eq!(short.status, libc::ERANGE);
        assert_eq!(short.host_error, -1);
        assert_eq!(short.argument_host_error, 717);
        unsafe {
            assert_eq!(
                (api.files_get)(
                    (&raw mut entry).cast(),
                    storage.as_mut_ptr(),
                    storage.len(),
                    &mut error,
                    &mut host_error
                ),
                1
            );
            assert_eq!(host_answer(&entry).unwrap().name, b"files-first");
        }
        assert_eq!(
            host_enumeration_read(&api, Some(8192), 1)
                .answer
                .unwrap()
                .name,
            b"files-second"
        );
        unsafe { assert_eq!((api.files_end)(), 1) };
        assert_eq!(
            host_enumeration_read(&api, Some(8192), 0)
                .answer
                .unwrap()
                .name,
            b"files-first"
        );
        unsafe { (api.end)() };

        configure_host_enumeration(false, c"fltest");
        unsafe {
            let handle = libc::dlopen(c"libnss_fltest.so.2".as_ptr(), libc::RTLD_NOW);
            assert!(!handle.is_null());
            let address = libc::dlsym(handle, c"_nss_fltest_set_host_enum_reentry".as_ptr());
            assert!(!address.is_null());
            let install: unsafe extern "C" fn(Option<unsafe extern "C" fn() -> c_int>) =
                std::mem::transmute(address);
            install(Some(host_enumeration_reentry));
            (api.set)(0);
            assert_eq!(
                host_enumeration_read(&api, None, 0).answer.unwrap().name,
                b"fltest-host-small"
            );
            assert_eq!(
                host_enumeration_read(&api, None, 0).answer.unwrap().name,
                b"fltest-host-large"
            );
            assert!(host_enumeration_read(&api, None, 0).answer.is_none());
            assert_eq!(
                HOST_ENUM_REENTRY_CALLS.load(std::sync::atomic::Ordering::Relaxed),
                1
            );
            (api.end)();
            install(None);
            libc::dlclose(handle);
            libc::alarm(0);
        }
        return;
    }
    let dir = host_enumeration_scratch("files-reentry");
    build_modules(&dir);
    std::fs::write(
        dir.join("hosts"),
        "198.51.100.7 files-first first-alias\n198.51.100.8 files-second second-alias\n",
    )
    .unwrap();
    for mode in ["strict", "hardened"] {
        let mut child = host_module_child(TEST, &dir, "hosts: files\n", mode);
        child
            .env("FRANKENLIBC_MODE", mode)
            .env_remove("FLTEST_HOST_ENUM");
        run_child(
            child,
            &format!("host enumeration files and callback isolation {mode}"),
        );
    }
}

#[repr(C)]
struct NetworkRawRecord {
    name: *mut c_char,
    aliases: *mut *mut c_char,
    family: c_int,
    number: u32,
}

#[derive(Debug, PartialEq, Eq)]
struct NetworkRecord {
    name: Vec<u8>,
    family: c_int,
    number: u32,
    aliases: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug)]
enum NetworkRequest<'a> {
    Name(&'a CStr),
    Address(u32, c_int),
}

struct NetworkApi {
    name: unsafe extern "C" fn(*const c_char) -> *mut c_void,
    address: unsafe extern "C" fn(u32, c_int) -> *mut c_void,
    name_r: unsafe extern "C" fn(
        *const c_char,
        *mut c_void,
        *mut c_char,
        usize,
        *mut *mut c_void,
        *mut c_int,
    ) -> c_int,
    address_r: unsafe extern "C" fn(
        u32,
        c_int,
        *mut c_void,
        *mut c_char,
        usize,
        *mut *mut c_void,
        *mut c_int,
    ) -> c_int,
    error: unsafe extern "C" fn() -> *mut c_int,
    resolver_error: unsafe extern "C" fn() -> *mut c_int,
}

fn network_api(host: bool) -> NetworkApi {
    unsafe extern "C" {
        #[link_name = "getnetbyname"]
        fn host_name(name: *const c_char) -> *mut c_void;
        #[link_name = "getnetbyaddr"]
        fn host_address(number: u32, family: c_int) -> *mut c_void;
        #[link_name = "getnetbyname_r"]
        fn host_name_r(
            name: *const c_char,
            output: *mut c_void,
            buffer: *mut c_char,
            capacity: usize,
            result: *mut *mut c_void,
            resolver_error: *mut c_int,
        ) -> c_int;
        #[link_name = "getnetbyaddr_r"]
        fn host_address_r(
            number: u32,
            family: c_int,
            output: *mut c_void,
            buffer: *mut c_char,
            capacity: usize,
            result: *mut *mut c_void,
            resolver_error: *mut c_int,
        ) -> c_int;
        #[link_name = "__h_errno_location"]
        fn host_resolver_error() -> *mut c_int;
    }
    use frankenlibc_abi::{errno_abi as e, resolv_abi as r, unistd_abi as u};
    assert_ne!(host_name as *const (), u::getnetbyname as *const ());
    assert_ne!(host_address_r as *const (), u::getnetbyaddr_r as *const ());
    if host {
        NetworkApi {
            name: host_name,
            address: host_address,
            name_r: host_name_r,
            address_r: host_address_r,
            error: libc::__errno_location,
            resolver_error: host_resolver_error,
        }
    } else {
        NetworkApi {
            name: u::getnetbyname,
            address: u::getnetbyaddr,
            name_r: u::getnetbyname_r,
            address_r: u::getnetbyaddr_r,
            error: e::__errno_location,
            resolver_error: r::__h_errno_location,
        }
    }
}

unsafe fn network_record(
    pointer: *mut c_void,
    bounds: Option<(usize, usize)>,
) -> Option<NetworkRecord> {
    if pointer.is_null() {
        return None;
    }
    // SAFETY: successful network calls publish the complete C netent layout.
    let entry = unsafe { &*pointer.cast::<NetworkRawRecord>() };
    let string = |pointer: *const c_char| {
        assert!(!pointer.is_null());
        if let Some((start, end)) = bounds {
            let address = pointer as usize;
            assert!(
                (start..end).contains(&address),
                "network string escaped caller buffer"
            );
            // SAFETY: the complete remaining range is inside the caller buffer.
            let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), end - address) };
            let length = bytes
                .iter()
                .position(|&byte| byte == 0)
                .expect("terminated network string");
            bytes[..length].to_vec()
        } else {
            // SAFETY: non-reentrant answers own terminated strings.
            unsafe { CStr::from_ptr(pointer) }.to_bytes().to_vec()
        }
    };
    assert!(!entry.aliases.is_null());
    let mut aliases = Vec::new();
    for index in 0..4096 {
        let address = (entry.aliases as usize)
            .checked_add(index * std::mem::size_of::<usize>())
            .unwrap();
        assert_eq!(address % std::mem::align_of::<usize>(), 0);
        if let Some((start, end)) = bounds {
            assert!(address >= start && address <= end);
            assert!(std::mem::size_of::<usize>() <= end - address);
        }
        // SAFETY: caller-backed slots were bounded above; owned output follows
        // the API's NULL-terminated alias-array contract.
        let alias = unsafe { *(address as *const *const c_char) };
        if alias.is_null() {
            return Some(NetworkRecord {
                name: string(entry.name),
                family: entry.family,
                number: entry.number,
                aliases,
            });
        }
        aliases.push(string(alias));
    }
    panic!("network alias array was not terminated");
}

#[derive(Debug, PartialEq, Eq)]
struct NetworkOutcome {
    status: c_int,
    error: c_int,
    resolver_error: c_int,
    global_resolver_error: c_int,
    answer: Option<NetworkRecord>,
}

fn network_call(
    api: &NetworkApi,
    request: NetworkRequest<'_>,
    capacity: Option<usize>,
    offset: usize,
) -> NetworkOutcome {
    if let Some(capacity) = capacity {
        let mut storage = RpcCallerBuffer([0x5a; 8192 + 16]);
        assert!(offset + capacity <= storage.0.len());
        let mut output: NetworkRawRecord = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::dangling_mut();
        let mut resolver_error = 717;
        let buffer = unsafe { storage.0.as_mut_ptr().add(offset).cast::<c_char>() };
        unsafe {
            *(api.error)() = 619;
            *(api.resolver_error)() = 811;
        }
        // SAFETY: all outputs are complete, writable objects; the exact caller
        // budget may be short or start at an unaligned byte address.
        let status = unsafe {
            match request {
                NetworkRequest::Name(name) => (api.name_r)(
                    name.as_ptr(),
                    (&raw mut output).cast(),
                    buffer,
                    capacity,
                    &mut result,
                    &mut resolver_error,
                ),
                NetworkRequest::Address(number, family) => (api.address_r)(
                    number,
                    family,
                    (&raw mut output).cast(),
                    buffer,
                    capacity,
                    &mut result,
                    &mut resolver_error,
                ),
            }
        };
        let error = unsafe { *(api.error)() };
        let global_resolver_error = unsafe { *(api.resolver_error)() };
        assert!(
            storage.0[..offset]
                .iter()
                .chain(&storage.0[offset + capacity..])
                .all(|&byte| byte == 0x5a),
            "network wrote outside the caller's buffer"
        );
        if !result.is_null() {
            assert_eq!(result, (&raw mut output).cast());
            assert_eq!(status, 0);
        }
        let answer =
            unsafe { network_record(result, Some((buffer as usize, buffer as usize + capacity))) };
        NetworkOutcome {
            status,
            error,
            resolver_error,
            global_resolver_error,
            answer,
        }
    } else {
        unsafe {
            *(api.error)() = 619;
            *(api.resolver_error)() = 811;
        }
        // SAFETY: names are live C strings and address keys contain scalars.
        let result = unsafe {
            match request {
                NetworkRequest::Name(name) => (api.name)(name.as_ptr()),
                NetworkRequest::Address(number, family) => (api.address)(number, family),
            }
        };
        let error = unsafe { *(api.error)() };
        let resolver_error = unsafe { *(api.resolver_error)() };
        NetworkOutcome {
            status: 0,
            error,
            resolver_error,
            global_resolver_error: resolver_error,
            answer: unsafe { network_record(result, None) },
        }
    }
}

fn configure_networks(host: bool, sources: &CStr) {
    unsafe extern "C" {
        fn __nss_configure_lookup(database: *const c_char, sources: *const c_char) -> c_int;
    }
    let configure = if host {
        __nss_configure_lookup
    } else {
        frankenlibc_abi::glibc_internal_abi::__nss_configure_lookup
    };
    assert_eq!(
        unsafe { configure(c"networks".as_ptr(), sources.as_ptr()) },
        0
    );
}

#[test]
fn networks_lookups_match_glibc_module_policy() {
    const TEST: &str = "networks_lookups_match_glibc_module_policy";
    if std::env::var_os(CHILD_ENV).is_some() {
        let host = std::env::var("FLTEST_NETWORK_PROVIDER").unwrap() == "host";
        let sources = std::env::var("FLTEST_NETWORK_SOURCES").unwrap();
        configure_networks(host, &CString::new(sources.as_str()).unwrap());
        unsafe { libc::alarm(20) };
        let api = network_api(host);
        let mut transcript = String::new();
        let queries = [
            NetworkRequest::Name(c"loopback"),
            NetworkRequest::Name(c"LOOPBACK"),
            NetworkRequest::Name(c"fltest-network"),
            NetworkRequest::Name(c"fltest-net"),
            NetworkRequest::Name(c"shared-network"),
            NetworkRequest::Name(c"fltest-large-network"),
            NetworkRequest::Name(c"missing-network"),
            NetworkRequest::Name(c"fltest-again"),
            NetworkRequest::Name(c"fltest-internal-again"),
            NetworkRequest::Name(c"fltest-range-not-internal"),
            NetworkRequest::Name(c"fltest-unavail"),
            NetworkRequest::Name(c"fltest-unavail-range"),
            NetworkRequest::Name(c"fltest-unavail-range-internal"),
            NetworkRequest::Name(c"fltest-errno-none"),
            NetworkRequest::Name(c"fltest-errno-again"),
            NetworkRequest::Name(c"fltest-errno-unavail"),
            NetworkRequest::Name(c"fltest-errno-success"),
            NetworkRequest::Name(c"fltest-errno-written"),
            NetworkRequest::Name(c"fltest-chain-success"),
            NetworkRequest::Name(c"fltest-chain-notfound"),
            NetworkRequest::Address(127, libc::AF_INET),
            NetworkRequest::Address(0xdead_beef, libc::AF_INET),
            NetworkRequest::Address(0xdead_beef, libc::AF_UNSPEC),
            NetworkRequest::Address(0xfedc_ba98, libc::AF_INET),
            NetworkRequest::Address(0xdead_beef, libc::AF_INET6),
            NetworkRequest::Address(u32::MAX, libc::AF_INET),
        ];
        for query in queries {
            let mut budgets = vec![(Some(8192), 1), (None, 0)];
            // Native file parsers can need space for preceding unrelated
            // lines. Compare tiny exact budgets where the module answers.
            if sources == "fltest" {
                budgets.splice(0..0, [(Some(0), 0), (Some(7), 1), (Some(96), 3)]);
            }
            for (capacity, offset) in budgets {
                writeln!(
                    transcript,
                    "{query:?} {capacity:?}/{offset} {:?}",
                    network_call(&api, query, capacity, offset)
                )
                .unwrap();
            }
        }
        if sources == "fltest" {
            let pointer_size = std::mem::size_of::<*mut c_char>();
            let packed_size = 3 * pointer_size
                + b"fltest-network\0".len()
                + b"fltest-net\0".len()
                + b"shared-network\0".len();
            for offset in 0..pointer_size {
                let needed = packed_size + (pointer_size - offset) % pointer_size;
                let short = network_call(
                    &api,
                    NetworkRequest::Name(c"fltest-network"),
                    Some(needed - 1),
                    offset,
                );
                assert_eq!(
                    (short.status, short.error, short.resolver_error),
                    (libc::ERANGE, libc::ERANGE, -1)
                );
                assert!(short.answer.is_none());
                let exact = network_call(
                    &api,
                    NetworkRequest::Name(c"fltest-network"),
                    Some(needed),
                    offset,
                );
                assert_eq!(
                    (exact.status, exact.error, exact.resolver_error),
                    (0, 0, 717)
                );
                assert_eq!(exact.answer.as_ref().unwrap().number, 0xdead_beef);
                writeln!(transcript, "exact {needed}/{offset} {short:?} {exact:?}").unwrap();
            }
            let large = network_call(&api, NetworkRequest::Name(c"fltest-large-network"), None, 0);
            assert_eq!(large.answer.as_ref().unwrap().aliases[2], vec![b'n'; 3072]);
        }
        println!("NETWORK_LOOKUP_BEGIN\n{transcript}NETWORK_LOOKUP_END");
        unsafe { libc::alarm(0) };
        return;
    }

    let dir = host_enumeration_scratch("network-lookups");
    build_modules(&dir);
    let cases = [
        "fltest",
        "files",
        "fltest files",
        "files fltest",
        "fltest [SUCCESS=continue] files",
        "fltest [SUCCESS=continue] fltestnoig",
        "fltest [SUCCESS=continue] flmissing",
        "fltest fltestnoig",
        "fltest [SUCCESS=merge] files",
        "fltest [NOTFOUND=return] files",
        "fltest [TRYAGAIN=return] files",
        "fltest [TRYAGAIN=continue] files",
        "fltest [UNAVAIL=return] files",
        "flmissing files",
        "flmissing [UNAVAIL=return] files",
        "fltest [TRYAGAIN=continue] flmissing",
        "fltest [NOTFOUND=continue] flmissing",
        "flmissing",
        "compat files",
    ];
    let mut compared = 0;
    for (index, sources) in cases.into_iter().enumerate() {
        let mut oracle = None;
        for (provider, mode) in [("host", "strict"), ("fl", "strict"), ("fl", "hardened")] {
            let label = format!("network-lookup-{index}-{provider}-{mode}");
            let mut child =
                host_module_child(TEST, &dir, &format!("networks: {sources}\n"), &label);
            child
                .env("FLTEST_NETWORK_PROVIDER", provider)
                .env("FLTEST_NETWORK_SOURCES", sources)
                .env("FRANKENLIBC_MODE", mode)
                .env_remove("FRANKENLIBC_NETWORKS_PATH")
                .env_remove("LD_PRELOAD")
                .env_remove("LD_AUDIT");
            let output = run_child(child, &label);
            let stdout = std::str::from_utf8(&output.stdout).unwrap();
            let transcript = stdout
                .split_once("NETWORK_LOOKUP_BEGIN\n")
                .and_then(|(_, rest)| rest.split_once("NETWORK_LOOKUP_END"))
                .map(|(text, _)| text)
                .expect("executed network lookup transcript")
                .to_owned();
            assert!(transcript.lines().count() >= 48);
            if sources == "fltest" {
                assert!(
                    transcript.contains("number: 3735928559")
                        && transcript.contains("number: 4275878552"),
                    "modules must preserve complete unsigned network numbers"
                );
            }
            if let Some(expected) = &oracle {
                assert_eq!(&transcript, expected, "{label}: sources={sources}");
                compared += 1;
            } else {
                oracle = Some(transcript);
            }
        }
    }
    assert_eq!(compared, 38);
    eprintln!("Network lookups: {compared} independent GNU/candidate process comparisons");
}

static NETWORK_REENTRY_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

unsafe extern "C" fn network_lookup_reentry() -> c_int {
    use frankenlibc_abi::unistd_abi as u;
    NETWORK_REENTRY_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // SAFETY: this independent name lookup runs inside another name callback.
    // The outer lookup must have released its mutable TLS storage borrow.
    unsafe {
        let result = u::getnetbyname(c"fltest-network".as_ptr()).cast::<NetworkRawRecord>();
        if result.is_null() || (*result).number != 0xdead_beef {
            return 1;
        }
    }
    0
}

#[test]
fn networks_runtime_policy_files_and_callback_isolation() {
    const TEST: &str = "networks_runtime_policy_files_and_callback_isolation";
    if std::env::var_os(CHILD_ENV).is_some() {
        use frankenlibc_abi::unistd_abi as u;
        unsafe { libc::alarm(20) };
        let api = network_api(false);
        let files = NetworkRequest::Name(c"native-alias");
        let initial = network_call(&api, files, Some(8192), 1);
        assert_eq!(initial.answer.as_ref().unwrap().number, 0xabcd_ef01);
        configure_networks(false, c"fltest");
        assert!(network_call(&api, files, Some(8192), 1).answer.is_none());
        assert_eq!(
            network_call(&api, NetworkRequest::Name(c"fltest-net"), None, 0)
                .answer
                .as_ref()
                .unwrap()
                .number,
            0xdead_beef
        );

        unsafe {
            let previous =
                u::getnetbyname(c"fltest-growing-key".as_ptr()).cast::<NetworkRawRecord>();
            assert!(!previous.is_null());
            // The key lives inside reusable output that must grow during the
            // next lookup; it must be retained before any possible relocation.
            let grown = u::getnetbyname((*previous).name);
            assert_eq!(
                network_record(grown, None).unwrap().aliases[2],
                vec![b'n'; 3072]
            );
            let by_name = u::getnetbyname(c"fltest-network".as_ptr());
            let before = network_record(by_name, None).unwrap();
            let by_address = u::getnetbyaddr(0xfedc_ba98, libc::AF_INET);
            assert_eq!(
                network_record(by_address, None).unwrap().number,
                0xfedc_ba98
            );
            assert_eq!(network_record(by_name, None).unwrap(), before);
        }

        let mut output: NetworkRawRecord = unsafe { std::mem::zeroed() };
        let mut storage = RpcCallerBuffer([0x5a; 8192 + 16]);
        let buffer = unsafe { storage.0.as_mut_ptr().add(1).cast::<c_char>() };
        let mut error = 717;
        let mut resolver_error = 811;
        // Direct files providers must never inherit public module overrides.
        unsafe {
            *(api.error)() = 619;
            assert_eq!(
                u::_nss_files_getnetbyname_r(
                    c"native-alias".as_ptr(),
                    (&raw mut output).cast(),
                    buffer,
                    8192,
                    &mut error,
                    &mut resolver_error,
                ),
                1
            );
            assert_eq!((*(api.error)(), error, resolver_error), (619, 717, 811));
            assert_eq!(output.number, 0xabcd_ef01);
            let record = network_record(
                (&raw mut output).cast(),
                Some((buffer as usize, buffer as usize + 8192)),
            )
            .unwrap();
            assert_eq!(record.name, b"native-network");
            assert_eq!(record.aliases, [b"native-alias".to_vec()]);
            assert_eq!(
                u::_nss_files_getnetbyaddr_r(
                    0xabcd_ef01,
                    libc::AF_INET,
                    (&raw mut output).cast(),
                    buffer,
                    8192,
                    &mut error,
                    &mut resolver_error,
                ),
                1
            );
            assert_eq!(output.number, 0xabcd_ef01);
            assert_eq!(
                u::_nss_files_getnetbyname_r(
                    c"fltest-net".as_ptr(),
                    (&raw mut output).cast(),
                    buffer,
                    8192,
                    &mut error,
                    &mut resolver_error,
                ),
                0
            );
            assert_eq!((error, resolver_error), (717, 1));

            u::setnetent(0);
            let published = u::getnetent();
            let before = network_record(published, None).unwrap();
            assert_eq!(before.number, 0xabcd_ef01);
            let keyed = network_call(&api, NetworkRequest::Name(c"fltest-large-network"), None, 0);
            assert_eq!(keyed.answer.as_ref().unwrap().number, 0xfedc_ba98);
            assert_eq!(network_record(published, None).unwrap(), before);
            u::endnetent();
        }

        configure_networks(false, c"files");
        assert_eq!(
            network_call(&api, files, None, 0)
                .answer
                .as_ref()
                .unwrap()
                .number,
            0xabcd_ef01
        );
        configure_rpc(false, c"flmissing");
        assert_eq!(
            network_call(&api, files, None, 0)
                .answer
                .as_ref()
                .unwrap()
                .number,
            0xabcd_ef01
        );
        configure_networks(false, c"fltest");
        unsafe {
            let handle = libc::dlopen(c"libnss_fltest.so.2".as_ptr(), libc::RTLD_NOW);
            assert!(!handle.is_null());
            let symbol = libc::dlsym(handle, c"_nss_fltest_set_network_reentry".as_ptr());
            assert!(!symbol.is_null());
            let install: unsafe extern "C" fn(Option<unsafe extern "C" fn() -> c_int>) =
                std::mem::transmute(symbol);
            install(Some(network_lookup_reentry));
            let nested = network_call(&api, NetworkRequest::Name(c"fltest-reentry"), None, 0);
            assert_eq!(nested.answer.as_ref().unwrap().number, 0xdead_beef);
            assert_eq!(
                NETWORK_REENTRY_CALLS.load(std::sync::atomic::Ordering::Relaxed),
                1
            );
            install(None);
            assert_eq!(libc::dlclose(handle), 0);
        }

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let workers = (0..4)
            .map(|index| {
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let number = if index % 2 == 0 {
                        0xdead_beef
                    } else {
                        0xfedc_ba98
                    };
                    // SAFETY: each thread's non-reentrant answer must remain its
                    // own while all other threads simultaneously retain answers.
                    let result = unsafe { u::getnetbyaddr(number, libc::AF_INET) };
                    assert!(!result.is_null());
                    barrier.wait();
                    let record = unsafe { network_record(result, None) }.unwrap();
                    assert_eq!(record.number, number);
                    if index % 2 != 0 {
                        assert_eq!(record.aliases[2], vec![b'n'; 3072]);
                    }
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }
        unsafe { libc::alarm(0) };
        return;
    }
    let dir = host_enumeration_scratch("network-isolation");
    build_modules(&dir);
    let path = dir.join("networks");
    std::fs::write(
        &path,
        "native-network 171.205.239.1 native-alias\nsecond-network 10\n",
    )
    .unwrap();
    for mode in ["strict", "hardened"] {
        let mut child = host_module_child(TEST, &dir, "networks: files\n", mode);
        child
            .env("FRANKENLIBC_NETWORKS_PATH", &path)
            .env("FRANKENLIBC_MODE", mode)
            .env_remove("LD_PRELOAD")
            .env_remove("LD_AUDIT");
        run_child(
            child,
            &format!("networks files, overrides and callback isolation {mode}"),
        );
    }
}

// RPC has the same scalar field widths as protocols, but a separate public ABI
// and different errno rules. Keep its provider pointers and result layout
// explicit so a host/candidate comparison cannot call the same implementation.
#[repr(C)]
struct RpcRawRecord {
    name: *mut c_char,
    aliases: *mut *mut c_char,
    number: c_int,
}

#[derive(Debug, PartialEq, Eq)]
struct RpcRecord {
    name: Vec<u8>,
    number: c_int,
    aliases: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug)]
enum RpcRequest<'a> {
    Name(&'a CStr),
    Number(c_int),
    Next,
}

struct RpcApi {
    name: unsafe extern "C" fn(*const c_char) -> *mut c_void,
    number: unsafe extern "C" fn(c_int) -> *mut c_void,
    name_r: unsafe extern "C" fn(
        *const c_char,
        *mut c_void,
        *mut c_char,
        usize,
        *mut *mut c_void,
    ) -> c_int,
    number_r:
        unsafe extern "C" fn(c_int, *mut c_void, *mut c_char, usize, *mut *mut c_void) -> c_int,
    set: unsafe extern "C" fn(c_int),
    get: unsafe extern "C" fn() -> *mut c_void,
    get_r: unsafe extern "C" fn(*mut c_void, *mut c_char, usize, *mut *mut c_void) -> c_int,
    end: unsafe extern "C" fn(),
    error: unsafe extern "C" fn() -> *mut c_int,
}

fn rpc_api(host: bool) -> RpcApi {
    unsafe extern "C" {
        #[link_name = "getrpcbyname"]
        fn host_name(name: *const c_char) -> *mut c_void;
        #[link_name = "getrpcbynumber"]
        fn host_number(number: c_int) -> *mut c_void;
        #[link_name = "getrpcbyname_r"]
        fn host_name_r(
            name: *const c_char,
            output: *mut c_void,
            buffer: *mut c_char,
            capacity: usize,
            result: *mut *mut c_void,
        ) -> c_int;
        #[link_name = "getrpcbynumber_r"]
        fn host_number_r(
            number: c_int,
            output: *mut c_void,
            buffer: *mut c_char,
            capacity: usize,
            result: *mut *mut c_void,
        ) -> c_int;
        #[link_name = "setrpcent"]
        fn host_set(stayopen: c_int);
        #[link_name = "getrpcent"]
        fn host_get() -> *mut c_void;
        #[link_name = "getrpcent_r"]
        fn host_get_r(
            output: *mut c_void,
            buffer: *mut c_char,
            capacity: usize,
            result: *mut *mut c_void,
        ) -> c_int;
        #[link_name = "endrpcent"]
        fn host_end();
    }
    use frankenlibc_abi::{errno_abi as e, unistd_abi as u};
    assert_ne!(host_name as *const (), u::getrpcbyname as *const ());
    assert_ne!(host_number_r as *const (), u::getrpcbynumber_r as *const ());
    assert_ne!(host_get_r as *const (), u::getrpcent_r as *const ());
    if host {
        RpcApi {
            name: host_name,
            number: host_number,
            name_r: host_name_r,
            number_r: host_number_r,
            set: host_set,
            get: host_get,
            get_r: host_get_r,
            end: host_end,
            error: libc::__errno_location,
        }
    } else {
        RpcApi {
            name: u::getrpcbyname,
            number: u::getrpcbynumber,
            name_r: u::getrpcbyname_r,
            number_r: u::getrpcbynumber_r,
            set: u::setrpcent,
            get: u::getrpcent,
            get_r: u::getrpcent_r,
            end: u::endrpcent,
            error: e::__errno_location,
        }
    }
}

unsafe fn rpc_record(pointer: *mut c_void, bounds: Option<(usize, usize)>) -> Option<RpcRecord> {
    if pointer.is_null() {
        return None;
    }
    // SAFETY: successful calls publish the complete C rpcent layout.
    let entry = unsafe { &*pointer.cast::<RpcRawRecord>() };
    let string = |pointer: *const c_char| {
        assert!(!pointer.is_null());
        if let Some((start, end)) = bounds {
            let address = pointer as usize;
            assert!((start..end).contains(&address), "RPC string escaped caller buffer");
            // SAFETY: the complete remaining range is inside the caller buffer.
            let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), end - address) };
            let length = bytes.iter().position(|&byte| byte == 0).expect("terminated RPC string");
            bytes[..length].to_vec()
        } else {
            // SAFETY: non-reentrant answers own terminated strings.
            unsafe { CStr::from_ptr(pointer) }.to_bytes().to_vec()
        }
    };
    assert!(!entry.aliases.is_null());
    let mut aliases = Vec::new();
    for index in 0..4096 {
        let address = (entry.aliases as usize)
            .checked_add(index * std::mem::size_of::<usize>())
            .unwrap();
        assert_eq!(address % std::mem::align_of::<usize>(), 0);
        if let Some((start, end)) = bounds {
            assert!(address >= start && address <= end);
            assert!(std::mem::size_of::<usize>() <= end - address);
        }
        // SAFETY: caller-backed slots were bounded above; owned output follows
        // the API's NULL-terminated alias-array contract.
        let alias = unsafe { *(address as *const *const c_char) };
        if alias.is_null() {
            return Some(RpcRecord {
                name: string(entry.name),
                number: entry.number,
                aliases,
            });
        }
        aliases.push(string(alias));
    }
    panic!("RPC alias array was not terminated");
}

#[repr(align(16))]
struct RpcCallerBuffer([u8; 8192 + 16]);

fn rpc_call(
    api: &RpcApi,
    request: RpcRequest<'_>,
    capacity: Option<usize>,
    offset: usize,
) -> (c_int, c_int, Option<RpcRecord>) {
    if let Some(capacity) = capacity {
        let mut storage = RpcCallerBuffer([0x5a; 8192 + 16]);
        assert!(offset + capacity <= storage.0.len());
        let mut output: RpcRawRecord = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::dangling_mut();
        let buffer = unsafe { storage.0.as_mut_ptr().add(offset).cast::<c_char>() };
        unsafe { *(api.error)() = 619 };
        // SAFETY: every public API receives complete output objects and an
        // exact, possibly short or unaligned, caller-owned buffer range.
        let status = unsafe {
            match request {
                RpcRequest::Name(name) => (api.name_r)(
                    name.as_ptr(), (&raw mut output).cast(), buffer, capacity, &mut result,
                ),
                RpcRequest::Number(number) => (api.number_r)(
                    number, (&raw mut output).cast(), buffer, capacity, &mut result,
                ),
                RpcRequest::Next => {
                    (api.get_r)((&raw mut output).cast(), buffer, capacity, &mut result)
                }
            }
        };
        let error = unsafe { *(api.error)() };
        assert!(
            storage.0[..offset]
                .iter()
                .chain(&storage.0[offset + capacity..])
                .all(|&byte| byte == 0x5a),
            "RPC wrote outside the caller's exact buffer"
        );
        if !result.is_null() {
            assert_eq!(result, (&raw mut output).cast());
            assert_eq!(status, 0);
        }
        let answer = unsafe {
            rpc_record(result, Some((buffer as usize, buffer as usize + capacity)))
        };
        (status, error, answer)
    } else {
        unsafe { *(api.error)() = 619 };
        let result = unsafe {
            match request {
                RpcRequest::Name(name) => (api.name)(name.as_ptr()),
                RpcRequest::Number(number) => (api.number)(number),
                RpcRequest::Next => (api.get)(),
            }
        };
        let error = unsafe { *(api.error)() };
        (0, error, unsafe { rpc_record(result, None) })
    }
}

fn configure_rpc(host: bool, sources: &CStr) {
    unsafe extern "C" {
        fn __nss_configure_lookup(database: *const c_char, sources: *const c_char) -> c_int;
    }
    let configure = if host {
        __nss_configure_lookup
    } else {
        frankenlibc_abi::glibc_internal_abi::__nss_configure_lookup
    };
    assert_eq!(unsafe { configure(c"rpc".as_ptr(), sources.as_ptr()) }, 0);
}

fn rpc_module_child(test: &str, dir: &Path, sources: &str, tag: &str) -> Command {
    let mut child = host_module_child(test, dir, &format!("rpc: {sources}\n"), tag);
    child
        .env("FLTEST_RPC_SOURCES", sources)
        .env_remove("LD_PRELOAD")
        .env_remove("LD_AUDIT")
        .env_remove("FLTEST_RPC_ENUM")
        .env_remove("FLTEST_RPC_ISOLATION_PATH");
    child
}

#[test]
fn rpc_lookups_match_glibc_module_policy() {
    const TEST: &str = "rpc_lookups_match_glibc_module_policy";
    if std::env::var_os(CHILD_ENV).is_some() {
        let host = std::env::var("FLTEST_RPC_PROVIDER").unwrap() == "host";
        let sources = std::env::var("FLTEST_RPC_SOURCES").unwrap();
        configure_rpc(host, &CString::new(sources.as_str()).unwrap());
        unsafe { libc::alarm(20) };
        let api = rpc_api(host);
        let mut transcript = String::new();
        let queries = [
            RpcRequest::Name(c"portmapper"),
            RpcRequest::Name(c"PORTMAPPER"),
            RpcRequest::Name(c"fltest-rpc-record"),
            RpcRequest::Name(c"fltest-rpc"),
            RpcRequest::Name(c"shared-rpc"),
            RpcRequest::Name(c"fltest-large-rpc"),
            RpcRequest::Name(c"fltest-negative"),
            RpcRequest::Name(c"fltest-wide"),
            RpcRequest::Name(c"missing-rpc"),
            RpcRequest::Name(c"fltest-again"),
            RpcRequest::Name(c"fltest-unavail"),
            RpcRequest::Name(c"fltest-errno-none"),
            RpcRequest::Name(c"fltest-errno-again"),
            RpcRequest::Name(c"fltest-errno-unavail"),
            RpcRequest::Name(c"fltest-errno-success"),
            RpcRequest::Name(c"fltest-errno-written"),
            RpcRequest::Name(c"fltest-chain-success"),
            RpcRequest::Name(c"fltest-chain-notfound"),
            RpcRequest::Number(100000),
            RpcRequest::Number(145001),
            RpcRequest::Number(145002),
            RpcRequest::Number(-7),
            RpcRequest::Number(c_int::MAX),
            RpcRequest::Number(987654),
        ];
        for query in queries {
            // A files scan may need space for earlier unrelated lines. Compare
            // exact tiny budgets only when the configured module must answer.
            let module_answer = match query {
                RpcRequest::Name(name) => [
                    c"portmapper",
                    c"fltest-rpc-record",
                    c"fltest-rpc",
                    c"shared-rpc",
                    c"fltest-large-rpc",
                    c"fltest-negative",
                    c"fltest-wide",
                    c"fltest-errno-success",
                    c"fltest-errno-written",
                ]
                .contains(&name),
                RpcRequest::Number(number) => {
                    matches!(number, 100000 | 145001 | 145002 | -7 | c_int::MAX)
                }
                RpcRequest::Next => false,
            };
            let mut budgets = Vec::new();
            if sources == "fltest" || (sources.starts_with("fltest ") && module_answer) {
                budgets.extend([(Some(0), 0), (Some(7), 1)]);
            }
            if sources == "fltest" {
                budgets.push((Some(96), 3));
            }
            budgets.extend([(Some(8192), 1), (None, 0)]);
            for (capacity, offset) in budgets {
                writeln!(
                    transcript,
                    "{query:?} {capacity:?}/{offset} {:?}",
                    rpc_call(&api, query, capacity, offset)
                )
                .unwrap();
            }
        }
        if sources == "fltest" {
            // Probe the actual one-byte success boundary at every pointer
            // alignment, including all strings and the terminating alias slot.
            let pointer_size = std::mem::size_of::<*mut c_char>();
            let packed_size = 3 * pointer_size + b"fltest-rpc-record\0".len()
                + b"fltest-rpc\0".len() + b"shared-rpc\0".len();
            for offset in 0..pointer_size {
                let needed = packed_size + (pointer_size - offset) % pointer_size;
                let short = rpc_call(
                    &api, RpcRequest::Name(c"fltest-rpc-record"), Some(needed - 1), offset,
                );
                assert_eq!(short, (libc::ERANGE, libc::ERANGE, None));
                let exact = rpc_call(
                    &api, RpcRequest::Name(c"fltest-rpc-record"), Some(needed), offset,
                );
                assert_eq!((exact.0, exact.1), (0, 0));
                assert_eq!(exact.2.as_ref().unwrap().number, 145001);
                writeln!(transcript, "exact {needed}/{offset} {short:?} {exact:?}").unwrap();
            }
            let large = rpc_call(&api, RpcRequest::Name(c"fltest-large-rpc"), None, 0);
            assert_eq!(large.2.as_ref().unwrap().aliases[2], vec![b'r'; 3072]);
        }
        println!("RPC_LOOKUP_BEGIN\n{transcript}RPC_LOOKUP_END");
        unsafe { libc::alarm(0) };
        return;
    }

    let dir = host_enumeration_scratch("rpc-lookups");
    build_modules(&dir);
    let cases = [
        "fltest",
        "files",
        "fltest files",
        "files fltest",
        "fltest [SUCCESS=continue] files",
        "fltest [SUCCESS=continue] fltestnoig",
        "fltest fltestnoig",
        "fltest [SUCCESS=merge] files",
        "fltest [NOTFOUND=return] files",
        "fltest [TRYAGAIN=return] files",
        "fltest [TRYAGAIN=continue] files",
        "fltest [UNAVAIL=return] files",
        "flmissing files",
        "flmissing [UNAVAIL=return] files",
        "compat files",
    ];
    let mut compared = 0;
    for (index, sources) in cases.into_iter().enumerate() {
        let mut oracle = None;
        for (provider, mode) in [("host", "strict"), ("fl", "strict"), ("fl", "hardened")] {
            let label = format!("rpc-lookup-{index}-{provider}-{mode}");
            let mut child = rpc_module_child(TEST, &dir, sources, &label);
            child
                .env("FLTEST_RPC_PROVIDER", provider)
                .env("FRANKENLIBC_MODE", mode);
            let output = run_child(child, &label);
            let stdout = std::str::from_utf8(&output.stdout).unwrap();
            let transcript = stdout
                .split_once("RPC_LOOKUP_BEGIN\n")
                .and_then(|(_, rest)| rest.split_once("RPC_LOOKUP_END"))
                .map(|(text, _)| text)
                .expect("executed RPC lookup transcript")
                .to_owned();
            assert!(transcript.lines().count() >= 48);
            if sources == "fltest" {
                assert!(
                    transcript.contains("number: 145001")
                        && transcript.contains("number: 145002")
                        && transcript.contains("number: -7")
                        && transcript.contains("number: 2147483647"),
                    "module answers must preserve aliases and full signed program numbers"
                );
            }
            if let Some(expected) = &oracle {
                assert_eq!(&transcript, expected, "{label}: sources={sources}");
                compared += 1;
            } else {
                oracle = Some(transcript);
            }
        }
    }
    assert_eq!(compared, 30);
    eprintln!("RPC lookups: {compared} independent GNU/candidate process comparisons");
}

fn rpc_enumeration_transcript(api: &RpcApi) -> String {
    let mut transcript = String::new();
    unsafe { (api.end)() };
    for capacity in [0, 1, 7] {
        writeln!(
            transcript,
            "implicit {capacity} {:?}",
            rpc_call(api, RpcRequest::Next, Some(capacity), 1)
        )
        .unwrap();
    }
    for index in 0..7 {
        let answer = rpc_call(api, RpcRequest::Next, Some(8192), index % 2);
        let done = answer.2.is_none();
        writeln!(transcript, "implicit record {index} {answer:?}").unwrap();
        if done {
            break;
        }
    }
    unsafe {
        (api.end)();
        *(api.error)() = 619;
        (api.set)(1);
    }
    writeln!(transcript, "set stayopen errno {}", unsafe { *(api.error)() }).unwrap();
    for index in 0..7 {
        let answer = rpc_call(api, RpcRequest::Next, None, 0);
        let done = answer.2.is_none();
        writeln!(transcript, "owned record {index} {answer:?}").unwrap();
        if done {
            break;
        }
    }
    unsafe { (api.set)(0) };
    writeln!(
        transcript,
        "short {:?}",
        rpc_call(api, RpcRequest::Next, Some(1), 0)
    )
    .unwrap();
    writeln!(
        transcript,
        "retry {:?}",
        rpc_call(api, RpcRequest::Next, Some(8192), 1)
    )
    .unwrap();
    unsafe {
        (api.end)();
        (api.set)(0);
    }
    writeln!(
        transcript,
        "early end {:?}",
        rpc_call(api, RpcRequest::Next, Some(8192), 0)
    )
    .unwrap();
    unsafe {
        (api.end)();
        (api.end)();
    }
    writeln!(
        transcript,
        "after end {:?}",
        rpc_call(api, RpcRequest::Next, Some(8192), 1)
    )
    .unwrap();
    unsafe { (api.end)() };
    transcript
}

#[test]
fn rpc_enumeration_matches_glibc_module_policy_and_isolation() {
    const TEST: &str = "rpc_enumeration_matches_glibc_module_policy_and_isolation";
    if std::env::var_os(CHILD_ENV).is_some() {
        unsafe { libc::alarm(20) };
        #[cfg(debug_assertions)]
        if let Some(path) = std::env::var_os("FLTEST_RPC_ISOLATION_PATH") {
            rpc_native_isolation(&PathBuf::from(path));
            unsafe { libc::alarm(0) };
            println!("RPC files, buffer ownership and recursive provider isolation checked");
            return;
        }
        let host = std::env::var("FLTEST_RPC_PROVIDER").unwrap() == "host";
        let sources = CString::new(std::env::var("FLTEST_RPC_SOURCES").unwrap()).unwrap();
        configure_rpc(host, &sources);
        let transcript = rpc_enumeration_transcript(&rpc_api(host));
        println!("RPC_ENUM_BEGIN\n{transcript}RPC_ENUM_END");
        unsafe { libc::alarm(0) };
        return;
    }

    let dir = host_enumeration_scratch("rpc-enumeration");
    build_modules(&dir);
    let module = Command::new("cc")
        .args([
            "-O2",
            "-fPIC",
            "-shared",
            "-DSERVICE=fltestgetonly",
            "-DNO_RPC_SET",
            "-DNO_RPC_END",
        ])
        .arg(repo_root().join("tests/integration/fixture_nss_module_lib.c"))
        .arg("-o")
        .arg(dir.join("libnss_fltestgetonly.so.2"))
        .output()
        .expect("build get-only RPC enumeration provider");
    assert!(
        module.status.success(),
        "{}",
        String::from_utf8_lossy(&module.stderr)
    );
    let cases = [
        ("fltest", "normal"),
        ("fltest fltestnoig", "normal"),
        ("fltest [SUCCESS=continue] fltestnoig", "normal"),
        ("fltest [SUCCESS=merge] fltestnoig", "normal"),
        ("fltest [TRYAGAIN=continue] fltestnoig", "normal"),
        ("fltest [NOTFOUND=return] fltestnoig", "normal"),
        (
            "fltest [SUCCESS=return NOTFOUND=return UNAVAIL=return TRYAGAIN=return] fltestnoig",
            "normal",
        ),
        ("fltest [UNAVAIL=return] fltestnoig", "get-unavail"),
        ("fltest [UNAVAIL=continue] fltestnoig", "get-unavail"),
        ("fltest [TRYAGAIN=return] fltestnoig", "get-again"),
        ("fltest [TRYAGAIN=continue] fltestnoig", "get-again"),
        ("fltest [TRYAGAIN=return] fltestnoig", "get-quiet-again"),
        ("fltest fltestnoig", "get-notfound"),
        ("fltest [NOTFOUND=return] fltestnoig", "get-notfound"),
        ("fltest fltestnoig", "get-return"),
        ("fltest [!SUCCESS=continue] fltestnoig", "get-return"),
        ("fltest fltestnoig", "set-unavail"),
        ("fltest [UNAVAIL=return] fltestnoig", "set-unavail"),
        ("fltest [TRYAGAIN=return] fltestnoig", "set-again"),
        ("fltest [NOTFOUND=return] fltestnoig", "set-notfound"),
        ("fltest fltestnoig", "set-return"),
        ("flmissing fltest", "normal"),
        ("flmissing", "normal"),
        ("flmissing [UNAVAIL=return] fltest", "normal"),
        ("fltestgetonly", "normal"),
        ("fltestgetonly fltest", "normal"),
        ("fltestgetonly [UNAVAIL=return] fltest", "normal"),
        ("fltest fltestgetonly fltestnoig", "normal"),
        ("fltest flmissing [UNAVAIL=return] fltestnoig", "normal"),
        ("files", "normal"),
        ("fltest files", "normal"),
    ];
    let mut compared = 0;
    for (index, (sources, scenario)) in cases.into_iter().enumerate() {
        let mut oracle = None;
        for (provider, mode) in [("host", "strict"), ("fl", "strict"), ("fl", "hardened")] {
            let label = format!("rpc-enum-{index}-{provider}-{mode}");
            let mut child = rpc_module_child(TEST, &dir, sources, &label);
            child
                .env("FLTEST_RPC_PROVIDER", provider)
                .env("FLTEST_RPC_ENUM", scenario)
                .env("FLTEST_TRACE", "1")
                .env("FRANKENLIBC_MODE", mode);
            let output = run_child(child, &label);
            let stdout = std::str::from_utf8(&output.stdout).unwrap();
            let transcript = stdout
                .split_once("RPC_ENUM_BEGIN\n")
                .and_then(|(_, rest)| rest.split_once("RPC_ENUM_END"))
                .map(|(text, _)| text)
                .expect("executed RPC enumeration transcript")
                .to_owned();
            assert!(transcript.lines().count() >= 10);
            let lifecycle = String::from_utf8_lossy(&output.stderr)
                .lines()
                .filter(|line| line.contains(":setrpcent(") || line.contains(":endrpcent("))
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if sources == "fltest" {
                assert!(
                    transcript.contains("number: 145001") && transcript.contains("number: 145002"),
                    "small and complete large module records must be observed"
                );
                assert!(String::from_utf8_lossy(&output.stderr).contains("fltest:getrpcent_r("));
            }
            if sources == "fltest fltestnoig" && scenario == "normal" {
                assert!(
                    lifecycle
                        .iter()
                        .filter(|line| line.contains("fltestnoig:endrpcent("))
                        .count()
                        >= 4,
                    "early and repeated cleanup must reach later configured modules"
                );
            }
            if let Some(expected) = &oracle {
                assert_eq!(
                    &(transcript, lifecycle),
                    expected,
                    "{label}: {sources}, {scenario}"
                );
                compared += 1;
            } else {
                oracle = Some((transcript, lifecycle));
            }
        }
    }
    assert_eq!(compared, 62);
    eprintln!("RPC enumeration: {compared} independent GNU/candidate process comparisons");

    #[cfg(debug_assertions)]
    {
        let path = dir.join("rpc");
        let aliases = (0..24).map(|index| format!("files-alias-{index}")).collect::<Vec<_>>();
        std::fs::write(
            &path,
            format!(
                "{} 145011 local-first {}\nfiles-second 145012 local-second\nportmapper 100000 local-portmapper\n",
                "f".repeat(1800),
                aliases.join(" ")
            ),
        )
        .unwrap();
        for mode in ["strict", "hardened"] {
            let mut child = rpc_module_child(TEST, &dir, "fltest", mode);
            child
                .env("FLTEST_RPC_ISOLATION_PATH", &path)
                .env("FRANKENLIBC_MODE", mode);
            let output = run_child(child, &format!("RPC files and callback isolation {mode}"));
            assert!(
                String::from_utf8_lossy(&output.stdout)
                    .contains("RPC files, buffer ownership and recursive provider isolation checked")
            );
        }
    }
}

#[cfg(debug_assertions)]
static RPC_ENUM_REENTRY_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(debug_assertions)]
unsafe extern "C" fn rpc_enumeration_reentry() -> c_int {
    use frankenlibc_abi::{errno_abi as e, unistd_abi as u};
    RPC_ENUM_REENTRY_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut output: RpcRawRecord = unsafe { std::mem::zeroed() };
    let mut buffer = [0 as c_char; 1024];
    let mut result = std::ptr::null_mut();
    // SAFETY: the provider invokes this callback while enumeration is leased.
    // Recursive enumeration must fail before borrowing the cursor a second time;
    // an independent keyed query must still complete with its own result storage.
    unsafe {
        u::setrpcent(0);
        if *e::__errno_location() != libc::EDEADLK {
            return 1;
        }
        if !u::getrpcent().is_null() || *e::__errno_location() != libc::EDEADLK {
            return 2;
        }
        if u::getrpcent_r(
            (&raw mut output).cast(),
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        ) != libc::EDEADLK || !result.is_null() {
            return 3;
        }
        u::endrpcent();
        if *e::__errno_location() != libc::EDEADLK {
            return 4;
        }
        let keyed = u::getrpcbyname(c"fltest-rpc".as_ptr()).cast::<RpcRawRecord>();
        if keyed.is_null() || (*keyed).number != 145001 {
            return 5;
        }
    }
    0
}

#[cfg(debug_assertions)]
fn rpc_native_isolation(path: &Path) {
    use frankenlibc_abi::unistd_abi as u;
    u::with_rpc_database_for_tests(path, || {
        let api = rpc_api(false);
        configure_rpc(false, c"fltest");
        let mut output: RpcRawRecord = unsafe { std::mem::zeroed() };
        let mut storage = [0 as c_char; 8192];
        let mut error = 717;
        unsafe {
            assert_eq!(u::_nss_files_setrpcent(0), 1);
            assert_eq!(
                u::_nss_files_getrpcent_r(
                    (&raw mut output).cast(),
                    storage.as_mut_ptr(),
                    storage.len(),
                    &mut error,
                ),
                1
            );
            assert_eq!(output.number, 145011);
            // Closing an uninitialized public module cursor must not disturb
            // the separately opened direct-files provider.
            (api.end)();
            assert_eq!(
                u::_nss_files_getrpcent_r(
                    (&raw mut output).cast(),
                    storage.as_mut_ptr(),
                    storage.len(),
                    &mut error,
                ),
                1
            );
            assert_eq!(output.number, 145012);
            assert_eq!(u::_nss_files_endrpcent(), 1);
            for (name, capacity, status, expected_error) in [
                (c"local-first", storage.len(), 1, 717),
                (c"missing-rpc", storage.len(), 0, 717),
                (c"local-first", 1, -2, libc::ERANGE),
            ] {
                error = 717;
                *(api.error)() = 619;
                assert_eq!(
                    u::_nss_files_getrpcbyname_r(
                        name.as_ptr(),
                        (&raw mut output).cast(),
                        storage.as_mut_ptr(),
                        capacity,
                        &mut error,
                    ),
                    status
                );
                assert_eq!((*(api.error)(), error), (619, expected_error));
                if status == 1 {
                    let record = rpc_record(
                        (&raw mut output).cast(),
                        Some((storage.as_ptr() as usize, storage.as_ptr() as usize + capacity)),
                    )
                    .unwrap();
                    assert_eq!(record.number, 145011);
                    assert_eq!(record.name.len(), 1800);
                    assert_eq!(record.aliases.len(), 25);
                }
            }
            error = 717;
            *(api.error)() = 619;
            assert_eq!(
                u::_nss_files_getrpcbynumber_r(
                    100000,
                    (&raw mut output).cast(),
                    storage.as_mut_ptr(),
                    storage.len(),
                    &mut error,
                ),
                1
            );
            assert_eq!(CStr::from_ptr(output.name).to_bytes(), b"portmapper");
            assert_eq!((*(api.error)(), error), (619, 717));

            (api.set)(0);
            let published = (api.get)();
            assert!(!published.is_null());
            let before = rpc_record(published, None).unwrap();
            assert_eq!(before.number, 145001);
            let keyed = rpc_call(&api, RpcRequest::Number(c_int::MAX), None, 0).2.unwrap();
            assert_eq!(keyed.number, c_int::MAX);
            assert_eq!(rpc_record(published, None).unwrap(), before);

            assert_eq!(u::_nss_files_setrpcent(0), 1);
            assert_eq!(
                u::_nss_files_getrpcent_r(
                    (&raw mut output).cast(),
                    storage.as_mut_ptr(),
                    1,
                    &mut error,
                ),
                -2
            );
            assert_eq!(error, libc::ERANGE);
            assert_eq!(
                u::_nss_files_getrpcent_r(
                    (&raw mut output).cast(),
                    storage.as_mut_ptr(),
                    storage.len(),
                    &mut error,
                ),
                1
            );
            assert_eq!(output.number, 145011, "ERANGE must retain the pending files record");
            assert_eq!(u::_nss_files_endrpcent(), 1);
        }
        let large = rpc_call(&api, RpcRequest::Next, None, 0).2.unwrap();
        assert_eq!(large.number, 145002);
        assert_eq!(large.aliases[2], vec![b'r'; 3072]);
        assert!(rpc_call(&api, RpcRequest::Next, None, 0).2.is_none());
        unsafe { (api.end)() };

        // Once files is selected publicly, it deliberately shares the direct
        // provider cursor. A short read retains its entry for either interface.
        configure_rpc(false, c"files");
        unsafe { (api.set)(0) };
        assert_eq!(
            rpc_call(&api, RpcRequest::Next, Some(1), 1),
            (libc::ERANGE, libc::ERANGE, None)
        );
        unsafe {
            assert_eq!(
                u::_nss_files_getrpcent_r(
                    (&raw mut output).cast(),
                    storage.as_mut_ptr(),
                    storage.len(),
                    &mut error,
                ),
                1
            );
            assert_eq!(output.number, 145011);
        }
        assert_eq!(
            rpc_call(&api, RpcRequest::Next, Some(8192), 1).2.unwrap().number,
            145012
        );
        unsafe { assert_eq!(u::_nss_files_endrpcent(), 1) };
        assert_eq!(
            rpc_call(&api, RpcRequest::Next, Some(8192), 0).2.unwrap().number,
            145011
        );
        unsafe { (api.end)() };

        configure_rpc(false, c"fltest");
        unsafe {
            let handle = libc::dlopen(c"libnss_fltest.so.2".as_ptr(), libc::RTLD_NOW);
            assert!(!handle.is_null());
            let symbol = libc::dlsym(handle, c"_nss_fltest_set_rpc_enum_reentry".as_ptr());
            assert!(!symbol.is_null());
            let install: unsafe extern "C" fn(Option<unsafe extern "C" fn() -> c_int>) =
                std::mem::transmute(symbol);
            install(Some(rpc_enumeration_reentry));
            (api.set)(0);
            assert_eq!(
                rpc_call(&api, RpcRequest::Next, None, 0).2.unwrap().number,
                145001
            );
            assert_eq!(
                rpc_call(&api, RpcRequest::Next, None, 0).2.unwrap().number,
                145002
            );
            assert!(rpc_call(&api, RpcRequest::Next, None, 0).2.is_none());
            assert_eq!(
                RPC_ENUM_REENTRY_CALLS.load(std::sync::atomic::Ordering::Relaxed),
                1
            );
            (api.end)();
            install(None);
            assert_eq!(libc::dlclose(handle), 0);
        }

        // The source position belongs to the process. Independent consumers
        // must not each restart the second module when the first reaches EOF.
        configure_rpc(false, c"fltest fltestnoig");
        unsafe { (api.set)(0) };
        let start = std::sync::Arc::new(std::sync::Barrier::new(3));
        let workers = (0..3)
            .map(|_| {
                let start = std::sync::Arc::clone(&start);
                std::thread::spawn(move || {
                    let api = rpc_api(false);
                    let mut names = Vec::new();
                    start.wait();
                    for _ in 0..8 {
                        let (status, error, answer) =
                            rpc_call(&api, RpcRequest::Next, Some(8192), 1);
                        if status == libc::ENOENT {
                            assert!(answer.is_none());
                            assert_eq!(error, 619, "cursor serialization must preserve errno");
                            return names;
                        }
                        assert_eq!((status, error), (0, 0));
                        names.push(answer.expect("successful RPC enumeration needs a record").name);
                    }
                    panic!("configured RPC enumeration repeated records without reaching EOF");
                })
            })
            .collect::<Vec<_>>();
        let mut names = workers
            .into_iter()
            .flat_map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![
                b"fltest-rpc-large".to_vec(),
                b"fltest-rpc-small".to_vec(),
                b"fltestnoig-rpc-large".to_vec(),
                b"fltestnoig-rpc-small".to_vec(),
            ]
        );

        // Cleanup and rewind from a different thread affect that same cursor.
        std::thread::spawn(|| unsafe { u::endrpcent() }).join().unwrap();
        assert_eq!(
            rpc_call(&api, RpcRequest::Next, Some(8192), 0).2.unwrap().name,
            b"fltest-rpc-small"
        );
        std::thread::spawn(|| unsafe { u::setrpcent(0) }).join().unwrap();
        assert_eq!(
            rpc_call(&api, RpcRequest::Next, Some(8192), 1).2.unwrap().name,
            b"fltest-rpc-small"
        );
        unsafe { (api.end)() };
    });
}
