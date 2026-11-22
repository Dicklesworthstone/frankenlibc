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
