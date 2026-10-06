#![cfg(target_os = "linux")]

//! NSS service modules (`libnss_<service>.so.2`) behind the passwd, group,
//! shadow and initgroups databases.
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

use std::ffi::{CStr, CString, c_char, c_int};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

const CHILD_ENV: &str = "FRANKENLIBC_NSS_MODULE_CHILD";

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
    for (service, extra) in [("fltest", None), ("fltestnoig", Some("-DNO_INITGROUPS"))] {
        let mut cc = Command::new("cc");
        cc.args(["-O2", "-fPIC", "-shared", &format!("-DSERVICE={service}")]);
        if let Some(flag) = extra {
            cc.arg(flag);
        }
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

fn run_child(mut command: Command, label: &str) {
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
}

fn child_test_command(test_name: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("test binary path"));
    command.args(["--exact", test_name, "--nocapture", "--test-threads", "1"]);
    command
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
