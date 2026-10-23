#![cfg(target_os = "linux")]

//! NSS service modules (`libnss_<service>.so.2`) behind the passwd, group,
//! shadow, initgroups and hosts databases.
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
        assert!(head.is_null(), "failed lookup published a partial addrinfo list");
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
                fn __nss_configure_lookup(
                    database: *const c_char,
                    sources: *const c_char,
                ) -> c_int;
            }
            let sources = CString::new(std::env::var("FLTEST_TUPLE_SOURCES").unwrap()).unwrap();
            // SAFETY: this child owns its process-local hosts configuration.
            assert_eq!(unsafe { __nss_configure_lookup(c"hosts".as_ptr(), sources.as_ptr()) }, 0);
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
                let family = if scenario == "family" { libc::AF_INET } else { libc::AF_UNSPEC };
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
                .env("FLTEST_REQUIRE_TUPLE_HEAD_RESET", if provider == "fl" { "1" } else { "0" })
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
                assert!(trace.contains(":gethostbyname4_r_ERANGE("), "{label}: {trace}");
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
            assert!(trace.contains("fltesttupleonly:gethostbyname4_r("), "{label}: {trace}");
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
