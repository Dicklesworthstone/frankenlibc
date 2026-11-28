#![cfg(target_os = "linux")]

//! Native compat integration through the public account APIs. The GNU
//! directive differential matrix lives in check_nss_compat.py; these tests
//! cover process-local source overrides and shared public enumeration using
//! native files backends, without loading any compatibility provider DSO.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::mem::MaybeUninit;
use std::process::Command;

use frankenlibc_abi::{errno_abi, glibc_internal_abi, grp_abi, pwd_abi, unistd_abi};

const CHILD: &str = "FRANKENLIBC_NATIVE_COMPAT_RUST_CHILD";
const CONFIG: &str = "passwd: compat\ngroup: compat\nshadow: compat\n\
    passwd_compat: files\ngroup_compat: files\nshadow_compat: files\n";
const PASSWD: &str = "native_local:x:61001:62001:Local:/local:/bin/sh\n\
    +native_remote:override:::Selected:/selected:/bin/false\n\
    native_remote:x:61002:62002:Remote:/remote:/bin/sh\n";
const GROUP: &str = "native_local_group:x:62001:native_local\n\
    +native_remote_group\n\
    native_remote_group:x:62002:native_remote\n";
const SHADOW: &str = "native_local:!:1:2:3:4:5:6:7\n\
    +native_remote:override:::::::\n\
    native_remote:hash:11:12:13:14:15:16:17\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Database {
    Passwd,
    Group,
    Shadow,
}

impl Database {
    const ALL: [Self; 3] = [Self::Passwd, Self::Group, Self::Shadow];

    fn backing(self) -> &'static CStr {
        match self {
            Self::Passwd => c"passwd_compat",
            Self::Group => c"group_compat",
            Self::Shadow => c"shadow_compat",
        }
    }

    fn local(self) -> &'static [u8] {
        match self {
            Self::Group => b"native_local_group",
            _ => b"native_local",
        }
    }

    fn remote(self) -> &'static CStr {
        match self {
            Self::Group => c"native_remote_group",
            _ => c"native_remote",
        }
    }

    fn imported_password(self) -> &'static [u8] {
        match self {
            Self::Group => b"x",
            _ => b"override",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    name: Vec<u8>,
    password: Vec<u8>,
}

unsafe fn copy_entry(name: *const c_char, password: *const c_char) -> Entry {
    // SAFETY: successful account APIs return live, terminated fields. Every
    // caller copies them before releasing its buffer or invoking another API.
    unsafe {
        Entry {
            name: CStr::from_ptr(name).to_bytes().to_vec(),
            password: CStr::from_ptr(password).to_bytes().to_vec(),
        }
    }
}

fn read(database: Database, name: Option<&CStr>, capacity: usize) -> (c_int, Option<Entry>) {
    let mut buffer = vec![0 as c_char; capacity];
    macro_rules! account {
        ($record:ty, $lookup:path, $next:path, $name:ident, $password:ident) => {{
            let mut record = MaybeUninit::<$record>::uninit();
            let mut result = std::ptr::dangling_mut();
            // SAFETY: the complete typed record, result slot and exact caller
            // buffer remain writable until the returned fields are copied.
            let status = unsafe {
                match name {
                    Some(name) => $lookup(
                        name.as_ptr(),
                        record.as_mut_ptr(),
                        buffer.as_mut_ptr(),
                        capacity,
                        &mut result,
                    ),
                    None => $next(
                        record.as_mut_ptr(),
                        buffer.as_mut_ptr(),
                        capacity,
                        &mut result,
                    ),
                }
            };
            let value = if result.is_null() {
                None
            } else {
                assert_eq!(status, 0);
                assert_eq!(result, record.as_mut_ptr());
                // SAFETY: success initialized this exact record and buffer.
                let record = unsafe { record.assume_init_ref() };
                Some(unsafe { copy_entry(record.$name, record.$password) })
            };
            (status, value)
        }};
    }
    match database {
        Database::Passwd => account!(
            libc::passwd,
            pwd_abi::getpwnam_r,
            pwd_abi::getpwent_r,
            pw_name,
            pw_passwd
        ),
        Database::Group => account!(
            libc::group,
            grp_abi::getgrnam_r,
            grp_abi::getgrent_r,
            gr_name,
            gr_passwd
        ),
        Database::Shadow => {
            let mut record = MaybeUninit::<libc::spwd>::uninit();
            let mut result: *mut c_void = std::ptr::dangling_mut();
            // SAFETY: Spwd storage has the public C layout used by the opaque
            // shadow entry points, and all output storage remains live.
            let status = unsafe {
                match name {
                    Some(name) => pwd_abi::getspnam_r(
                        name.as_ptr(),
                        record.as_mut_ptr().cast(),
                        buffer.as_mut_ptr(),
                        capacity,
                        &mut result,
                    ),
                    None => pwd_abi::getspent_r(
                        record.as_mut_ptr().cast(),
                        buffer.as_mut_ptr(),
                        capacity,
                        &mut result,
                    ),
                }
            };
            let value = if result.is_null() {
                None
            } else {
                assert_eq!(status, 0);
                assert_eq!(result, record.as_mut_ptr().cast());
                // SAFETY: success initialized this exact record and buffer.
                let record = unsafe { record.assume_init_ref() };
                Some(unsafe { copy_entry(record.sp_namp, record.sp_pwdp) })
            };
            (status, value)
        }
    }
}

fn static_next(database: Database) -> Entry {
    // SAFETY: each successful non-reentrant call owns live thread-local
    // storage. Copy it before another call can replace the fields.
    unsafe {
        match database {
            Database::Passwd => {
                let record = pwd_abi::getpwent();
                assert!(!record.is_null());
                copy_entry((*record).pw_name, (*record).pw_passwd)
            }
            Database::Group => {
                let record = grp_abi::getgrent();
                assert!(!record.is_null());
                copy_entry((*record).gr_name, (*record).gr_passwd)
            }
            Database::Shadow => {
                let record = pwd_abi::getspent().cast::<libc::spwd>();
                assert!(!record.is_null());
                copy_entry((*record).sp_namp, (*record).sp_pwdp)
            }
        }
    }
}

fn rewind(database: Database) {
    // SAFETY: each public entry point rewinds its shared account cursor.
    unsafe {
        match database {
            Database::Passwd => pwd_abi::setpwent(),
            Database::Group => grp_abi::setgrent(),
            Database::Shadow => pwd_abi::setspent(),
        }
    }
}

fn end(database: Database) {
    // SAFETY: each public entry point closes its own shared account cursor.
    unsafe {
        match database {
            Database::Passwd => pwd_abi::endpwent(),
            Database::Group => grp_abi::endgrent(),
            Database::Shadow => pwd_abi::endspent(),
        }
    }
}

fn configure(database: Database, sources: &CStr) {
    // SAFETY: both input strings are live and terminated; errno is local to
    // this test child. A successful source override preserves its value.
    unsafe {
        *errno_abi::__errno_location() = 731;
        assert_eq!(
            glibc_internal_abi::__nss_configure_lookup(
                database.backing().as_ptr(),
                sources.as_ptr()
            ),
            0
        );
        assert_eq!(*errno_abi::__errno_location(), 731);
    }
}

fn assert_imported(database: Database) {
    let (status, entry) = read(database, Some(database.remote()), 2048);
    assert_eq!(status, 0, "{database:?}");
    let entry = entry.expect("the files backing service must supply the selected account");
    assert_eq!(entry.name, database.remote().to_bytes());
    assert_eq!(entry.password, database.imported_password());
}

fn assert_no_gnu_compat_loaded() {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    assert!(
        !maps.contains("libnss_compat.so"),
        "native compat loaded GNU's compatibility provider"
    );
}

fn isolated(name: &str, body: impl FnOnce()) {
    if std::env::var(CHILD).ok().as_deref() == Some(name) {
        assert_no_gnu_compat_loaded();
        body();
        assert_no_gnu_compat_loaded();
        return;
    }
    for mode in ["strict", "hardened"] {
        let directory =
            std::env::temp_dir().join(format!("frankenlibc-{name}-{mode}-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        for (file, content) in [
            ("passwd", PASSWD),
            ("group", GROUP),
            ("shadow", SHADOW),
            ("nsswitch.conf", CONFIG),
        ] {
            std::fs::write(directory.join(file), content).unwrap();
        }
        // Configure only the child's environment: NSS overrides freeze
        // process-global state, so independent tests must never share it.
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env(CHILD, name)
            .env("FRANKENLIBC_MODE", mode)
            .env("FRANKENLIBC_NSSWITCH_CONF", directory.join("nsswitch.conf"))
            .env("FRANKENLIBC_PASSWD_PATH", directory.join("passwd"))
            .env("FRANKENLIBC_GROUP_PATH", directory.join("group"))
            .env("FRANKENLIBC_SHADOW_PATH", directory.join("shadow"))
            .env_remove("LD_PRELOAD")
            .output()
            .expect("native compat child must execute");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{name}/{mode}\n{stdout}\n{stderr}");
        assert!(
            stdout.contains("test result: ok. 1 passed;"),
            "child filter must execute exactly one test:\n{stdout}"
        );
    }
}

#[test]
fn native_compat_runtime_backends_keep_account_policies_independent() {
    isolated(
        "native_compat_runtime_backends_keep_account_policies_independent",
        || {
            for database in Database::ALL {
                assert_imported(database);
            }
            for database in Database::ALL {
                // A recursive first backend is unavailable. The pseudo-database
                // selects one service and must not follow its ordinary NSS action
                // into the later files service or recurse back into itself.
                configure(database, c"compat [UNAVAIL=continue] files");
                let (status, result) = read(database, Some(database.remote()), 2048);
                assert_eq!(status, libc::EDEADLK, "{database:?}");
                assert!(result.is_none());
                for other in Database::ALL {
                    if other != database {
                        assert_imported(other);
                    }
                }
                // Rejected replacements must leave the previous policy intact.
                // SAFETY: both strings are live and terminated, and errno belongs
                // to this isolated child thread.
                unsafe {
                    assert_eq!(
                        glibc_internal_abi::__nss_configure_lookup(
                            database.backing().as_ptr(),
                            c"files [SUCCESS=invalid]".as_ptr()
                        ),
                        -1
                    );
                    assert_eq!(*errno_abi::__errno_location(), libc::EINVAL);
                }
                assert_eq!(
                    read(database, Some(database.remote()), 2048).0,
                    libc::EDEADLK
                );
                configure(database, c"files");
                assert_imported(database);
            }
        },
    );
}

#[test]
fn native_compat_public_enumeration_shares_cursor_and_preserves_range_retries() {
    isolated(
        "native_compat_public_enumeration_shares_cursor_and_preserves_range_retries",
        || {
            for database in Database::ALL {
                rewind(database);
                assert_eq!(static_next(database).name, database.local());
                let (status, result) = read(database, None, 8);
                assert_eq!(status, libc::ERANGE);
                assert!(result.is_none());
                let (status, entry) = std::thread::spawn(move || read(database, None, 2048))
                    .join()
                    .unwrap();
                assert_eq!(status, 0);
                let entry = entry.expect("the other thread must resume the shared cursor");
                assert_eq!(entry.name, database.remote().to_bytes());
                assert_eq!(entry.password, database.imported_password());
                if database == Database::Group {
                    let mut groups = [0; 8];
                    let mut count = groups.len() as c_int;
                    // SAFETY: the user is terminated and all eight gids plus the
                    // capacity slot are writable for this independent traversal.
                    let result = unsafe {
                        unistd_abi::getgrouplist(
                            c"native_remote".as_ptr(),
                            62000,
                            groups.as_mut_ptr(),
                            &mut count,
                        )
                    };
                    assert_eq!(result, 3);
                    assert_eq!(count, 3);
                    assert_eq!(&groups[..3], &[62000, 62002, 62002]);
                }
                // A local row with the same name still follows the imported row.
                // Supplementary-group collection must not rewind this cursor.
                let local = static_next(database);
                assert_eq!(local.name, database.remote().to_bytes());
                assert_eq!(
                    local.password,
                    if database == Database::Shadow {
                        b"hash".as_slice()
                    } else {
                        b"x"
                    }
                );
                let (status, result) = read(database, None, 2048);
                assert_eq!(status, libc::ENOENT);
                assert!(result.is_none());
                rewind(database);
                assert_eq!(static_next(database).name, database.local());
                end(database);
            }
        },
    );
}
