//! Differential gate: getrpcent / getrpcbyname / getrpcbynumber must match
//! glibc, including r_aliases (/etc/rpc entries carry several aliases, e.g.
//! `portmapper 100000 portmap sunrpc rpcbind`).
//!
//! Both fl and glibc read the same /etc/rpc; glibc is reached via dlsym to
//! bypass fl's no_mangle interposition.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as flu;
use std::ffi::{CStr, CString, c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;
static RPC_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[repr(C)]
struct RpcEnt {
    r_name: *mut c_char,
    r_aliases: *mut *mut c_char,
    r_number: c_int,
}

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
unsafe fn sym(lib: *mut c_void, name: &CStr) -> *mut c_void {
    let p = unsafe { dlsym(lib, name.as_ptr()) };
    assert!(!p.is_null(), "dlsym {name:?} failed");
    p
}
fn cstr(p: *const c_char) -> Vec<u8> {
    if p.is_null() {
        return Vec::new();
    }
    unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()
}
fn alias_vec(mut pp: *mut *mut c_char) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if pp.is_null() {
        return out;
    }
    unsafe {
        while !(*pp).is_null() {
            out.push(cstr(*pp));
            pp = pp.add(1);
        }
    }
    out
}
type Snap = (Vec<u8>, c_int, Vec<Vec<u8>>);
fn snap(p: *const RpcEnt) -> Option<Snap> {
    if p.is_null() {
        return None;
    }
    let s = unsafe { &*p };
    Some((cstr(s.r_name), s.r_number, alias_vec(s.r_aliases)))
}

#[test]
fn getrpcent_matches_glibc() {
    let _serial = RPC_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let lib = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!lib.is_null(), "dlopen libc.so.6 failed");
    type Ent = extern "C" fn() -> *mut RpcEnt;
    type Ctl = extern "C" fn(c_int);
    type End = extern "C" fn();
    type ByName = extern "C" fn(*const c_char) -> *mut RpcEnt;
    type ByNum = extern "C" fn(c_int) -> *mut RpcEnt;

    let g_ent: Ent = unsafe { std::mem::transmute(sym(lib, c"getrpcent")) };
    let g_set: Ctl = unsafe { std::mem::transmute(sym(lib, c"setrpcent")) };
    let g_end: End = unsafe { std::mem::transmute(sym(lib, c"endrpcent")) };
    let g_byname: ByName = unsafe { std::mem::transmute(sym(lib, c"getrpcbyname")) };
    let g_bynum: ByNum = unsafe { std::mem::transmute(sym(lib, c"getrpcbynumber")) };

    // Lockstep enumeration.
    let mut glist: Vec<Snap> = Vec::new();
    g_set(1);
    while let Some(s) = snap(g_ent()) {
        glist.push(s);
        if glist.len() > 2000 {
            break;
        }
    }
    g_end();

    let mut flist: Vec<Snap> = Vec::new();
    unsafe { flu::setrpcent(1) };
    while let Some(s) = snap(unsafe { flu::getrpcent().cast::<RpcEnt>() }) {
        flist.push(s);
        if flist.len() > 2000 {
            break;
        }
    }
    unsafe { flu::endrpcent() };

    assert_eq!(flist, glist, "getrpcent enumeration diverged from glibc");

    // Re-query each name and number.
    for (name, num, aliases) in &glist {
        let cn = CString::new(name.clone()).unwrap();
        let g = snap(g_byname(cn.as_ptr()));
        let f = snap(unsafe { flu::getrpcbyname(cn.as_ptr()).cast::<RpcEnt>() });
        assert_eq!(f, g, "getrpcbyname({name:?}) diverged");

        let g = snap(g_bynum(*num));
        let f = snap(unsafe { flu::getrpcbynumber(*num).cast::<RpcEnt>() });
        assert_eq!(f, g, "getrpcbynumber({num}) diverged");

        // RPC names and aliases are case-sensitive, unlike host names.
        for query in std::iter::once(name.to_ascii_uppercase()).chain(aliases.iter().cloned()) {
            let query = CString::new(query).unwrap();
            assert_eq!(
                snap(unsafe { flu::getrpcbyname(query.as_ptr()).cast::<RpcEnt>() }),
                snap(g_byname(query.as_ptr())),
                "getrpcbyname({query:?}) diverged"
            );
        }
    }
}

#[cfg(debug_assertions)]
fn fixture_path(label: &str, content: &[u8]) -> std::path::PathBuf {
    static SERIAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let serial = SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "frankenlibc-rpc-{}-{timestamp}-{serial}-{label}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("rpc");
    std::fs::write(&path, content).unwrap();
    path
}

#[cfg(debug_assertions)]
fn large_fixture() -> (Vec<u8>, Snap, Snap, Snap) {
    let name = format!("rpc-{}", "q".repeat(4096)).into_bytes();
    let aliases: Vec<Vec<u8>> = (0..96)
        .map(|index| format!("Alias{index:03}_{}", "x".repeat(24)).into_bytes())
        .collect();
    let mut content = b"# header\nmalformed\ninvalid not-a-number\n#".to_vec();
    content.extend(std::iter::repeat_n(b'c', 3072));
    content.push(b'\n');
    content.extend_from_slice(&name);
    content.extend_from_slice(b" 700001");
    for alias in &aliases {
        content.push(b' ');
        content.extend_from_slice(alias);
    }
    content.extend_from_slice(b"\nbad -1\nomega 700002 tail\nraw\xff 700003 alias\xfe\n");
    (
        content,
        (name, 700001, aliases),
        (b"omega".to_vec(), 700002, vec![b"tail".to_vec()]),
        (b"raw\xff".to_vec(), 700003, vec![b"alias\xfe".to_vec()]),
    )
}

#[cfg(debug_assertions)]
fn set_errno(value: c_int) {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = value };
}

#[cfg(debug_assertions)]
fn errno() -> c_int {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() }
}

#[cfg(debug_assertions)]
fn assert_caller_owned(entry: &RpcEnt, buffer: *mut c_char, capacity: usize) {
    let base = buffer as usize;
    let end = base + capacity;
    let string_is_owned = |value: *mut c_char| {
        let start = value as usize;
        assert!(start >= base && start < end, "string escapes caller storage");
        let bytes = unsafe { std::slice::from_raw_parts(value.cast::<u8>(), end - start) };
        assert!(bytes.contains(&0), "unterminated string in caller storage");
    };
    string_is_owned(entry.r_name);
    let table = entry.r_aliases as usize;
    assert_eq!(table % std::mem::align_of::<*mut c_char>(), 0);
    assert!(table >= base && table < end, "alias table escapes caller storage");
    let slots = (end - table) / std::mem::size_of::<*mut c_char>();
    let mut terminated = false;
    for index in 0..slots {
        let value = unsafe { *entry.r_aliases.add(index) };
        if value.is_null() {
            terminated = true;
            break;
        }
        string_is_owned(value);
    }
    assert!(terminated, "alias table lacks a bounded NULL terminator");
}

#[cfg(debug_assertions)]
fn call_r(
    capacity: usize,
    operation: impl FnOnce(*mut c_void, *mut c_char, usize, *mut *mut c_void) -> c_int,
) -> (c_int, c_int, Option<Snap>) {
    let mut record = std::mem::MaybeUninit::<RpcEnt>::uninit();
    let mut storage = vec![0xa5u8; capacity + 2];
    let buffer = unsafe { storage.as_mut_ptr().add(1).cast::<c_char>() };
    let mut result = std::ptr::dangling_mut::<c_void>();
    set_errno(77);
    let rc = operation(record.as_mut_ptr().cast(), buffer, capacity, &mut result);
    let observed_errno = errno();
    assert_eq!(storage[0], 0xa5, "write before caller buffer");
    assert_eq!(storage[capacity + 1], 0xa5, "write after caller buffer");
    if result.is_null() {
        return (rc, observed_errno, None);
    }
    assert_eq!(rc, 0);
    assert_eq!(result, record.as_mut_ptr().cast(), "wrong result ownership");
    let record = unsafe { record.assume_init() };
    assert_caller_owned(&record, buffer, capacity);
    (rc, observed_errno, snap(&record))
}

#[cfg(debug_assertions)]
fn call_nss(
    capacity: usize,
    operation: impl FnOnce(*mut c_void, *mut c_char, usize, *mut c_int) -> c_int,
) -> (c_int, c_int, c_int, Option<Snap>) {
    let mut record = std::mem::MaybeUninit::<RpcEnt>::uninit();
    let mut storage = vec![0xa5u8; capacity + 2];
    let buffer = unsafe { storage.as_mut_ptr().add(1).cast::<c_char>() };
    let mut error = 99;
    set_errno(77);
    let status = operation(record.as_mut_ptr().cast(), buffer, capacity, &mut error);
    let observed_errno = errno();
    assert_eq!(storage[0], 0xa5);
    assert_eq!(storage[capacity + 1], 0xa5);
    let answer = if status == 1 {
        let record = unsafe { record.assume_init() };
        assert_caller_owned(&record, buffer, capacity);
        snap(&record)
    } else {
        None
    };
    (status, error, observed_errno, answer)
}

#[test]
#[cfg(debug_assertions)]
fn rpc_private_database_keeps_large_records_and_retries() {
    let _serial = RPC_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let (content, first, second, third) = large_fixture();
    let path = fixture_path("records", &content);
    flu::with_rpc_database_for_tests(&path, || {
        unsafe { flu::setrpcent(1) };
        assert_eq!(
            call_r(1, |record, buffer, size, result| unsafe {
                flu::getrpcent_r(record, buffer, size, result)
            }),
            (libc::ERANGE, libc::ERANGE, None)
        );
        for expected in [&first, &second, &third] {
            assert_eq!(
                call_r(16384, |record, buffer, size, result| unsafe {
                    flu::getrpcent_r(record, buffer, size, result)
                }),
                (0, 77, Some(expected.clone()))
            );
        }
        for _ in 0..2 {
            assert_eq!(
                call_r(16384, |record, buffer, size, result| unsafe {
                    flu::getrpcent_r(record, buffer, size, result)
                }),
                (libc::ENOENT, 77, None)
            );
        }
        assert_eq!(
            call_r(1, |record, buffer, size, result| unsafe {
                flu::getrpcent_r(record, buffer, size, result)
            }),
            (libc::ERANGE, libc::ERANGE, None)
        );

        unsafe { flu::setrpcent(0) };
        assert_eq!(snap(unsafe { flu::getrpcent().cast() }), Some(first.clone()));
        let last_alias = CString::new(first.2.last().unwrap().clone()).unwrap();
        let static_answer = unsafe { flu::getrpcbyname(last_alias.as_ptr()).cast::<RpcEnt>() };
        assert_eq!(snap(static_answer), Some(first.clone()));
        assert_eq!(
            call_r(16384, |record, buffer, size, result| unsafe {
                flu::getrpcbynumber_r(second.1, record, buffer, size, result)
            }),
            (0, 0, Some(second.clone()))
        );
        // A reentrant lookup must not overwrite the nonreentrant answer.
        assert_eq!(snap(static_answer), Some(first.clone()));
        // Keyed lookups do not disturb the process-wide enumeration cursor.
        assert_eq!(snap(unsafe { flu::getrpcent().cast() }), Some(second.clone()));

        for query in [
            CString::new(first.0.clone()).unwrap(),
            last_alias,
            CString::new(third.2[0].clone()).unwrap(),
        ] {
            let expected = if query.as_bytes() == third.2[0] { &third } else { &first };
            assert_eq!(
                call_r(16384, |record, buffer, size, result| unsafe {
                    flu::getrpcbyname_r(query.as_ptr(), record, buffer, size, result)
                }),
                (0, 0, Some(expected.clone()))
            );
        }
        assert_eq!(snap(unsafe { flu::getrpcbynumber(first.1).cast() }), Some(first.clone()));
        for query in [c"OMEGA", c"missing", c"alias095_xxxxxxxxxxxxxxxxxxxxxxxx"] {
            assert_eq!(
                call_r(16384, |record, buffer, size, result| unsafe {
                    flu::getrpcbyname_r(query.as_ptr(), record, buffer, size, result)
                }),
                (0, 0, None)
            );
        }
        // Even a missing key needs complete earlier records before a miss.
        assert_eq!(
            call_r(64, |record, buffer, size, result| unsafe {
                flu::getrpcbyname_r(c"missing".as_ptr(), record, buffer, size, result)
            }),
            (libc::ERANGE, libc::ERANGE, None)
        );
        unsafe { flu::endrpcent() };
        assert_eq!(snap(unsafe { flu::getrpcent().cast() }), Some(first.clone()));
    });
}

#[test]
#[cfg(debug_assertions)]
fn rpc_files_provider_returns_records_and_distinguishes_source_errors() {
    let _serial = RPC_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let (content, first, second, third) = large_fixture();
    let path = fixture_path("provider", &content);
    flu::with_rpc_database_for_tests(&path, || {
        assert_eq!(unsafe { flu::_nss_files_setrpcent(1) }, 1);
        assert_eq!(
            call_nss(1, |record, buffer, size, error| unsafe {
                flu::_nss_files_getrpcent_r(record, buffer, size, error)
            }),
            (-2, libc::ERANGE, 77, None)
        );
        for expected in [&first, &second, &third] {
            assert_eq!(
                call_nss(16384, |record, buffer, size, error| unsafe {
                    flu::_nss_files_getrpcent_r(record, buffer, size, error)
                }),
                (1, 99, 77, Some(expected.clone()))
            );
        }
        assert_eq!(
            call_nss(16384, |record, buffer, size, error| unsafe {
                flu::_nss_files_getrpcent_r(record, buffer, size, error)
            }),
            (0, 99, 77, None)
        );
        let alias = CString::new(first.2.last().unwrap().clone()).unwrap();
        assert_eq!(
            call_nss(16384, |record, buffer, size, error| unsafe {
                flu::_nss_files_getrpcbyname_r(alias.as_ptr(), record, buffer, size, error)
            }),
            (1, 99, 77, Some(first.clone()))
        );
        assert_eq!(
            call_nss(16384, |record, buffer, size, error| unsafe {
                flu::_nss_files_getrpcbynumber_r(second.1, record, buffer, size, error)
            }),
            (1, 99, 77, Some(second.clone()))
        );
        assert_eq!(
            call_nss(16384, |record, buffer, size, error| unsafe {
                flu::_nss_files_getrpcbyname_r(c"OMEGA".as_ptr(), record, buffer, size, error)
            }),
            (0, 99, 77, None)
        );
        assert_eq!(unsafe { flu::_nss_files_setrpcent(0) }, 1);
        assert_eq!(
            call_nss(16384, |record, buffer, size, error| unsafe {
                flu::_nss_files_getrpcent_r(record, buffer, size, error)
            }).3,
            Some(first.clone())
        );
        assert_eq!(unsafe { flu::_nss_files_endrpcent() }, 1);
        // End closes the source; a changed file is visible after reopening.
        std::fs::write(&path, b"replacement 700099 fresh\n").unwrap();
        assert_eq!(
            call_nss(256, |record, buffer, size, error| unsafe {
                flu::_nss_files_getrpcent_r(record, buffer, size, error)
            }),
            (1, 99, 77, Some((b"replacement".to_vec(), 700099, vec![b"fresh".to_vec()])))
        );
    });

    let missing = path.with_file_name("missing-rpc");
    flu::with_rpc_database_for_tests(&missing, || {
        set_errno(77);
        assert_eq!(unsafe { flu::_nss_files_setrpcent(0) }, -1);
        assert_eq!(errno(), libc::ENOENT);
        assert_eq!(
            call_nss(256, |record, buffer, size, error| unsafe {
                flu::_nss_files_getrpcent_r(record, buffer, size, error)
            }),
            (-1, 99, 77, None)
        );
        assert_eq!(
            call_nss(256, |record, buffer, size, error| unsafe {
                flu::_nss_files_getrpcbyname_r(c"missing".as_ptr(), record, buffer, size, error)
            }),
            (-1, 99, libc::ENOENT, None)
        );
        assert_eq!(
            call_r(256, |record, buffer, size, result| unsafe {
                flu::getrpcent_r(record, buffer, size, result)
            }),
            (libc::ENOENT, 77, None)
        );
        assert_eq!(
            call_r(256, |record, buffer, size, result| unsafe {
                flu::getrpcbynumber_r(700001, record, buffer, size, result)
            }),
            (libc::ENOENT, libc::ENOENT, None)
        );
    });

    flu::with_rpc_database_for_tests(path.parent().unwrap(), || {
        assert_eq!(unsafe { flu::_nss_files_setrpcent(0) }, 1);
        assert_eq!(
            call_nss(256, |record, buffer, size, error| unsafe {
                flu::_nss_files_getrpcent_r(record, buffer, size, error)
            }),
            (-1, libc::EISDIR, libc::EISDIR, None)
        );
        assert_eq!(
            call_r(256, |record, buffer, size, result| unsafe {
                flu::getrpcent_r(record, buffer, size, result)
            }),
            (libc::ENOENT, libc::EISDIR, None)
        );
    });
}

#[test]
#[cfg(debug_assertions)]
fn rpc_enumeration_shares_one_cursor_across_threads() {
    let _serial = RPC_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let mut content = String::new();
    for number in 0..128 {
        content.push_str(&format!("record{number} {} alias{number}\n", 710000 + number));
    }
    let path = fixture_path("threads", content.as_bytes());
    flu::with_rpc_database_for_tests(&path, || {
        // Open here before workers: the shared descriptor owns this source.
        unsafe { flu::setrpcent(1) };
        let workers: Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    let mut numbers = Vec::new();
                    loop {
                        let (rc, _, answer) = call_r(256, |record, buffer, size, result| unsafe {
                            flu::getrpcent_r(record, buffer, size, result)
                        });
                        if rc == libc::ENOENT {
                            assert!(answer.is_none());
                            break;
                        }
                        assert_eq!(rc, 0);
                        numbers.push(answer.expect("successful enumeration needs a record").1);
                    }
                    numbers
                })
            })
            .collect();
        let mut numbers: Vec<_> = workers
            .into_iter()
            .flat_map(|worker| worker.join().unwrap())
            .collect();
        numbers.sort_unstable();
        assert_eq!(numbers, (710000..710128).collect::<Vec<_>>());
    });
}
