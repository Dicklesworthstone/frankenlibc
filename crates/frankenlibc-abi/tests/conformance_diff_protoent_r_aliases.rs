//! Differential gate: reentrant getprotobyname_r / getprotobynumber_r /
//! getprotoent_r must return the canonical name and aliases like glibc.
//!
//! fl's reentrant protoent path wrote an empty p_aliases list, and
//! getprotobyname_r matched only the canonical name (not aliases) and echoed
//! it. Now all three route through the shared parser. glibc is reached via
//! dlsym to bypass fl's no_mangle interposition; both read /etc/protocols.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as flu;
use std::ffi::{CStr, CString, c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;

#[repr(C)]
struct Protoent {
    p_name: *mut c_char,
    p_aliases: *mut *mut c_char,
    p_proto: c_int,
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
fn snap(rc: c_int, res: *mut Protoent) -> Option<Snap> {
    if rc != 0 || res.is_null() {
        return None;
    }
    let s = unsafe { &*res };
    Some((cstr(s.p_name), s.p_proto, alias_vec(s.p_aliases)))
}

type ByNameR =
    extern "C" fn(*const c_char, *mut Protoent, *mut c_char, usize, *mut *mut Protoent) -> c_int;
type ByNumR = extern "C" fn(c_int, *mut Protoent, *mut c_char, usize, *mut *mut Protoent) -> c_int;
type EntR = extern "C" fn(*mut Protoent, *mut c_char, usize, *mut *mut Protoent) -> c_int;
type Ent = extern "C" fn() -> *mut Protoent;
type Ctl = extern "C" fn(c_int);
type End = extern "C" fn();

#[test]
fn protoent_reentrant_matches_glibc() {
    let lib = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!lib.is_null(), "dlopen libc.so.6 failed");
    let g_byname: ByNameR = unsafe { std::mem::transmute(sym(lib, c"getprotobyname_r")) };
    let g_bynum: ByNumR = unsafe { std::mem::transmute(sym(lib, c"getprotobynumber_r")) };
    let g_entr: EntR = unsafe { std::mem::transmute(sym(lib, c"getprotoent_r")) };
    let g_ent: Ent = unsafe { std::mem::transmute(sym(lib, c"getprotoent")) };
    let g_set: Ctl = unsafe { std::mem::transmute(sym(lib, c"setprotoent")) };
    let g_end: End = unsafe { std::mem::transmute(sym(lib, c"endprotoent")) };

    let mk = || -> (Protoent, [c_char; 1024]) {
        (
            Protoent {
                p_name: std::ptr::null_mut(),
                p_aliases: std::ptr::null_mut(),
                p_proto: 0,
            },
            [0; 1024],
        )
    };

    // Enumerate probe names/numbers from host db (+ first alias of each).
    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut nums: Vec<c_int> = Vec::new();
    g_set(1);
    loop {
        let e = g_ent();
        if e.is_null() {
            break;
        }
        let s = unsafe { &*e };
        names.push(cstr(s.p_name));
        nums.push(s.p_proto);
        let al = alias_vec(s.p_aliases);
        if let Some(a) = al.first() {
            names.push(a.clone());
        }
        if names.len() > 200 {
            break;
        }
    }
    g_end();

    let mut mismatches = Vec::new();

    for name in &names {
        let cn = CString::new(name.clone()).unwrap();
        let (mut ge, mut gb) = mk();
        let mut gres: *mut Protoent = std::ptr::null_mut();
        let grc = g_byname(cn.as_ptr(), &mut ge, gb.as_mut_ptr(), gb.len(), &mut gres);
        let g = snap(grc, gres);
        let (mut fe, mut fb) = mk();
        let mut fres: *mut Protoent = std::ptr::null_mut();
        let frc = unsafe {
            flu::getprotobyname_r(
                cn.as_ptr(),
                (&mut fe as *mut Protoent).cast(),
                fb.as_mut_ptr(),
                fb.len(),
                (&mut fres as *mut *mut Protoent).cast(),
            )
        };
        let f = snap(frc, fres);
        if g != f {
            mismatches.push(format!("getprotobyname_r({name:?}): glibc={g:?} fl={f:?}"));
        }
    }

    for &num in &nums {
        let (mut ge, mut gb) = mk();
        let mut gres: *mut Protoent = std::ptr::null_mut();
        let grc = g_bynum(num, &mut ge, gb.as_mut_ptr(), gb.len(), &mut gres);
        let g = snap(grc, gres);
        let (mut fe, mut fb) = mk();
        let mut fres: *mut Protoent = std::ptr::null_mut();
        let frc = unsafe {
            flu::getprotobynumber_r(
                num,
                (&mut fe as *mut Protoent).cast(),
                fb.as_mut_ptr(),
                fb.len(),
                (&mut fres as *mut *mut Protoent).cast(),
            )
        };
        let f = snap(frc, fres);
        if g != f {
            mismatches.push(format!("getprotobynumber_r({num}): glibc={g:?} fl={f:?}"));
        }
    }

    // getprotoent_r lockstep enumeration
    let mut glist = Vec::new();
    g_set(1);
    loop {
        let (mut e, mut b) = mk();
        let mut res: *mut Protoent = std::ptr::null_mut();
        let rc = g_entr(&mut e, b.as_mut_ptr(), b.len(), &mut res);
        match snap(rc, res) {
            Some(s) => glist.push(s),
            None => break,
        }
        if glist.len() > 2000 {
            break;
        }
    }
    g_end();

    let mut flist = Vec::new();
    unsafe { flu::setprotoent(1) };
    loop {
        let (mut e, mut b) = mk();
        let mut res: *mut Protoent = std::ptr::null_mut();
        let rc = unsafe {
            flu::getprotoent_r(
                (&mut e as *mut Protoent).cast(),
                b.as_mut_ptr(),
                b.len(),
                (&mut res as *mut *mut Protoent).cast(),
            )
        };
        match snap(rc, res) {
            Some(s) => flist.push(s),
            None => break,
        }
        if flist.len() > 2000 {
            break;
        }
    }
    unsafe { flu::endprotoent() };
    if flist != glist {
        mismatches.push(format!(
            "getprotoent_r enumeration diverged: fl_len={} glibc_len={}",
            flist.len(),
            glist.len()
        ));
    }

    assert!(
        mismatches.is_empty(),
        "reentrant protoent diverged from glibc ({} cases):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

fn protocol_child(test: &str) -> bool {
    const CHILD: &str = "FRANKENLIBC_PROTOCOL_ENUM_CHILD";
    if std::env::var_os(CHILD).is_some() {
        // SAFETY: only this selected test executes in the isolated process.
        unsafe { libc::alarm(30) };
        return false;
    }
    for mode in ["strict", "hardened"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env(CHILD, test)
            .env("FRANKENLIBC_MODE", mode)
            .env_remove("FRANKENLIBC_PROTOCOLS_PATH")
            .env_remove("LD_PRELOAD")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{test}/{mode}: {:?}\n{stdout}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
        );
    }
    true
}

fn empty_protocol() -> Protoent {
    Protoent {
        p_name: std::ptr::null_mut(),
        p_aliases: std::ptr::null_mut(),
        p_proto: 0,
    }
}

fn protocol_errno() -> c_int {
    // SAFETY: this ABI returns the calling owner's live errno slot.
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() }
}

fn plant_protocol_errno() {
    // SAFETY: the isolated test owns this errno slot.
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = libc::EDOM };
}

fn retained_protocol_file(label: &str, contents: &[u8]) -> std::path::PathBuf {
    use std::io::Write;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "frankenlibc-protocol-{label}-{}-{nonce}",
        std::process::id(),
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    file.write_all(contents).unwrap();
    // Keep the unique input available for diagnosis; no system database changes.
    path
}

fn select_protocol_file(path: &std::path::Path) {
    // SAFETY: child tests select their source before creating native workers.
    unsafe { std::env::set_var("FRANKENLIBC_PROTOCOLS_PATH", path) };
}

fn gnu_protocol_line(line: &[u8]) -> Snap {
    type Parse =
        unsafe extern "C" fn(*mut c_char, *mut Protoent, *mut c_void, usize, *mut c_int) -> c_int;
    // This private GNU parser is an independent oracle for synthetic records;
    // it does not consult the candidate's configurable protocols path.
    let library = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!library.is_null());
    let parser: Parse = unsafe { std::mem::transmute(sym(library, c"_nss_files_parse_protoent")) };
    assert_ne!(
        parser as *const (),
        flu::_nss_files_parse_protoent as *const ()
    );
    let mut storage = vec![0u64; 2048];
    let capacity = storage.len() * std::mem::size_of::<u64>();
    assert!(line.len() + 1 < capacity);
    let buffer = storage.as_mut_ptr().cast::<c_char>();
    let mut entry = empty_protocol();
    let mut error = 717;
    // SAFETY: the aligned writable storage contains the complete terminated
    // line and ample space for GNU's trailing alias pointer array.
    unsafe {
        std::ptr::copy_nonoverlapping(line.as_ptr(), buffer.cast(), line.len());
        assert_eq!(
            parser(buffer, &mut entry, buffer.cast(), capacity, &mut error),
            1,
        );
    }
    snap(0, &mut entry).unwrap()
}

fn protocol_fixture() -> (std::path::PathBuf, Vec<Snap>) {
    let aliases = (0..72)
        .map(|index| format!("protocol_alias_{index}"))
        .collect::<Vec<_>>()
        .join(" ");
    let lines = [
        format!("{} +253 {aliases}", "p".repeat(1200)),
        "unsigned-max 4294967295 MAXPROTOCOL".to_owned(),
        "tail 254 LASTPROTOCOL".to_owned(),
    ];
    let expected = lines
        .iter()
        .map(|line| gnu_protocol_line(line.as_bytes()))
        .collect::<Vec<_>>();
    assert_eq!(expected[0].0.len(), 1200);
    assert_eq!(expected[0].2.len(), 72);
    assert_eq!(expected[0].1, 253);
    assert_eq!(expected[1].1, -1);
    let contents = format!(
        "# retained synthetic protocols\ninvalid\n{}\n",
        lines.join("\n")
    );
    (
        retained_protocol_file("records", contents.as_bytes()),
        expected,
    )
}

fn protocol_files_read(capacity: usize) -> (c_int, c_int, c_int, Option<Snap>) {
    let mut entry = empty_protocol();
    let mut buffer = vec![0 as c_char; capacity.max(1)];
    let mut error = 717;
    plant_protocol_errno();
    // SAFETY: both output slots and the advertised buffer are live.
    let status = unsafe {
        flu::_nss_files_getprotoent_r(
            (&raw mut entry).cast(),
            buffer.as_mut_ptr(),
            capacity,
            &mut error,
        )
    };
    let ordinary_errno = protocol_errno();
    let record = (status == 1).then(|| snap(0, &mut entry).unwrap());
    (status, error, ordinary_errno, record)
}

fn protocol_public_read(capacity: usize) -> (c_int, c_int, Option<Snap>) {
    let mut entry = empty_protocol();
    let mut buffer = vec![0 as c_char; capacity.max(1)];
    let mut result = (&raw mut entry).cast::<c_void>();
    plant_protocol_errno();
    // SAFETY: all caller objects are live and have the advertised capacities.
    let rc = unsafe {
        flu::getprotoent_r(
            (&raw mut entry).cast(),
            buffer.as_mut_ptr(),
            capacity,
            &mut result,
        )
    };
    let error = protocol_errno();
    if rc != 0 {
        assert!(
            result.is_null(),
            "failed lookup must clear the result pointer"
        );
    }
    (rc, error, snap(rc, result.cast()))
}

#[test]
fn protocols_complete_records_match_independent_gnu_parser() {
    const TEST: &str = "protocols_complete_records_match_independent_gnu_parser";
    if protocol_child(TEST) {
        return;
    }
    let (path, expected) = protocol_fixture();
    select_protocol_file(&path);
    unsafe { flu::setprotoent(0) };
    for record in &expected {
        assert_eq!(
            snap(0, unsafe { flu::getprotoent() }.cast()).as_ref(),
            Some(record)
        );
    }
    assert!(unsafe { flu::getprotoent() }.is_null());
    unsafe { flu::endprotoent() };

    for record in &expected {
        let name = CString::new(record.2.last().unwrap().clone()).unwrap();
        let by_name = unsafe { frankenlibc_abi::resolv_abi::getprotobyname(name.as_ptr()) };
        assert_eq!(snap(0, by_name.cast()).as_ref(), Some(record));
        let by_number = unsafe { frankenlibc_abi::resolv_abi::getprotobynumber(record.1) };
        assert_eq!(snap(0, by_number.cast()).as_ref(), Some(record));
        for by_number in [false, true] {
            let mut entry = empty_protocol();
            let mut buffer = vec![0 as c_char; 16384];
            let mut result = std::ptr::null_mut();
            // SAFETY: query strings, complete result, and buffer remain live.
            let rc = unsafe {
                if by_number {
                    flu::getprotobynumber_r(
                        record.1,
                        (&raw mut entry).cast(),
                        buffer.as_mut_ptr(),
                        buffer.len(),
                        &mut result,
                    )
                } else {
                    flu::getprotobyname_r(
                        name.as_ptr(),
                        (&raw mut entry).cast(),
                        buffer.as_mut_ptr(),
                        buffer.len(),
                        &mut result,
                    )
                }
            };
            assert_eq!(rc, 0);
            assert_eq!(snap(rc, result.cast()).as_ref(), Some(record));
        }
    }
    unsafe { libc::alarm(0) };
}

#[test]
fn protocols_retry_cursor_errors_and_source_changes_match_gnu() {
    const TEST: &str = "protocols_retry_cursor_errors_and_source_changes_match_gnu";
    if protocol_child(TEST) {
        return;
    }
    // Drive the original record-loss bug on the real common database before
    // selecting a synthetic source: a short result must not consume a record.
    let library = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!library.is_null());
    let host_read: EntR = unsafe { std::mem::transmute(sym(library, c"getprotoent_r")) };
    let host_set: Ctl = unsafe { std::mem::transmute(sym(library, c"setprotoent")) };
    let host_end: End = unsafe { std::mem::transmute(sym(library, c"endprotoent")) };
    assert_ne!(host_read as *const (), flu::getprotoent_r as *const ());
    host_set(0);
    unsafe { flu::setprotoent(0) };
    let mut entry = empty_protocol();
    let mut buffer = vec![0 as c_char; 16384];
    let mut result = std::ptr::null_mut();
    let host_small = host_read(&mut entry, buffer.as_mut_ptr(), 8, &mut result);
    assert_eq!(host_small, libc::ERANGE);
    assert!(result.is_null());
    let candidate_small = protocol_public_read(8);
    assert_eq!(candidate_small.0, libc::ERANGE);
    let host_rc = host_read(&mut entry, buffer.as_mut_ptr(), buffer.len(), &mut result);
    let host_first = snap(host_rc, result).expect("nonempty /etc/protocols oracle");
    let candidate_first = protocol_public_read(16384);
    assert_eq!(
        candidate_first.2.as_ref(),
        Some(&host_first),
        "ERANGE consumed a protocol record"
    );
    assert_eq!(candidate_small.1, libc::ERANGE);
    host_end();
    unsafe { flu::endprotoent() };

    let (path, expected) = protocol_fixture();
    select_protocol_file(&path);
    assert_eq!(unsafe { flu::_nss_files_setprotoent(0) }, 1);
    for capacity in [0, 1, 2, 16] {
        let actual = protocol_files_read(capacity);
        assert_eq!(
            (actual.0, actual.1, actual.2),
            (
                -2,
                libc::ERANGE,
                if capacity < 2 {
                    libc::EDOM
                } else {
                    libc::ERANGE
                }
            )
        );
        assert!(actual.3.is_none());
    }
    assert_eq!(protocol_public_read(16384).2.as_ref(), Some(&expected[0]));
    assert_eq!(protocol_files_read(16384).3.as_ref(), Some(&expected[1]));
    assert_eq!(protocol_public_read(16384).2.as_ref(), Some(&expected[2]));
    for capacity in [0, 1, 2] {
        let actual = protocol_files_read(capacity);
        assert_eq!(
            (actual.0, actual.1, actual.2),
            (
                -2,
                libc::ERANGE,
                if capacity < 2 {
                    libc::EDOM
                } else {
                    libc::ERANGE
                }
            )
        );
    }
    assert_eq!(protocol_files_read(3), (0, 717, libc::EDOM, None));
    // Live GNU public EOF returns ENOENT while preserving ordinary errno;
    // unlike a missing backing file, it does not report a new I/O failure.
    assert_eq!(
        protocol_public_read(16384),
        (libc::ENOENT, libc::EDOM, None)
    );

    unsafe { flu::setprotoent(0) };
    assert_eq!(protocol_public_read(16).0, libc::ERANGE);
    assert_eq!(protocol_files_read(16384).3.as_ref(), Some(&expected[0]));
    assert_eq!(protocol_public_read(16384).2.as_ref(), Some(&expected[1]));
    unsafe { flu::setprotoent(0) };
    assert_eq!(protocol_public_read(16).0, libc::ERANGE);
    let replacement = retained_protocol_file("replacement", b"replacement +77 NEWPROTOCOL\n");
    select_protocol_file(&replacement);
    let changed = gnu_protocol_line(b"replacement +77 NEWPROTOCOL");
    assert_eq!(protocol_public_read(16384).2.as_ref(), Some(&changed));
    let keyed = unsafe { frankenlibc_abi::resolv_abi::getprotobyname(c"NEWPROTOCOL".as_ptr()) };
    assert_eq!(snap(0, keyed.cast()).as_ref(), Some(&changed));

    let missing = replacement.with_extension("missing");
    assert!(!missing.exists());
    select_protocol_file(&missing);
    plant_protocol_errno();
    assert_eq!(unsafe { flu::_nss_files_setprotoent(0) }, -1);
    assert_eq!(protocol_errno(), libc::ENOENT);
    assert_eq!(
        protocol_files_read(16384),
        (-1, libc::ENOENT, libc::ENOENT, None)
    );
    assert_eq!(
        protocol_public_read(16384),
        (libc::ENOENT, libc::ENOENT, None)
    );
    plant_protocol_errno();
    assert!(unsafe { flu::getprotoent() }.is_null());
    assert_eq!(protocol_errno(), libc::ENOENT);
    unsafe {
        flu::endprotoent();
        libc::alarm(0)
    };
}

struct ProtocolWorkerContext {
    creator: *mut Protoent,
    keyed_creator: *mut Protoent,
    expected: *const Snap,
}

unsafe fn protocol_record_matches(record: *mut Protoent, expected: &Snap) -> bool {
    // SAFETY: the caller keeps the provider's record and all its strings live.
    unsafe {
        if record.is_null()
            || (*record).p_name.is_null()
            || (*record).p_aliases.is_null()
            || (*record).p_proto != expected.1
            || CStr::from_ptr((*record).p_name).to_bytes() != expected.0.as_slice()
        {
            return false;
        }
        for (index, alias) in expected.2.iter().enumerate() {
            let pointer = *(*record).p_aliases.add(index);
            if pointer.is_null() || CStr::from_ptr(pointer).to_bytes() != alias.as_slice() {
                return false;
            }
        }
        (*(*record).p_aliases.add(expected.2.len())).is_null()
    }
}

unsafe extern "C" fn protocol_native_worker(argument: *mut c_void) -> *mut c_void {
    if frankenlibc_core::pthread::thread::current_thread_handle().is_none() {
        return 1usize as *mut c_void;
    }
    // SAFETY: the creator retains this context and expected records through join.
    // Avoid allocating test-side scratch through the creator's host TLS.
    unsafe {
        let context = &*argument.cast::<ProtocolWorkerContext>();
        let expected = &*context.expected;
        let first = flu::getprotoent().cast::<Protoent>();
        if !protocol_record_matches(first, expected) || first == context.creator {
            return 2usize as *mut c_void;
        }
        if (*first).p_name == (*context.creator).p_name
            || (*first).p_aliases == (*context.creator).p_aliases
        {
            return 3usize as *mut c_void;
        }
        let keyed = frankenlibc_abi::resolv_abi::getprotobynumber(253).cast::<Protoent>();
        if !protocol_record_matches(keyed, expected)
            || keyed == context.keyed_creator
            || (*keyed).p_name == (*context.keyed_creator).p_name
        {
            return 4usize as *mut c_void;
        }
        let mut output = empty_protocol();
        let mut buffer = [0 as c_char; 8];
        let mut result = std::ptr::null_mut();
        if flu::getprotoent_r(
            (&raw mut output).cast(),
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        ) != libc::ERANGE
            || !result.is_null()
        {
            return 5usize as *mut c_void;
        }
        let second = flu::getprotoent().cast::<Protoent>();
        if second.is_null()
            || (*second).p_proto != -1
            || CStr::from_ptr((*second).p_name).to_bytes() != b"unsigned-max"
        {
            return 6usize as *mut c_void;
        }
        let third = flu::getprotoent().cast::<Protoent>();
        if third.is_null() || CStr::from_ptr((*third).p_name).to_bytes() != b"tail" {
            return 7usize as *mut c_void;
        }
        if !flu::getprotoent().is_null() {
            return 8usize as *mut c_void;
        }
        flu::endprotoent();
    }
    std::ptr::null_mut()
}

#[test]
fn protocols_native_workers_preserve_creator_records_and_pending_cursor() {
    const TEST: &str = "protocols_native_workers_preserve_creator_records_and_pending_cursor";
    if protocol_child(TEST) {
        return;
    }
    let (path, expected) = protocol_fixture();
    select_protocol_file(&path);
    unsafe { flu::setprotoent(0) };
    let creator = unsafe { flu::getprotoent() }.cast::<Protoent>();
    assert_eq!(snap(0, creator).as_ref(), Some(&expected[0]));
    let keyed_creator =
        unsafe { frankenlibc_abi::resolv_abi::getprotobynumber(253) }.cast::<Protoent>();
    assert_eq!(snap(0, keyed_creator).as_ref(), Some(&expected[0]));
    assert_eq!(protocol_public_read(8).0, libc::ERANGE);
    let mut context = ProtocolWorkerContext {
        creator,
        keyed_creator,
        expected: &expected[0],
    };
    struct RestoreBackend(bool);
    impl Drop for RestoreBackend {
        fn drop(&mut self) {
            frankenlibc_abi::pthread_abi::pthread_threading_restore_for_tests(self.0);
        }
    }
    let _restore = RestoreBackend(
        frankenlibc_abi::pthread_abi::pthread_threading_swap_force_native_for_tests(),
    );
    for _ in 0..3 {
        let mut thread = 0;
        let mut result = std::ptr::null_mut();
        // SAFETY: argument storage remains live through the matching join.
        assert_eq!(
            unsafe {
                frankenlibc_abi::pthread_abi::pthread_create(
                    &mut thread,
                    std::ptr::null(),
                    Some(protocol_native_worker),
                    (&raw mut context).cast(),
                )
            },
            0
        );
        assert_eq!(
            unsafe { frankenlibc_abi::pthread_abi::pthread_join(thread, &mut result) },
            0
        );
        assert_eq!(result as usize, 0, "native protocol worker failed");
        assert_eq!(snap(0, creator).as_ref(), Some(&expected[0]));
        assert_eq!(snap(0, keyed_creator).as_ref(), Some(&expected[0]));
    }
    assert_eq!(protocol_files_read(16384).3.as_ref(), Some(&expected[1]));
    assert_eq!(protocol_public_read(16384).2.as_ref(), Some(&expected[2]));
    assert!(unsafe { flu::getprotoent() }.is_null());
    unsafe {
        flu::endprotoent();
        libc::alarm(0)
    };
}
