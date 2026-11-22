//! Differential gate: reentrant getservbyname_r / getservbyport_r /
//! getservent_r must return the canonical name, correct s_port byte order,
//! AND the entry's aliases, exactly like glibc.
//!
//! fl's reentrant servent path previously wrote an empty s_aliases list, and
//! getservent_r additionally computed s_port with a 32-bit byteswap (port 1
//! -> 16777216 instead of htons(1) = 256). Both fl and glibc read the same
//! /etc/services; glibc is reached via dlsym to bypass fl's no_mangle
//! interposition.
//!
//! Network fixtures additionally cover the public netent APIs and the files
//! NSS provider. Each fixture runs in a fresh strict/hardened child; no host
//! database is modified. GNU's exported parser supplies field-level oracles
//! for valid records, while explicit assertions pin cursor and error behavior.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::inet_abi as fli;
use frankenlibc_abi::unistd_abi as flu;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::io::Write;
use std::ptr;

const RTLD_NOW: c_int = 2;

#[repr(C)]
struct Servent {
    s_name: *mut c_char,
    s_aliases: *mut *mut c_char,
    s_port: c_int,
    s_proto: *mut c_char,
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
type Snap = (Vec<u8>, c_int, Vec<u8>, Vec<Vec<u8>>);
fn snap(rc: c_int, res: *mut Servent) -> Option<Snap> {
    if rc != 0 || res.is_null() {
        return None;
    }
    let s = unsafe { &*res };
    Some((
        cstr(s.s_name),
        s.s_port,
        cstr(s.s_proto),
        alias_vec(s.s_aliases),
    ))
}

type ByNameR = extern "C" fn(
    *const c_char,
    *const c_char,
    *mut Servent,
    *mut c_char,
    usize,
    *mut *mut Servent,
) -> c_int;
type ByPortR = extern "C" fn(
    c_int,
    *const c_char,
    *mut Servent,
    *mut c_char,
    usize,
    *mut *mut Servent,
) -> c_int;
type EntR = extern "C" fn(*mut Servent, *mut c_char, usize, *mut *mut Servent) -> c_int;
type Ent = extern "C" fn() -> *mut Servent;
type Ctl = extern "C" fn(c_int);
type End = extern "C" fn();

#[test]
fn servent_reentrant_matches_glibc() {
    let lib = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!lib.is_null(), "dlopen libc.so.6 failed");
    let g_byname: ByNameR = unsafe { std::mem::transmute(sym(lib, c"getservbyname_r")) };
    let g_byport: ByPortR = unsafe { std::mem::transmute(sym(lib, c"getservbyport_r")) };
    let g_entr: EntR = unsafe { std::mem::transmute(sym(lib, c"getservent_r")) };
    let g_ent: Ent = unsafe { std::mem::transmute(sym(lib, c"getservent")) };
    let g_set: Ctl = unsafe { std::mem::transmute(sym(lib, c"setservent")) };
    let g_end: End = unsafe { std::mem::transmute(sym(lib, c"endservent")) };

    // Enumerate probe targets from the host db.
    let mut probes: Vec<(Vec<u8>, Vec<u8>, c_int)> = Vec::new();
    g_set(1);
    loop {
        let e = g_ent();
        if e.is_null() {
            break;
        }
        let s = unsafe { &*e };
        probes.push((cstr(s.s_name), cstr(s.s_proto), s.s_port));
        let al = alias_vec(s.s_aliases);
        if let Some(a) = al.first() {
            probes.push((a.clone(), cstr(s.s_proto), s.s_port));
        }
        if probes.len() > 120 {
            break;
        }
    }
    g_end();

    let mut mismatches = Vec::new();
    let mk = || -> (Servent, [c_char; 1024]) {
        (
            Servent {
                s_name: std::ptr::null_mut(),
                s_aliases: std::ptr::null_mut(),
                s_port: 0,
                s_proto: std::ptr::null_mut(),
            },
            [0; 1024],
        )
    };

    for (name, proto, port_nbo) in &probes {
        let cn = CString::new(name.clone()).unwrap();
        let cp = CString::new(proto.clone()).unwrap();

        // getservbyname_r
        let (mut ge, mut gb) = mk();
        let mut gres: *mut Servent = std::ptr::null_mut();
        let grc = g_byname(
            cn.as_ptr(),
            cp.as_ptr(),
            &mut ge,
            gb.as_mut_ptr(),
            gb.len(),
            &mut gres,
        );
        let g = snap(grc, gres);

        let (mut fe, mut fb) = mk();
        let mut fres: *mut Servent = std::ptr::null_mut();
        let frc = unsafe {
            fli::getservbyname_r(
                cn.as_ptr(),
                cp.as_ptr(),
                (&mut fe as *mut Servent).cast(),
                fb.as_mut_ptr(),
                fb.len(),
                (&mut fres as *mut *mut Servent).cast(),
            )
        };
        let f = snap(frc, fres);
        if g != f {
            mismatches.push(format!(
                "getservbyname_r({name:?},{proto:?}): glibc={g:?} fl={f:?}"
            ));
        }

        // getservbyport_r
        let (mut ge, mut gb) = mk();
        let mut gres: *mut Servent = std::ptr::null_mut();
        let grc = g_byport(
            *port_nbo,
            cp.as_ptr(),
            &mut ge,
            gb.as_mut_ptr(),
            gb.len(),
            &mut gres,
        );
        let g = snap(grc, gres);

        let (mut fe, mut fb) = mk();
        let mut fres: *mut Servent = std::ptr::null_mut();
        let frc = unsafe {
            fli::getservbyport_r(
                *port_nbo,
                cp.as_ptr(),
                (&mut fe as *mut Servent).cast(),
                fb.as_mut_ptr(),
                fb.len(),
                (&mut fres as *mut *mut Servent).cast(),
            )
        };
        let f = snap(frc, fres);
        if g != f {
            mismatches.push(format!(
                "getservbyport_r({port_nbo},{proto:?}): glibc={g:?} fl={f:?}"
            ));
        }
    }

    // getservent_r lockstep enumeration
    let mut glist = Vec::new();
    g_set(1);
    loop {
        let (mut e, mut b) = mk();
        let mut res: *mut Servent = std::ptr::null_mut();
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
    unsafe { flu::setservent(1) };
    loop {
        let (mut e, mut b) = mk();
        let mut res: *mut Servent = std::ptr::null_mut();
        let rc = unsafe {
            flu::getservent_r(
                (&mut e as *mut Servent).cast(),
                b.as_mut_ptr(),
                b.len(),
                (&mut res as *mut *mut Servent).cast(),
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
    unsafe { flu::endservent() };
    if flist != glist {
        // Report the FIRST differing entry, not just the lengths: the two lists
        // can be the same length and still diverge entry-for-entry, in which case
        // a length-only message says nothing about what is wrong (bd-5zait2).
        let first_diff = flist
            .iter()
            .zip(glist.iter())
            .enumerate()
            .find(|(_, (f, g))| f != g)
            .map(|(i, (f, g))| {
                format!("\n  first differing index {i}:\n    fl:    {f:?}\n    glibc: {g:?}")
            })
            .unwrap_or_default();
        mismatches.push(format!(
            "getservent_r enumeration diverged: fl_len={} glibc_len={}{}",
            flist.len(),
            glist.len(),
            first_diff
        ));
    }

    assert!(
        mismatches.is_empty(),
        "reentrant servent diverged from glibc ({} cases):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

#[repr(C)]
#[derive(Default)]
struct Netent {
    n_name: *mut c_char,
    n_aliases: *mut *mut c_char,
    n_addrtype: c_int,
    n_net: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NetworkSnapshot {
    name: Vec<u8>,
    aliases: Vec<Vec<u8>>,
    family: c_int,
    number: u32,
}

const NETWORK_ERRNO_SENTINEL: c_int = 711;
const NETWORK_ERROR_SENTINEL: c_int = 712;
const NETWORK_HERROR_SENTINEL: c_int = 713;
const NETWORK_HOST_NOT_FOUND: c_int = 1;
const NETWORK_INTERNAL_ERROR: c_int = -1;
const NETWORK_NSS_SUCCESS: c_int = 1;
const NETWORK_NSS_NOTFOUND: c_int = 0;
const NETWORK_NSS_UNAVAIL: c_int = -1;
const NETWORK_NSS_TRYAGAIN: c_int = -2;

fn network_errno() -> c_int {
    // SAFETY: the ABI accessor returns this thread's initialized errno cell.
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() }
}

fn set_network_errno(value: c_int) {
    // SAFETY: the ABI accessor returns this thread's writable errno cell.
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = value };
}

fn network_long_name() -> String {
    format!("long_network_{}", "n".repeat(700))
}

fn network_fixture_lines() -> Vec<String> {
    let aliases = (0..80)
        .map(|index| format!("long_alias_{index:03}_{}", "a".repeat(13)))
        .collect::<Vec<_>>()
        .join(" ");
    vec![
        "MiXeDNet 127 primary AliasTwo repeated repeated # not-an-alias".into(),
        "OctalNet 0xa.020 hexAlias octAlias".into(),
        format!("{} 192.168.1 {aliases}", network_long_name()),
        "NoAliases 1.2.3.4".into(),
        "ZeroNet 0 zeroAlias".into(),
        "MaxNet 255.255.255.255 maxAlias".into(),
    ]
}

fn network_fixture_bytes() -> Vec<u8> {
    // The last record deliberately has no final newline.
    format!(
        "# isolated networks fixture\n\n \t# indented comment\n{}",
        network_fixture_lines().join("\n\n")
    )
    .into_bytes()
}

fn with_network_fixture(test: &str, content: Option<&[u8]>, run: impl FnOnce()) {
    const CHILD: &str = "FRANKENLIBC_NETWORK_TEST_CHILD";
    if std::env::var(CHILD).as_deref() == Ok(test) {
        run();
        return;
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    for mode in ["strict", "hardened"] {
        let path = std::env::temp_dir().join(format!(
            "frankenlibc-networks-{}-{nonce}-{mode}-{test}",
            std::process::id()
        ));
        assert!(!path.exists(), "fixture paths must be unique");
        if let Some(content) = content {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .expect("create isolated networks fixture");
            file.write_all(content).expect("write networks fixture");
        }
        // Retain the fixture for inspection. In particular, no global process
        // environment is changed and no /etc file is opened for writing.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env(CHILD, test)
            .env("FRANKENLIBC_MODE", mode)
            .env("FRANKENLIBC_NETWORKS_PATH", &path)
            .output()
            .expect("run isolated networks test");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "networks child {test} mode={mode} failed:\n{stdout}\n{stderr}"
        );
        assert!(
            stdout.contains("test result: ok. 1 passed; 0 failed;"),
            "networks child must execute exactly one test:\n{stdout}\n{stderr}"
        );
    }
}

struct NetworkBuffer {
    bytes: Vec<u8>,
    start: usize,
    length: usize,
}

impl NetworkBuffer {
    fn new(length: usize) -> Self {
        let align = std::mem::align_of::<*mut c_char>();
        let bytes = vec![0xa5; length + 3 * align];
        let start = align - (bytes.as_ptr() as usize % align) + 1;
        assert_ne!((bytes.as_ptr() as usize + start) % align, 0);
        Self {
            bytes,
            start,
            length,
        }
    }

    fn pointer(&mut self) -> *mut c_char {
        self.bytes[self.start..].as_mut_ptr().cast()
    }

    fn region(&self) -> &[u8] {
        &self.bytes[self.start..self.start + self.length]
    }

    fn assert_guards(&self) {
        assert!(self.bytes[..self.start].iter().all(|&byte| byte == 0xa5));
        assert!(
            self.bytes[self.start + self.length..]
                .iter()
                .all(|&byte| byte == 0xa5),
            "network packing exceeded the caller's buffer length"
        );
    }
}

fn network_string(pointer: *const c_char, region: Option<&[u8]>) -> Vec<u8> {
    assert!(!pointer.is_null(), "network strings must be non-null");
    if let Some(region) = region {
        let offset = (pointer as usize)
            .checked_sub(region.as_ptr() as usize)
            .expect("network string precedes the caller's buffer");
        let tail = region
            .get(offset..)
            .expect("network string exceeds the caller's buffer");
        let length = tail
            .iter()
            .position(|&byte| byte == 0)
            .expect("network string must terminate within the caller's buffer");
        return tail[..length].to_vec();
    }
    // SAFETY: successful nonreentrant netent calls promise live C strings
    // until the next call; this snapshot is made before another ABI call.
    unsafe { CStr::from_ptr(pointer).to_bytes().to_vec() }
}

fn network_snapshot(entry: &Netent, region: Option<&[u8]>) -> NetworkSnapshot {
    assert!(
        !entry.n_aliases.is_null(),
        "alias table must contain a NULL"
    );
    assert_eq!(
        entry.n_aliases as usize % std::mem::align_of::<*mut c_char>(),
        0,
        "alias pointers must be aligned even when the caller buffer is not"
    );
    let mut aliases = Vec::new();
    for index in 0..=1024 {
        let slot = entry.n_aliases.wrapping_add(index);
        if let Some(region) = region {
            let start = region.as_ptr() as usize;
            let end = start + region.len();
            let slot_end = (slot as usize)
                .checked_add(std::mem::size_of::<*mut c_char>())
                .unwrap();
            assert!(
                slot as usize >= start && slot_end <= end,
                "the complete alias pointer table must be in caller storage"
            );
        }
        // SAFETY: alignment and caller-buffer bounds were checked above;
        // nonreentrant results promise a live NULL-terminated pointer table.
        let alias = unsafe { slot.read() };
        if alias.is_null() {
            return NetworkSnapshot {
                name: network_string(entry.n_name, region),
                aliases,
                family: entry.n_addrtype,
                number: entry.n_net,
            };
        }
        aliases.push(network_string(alias, region));
    }
    panic!("network alias table was not NULL-terminated");
}

fn network_expected() -> Vec<NetworkSnapshot> {
    type Parse =
        unsafe extern "C" fn(*mut c_char, *mut Netent, *mut c_void, usize, *mut c_int) -> c_int;
    // SAFETY: the symbols are obtained from an explicit live libc handle and
    // their signatures match the GNU exported network parser ABI.
    let parse: Parse = unsafe {
        let library = dlopen(c"libc.so.6".as_ptr(), RTLD_NOW);
        assert!(!library.is_null());
        std::mem::transmute(sym(library, c"_nss_files_parse_netent"))
    };
    network_fixture_lines()
        .into_iter()
        .map(|line| {
            let mut buffer = vec![0u8; 16_384];
            buffer[..line.len()].copy_from_slice(line.as_bytes());
            let mut entry = Netent::default();
            let mut error = NETWORK_ERROR_SENTINEL;
            // SAFETY: mutable line and parser data share one sufficiently
            // large live allocation, with a NUL after the line text.
            let rc = unsafe {
                parse(
                    buffer.as_mut_ptr().cast(),
                    &mut entry,
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut error,
                )
            };
            assert_eq!(rc, 1, "GNU must parse every oracle fixture line");
            assert_eq!(error, NETWORK_ERROR_SENTINEL);
            network_snapshot(&entry, Some(&buffer))
        })
        .collect()
}

fn network_nonreentrant_snapshot(entry: *mut c_void) -> NetworkSnapshot {
    assert!(
        !entry.is_null(),
        "network lookup unexpectedly returned NULL"
    );
    // SAFETY: a successful call returns an aligned live netent; snapshot it
    // immediately before any other call can reuse its backing storage.
    network_snapshot(unsafe { &*entry.cast::<Netent>() }, None)
}

fn network_next_snapshot() -> NetworkSnapshot {
    let mut entry = Netent::default();
    let mut buffer = NetworkBuffer::new(16_384);
    let mut result = ptr::null_mut();
    let mut h_error = NETWORK_HERROR_SENTINEL;
    set_network_errno(NETWORK_ERRNO_SENTINEL);
    // SAFETY: all pointers refer to live correctly typed caller storage.
    let rc = unsafe {
        flu::getnetent_r(
            (&raw mut entry).cast(),
            buffer.pointer(),
            buffer.length,
            &mut result,
            &mut h_error,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(result, (&raw mut entry).cast());
    assert_eq!(h_error, NETWORK_HERROR_SENTINEL);
    assert_eq!(network_errno(), NETWORK_ERRNO_SENTINEL);
    buffer.assert_guards();
    network_snapshot(&entry, Some(buffer.region()))
}

#[test]
fn network_public_lookup_aliases_and_address_families() {
    with_network_fixture(
        "network_public_lookup_aliases_and_address_families",
        Some(&network_fixture_bytes()),
        || {
            let expected = network_expected();
            assert_eq!(
                expected
                    .iter()
                    .map(|entry| entry.number)
                    .collect::<Vec<_>>(),
                [
                    0x7f00_0000,
                    0x0a10_0000,
                    0xc0a8_0100,
                    0x0102_0304,
                    0,
                    u32::MAX
                ]
            );
            for wanted in &expected {
                let mut names = vec![wanted.name.clone(), wanted.name.to_ascii_uppercase()];
                names.extend(
                    wanted
                        .aliases
                        .iter()
                        .map(|alias| alias.to_ascii_uppercase()),
                );
                for name in names {
                    let query = CString::new(name).unwrap();
                    let mut entry = Netent::default();
                    let mut buffer = NetworkBuffer::new(16_384);
                    let mut result = ptr::null_mut();
                    let mut h_error = NETWORK_HERROR_SENTINEL;
                    set_network_errno(NETWORK_ERRNO_SENTINEL);
                    // SAFETY: inputs are terminated and every output is live.
                    let rc = unsafe {
                        flu::getnetbyname_r(
                            query.as_ptr(),
                            (&raw mut entry).cast(),
                            buffer.pointer(),
                            buffer.length,
                            &mut result,
                            &mut h_error,
                        )
                    };
                    assert_eq!(rc, 0, "getnetbyname_r({query:?})");
                    assert_eq!(result, (&raw mut entry).cast());
                    assert_eq!(h_error, NETWORK_HERROR_SENTINEL);
                    assert_eq!(network_errno(), 0);
                    assert_eq!(&network_snapshot(&entry, Some(buffer.region())), wanted);
                    buffer.assert_guards();
                }
                for family in [libc::AF_INET, libc::AF_UNSPEC] {
                    let mut entry = Netent::default();
                    let mut buffer = NetworkBuffer::new(16_384);
                    let mut result = ptr::null_mut();
                    let mut h_error = NETWORK_HERROR_SENTINEL;
                    set_network_errno(NETWORK_ERRNO_SENTINEL);
                    // SAFETY: output storage remains live throughout the call.
                    let rc = unsafe {
                        flu::getnetbyaddr_r(
                            wanted.number,
                            family,
                            (&raw mut entry).cast(),
                            buffer.pointer(),
                            buffer.length,
                            &mut result,
                            &mut h_error,
                        )
                    };
                    assert_eq!(rc, 0);
                    assert_eq!(result, (&raw mut entry).cast());
                    assert_eq!(h_error, NETWORK_HERROR_SENTINEL);
                    assert_eq!(network_errno(), 0);
                    assert_eq!(&network_snapshot(&entry, Some(buffer.region())), wanted);
                    buffer.assert_guards();
                }
            }

            // A miss and an unsupported family are ordinary lookup failures;
            // unlike enumeration, keyed lookups publish HOST_NOT_FOUND.
            for by_address in [false, true] {
                let mut entry = Netent::default();
                let mut buffer = NetworkBuffer::new(16_384);
                let mut result = (&raw mut entry).cast();
                let mut h_error = NETWORK_HERROR_SENTINEL;
                set_network_errno(NETWORK_ERRNO_SENTINEL);
                // SAFETY: all arguments satisfy the reentrant ABI contract.
                let rc = unsafe {
                    if by_address {
                        flu::getnetbyaddr_r(
                            expected[0].number,
                            libc::AF_INET6,
                            (&raw mut entry).cast(),
                            buffer.pointer(),
                            buffer.length,
                            &mut result,
                            &mut h_error,
                        )
                    } else {
                        flu::getnetbyname_r(
                            c"absent-network-fixture-name".as_ptr(),
                            (&raw mut entry).cast(),
                            buffer.pointer(),
                            buffer.length,
                            &mut result,
                            &mut h_error,
                        )
                    }
                };
                assert_eq!(rc, 0);
                assert!(result.is_null());
                assert_eq!(h_error, NETWORK_HOST_NOT_FOUND);
                assert_eq!(network_errno(), 0);
                buffer.assert_guards();
            }
            for by_address in [false, true] {
                let mut entry = Netent::default();
                let mut buffer = NetworkBuffer::new(1);
                let mut result = (&raw mut entry).cast();
                let mut h_error = NETWORK_HERROR_SENTINEL;
                set_network_errno(NETWORK_ERRNO_SENTINEL);
                // SAFETY: the one-byte region is valid but deliberately small.
                let rc = unsafe {
                    if by_address {
                        flu::getnetbyaddr_r(
                            expected[0].number,
                            libc::AF_INET,
                            (&raw mut entry).cast(),
                            buffer.pointer(),
                            buffer.length,
                            &mut result,
                            &mut h_error,
                        )
                    } else {
                        flu::getnetbyname_r(
                            c"primary".as_ptr(),
                            (&raw mut entry).cast(),
                            buffer.pointer(),
                            buffer.length,
                            &mut result,
                            &mut h_error,
                        )
                    }
                };
                assert_eq!(rc, libc::ERANGE);
                assert!(result.is_null());
                assert_eq!(h_error, NETWORK_INTERNAL_ERROR);
                assert_eq!(network_errno(), libc::ERANGE);
                buffer.assert_guards();
            }
        },
    );
}

#[test]
fn network_reentrant_cursor_retries_and_thread_isolation() {
    with_network_fixture(
        "network_reentrant_cursor_retries_and_thread_isolation",
        Some(&network_fixture_bytes()),
        || {
            let expected = network_expected();
            // SAFETY: iterator control functions have no pointer preconditions.
            unsafe { flu::setnetent(1) };
            for wanted in &expected {
                for length in [1, 16, 16] {
                    let mut entry = Netent::default();
                    let mut buffer = NetworkBuffer::new(length);
                    let mut result = (&raw mut entry).cast();
                    let mut h_error = NETWORK_HERROR_SENTINEL;
                    set_network_errno(NETWORK_ERRNO_SENTINEL);
                    // SAFETY: writable storage is valid, but intentionally too
                    // small; retries must leave the same record pending.
                    let rc = unsafe {
                        flu::getnetent_r(
                            (&raw mut entry).cast(),
                            buffer.pointer(),
                            buffer.length,
                            &mut result,
                            &mut h_error,
                        )
                    };
                    assert_eq!(rc, libc::ERANGE);
                    assert!(result.is_null());
                    assert_eq!(h_error, NETWORK_HERROR_SENTINEL);
                    assert_eq!(network_errno(), libc::ERANGE);
                    buffer.assert_guards();
                }
                assert_eq!(&network_next_snapshot(), wanted);
            }
            for _ in 0..2 {
                let mut entry = Netent::default();
                let mut buffer = NetworkBuffer::new(16_384);
                let mut result = (&raw mut entry).cast();
                let mut h_error = NETWORK_HERROR_SENTINEL;
                set_network_errno(NETWORK_ERRNO_SENTINEL);
                // SAFETY: every output slot is live writable caller storage.
                let rc = unsafe {
                    flu::getnetent_r(
                        (&raw mut entry).cast(),
                        buffer.pointer(),
                        buffer.length,
                        &mut result,
                        &mut h_error,
                    )
                };
                assert_eq!(rc, libc::ENOENT);
                assert!(result.is_null());
                assert_eq!(h_error, NETWORK_HERROR_SENTINEL);
                assert_eq!(network_errno(), NETWORK_ERRNO_SENTINEL);
                buffer.assert_guards();
            }

            // setnetent rewinds EOF; a second thread has its own cursor even
            // when both threads enumerate the same fixture simultaneously.
            // SAFETY: iterator control functions have no pointer preconditions.
            unsafe { flu::setnetent(0) };
            assert_eq!(network_next_snapshot(), expected[0]);
            let worker_expected = expected.clone();
            std::thread::spawn(move || {
                // SAFETY: this changes only the worker's iterator state.
                unsafe { flu::setnetent(0) };
                assert_eq!(network_next_snapshot(), worker_expected[0]);
                assert_eq!(network_next_snapshot(), worker_expected[1]);
                // SAFETY: closing a thread-local iterator has no preconditions.
                unsafe { flu::endnetent() };
            })
            .join()
            .expect("independent network iterator thread");
            assert_eq!(network_next_snapshot(), expected[1]);
            // SAFETY: closing permits the next getnetent_r to reopen the file.
            unsafe { flu::endnetent() };
            assert_eq!(network_next_snapshot(), expected[0]);
            // SAFETY: close the reopened thread-local iterator.
            unsafe { flu::endnetent() };
        },
    );
}

#[test]
fn network_nonreentrant_preserves_long_records() {
    with_network_fixture(
        "network_nonreentrant_preserves_long_records",
        Some(&network_fixture_bytes()),
        || {
            let expected = network_expected();
            assert!(expected[2].name.len() > 512);
            assert_eq!(expected[2].aliases.len(), 80);
            // SAFETY: iterator control has no pointer preconditions.
            unsafe { flu::setnetent(1) };
            for (index, wanted) in expected.iter().enumerate() {
                // Mixing the reentrant and nonreentrant API must still consume
                // one ordered stream; the long record takes the nonreentrant path.
                let actual = if index == 1 {
                    network_next_snapshot()
                } else {
                    // SAFETY: snapshot the live result before the next call.
                    network_nonreentrant_snapshot(unsafe { flu::getnetent() })
                };
                assert_eq!(&actual, wanted);
            }
            // SAFETY: end of this fixture is an ordinary iterator result.
            assert!(unsafe { flu::getnetent() }.is_null());
            // SAFETY: iterator control has no pointer preconditions.
            unsafe { flu::endnetent() };

            for wanted in &expected {
                let query = CString::new(wanted.name.to_ascii_uppercase()).unwrap();
                // SAFETY: query is a live NUL-terminated name.
                let actual =
                    network_nonreentrant_snapshot(unsafe { flu::getnetbyname(query.as_ptr()) });
                assert_eq!(&actual, wanted);
                if let Some(alias) = wanted.aliases.last() {
                    let query = CString::new(alias.to_ascii_uppercase()).unwrap();
                    // SAFETY: query is a live NUL-terminated alias.
                    let actual =
                        network_nonreentrant_snapshot(unsafe { flu::getnetbyname(query.as_ptr()) });
                    assert_eq!(&actual, wanted);
                }
                for family in [libc::AF_INET, libc::AF_UNSPEC] {
                    // SAFETY: the numeric lookup takes no caller pointers.
                    let actual = network_nonreentrant_snapshot(unsafe {
                        flu::getnetbyaddr(wanted.number, family)
                    });
                    assert_eq!(&actual, wanted);
                }
            }
            // SAFETY: AF_INET6 cannot match an AF_INET networks entry.
            assert!(unsafe { flu::getnetbyaddr(expected[0].number, libc::AF_INET6) }.is_null());
        },
    );
}

#[test]
fn network_nss_files_lookup_and_cursor_contracts() {
    with_network_fixture(
        "network_nss_files_lookup_and_cursor_contracts",
        Some(&network_fixture_bytes()),
        || {
            let expected = network_expected();
            for wanted in &expected {
                let query = CString::new(
                    wanted
                        .aliases
                        .last()
                        .unwrap_or(&wanted.name)
                        .to_ascii_uppercase(),
                )
                .unwrap();
                for family in [None, Some(libc::AF_INET), Some(libc::AF_UNSPEC)] {
                    let lengths: &[usize] = if wanted.name.len() > 512 {
                        &[1, 128, 16_384]
                    } else {
                        &[1, 16_384]
                    };
                    for &length in lengths {
                        let mut entry = Netent::default();
                        let mut buffer = NetworkBuffer::new(length);
                        let mut error = NETWORK_ERROR_SENTINEL;
                        let mut h_error = NETWORK_HERROR_SENTINEL;
                        set_network_errno(NETWORK_ERRNO_SENTINEL);
                        // SAFETY: names and all NSS output storage remain live.
                        let status = unsafe {
                            if let Some(family) = family {
                                flu::_nss_files_getnetbyaddr_r(
                                    wanted.number,
                                    family,
                                    (&raw mut entry).cast(),
                                    buffer.pointer(),
                                    buffer.length,
                                    &mut error,
                                    &mut h_error,
                                )
                            } else {
                                flu::_nss_files_getnetbyname_r(
                                    query.as_ptr(),
                                    (&raw mut entry).cast(),
                                    buffer.pointer(),
                                    buffer.length,
                                    &mut error,
                                    &mut h_error,
                                )
                            }
                        };
                        if length < 16_384 {
                            assert_eq!(status, NETWORK_NSS_TRYAGAIN);
                            assert_eq!(error, libc::ERANGE);
                            assert_eq!(h_error, NETWORK_INTERNAL_ERROR);
                            assert_eq!(
                                network_errno(),
                                if length == 1 {
                                    NETWORK_ERRNO_SENTINEL
                                } else {
                                    libc::ERANGE
                                }
                            );
                        } else {
                            assert_eq!(status, NETWORK_NSS_SUCCESS);
                            assert_eq!(error, NETWORK_ERROR_SENTINEL);
                            assert_eq!(h_error, NETWORK_HERROR_SENTINEL);
                            assert_eq!(network_errno(), NETWORK_ERRNO_SENTINEL);
                            assert_eq!(&network_snapshot(&entry, Some(buffer.region())), wanted);
                        }
                        buffer.assert_guards();
                    }
                }
            }
            for by_address in [false, true] {
                let mut entry = Netent::default();
                let mut buffer = NetworkBuffer::new(16_384);
                let mut error = NETWORK_ERROR_SENTINEL;
                let mut h_error = NETWORK_HERROR_SENTINEL;
                set_network_errno(NETWORK_ERRNO_SENTINEL);
                // SAFETY: all output slots satisfy the NSS call contract.
                let status = unsafe {
                    if by_address {
                        flu::_nss_files_getnetbyaddr_r(
                            expected[0].number,
                            libc::AF_INET6,
                            (&raw mut entry).cast(),
                            buffer.pointer(),
                            buffer.length,
                            &mut error,
                            &mut h_error,
                        )
                    } else {
                        flu::_nss_files_getnetbyname_r(
                            c"absent-network-fixture-name".as_ptr(),
                            (&raw mut entry).cast(),
                            buffer.pointer(),
                            buffer.length,
                            &mut error,
                            &mut h_error,
                        )
                    }
                };
                assert_eq!(status, NETWORK_NSS_NOTFOUND);
                assert_eq!(error, NETWORK_ERROR_SENTINEL);
                assert_eq!(h_error, NETWORK_HOST_NOT_FOUND);
                assert_eq!(network_errno(), NETWORK_ERRNO_SENTINEL);
                buffer.assert_guards();
            }

            set_network_errno(NETWORK_ERRNO_SENTINEL);
            // SAFETY: NSS control functions take no caller storage.
            assert_eq!(unsafe { flu::_nss_files_setnetent(1) }, NETWORK_NSS_SUCCESS);
            assert_eq!(network_errno(), NETWORK_ERRNO_SENTINEL);
            for wanted in &expected {
                let mut entry = Netent::default();
                let mut error = NETWORK_ERROR_SENTINEL;
                let mut h_error = NETWORK_HERROR_SENTINEL;
                for length in [1, 16, 16] {
                    let mut tiny = NetworkBuffer::new(length);
                    set_network_errno(NETWORK_ERRNO_SENTINEL);
                    // SAFETY: both sizes are valid but too small. Sixteen
                    // bytes reaches packing, exercising the pending-line retry.
                    let status = unsafe {
                        flu::_nss_files_getnetent_r(
                            (&raw mut entry).cast(),
                            tiny.pointer(),
                            tiny.length,
                            &mut error,
                            &mut h_error,
                        )
                    };
                    assert_eq!(status, NETWORK_NSS_TRYAGAIN);
                    assert_eq!(error, libc::ERANGE);
                    assert_eq!(h_error, NETWORK_INTERNAL_ERROR);
                    assert_eq!(
                        network_errno(),
                        if length == 1 {
                            NETWORK_ERRNO_SENTINEL
                        } else {
                            libc::ERANGE
                        }
                    );
                    tiny.assert_guards();
                }

                let mut buffer = NetworkBuffer::new(16_384);
                error = NETWORK_ERROR_SENTINEL;
                h_error = NETWORK_HERROR_SENTINEL;
                set_network_errno(NETWORK_ERRNO_SENTINEL);
                // SAFETY: enlarged storage can hold the pending record.
                let status = unsafe {
                    flu::_nss_files_getnetent_r(
                        (&raw mut entry).cast(),
                        buffer.pointer(),
                        buffer.length,
                        &mut error,
                        &mut h_error,
                    )
                };
                assert_eq!(status, NETWORK_NSS_SUCCESS);
                assert_eq!(error, NETWORK_ERROR_SENTINEL);
                assert_eq!(h_error, NETWORK_HERROR_SENTINEL);
                assert_eq!(network_errno(), NETWORK_ERRNO_SENTINEL);
                assert_eq!(&network_snapshot(&entry, Some(buffer.region())), wanted);
                buffer.assert_guards();
            }
            for _ in 0..2 {
                let mut entry = Netent::default();
                let mut buffer = NetworkBuffer::new(16_384);
                let mut error = NETWORK_ERROR_SENTINEL;
                let mut h_error = NETWORK_HERROR_SENTINEL;
                set_network_errno(NETWORK_ERRNO_SENTINEL);
                // SAFETY: all outputs are live, even though EOF yields no entry.
                let status = unsafe {
                    flu::_nss_files_getnetent_r(
                        (&raw mut entry).cast(),
                        buffer.pointer(),
                        buffer.length,
                        &mut error,
                        &mut h_error,
                    )
                };
                assert_eq!(status, NETWORK_NSS_NOTFOUND);
                assert_eq!(error, NETWORK_ERROR_SENTINEL);
                assert_eq!(h_error, NETWORK_HOST_NOT_FOUND);
                assert_eq!(network_errno(), NETWORK_ERRNO_SENTINEL);
                buffer.assert_guards();
            }
            // SAFETY: provider rewind and close use the same public cursor.
            assert_eq!(unsafe { flu::_nss_files_setnetent(0) }, NETWORK_NSS_SUCCESS);
            assert_eq!(network_next_snapshot(), expected[0]);
            // SAFETY: provider close permits the public iterator to reopen.
            assert_eq!(unsafe { flu::_nss_files_endnetent() }, NETWORK_NSS_SUCCESS);
            assert_eq!(network_next_snapshot(), expected[0]);
            // SAFETY: close the reopened cursor.
            unsafe { flu::endnetent() };
        },
    );
}

#[test]
fn network_missing_file_is_unavailable() {
    with_network_fixture("network_missing_file_is_unavailable", None, || {
        // This is the native backend's explicit unavailable-source contract.
        // Unlike the valid-record field oracle, it does not claim differential
        // coverage against a host whose /etc/networks cannot be replaced.
        for by_address in [false, true] {
            let mut entry = Netent::default();
            let mut buffer = NetworkBuffer::new(4096);
            let mut result = (&raw mut entry).cast();
            let mut h_error = NETWORK_HERROR_SENTINEL;
            set_network_errno(NETWORK_ERRNO_SENTINEL);
            // SAFETY: the missing source does not affect caller pointer validity.
            let rc = unsafe {
                if by_address {
                    flu::getnetbyaddr_r(
                        0x7f00_0000,
                        libc::AF_INET,
                        (&raw mut entry).cast(),
                        buffer.pointer(),
                        buffer.length,
                        &mut result,
                        &mut h_error,
                    )
                } else {
                    flu::getnetbyname_r(
                        c"MiXeDNet".as_ptr(),
                        (&raw mut entry).cast(),
                        buffer.pointer(),
                        buffer.length,
                        &mut result,
                        &mut h_error,
                    )
                }
            };
            assert_eq!(rc, libc::ENOENT);
            assert!(result.is_null());
            assert_eq!(h_error, NETWORK_INTERNAL_ERROR);
            assert_eq!(network_errno(), libc::ENOENT);
            buffer.assert_guards();

            let mut error = NETWORK_ERROR_SENTINEL;
            h_error = NETWORK_HERROR_SENTINEL;
            // SAFETY: the same live outputs are suitable for an NSS call.
            let status = unsafe {
                if by_address {
                    flu::_nss_files_getnetbyaddr_r(
                        0x7f00_0000,
                        libc::AF_INET,
                        (&raw mut entry).cast(),
                        buffer.pointer(),
                        buffer.length,
                        &mut error,
                        &mut h_error,
                    )
                } else {
                    flu::_nss_files_getnetbyname_r(
                        c"MiXeDNet".as_ptr(),
                        (&raw mut entry).cast(),
                        buffer.pointer(),
                        buffer.length,
                        &mut error,
                        &mut h_error,
                    )
                }
            };
            assert_eq!(status, NETWORK_NSS_UNAVAIL);
            assert_eq!(error, libc::ENOENT);
            assert_eq!(h_error, NETWORK_INTERNAL_ERROR);
            buffer.assert_guards();
        }
        let mut entry = Netent::default();
        let mut buffer = NetworkBuffer::new(4096);
        let mut result = (&raw mut entry).cast();
        let mut h_error = NETWORK_HERROR_SENTINEL;
        // SAFETY: all output slots are live; reopening the missing file fails.
        let rc = unsafe {
            flu::getnetent_r(
                (&raw mut entry).cast(),
                buffer.pointer(),
                buffer.length,
                &mut result,
                &mut h_error,
            )
        };
        assert_eq!(rc, libc::ENOENT);
        assert!(result.is_null());
        assert_eq!(h_error, NETWORK_HERROR_SENTINEL);
        let mut error = NETWORK_ERROR_SENTINEL;
        // SAFETY: all NSS output slots are valid caller storage.
        let status = unsafe {
            flu::_nss_files_getnetent_r(
                (&raw mut entry).cast(),
                buffer.pointer(),
                buffer.length,
                &mut error,
                &mut h_error,
            )
        };
        assert_eq!(status, NETWORK_NSS_UNAVAIL);
        assert_eq!(error, libc::ENOENT);
        assert_eq!(h_error, NETWORK_INTERNAL_ERROR);
        buffer.assert_guards();
        // SAFETY: failed opens must still have a closable iterator state.
        assert_eq!(unsafe { flu::_nss_files_setnetent(0) }, NETWORK_NSS_UNAVAIL);
        // SAFETY: closing an unopened provider cursor succeeds.
        assert_eq!(unsafe { flu::_nss_files_endnetent() }, NETWORK_NSS_SUCCESS);
    });
}
