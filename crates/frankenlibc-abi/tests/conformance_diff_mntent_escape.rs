//! Differential gate for getmntent_r / addmntent octal-escape handling vs glibc.
//!
//! glibc's mount-table I/O octal-escapes whitespace and backslash in the four
//! string fields so values may contain spaces/tabs/newlines without breaking
//! the line format: `getmntent_r` DECODES `\040`→space, `\011`→tab, `\012`→
//! newline, `\134`→backslash (and nothing else — `\054` stays literal), and
//! `addmntent` ENCODES the same four. fl previously copied field bytes verbatim
//! in both directions, so a value with an embedded space round-tripped to a
//! corrupted, unparseable line. It also skipped lines with fewer than four
//! fields, where glibc returns them with the missing fields empty.
//!
//! fl is exercised through its own setmntent/getmntent_r/addmntent/endmntent
//! Rust paths; glibc is reached via dlsym on libc.so.6 so the fn pointers bypass
//! fl's no_mangle interposition of the same symbols. Both fill the identical
//! `struct mntent` ABI layout, read here through a shared repr(C) struct.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::io::Write;

const RTLD_NOW: c_int = 2;

#[repr(C)]
struct Mntent {
    mnt_fsname: *mut c_char,
    mnt_dir: *mut c_char,
    mnt_type: *mut c_char,
    mnt_opts: *mut c_char,
    mnt_freq: c_int,
    mnt_passno: c_int,
}

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
type SetFn = extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type GetRFn = extern "C" fn(*mut c_void, *mut Mntent, *mut c_char, c_int) -> *mut Mntent;
type EndFn = extern "C" fn(*mut c_void) -> c_int;
type AddFn = extern "C" fn(*mut c_void, *const Mntent) -> c_int;

fn libc() -> *mut c_void {
    let h = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!h.is_null(), "dlopen libc failed");
    h
}
fn sym(h: *mut c_void, name: &CStr) -> *mut c_void {
    let p = unsafe { dlsym(h, name.as_ptr()) };
    assert!(!p.is_null(), "missing libc symbol {name:?}");
    p
}

fn tmp_path(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("fl_mntent_{}_{}.tab", tag, std::process::id()));
    p
}

/// Read all entries from `path` using glibc's mntent family (via dlsym).
fn read_glibc(h: *mut c_void, path: &CStr) -> Vec<(String, String, String, String, i32, i32)> {
    let g_set: SetFn = unsafe { core::mem::transmute(sym(h, c"setmntent")) };
    let g_get: GetRFn = unsafe { core::mem::transmute(sym(h, c"getmntent_r")) };
    let g_end: EndFn = unsafe { core::mem::transmute(sym(h, c"endmntent")) };
    let mut out = Vec::new();
    let s = g_set(path.as_ptr(), c"r".as_ptr());
    assert!(!s.is_null(), "glibc setmntent failed");
    let mut buf = vec![0 as c_char; 8192];
    loop {
        let mut m: Mntent = unsafe { core::mem::zeroed() };
        let r = g_get(s, &mut m, buf.as_mut_ptr(), buf.len() as c_int);
        if r.is_null() {
            break;
        }
        out.push(entry_tuple(&m));
    }
    g_end(s);
    out
}

/// Read all entries from `path` using fl's mntent family.
fn read_fl(path: &CStr) -> Vec<(String, String, String, String, i32, i32)> {
    let mut out = Vec::new();
    let s = unsafe { fl::setmntent(path.as_ptr(), c"r".as_ptr()) };
    assert!(!s.is_null(), "fl setmntent failed");
    let mut buf = vec![0 as c_char; 8192];
    loop {
        let mut m: Mntent = unsafe { core::mem::zeroed() };
        let r = unsafe {
            fl::getmntent_r(
                s,
                (&mut m as *mut Mntent).cast(),
                buf.as_mut_ptr(),
                buf.len() as c_int,
            )
        };
        if r.is_null() {
            break;
        }
        out.push(entry_tuple(&m));
    }
    unsafe { fl::endmntent(s) };
    out
}

fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}
fn entry_tuple(m: &Mntent) -> (String, String, String, String, i32, i32) {
    (
        cstr(m.mnt_fsname),
        cstr(m.mnt_dir),
        cstr(m.mnt_type),
        cstr(m.mnt_opts),
        m.mnt_freq,
        m.mnt_passno,
    )
}

#[test]
fn getmntent_r_decode_matches_glibc() {
    let h = libc();
    let path = tmp_path("dec");
    {
        let mut f = std::fs::File::create(&path).unwrap();
        // Escaped values, short lines, comment, blank line, and a literal \054
        // (which glibc must NOT decode).
        f.write_all(
            b"server:/exp\\040path /mnt\\040dir nfs rw\\054x\\134y 0 0\n\
              tab\\011sep /d\\012nl t o 1 2\n\
              single\n\
              a b\n\
              # a comment line\n\
              \n\
              /dev/sda1 / ext4 rw,relatime 0 1\n",
        )
        .unwrap();
    }
    let cpath = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    let g = read_glibc(h, &cpath);
    let f = read_fl(&cpath);
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        f, g,
        "getmntent_r decode divergence\n fl={f:#?}\n glibc={g:#?}"
    );
    // sanity: the escapes were actually exercised
    assert!(
        g.iter().any(|e| e.0.contains(' ')),
        "oracle decoded a space"
    );
}

#[test]
fn addmntent_encode_matches_glibc() {
    let h = libc();
    // Build a struct with embedded space/tab/backslash and write it with both
    // implementations; the resulting files must be byte-identical.
    let fsname = c"host:/p with space";
    let dir = c"/m\ttab";
    let mtype = c"nfs";
    let opts = c"rw,a=b\\c";

    let m = Mntent {
        mnt_fsname: fsname.as_ptr() as *mut c_char,
        mnt_dir: dir.as_ptr() as *mut c_char,
        mnt_type: mtype.as_ptr() as *mut c_char,
        mnt_opts: opts.as_ptr() as *mut c_char,
        mnt_freq: 0,
        mnt_passno: 0,
    };

    // glibc write
    let gpath = tmp_path("enc_g");
    let gcpath = std::ffi::CString::new(gpath.to_str().unwrap()).unwrap();
    {
        let g_set: SetFn = unsafe { core::mem::transmute(sym(h, c"setmntent")) };
        let g_add: AddFn = unsafe { core::mem::transmute(sym(h, c"addmntent")) };
        let g_end: EndFn = unsafe { core::mem::transmute(sym(h, c"endmntent")) };
        let s = g_set(gcpath.as_ptr(), c"w".as_ptr());
        assert!(!s.is_null());
        assert_eq!(g_add(s, &m), 0);
        g_end(s);
    }
    // fl write
    let fpath = tmp_path("enc_f");
    let fcpath = std::ffi::CString::new(fpath.to_str().unwrap()).unwrap();
    {
        let s = unsafe { fl::setmntent(fcpath.as_ptr(), c"w".as_ptr()) };
        assert!(!s.is_null());
        assert_eq!(unsafe { fl::addmntent(s, (&m as *const Mntent).cast()) }, 0);
        unsafe { fl::endmntent(s) };
    }

    let gbytes = std::fs::read(&gpath).unwrap();
    let fbytes = std::fs::read(&fpath).unwrap();
    let _ = std::fs::remove_file(&gpath);
    let _ = std::fs::remove_file(&fpath);
    assert_eq!(
        fbytes,
        gbytes,
        "addmntent encode divergence\n fl={:?}\n glibc={:?}",
        String::from_utf8_lossy(&fbytes),
        String::from_utf8_lossy(&gbytes)
    );
    assert!(
        gbytes.windows(4).any(|w| w == b"\\040"),
        "oracle encoded a space escape"
    );
}
