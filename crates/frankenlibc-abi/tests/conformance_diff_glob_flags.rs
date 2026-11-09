#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc glob oracle

//! `glob` flag-semantics parity vs host glibc (bd-2g7oyh.NEW — coverage).
//!
//! The existing glob_differential_fuzz only exercises GLOB_BRACE / GLOB_NOSORT,
//! while the core implements GLOB_MARK, GLOB_NOCHECK, GLOB_PERIOD, GLOB_NOMAGIC,
//! GLOB_NOESCAPE and GLOB_ONLYDIR. This gate drives both engines over a fixed
//! temp directory (regular files, a hidden file, a subdir) and compares the
//! return code and the sorted match list for each flag and a few combinations.

use frankenlibc_abi::string_abi as fl;
use std::ffi::{CStr, CString, c_char, c_int, c_void};

#[repr(C)]
struct GlobT {
    gl_pathc: usize,
    gl_pathv: *mut *mut c_char,
    gl_offs: usize,
    gl_flags: c_int,
    p1: *mut c_void,
    p2: *mut c_void,
    p3: *mut c_void,
    p4: *mut c_void,
    p5: *mut c_void,
}

unsafe extern "C" {
    fn glob(p: *const c_char, f: c_int, errf: *mut c_void, g: *mut GlobT) -> c_int;
    fn globfree(g: *mut GlobT);
    fn glob64(p: *const c_char, f: c_int, errf: *mut c_void, g: *mut GlobT) -> c_int;
    fn globfree64(g: *mut GlobT);
}

const MARK: c_int = 0x0002;
const NOCHECK: c_int = 0x0010;
const NOESCAPE: c_int = 0x0040;
const PERIOD: c_int = 0x0080;
const NOMAGIC: c_int = 0x0800;
const ONLYDIR: c_int = 0x2000;
const DOOFFS: c_int = 0x0008;
const APPEND: c_int = 0x0020;

fn paths(g: &GlobT) -> Vec<String> {
    (0..g.gl_pathc)
        .map(|i| {
            let p = unsafe { *g.gl_pathv.add(g.gl_offs + i) };
            unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
        })
        .collect()
}

fn run(eng: u8, pat: &str, flags: c_int, dir: &str) -> (c_int, Vec<String>) {
    let cp = CString::new(pat).unwrap();
    let mut g: GlobT = unsafe { std::mem::zeroed() };
    let rc = if eng == 0 {
        unsafe { fl::glob(cp.as_ptr(), flags, None, (&mut g as *mut GlobT).cast()) }
    } else {
        unsafe { glob(cp.as_ptr(), flags, std::ptr::null_mut(), &mut g) }
    };
    let mut ps = if rc == 0 { paths(&g) } else { vec![] };
    // Compare directory-relative paths so the test is location-independent.
    for p in &mut ps {
        *p = p.replace(dir, "");
    }
    ps.sort();
    if rc == 0 {
        if eng == 0 {
            unsafe { fl::globfree((&mut g as *mut GlobT).cast()) };
        } else {
            unsafe { globfree(&mut g) };
        }
    }
    (rc, ps)
}

#[test]
fn glob_flags_match_glibc() {
    let dir = format!("/tmp/fl_glob_flags_{}", std::process::id());
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(format!("{dir}/a.txt"), "").unwrap();
    std::fs::write(format!("{dir}/b.txt"), "").unwrap();
    std::fs::write(format!("{dir}/.hidden"), "").unwrap();
    std::fs::write(format!("{dir}/plain"), "").unwrap();
    std::fs::create_dir(format!("{dir}/subdir")).unwrap();

    let p = |s: &str| format!("{dir}{s}");
    let cases: &[(String, c_int)] = &[
        (p("/*"), 0),
        (p("/*"), MARK),
        (p("/*"), PERIOD),
        (p("/*"), MARK | PERIOD),
        (p("/.*"), 0),
        (p("/sub*"), MARK),
        (p("/*.txt"), MARK),
        (p("/nomatch*"), 0),
        (p("/nomatch*"), NOCHECK),
        (p("/nomatch"), NOMAGIC),
        (p("/a.txt"), NOMAGIC),
        (p("/*"), ONLYDIR),
        (p("/a*"), NOESCAPE),
        (p("/[a-b].txt"), 0),
        (p("/[a-b].txt"), MARK),
        (p("/*"), NOCHECK | MARK),
    ];
    for (pat, flags) in cases {
        let a = run(0, pat, *flags, &dir);
        let b = run(1, pat, *flags, &dir);
        assert_eq!(a, b, "glob({pat:?}, {flags:#x}): fl={a:?} glibc={b:?}");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

unsafe fn append_call(eng: u8, large: bool, pattern: &CStr, flags: c_int, g: &mut GlobT) -> c_int {
    if eng == 0 {
        if large {
            unsafe {
                frankenlibc_abi::unistd_abi::glob64(
                    pattern.as_ptr(),
                    flags,
                    None,
                    (g as *mut GlobT).cast(),
                )
            }
        } else {
            unsafe { fl::glob(pattern.as_ptr(), flags, None, (g as *mut GlobT).cast()) }
        }
    } else if large {
        unsafe { glob64(pattern.as_ptr(), flags, std::ptr::null_mut(), g) }
    } else {
        unsafe { glob(pattern.as_ptr(), flags, std::ptr::null_mut(), g) }
    }
}

unsafe fn append_free(eng: u8, large: bool, g: &mut GlobT) {
    if eng == 0 {
        if large {
            unsafe { frankenlibc_abi::unistd_abi::globfree64((g as *mut GlobT).cast()) };
        } else {
            unsafe { fl::globfree((g as *mut GlobT).cast()) };
        }
    } else if large {
        unsafe { globfree64(g) };
    } else {
        unsafe { globfree(g) };
    }
}

fn append_vector(g: &GlobT, offset: usize, count: usize, previous: &[*mut c_char]) -> Vec<String> {
    assert_eq!((g.gl_offs, g.gl_pathc), (offset, count));
    if offset == 0 && count == 0 && g.gl_pathv.is_null() {
        return Vec::new();
    }
    assert!(!g.gl_pathv.is_null());
    for i in 0..offset {
        assert!(unsafe { *g.gl_pathv.add(i) }.is_null());
    }
    for (i, &old) in previous.iter().enumerate() {
        // Check retention before reading any old pathname: the pre-fix ABI
        // left these counted slots uninitialized when gl_offs was nonzero.
        assert_eq!(unsafe { *g.gl_pathv.add(offset + i) }, old);
    }
    for i in 0..count {
        assert!(!unsafe { *g.gl_pathv.add(offset + i) }.is_null());
    }
    assert!(unsafe { *g.gl_pathv.add(offset + count) }.is_null());
    paths(g)
}

fn append_observations(
    eng: u8,
    large: bool,
    offset: usize,
    initial_nomatch: bool,
) -> Vec<Vec<String>> {
    let words = [
        c"glob-offset-z",
        c"glob-offset-b",
        c"glob-offset-a",
        c"glob-offset-z",
    ];
    let mut g: GlobT = unsafe { std::mem::zeroed() };
    g.gl_offs = offset;
    let mut previous = Vec::new();
    let mut observations = Vec::new();
    if initial_nomatch {
        assert_eq!(unsafe { append_call(eng, large, c"", DOOFFS, &mut g) }, 3);
        assert!(append_vector(&g, offset, 0, &previous).is_empty());
    }
    for (i, word) in words.iter().enumerate() {
        let flags = DOOFFS | NOCHECK | if i > 0 || initial_nomatch { APPEND } else { 0 };
        assert_eq!(unsafe { append_call(eng, large, word, flags, &mut g) }, 0);
        let names = append_vector(&g, offset, i + 1, &previous);
        let expected: Vec<_> = words[..=i]
            .iter()
            .map(|word| word.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, expected, "append must retain order and duplicates");
        previous = (0..g.gl_pathc)
            .map(|j| unsafe { *g.gl_pathv.add(offset + j) })
            .collect();
        assert_eq!(
            unsafe { append_call(eng, large, c"", DOOFFS | APPEND, &mut g) },
            3
        );
        assert_eq!(append_vector(&g, offset, i + 1, &previous), names);
        observations.push(names);
    }
    unsafe { append_free(eng, large, &mut g) };
    observations
}

#[test]
fn glob_append_offsets_match_glibc() {
    for large in [false, true] {
        for offset in [0, 1, 2, 8] {
            for initial_nomatch in [false, true] {
                let host = append_observations(1, large, offset, initial_nomatch);
                let native = append_observations(0, large, offset, initial_nomatch);
                assert_eq!(
                    native, host,
                    "large={large} offset={offset} initial_nomatch={initial_nomatch}"
                );
            }
        }
    }
}

fn overflow_observation(eng: u8, large: bool, offset: usize) -> (c_int, c_int, usize, usize, bool) {
    let mut g: GlobT = unsafe { std::mem::zeroed() };
    g.gl_offs = offset;
    let errno = if eng == 0 {
        unsafe { frankenlibc_abi::errno_abi::__errno_location() }
    } else {
        unsafe { libc::__errno_location() }
    };
    unsafe { *errno = libc::EDOM };
    let result = unsafe {
        append_call(
            eng,
            large,
            c"glob-offset-overflow",
            DOOFFS | NOCHECK,
            &mut g,
        )
    };
    let observation = (
        result,
        unsafe { *errno },
        g.gl_pathc,
        g.gl_offs,
        g.gl_pathv.is_null(),
    );
    if g.gl_pathv.is_null() {
        unsafe { append_free(eng, large, &mut g) };
    }
    observation
}

#[test]
fn glob_offset_allocation_overflow_matches_glibc() {
    let pointer_size = std::mem::size_of::<*mut c_char>();
    let offsets = [
        usize::MAX,
        usize::MAX / pointer_size,
        usize::MAX / pointer_size + 1,
        isize::MAX as usize / pointer_size,
    ];
    for large in [false, true] {
        for (i, offset) in offsets.into_iter().enumerate() {
            let host = overflow_observation(1, large, offset);
            assert_eq!(
                host,
                (
                    1,
                    if i == 3 { libc::ENOMEM } else { libc::EDOM },
                    0,
                    offset,
                    true
                )
            );
            assert_eq!(
                overflow_observation(0, large, offset),
                host,
                "large={large} offset={offset}"
            );
        }
    }
}
