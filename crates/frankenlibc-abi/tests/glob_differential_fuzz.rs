#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc glob oracle

//! Randomized differential fuzzer for `glob` vs host glibc against a REAL
//! on-disk tree. The existing `glob_differential_probe` is a fixed battery
//! compared to hardcoded glibc references; this drives random patterns
//! (literals, `*`, `?`, `[...]` bracket expressions, `{a,b}` braces, and
//! subdirectory `/` components) under random flag combinations (MARK, NOSORT,
//! NOCHECK, NOESCAPE, PERIOD, BRACE, NOMAGIC, ONLYDIR) through both fl's `glob`
//! and the host's, against an identical absolute-path tempdir tree, and compares
//! the return code and the full matched-path list.

use std::ffi::{CString, c_char, c_int};

use frankenlibc_abi::string_abi as fl;

unsafe extern "C" {
    fn glob(
        pattern: *const c_char,
        flags: c_int,
        errfunc: Option<unsafe extern "C" fn(*const c_char, c_int) -> c_int>,
        pglob: *mut libc::glob_t,
    ) -> c_int;
    fn globfree(pglob: *mut libc::glob_t);
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() >> 11) as usize % n
    }
}

// glibc glob flag bit values (libc doesn't export NOMAGIC).
const FLAG_BITS: &[(c_int, &str)] = &[
    (2, "MARK"),
    (4, "NOSORT"),
    (16, "NOCHECK"),
    (64, "NOESCAPE"),
    (128, "PERIOD"),
    (1024, "BRACE"),
    (2048, "NOMAGIC"),
    (8192, "ONLYDIR"),
];

/// Build a tempdir tree with a mix of awkward names, returning its abs path.
fn make_tree() -> std::path::PathBuf {
    use std::os::unix::ffi::OsStrExt;
    // A per-process unique dir under the system temp dir.
    let mut dir = std::env::temp_dir();
    dir.push(format!("fl_glob_fuzz_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let files: &[&[u8]] = &[
        b"a.txt", b"b.txt", b"c.log", b"Foo", b"bar", b"BAR", b".hidden", b".cfg",
        b"x y.dat", b"star", b"d.LOG", b"ab", b"abc", b"1file",
    ];
    for f in files {
        let p = dir.join(std::ffi::OsStr::from_bytes(f));
        let _ = std::fs::write(&p, b"x");
    }
    let sub = dir.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    for f in [b"inner.txt".as_slice(), b"nested.log", b".deep", b"e.txt"] {
        let _ = std::fs::write(sub.join(std::ffi::OsStr::from_bytes(f)), b"x");
    }
    std::fs::create_dir_all(dir.join("Sub2")).unwrap();
    let _ = std::fs::write(dir.join("Sub2").join("z.txt"), b"x");
    dir
}

/// Random "magic part" appended to the tempdir prefix.
fn gen_pattern(r: &mut Lcg) -> Vec<u8> {
    // alphabet of literals that overlap the tree's names + metacharacters
    const TOK: &[&[u8]] = &[
        b"*", b"?", b"a", b"b", b"c", b".", b"txt", b"log", b"[a-c]", b"[!a-c]",
        b"[abF]", b"F", b"o", b"sub", b"Sub2", b"{a,b}", b"{Foo,bar}", b"x y",
        b"star", b"BAR", b"1", b"]", b"[", b"\\*",
    ];
    let segs = 1 + r.below(4);
    let mut out: Vec<u8> = Vec::new();
    for s in 0..segs {
        if s > 0 && r.below(3) == 0 {
            out.push(b'/'); // a path-component separator -> recurse into subdirs
        }
        let toks = 1 + r.below(3);
        for _ in 0..toks {
            out.extend_from_slice(TOK[r.below(TOK.len())]);
        }
    }
    out
}

fn collect(g: &libc::glob_t, ret: c_int) -> Vec<Vec<u8>> {
    if ret != 0 || g.gl_pathv.is_null() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for i in 0..g.gl_pathc {
        let p = unsafe { *g.gl_pathv.add(i) };
        if p.is_null() {
            break;
        }
        let mut bytes = Vec::new();
        let mut j = 0isize;
        loop {
            let b = unsafe { *p.offset(j) } as u8;
            if b == 0 {
                break;
            }
            bytes.push(b);
            j += 1;
        }
        out.push(bytes);
    }
    out
}

#[test]
fn glob_differential_fuzz_vs_glibc() {
    use std::os::unix::ffi::OsStrExt;
    let tree = make_tree();
    let mut prefix = tree.as_os_str().as_bytes().to_vec();
    prefix.push(b'/');

    let mut r = Lcg(0x610b_b17e_5a1d_0019);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..20_000 {
        let mut pat = prefix.clone();
        pat.extend(gen_pattern(&mut r));
        let Ok(cpat) = CString::new(pat.clone()) else {
            continue;
        };
        let mut flags: c_int = 0;
        for &(bit, _) in FLAG_BITS {
            if r.below(3) == 0 {
                flags |= bit;
            }
        }

        let mut g_fl: libc::glob_t = unsafe { std::mem::zeroed() };
        let mut g_lc: libc::glob_t = unsafe { std::mem::zeroed() };
        let ret_fl = unsafe {
            fl::glob(cpat.as_ptr(), flags, None, (&mut g_fl) as *mut libc::glob_t as *mut _)
        };
        let ret_lc = unsafe { glob(cpat.as_ptr(), flags, None, &mut g_lc) };

        let mut paths_fl = collect(&g_fl, ret_fl);
        let mut paths_lc = collect(&g_lc, ret_lc);
        // With GLOB_NOSORT the order is the underlying readdir order, which fl's
        // std::fs iteration need not match byte-for-byte; compare as sets there.
        if flags & 4 != 0 {
            paths_fl.sort();
            paths_lc.sort();
        }
        compared += 1;
        if (ret_fl != ret_lc || paths_fl != paths_lc) && divs.len() < 30 {
            let fnames: Vec<&str> = FLAG_BITS
                .iter()
                .filter(|(b, _)| flags & b != 0)
                .map(|(_, n)| *n)
                .collect();
            let strip = |v: &[Vec<u8>]| -> Vec<String> {
                v.iter()
                    .map(|p| {
                        String::from_utf8_lossy(p.strip_prefix(prefix.as_slice()).unwrap_or(p))
                            .into_owned()
                    })
                    .collect()
            };
            divs.push(format!(
                "pat={:?} flags=[{}]\n    fl   =(ret={ret_fl}, {:?})\n    glibc=(ret={ret_lc}, {:?})",
                String::from_utf8_lossy(pat.strip_prefix(prefix.as_slice()).unwrap_or(&pat)),
                fnames.join("|"),
                strip(&paths_fl),
                strip(&paths_lc),
            ));
        }

        unsafe {
            fl::globfree((&mut g_fl) as *mut libc::glob_t as *mut _);
            globfree(&mut g_lc);
        }
    }

    let _ = std::fs::remove_dir_all(&tree);
    assert!(
        divs.is_empty(),
        "glob diverged from host glibc on some of {compared} cases (showing up to 30):\n{}",
        divs.join("\n")
    );
    eprintln!("glob differential fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
