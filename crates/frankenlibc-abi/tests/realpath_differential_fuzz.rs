//! Randomized live differential fuzzer for `realpath` vs host glibc over a rich
//! on-disk tree (dirs, files, relative/absolute/chained/dangling/loop symlinks,
//! and symlinks whose targets contain `..`). The existing
//! `realpath_differential_probe` is a fixed ~20-case battery; this generates
//! random paths combining real names, `.`/`..`, nonexistent components, double
//! and trailing slashes, and symlink names, then compares the resolved string
//! AND the errno for BOTH fl resolvers — the primary (`fl::realpath`, /proc
//! based) and the pure-userspace fallback (`realpath_resolve_userspace`) — vs the
//! host's `realpath`.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc realpath oracle

use std::ffi::CString;
use std::fs;
use std::os::unix::fs::symlink;

use frankenlibc_abi::stdlib_abi as fl;

unsafe extern "C" {
    fn realpath(path: *const libc::c_char, resolved: *mut libc::c_char) -> *mut libc::c_char;
}

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}
fn clear_errno() {
    unsafe { *libc::__errno_location() = 0 };
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct Out {
    ok: bool,
    resolved: String,
    err: i32,
}

fn finish(is_null: bool, buf: &[u8]) -> Out {
    if is_null {
        Out {
            ok: false,
            resolved: String::new(),
            err: errno(),
        }
    } else {
        let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Out {
            ok: true,
            resolved: String::from_utf8_lossy(&buf[..n]).into_owned(),
            err: 0,
        }
    }
}

fn run_host(path: &CString) -> Out {
    clear_errno();
    let mut buf = vec![0u8; libc::PATH_MAX as usize + 16];
    let r = unsafe { realpath(path.as_ptr(), buf.as_mut_ptr() as *mut libc::c_char) };
    finish(r.is_null(), &buf)
}
fn run_fl(path: &CString) -> Out {
    clear_errno();
    let mut buf = vec![0u8; libc::PATH_MAX as usize + 16];
    let r = unsafe { fl::realpath(path.as_ptr(), buf.as_mut_ptr() as *mut std::ffi::c_char) };
    finish(r.is_null(), &buf)
}
fn run_fl_fallback(path: &str) -> Out {
    match fl::realpath_resolve_userspace(path.as_bytes()) {
        Ok(bytes) => Out {
            ok: true,
            resolved: String::from_utf8_lossy(&bytes).into_owned(),
            err: 0,
        },
        Err(e) => Out {
            ok: false,
            resolved: String::new(),
            err: e,
        },
    }
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

fn make_tree() -> std::path::PathBuf {
    let base = std::env::temp_dir().join(format!("fl_realpath_fuzz_{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(base.join("d/sub/deep")).unwrap();
    fs::write(base.join("d/f"), b"x").unwrap();
    fs::write(base.join("d/sub/g"), b"y").unwrap();
    let _ = symlink("d", base.join("lnk_dir")); // -> d (relative)
    let _ = symlink("d/f", base.join("lnk_file")); // -> d/f
    let _ = symlink(base.join("d/f"), base.join("lnk_abs")); // absolute target
    let _ = symlink("nonexistent_target", base.join("dangle")); // -> ENOENT
    let _ = symlink("loop", base.join("loop")); // self-loop -> ELOOP
    let _ = symlink("lnk_dir", base.join("chain")); // chain -> lnk_dir -> d
    let _ = symlink("d/..", base.join("updir")); // target contains `..`
    let _ = symlink("d/sub", base.join("to_sub"));
    let _ = symlink("../d/f", base.join("d/rel_up")); // .. in a relative target
    base
}

const NAMES: &[&str] = &[
    "d", "sub", "deep", "f", "g", "lnk_dir", "lnk_file", "lnk_abs", "dangle", "loop", "chain",
    "updir", "to_sub", "rel_up", "nope", "x", ".", "..",
];

fn gen_path(r: &mut Lcg, base: &str) -> String {
    let mut p = String::new();
    // Prefix: absolute base, bare absolute, or relative.
    match r.below(4) {
        0 | 1 => {
            p.push_str(base);
            p.push('/');
        }
        2 => p.push('/'),
        _ => {} // relative (resolved against CWD)
    }
    let segs = 1 + r.below(6);
    for i in 0..segs {
        if i > 0 {
            // single or double slash between components
            p.push('/');
            if r.below(5) == 0 {
                p.push('/');
            }
        }
        p.push_str(NAMES[r.below(NAMES.len())]);
    }
    if r.below(4) == 0 {
        p.push('/'); // trailing slash
    }
    p
}

#[test]
fn realpath_differential_fuzz_vs_glibc() {
    let base_pb = make_tree();
    // Canonicalize the base with glibc so expectations share the exact prefix.
    let base = {
        let c = CString::new(base_pb.to_string_lossy().as_bytes()).unwrap();
        run_host(&c).resolved
    };

    let mut r = Lcg(0x5eed_1234_abcd_0f0f);
    let mut prim_divs: Vec<String> = Vec::new();
    let mut fb_divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..40_000 {
        let path = gen_path(&mut r, &base);
        let Ok(c) = CString::new(path.as_str()) else {
            continue;
        };
        let h = run_host(&c);
        compared += 1;

        // Report divergences via eprintln immediately (the panic-on-assert
        // message is truncated by the runtime), relative to the tempdir prefix.
        let rel = |o: &Out| {
            if o.ok {
                o.resolved.replace(&base, "B")
            } else {
                format!("errno {}", o.err)
            }
        };
        let f = run_fl(&c);
        if h != f && prim_divs.len() < 30 {
            let m = format!("path={:?}  fl={}  glibc={}", path.replace(&base, "B"), rel(&f), rel(&h));
            eprintln!("PRIMARY DIV {m}");
            prim_divs.push(m);
        }
        let fb = run_fl_fallback(&path);
        if h != fb && fb_divs.len() < 30 {
            let m = format!("path={:?}  fl={}  glibc={}", path.replace(&base, "B"), rel(&fb), rel(&h));
            eprintln!("FALLBACK DIV {m}");
            fb_divs.push(m);
        }
    }

    let _ = fs::remove_dir_all(&base_pb);
    assert!(
        prim_divs.is_empty(),
        "realpath (primary) diverged from host glibc ({compared} compared):\n{}",
        prim_divs.join("\n")
    );
    assert!(
        fb_divs.is_empty(),
        "realpath (userspace fallback) diverged from host glibc ({compared} compared):\n{}",
        fb_divs.join("\n")
    );
    eprintln!("realpath differential fuzz: {compared} comparisons, 0 divergences (primary + fallback)");
}
