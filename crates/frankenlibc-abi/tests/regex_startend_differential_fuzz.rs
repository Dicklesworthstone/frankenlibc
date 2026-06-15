#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc regcomp/regexec oracle

//! Randomized differential fuzzer for the `REG_STARTEND` exec flag vs host glibc
//! — the BSD/GNU extension that matches `string[pmatch[0].rm_so..rm_eo]` with
//! embedded NULs allowed and no NUL terminator. frankenlibc previously ignored
//! the flag (always read the NUL-terminated C string); this drives random
//! patterns over random buffers (including embedded `\0`), random
//! `[rm_so, rm_eo)` regions, and random eflags, comparing the return code and
//! the full capture vector against the host. The subtleties pinned: offsets are
//! relative to `string` (rm_so re-added), `$` anchors at rm_eo, `^` anchors at
//! the true buffer start (so rm_so>0 forces NOTBOL), embedded NULs are scanned
//! for literals/classes, and `.` never matches a NUL.

use std::ffi::{CString, c_char, c_int, c_void};

use frankenlibc_abi::string_abi as fl;

unsafe extern "C" {
    fn regcomp(preg: *mut c_void, pattern: *const c_char, cflags: c_int) -> c_int;
    fn regexec(
        preg: *const c_void,
        string: *const c_char,
        nmatch: usize,
        pmatch: *mut c_void,
        eflags: c_int,
    ) -> c_int;
    fn regfree(preg: *mut c_void);
}

const REGEX_T_BYTES: usize = 256;

/// 8-aligned backing store for a `regex_t` (fl interprets it as a
/// pointer-containing struct, so the byte buffer must be pointer-aligned).
#[repr(C, align(8))]
struct Preg([u8; REGEX_T_BYTES]);
const REG_EXTENDED: c_int = 1;
const REG_NEWLINE: c_int = 4; // cflag
const REG_NOTBOL: c_int = 1; // eflag
const REG_NOTEOL: c_int = 2; // eflag
const REG_STARTEND: c_int = 4; // eflag

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct RegMatch {
    rm_so: i32,
    rm_eo: i32,
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

/// A random ERE pattern over an alphabet overlapping the subject bytes. `^` is
/// only emitted at the very start and `$` only at the very end, so the pattern
/// uses WELL-FORMED anchors — a NON-terminal `$`/`^` (e.g. `$x`, `x^`) exercises
/// the separate GNU mid-pattern line-boundary quirk tracked in bd-aedwrn, which
/// is orthogonal to REG_STARTEND.
fn gen_pattern(r: &mut Lcg) -> Vec<u8> {
    const ATOM: &[u8] = b"ab.c";
    let mut p = Vec::new();
    if r.below(2) == 0 {
        p.push(b'^');
    }
    let len = 1 + r.below(5);
    for _ in 0..len {
        match r.below(8) {
            0 => p.extend_from_slice(b"[ab]"),
            1 => p.extend_from_slice(b"[^a]"),
            2 => {
                p.push(b'(');
                p.push(ATOM[r.below(ATOM.len())]);
                p.push(b')');
            }
            3 => {
                p.push(ATOM[r.below(ATOM.len())]);
                p.push(b"*+?"[r.below(3)]);
            }
            4 => p.push(b'.'),
            _ => p.push(ATOM[r.below(ATOM.len())]),
        }
    }
    if r.below(2) == 0 {
        p.push(b'$');
    }
    p
}

/// A random subject buffer over a small alphabet that includes the embedded NUL
/// and a newline (to exercise embedded-NUL scanning and REG_NEWLINE).
fn gen_buf(r: &mut Lcg) -> Vec<u8> {
    const S: &[u8] = b"ab\0c\nab";
    let len = r.below(10);
    (0..len).map(|_| S[r.below(S.len())]).collect()
}

struct Run {
    comp: c_int,
    exec: c_int,
    pm: [RegMatch; 3],
}

type RegCompFn = unsafe extern "C" fn(*mut c_void, *const c_char, c_int) -> c_int;
type RegExecFn =
    unsafe extern "C" fn(*const c_void, *const c_char, usize, *mut c_void, c_int) -> c_int;
type RegFreeFn = unsafe extern "C" fn(*mut c_void);

#[derive(Clone, Copy)]
struct RegexEngine {
    comp: RegCompFn,
    exec: RegExecFn,
    free: RegFreeFn,
}

#[derive(Clone, Copy)]
struct RunParams {
    so: i32,
    eo: i32,
    cflags: c_int,
    eflags: c_int,
}

fn run(engine: RegexEngine, pat: &CString, buf: &[u8], params: RunParams) -> Run {
    let mut preg = Preg([0u8; REGEX_T_BYTES]);
    let comp = unsafe {
        (engine.comp)(
            preg.0.as_mut_ptr() as *mut c_void,
            pat.as_ptr(),
            params.cflags,
        )
    };
    let mut pm = [RegMatch::default(); 3];
    pm[0] = RegMatch {
        rm_so: params.so,
        rm_eo: params.eo,
    };
    let exec = if comp == 0 {
        // The buffer need not be NUL-terminated under REG_STARTEND, but pass a
        // pointer to the owned bytes; the impl reads only [..rm_eo].
        let e = unsafe {
            (engine.exec)(
                preg.0.as_ptr() as *const c_void,
                buf.as_ptr() as *const c_char,
                3,
                pm.as_mut_ptr() as *mut c_void,
                params.eflags,
            )
        };
        unsafe { (engine.free)(preg.0.as_mut_ptr() as *mut c_void) };
        e
    } else {
        -1
    };
    Run { comp, exec, pm }
}

#[test]
fn regex_startend_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x57a4_7e9d_1234_5678);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;
    let mut validity_skips = 0u64;
    let fl_engine = RegexEngine {
        comp: fl::regcomp,
        exec: fl::regexec,
        free: fl::regfree,
    };
    let lc_engine = RegexEngine {
        comp: regcomp,
        exec: regexec,
        free: regfree,
    };

    for _ in 0..200_000 {
        let pat = gen_pattern(&mut r);
        let buf = gen_buf(&mut r);
        let Ok(cpat) = CString::new(pat.clone()) else {
            continue;
        };
        // Region within the buffer. Allow eo up to buf.len(); so in [0, eo].
        let eo = r.below(buf.len() + 1);
        let so = r.below(eo + 1);
        let cflags = if r.below(2) == 0 {
            REG_EXTENDED
        } else {
            REG_EXTENDED | REG_NEWLINE
        };
        let eflags = REG_STARTEND
            | match r.below(4) {
                0 => 0,
                1 => REG_NOTBOL,
                2 => REG_NOTEOL,
                _ => REG_NOTBOL | REG_NOTEOL,
            };

        let params = RunParams {
            so: so as i32,
            eo: eo as i32,
            cflags,
            eflags,
        };

        let fl_run = run(fl_engine, &cpat, &buf, params);
        let lc_run = run(lc_engine, &cpat, &buf, params);

        if (fl_run.comp == 0) != (lc_run.comp == 0) {
            validity_skips += 1;
            continue;
        }
        if fl_run.comp != 0 {
            continue;
        }
        compared += 1;
        let fl_m = fl_run.exec == 0;
        let lc_m = lc_run.exec == 0;
        if (fl_m != lc_m || (fl_m && fl_run.pm != lc_run.pm)) && divs.len() < 30 {
            divs.push(format!(
                "pat={:?} buf={:02x?} region=[{so},{eo}) cf={cflags} ef={eflags}\n    fl   =(m={fl_m}, {:?})\n    glibc=(m={lc_m}, {:?})",
                String::from_utf8_lossy(&pat),
                buf,
                fl_run.pm,
                lc_run.pm
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "REG_STARTEND diverged from glibc ({compared} compared, {validity_skips} validity skips):\n{}",
        divs.join("\n")
    );
    eprintln!(
        "REG_STARTEND fuzz: {compared} compared, {validity_skips} validity skips, 0 divergences"
    );
}
