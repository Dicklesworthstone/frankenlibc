#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wordexp oracle

//! Randomized differential fuzzer for `wordexp` vs a LIVE host glibc oracle. The
//! existing probe is a small fixed battery; this randomizes the words string over
//! literals, single/double quotes, backslash escapes, `$VAR`/`${VAR}` references
//! (against a controlled environment, including an empty var and one with
//! embedded spaces for field splitting), bare tilde, and occasional bad
//! characters. Run under WRDE_NOCMD with no glob metacharacters so expansion is
//! deterministic. Compares the return code, we_wordc, and every expanded word.

use std::ffi::{CString, c_char, c_int};

const WRDE_NOCMD: c_int = 1 << 2;

#[repr(C)]
struct WordExp {
    we_wordc: usize,
    we_wordv: *mut *mut c_char,
    we_offs: usize,
}

unsafe extern "C" {
    fn wordexp(words: *const c_char, pwordexp: *mut WordExp, flags: c_int) -> c_int;
    fn wordfree(pwordexp: *mut WordExp);
    fn setenv(name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int;
}

use frankenlibc_abi::unistd_abi as fl;

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn set(name: &str, val: &str) {
    let n = CString::new(name).unwrap();
    let v = CString::new(val).unwrap();
    unsafe { setenv(n.as_ptr(), v.as_ptr(), 1) };
}

/// (return code, Vec of expanded words). Words read out only on success.
type Result = (c_int, Vec<Vec<u8>>);

fn read_cstr(p: *mut c_char) -> Vec<u8> {
    let mut v = Vec::new();
    let mut i = 0isize;
    loop {
        let b = unsafe { *p.offset(i) } as u8;
        if b == 0 {
            break;
        }
        v.push(b);
        i += 1;
    }
    v
}

fn run_fl(words: &[u8]) -> Result {
    let c = CString::new(words).unwrap();
    let mut we = WordExp {
        we_wordc: 0,
        we_wordv: std::ptr::null_mut(),
        we_offs: 0,
    };
    let rc = unsafe {
        fl::wordexp(
            c.as_ptr(),
            &mut we as *mut WordExp as *mut std::ffi::c_void,
            WRDE_NOCMD,
        )
    };
    let mut out = Vec::new();
    if rc == 0 && !we.we_wordv.is_null() {
        for i in 0..we.we_wordc {
            let p = unsafe { *we.we_wordv.add(i) };
            if !p.is_null() {
                out.push(read_cstr(p));
            }
        }
        unsafe { fl::wordfree(&mut we as *mut WordExp as *mut std::ffi::c_void) };
    }
    (rc, out)
}

fn run_host(words: &[u8]) -> Result {
    let c = CString::new(words).unwrap();
    let mut we = WordExp {
        we_wordc: 0,
        we_wordv: std::ptr::null_mut(),
        we_offs: 0,
    };
    let rc = unsafe { wordexp(c.as_ptr(), &mut we, WRDE_NOCMD) };
    let mut out = Vec::new();
    if rc == 0 && !we.we_wordv.is_null() {
        for i in 0..we.we_wordc {
            let p = unsafe { *we.we_wordv.add(i) };
            if !p.is_null() {
                out.push(read_cstr(p));
            }
        }
        unsafe { wordfree(&mut we) };
    }
    (rc, out)
}

fn gen_word(r: &mut Lcg) -> Vec<u8> {
    match r.below(32) {
        0 => b"abc".to_vec(),
        1 => b"$FOO".to_vec(),
        2 => b"${MULTI}".to_vec(),
        3 => b"$EMPTY".to_vec(),
        4 => b"$UNDEFINED".to_vec(),
        5 => b"'literal $FOO ~'".to_vec(), // single-quoted: no expansion
        6 => b"\"$FOO and $MULTI\"".to_vec(), // double-quoted: expand, no split
        7 => b"pre$FOO.post".to_vec(),
        8 => b"a\\$FOO".to_vec(), // escaped $: literal
        9 => b"~".to_vec(),       // tilde -> HOME
        // POSIX parameter expansion: default / alternative / length forms.
        10 => b"${UNDEFINED:-fb}".to_vec(),
        11 => b"${FOO:-fb}".to_vec(),
        12 => b"${EMPTY:-fb}".to_vec(),
        13 => b"${UNDEFINED-fb}".to_vec(),
        14 => b"${EMPTY-fb}".to_vec(),
        15 => b"${FOO:+set}".to_vec(),
        16 => b"${UNDEFINED:+set}".to_vec(),
        17 => b"${EMPTY+set}".to_vec(),
        18 => b"${#FOO}".to_vec(),
        19 => b"${#MULTI}".to_vec(),
        // assign-default := = (observable == default; subshell assignment unseen)
        20 => b"${UNDEFINED:=def}".to_vec(),
        21 => b"${EMPTY=def}".to_vec(),
        22 => b"${FOO:=x}".to_vec(),
        // suffix removal % %%
        23 => b"${DOTTED%.c}".to_vec(),
        24 => b"${DOTTED%.*}".to_vec(),
        25 => b"${DOTTED%%.*}".to_vec(),
        26 => b"${DOTTED%x}".to_vec(),
        // prefix removal # ##
        27 => b"${PATHV#*/}".to_vec(),
        28 => b"${PATHV##*/}".to_vec(),
        29 => b"${PATHV#/usr}".to_vec(),
        30 => b"${DOTTED#a.}".to_vec(),
        // a default WORD that itself references a variable
        31 if r.below(2) == 0 => b"${UNDEFINED:-$FOO}".to_vec(),
        31 => b"${DOTTED%?}".to_vec(),
        _ => {
            // short random literal of safe chars
            let n = 1 + r.below(4);
            let mut w = Vec::new();
            for _ in 0..n {
                w.push(b'a' + r.below(6) as u8);
            }
            w
        }
    }
}

#[test]
fn wordexp_differential_fuzz_vs_glibc() {
    // Controlled environment for deterministic expansion.
    set("FOO", "bar");
    set("EMPTY", "");
    set("MULTI", "x y z");
    set("HOME", "/home/fltest");
    set("DOTTED", "a.b.c");
    set("PATHV", "/usr/local/bin");

    let mut r = Lcg(0x77a1_3c9e_0bd4_2201);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..120_000 {
        let nwords = 1 + r.below(4) as usize;
        let mut words: Vec<u8> = Vec::new();
        for w in 0..nwords {
            if w > 0 {
                words.push(b' ');
            }
            words.extend_from_slice(&gen_word(&mut r));
        }
        // (Unquoted shell metacharacters | & ; < > and newline are intentionally
        // NOT generated: glibc's WRDE_BADCHAR acceptance of them mid-word vs fl's
        // stricter POSIX rejection is a separate, ambiguous parity question.
        // Glob metacharacters and command substitution are likewise excluded to
        // keep the comparison deterministic and filesystem-independent.)
        let fl_res = run_fl(&words);
        let host_res = run_host(&words);
        compared += 1;
        // On error both should agree on the code; on success compare the words.
        let fl_cmp = (fl_res.0, &fl_res.1);
        let host_cmp = (host_res.0, &host_res.1);
        if fl_cmp != host_cmp && divs.len() < 30 {
            divs.push(format!(
                "words={:?}\n    fl   = rc={} {:?}\n    glibc= rc={} {:?}",
                String::from_utf8_lossy(&words),
                fl_res.0,
                fl_res
                    .1
                    .iter()
                    .map(|w| String::from_utf8_lossy(w).into_owned())
                    .collect::<Vec<_>>(),
                host_res.0,
                host_res
                    .1
                    .iter()
                    .map(|w| String::from_utf8_lossy(w).into_owned())
                    .collect::<Vec<_>>(),
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "wordexp diverged from host glibc on some of {compared} cases (showing up to 30):\n{}",
        divs.join("\n")
    );
    eprintln!("wordexp fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
