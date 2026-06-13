#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc fnmatch oracle (libc, linked by std)

//! Randomized live differential fuzzer for `fnmatch` under FNM_EXTMATCH (the
//! GNU ksh-style extended-glob operators) vs host glibc. frankenlibc previously
//! ignored FNM_EXTMATCH entirely; this drives random patterns built from the
//! five extglob operators — `?(list)` `*(list)` `+(list)` `@(list)` `!(list)`
//! with `|`-separated, possibly NESTED sub-patterns containing `?`, `*`,
//! `[...]` and literals — against random subject strings, and asserts fl's
//! match verdict equals the live glibc oracle. FNM_CASEFOLD / FNM_NOESCAPE are
//! fuzzed; FNM_PATHNAME / FNM_PERIOD are out of scope for this pass (their
//! interaction with `/` and leading `.` inside a group is a separate quirk).

use std::ffi::{CString, c_char, c_int};

use frankenlibc_abi::string_abi::fnmatch as fl_fnmatch;

unsafe extern "C" {
    fn fnmatch(pattern: *const c_char, string: *const c_char, flags: c_int) -> c_int;
}

const NOESCAPE: c_int = 1 << 1;
const CASEFOLD: c_int = 1 << 4;
const EXTMATCH: c_int = 1 << 5;

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

// SCOPE NOTE: the generator now EXERCISES the formerly-quirky surface — `@`/`+`
// groups that can match the EMPTY STRING AS A VALUE (an empty alternative such
// as `@(b|)` / `+()` / `@(|b)`), including when absorbed by a preceding `*`
// (e.g. `*@(b|)` on "ba", `*+()` on "bb"). glibc rejects that empty-alternative
// match only when it completes a `*` at end of text while accepting it
// standalone; fl reproduces this exactly after bd-4aqdre, so this must stay
// 0-divergence. Still out of the randomized set: `!(list)` (its own follow-up
// gap) — covered by the fixed battery and the host probes.

/// A definitely-consuming atom (matches exactly one byte): literal, `?`, or a
/// bracket. Never matches empty, so an alternative beginning with one cannot.
fn gen_consuming_atom(r: &mut Lcg, out: &mut Vec<u8>) {
    const LIT: &[u8] = b"abc";
    match r.below(6) {
        0 | 1 | 2 | 3 => out.push(LIT[r.below(LIT.len())]),
        4 => out.push(b'?'),
        _ => out.extend_from_slice(b"[a-c]"),
    }
}

/// One alternative: a (possibly EMPTY) sequence of consuming atoms and nested
/// groups. An empty alternative lets the enclosing `@`/`+` group match the
/// empty string as a value — the `*`+empty-match surface fixed by bd-4aqdre.
fn gen_alt(r: &mut Lcg, depth: u32, out: &mut Vec<u8>) {
    // ~1 in 4 alternatives is empty (matches the empty string as a value).
    if r.below(4) == 0 {
        return;
    }
    gen_consuming_atom(r, out);
    let extra = r.below(3);
    for _ in 0..extra {
        if depth > 0 && r.below(3) == 0 {
            gen_group(r, depth - 1, out);
        } else {
            gen_consuming_atom(r, out);
        }
    }
}

/// One extglob group `X(alt|alt|...)`. Operators are `@` (exactly-one) and `+`
/// (one-or-more); alternatives may be empty, so a group can match the empty
/// string as a value. `?`/`*`/`!` are exercised by the realistic fixed battery
/// and host probes instead.
fn gen_group(r: &mut Lcg, depth: u32, out: &mut Vec<u8>) {
    const OPS: &[u8] = b"@+";
    out.push(OPS[r.below(OPS.len())]);
    out.push(b'(');
    let nalts = 1 + r.below(3);
    for a in 0..nalts {
        if a > 0 {
            out.push(b'|');
        }
        gen_alt(r, depth, out);
    }
    out.push(b')');
}

/// A whole top-level pattern: consuming atoms, a `*`, and `@`/`+` groups.
fn gen_pattern(r: &mut Lcg) -> Vec<u8> {
    let mut p = Vec::new();
    let ntok = 1 + r.below(4);
    for _ in 0..ntok {
        match r.below(4) {
            0 | 1 => gen_group(r, 1, &mut p),
            2 => p.push(b'*'),
            _ => gen_consuming_atom(r, &mut p),
        }
    }
    p
}

fn gen_text(r: &mut Lcg) -> Vec<u8> {
    const S: &[u8] = b"abc";
    let len = r.below(7);
    (0..len).map(|_| S[r.below(S.len())]).collect()
}

/// Fixed battery of realistic extglob patterns (the common real-world usage:
/// `*.@(c|h)`, `+([0-9])`, `!(*.o)`, …). Each expected verdict was captured from
/// host glibc; fl must agree exactly. This pins the operators (`?`/`*`/`!`) and
/// `*`-adjacency cases that the randomized generator intentionally avoids.
#[test]
fn fnmatch_extmatch_realistic_battery_matches_glibc() {
    let cases: &[(&str, &str, bool)] = &[
        ("a@(b|c)d", "abd", true),
        ("a@(b|c)d", "acd", true),
        ("a@(b|c)d", "ad", false),
        ("a?(b|c)d", "ad", true),
        ("a?(b|c)d", "abd", true),
        ("a?(b|c)d", "abcd", false),
        ("a*(b|c)d", "ad", true),
        ("a*(b|c)d", "abcbcd", true),
        ("a*(b|c)d", "axd", false),
        ("a+(b|c)d", "ad", false),
        ("a+(b|c)d", "abccbd", true),
        ("a!(b|c)d", "axd", true),
        ("a!(b|c)d", "abd", false),
        ("a!(b|c)d", "ad", true),
        ("a!(b|c)d", "abcd", true),
        ("!(*.o)", "foo.c", true),
        ("!(*.o)", "foo.o", false),
        ("@(a|b)*", "axyz", true),
        ("*(a|b)", "ababab", true),
        ("+([0-9])", "123", true),
        ("+([0-9])", "12a", false),
        ("@(foo|bar)", "foo", true),
        ("a@(b|c|)d", "ad", true),
        ("*.@(c|h|cpp)", "main.cpp", true),
        ("*.@(c|h|cpp)", "main.rs", false),
    ];
    for &(p, s, want) in cases {
        let cp = CString::new(p).unwrap();
        let cs = CString::new(s).unwrap();
        let fl = unsafe { fl_fnmatch(cp.as_ptr(), cs.as_ptr(), EXTMATCH) } == 0;
        let lc = unsafe { fnmatch(cp.as_ptr(), cs.as_ptr(), EXTMATCH) } == 0;
        assert_eq!(lc, want, "glibc baseline drift for ({p:?},{s:?})");
        assert_eq!(
            fl, want,
            "fl != glibc for ({p:?},{s:?}): fl={fl} glibc={lc}"
        );
    }
}

#[test]
fn fnmatch_extmatch_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x6d61_7463_685f_e417);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..400_000 {
        let pat = gen_pattern(&mut r);
        let text = gen_text(&mut r);
        let (Ok(cpat), Ok(ctext)) = (CString::new(pat.clone()), CString::new(text.clone())) else {
            continue;
        };
        let mut flags = EXTMATCH;
        if r.below(2) == 0 {
            flags |= CASEFOLD;
        }
        if r.below(3) == 0 {
            flags |= NOESCAPE;
        }

        let fl = unsafe { fl_fnmatch(cpat.as_ptr(), ctext.as_ptr(), flags) } == 0;
        let lc = unsafe { fnmatch(cpat.as_ptr(), ctext.as_ptr(), flags) } == 0;
        compared += 1;
        if fl != lc && divs.len() < 40 {
            divs.push(format!(
                "pat={:?} text={:?} flags={flags:#x}  fl={fl} glibc={lc}",
                String::from_utf8_lossy(&pat),
                String::from_utf8_lossy(&text),
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "fnmatch FNM_EXTMATCH diverged from glibc ({compared} compared):\n{}",
        divs.join("\n")
    );
    eprintln!("fnmatch FNM_EXTMATCH fuzz: {compared} compared, 0 divergences vs host glibc");
}
