// regexec head-to-head: fl clean-room Thompson NFA (linear) vs host glibc regex. Patterns
// that stress backtracking / DFA-state-explosion, matched against an all-'a' text with no
// 'b' (NO-MATCH → full scan). Compile once; time exec only. Both must return REG_NOMATCH.
use std::ffi::{c_void, CString};
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_core::string::regex;

fn main() {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc failed");
        type RegcompFn = unsafe extern "C" fn(*mut libc::regex_t, *const libc::c_char, i32) -> i32;
        type RegexecFn = unsafe extern "C" fn(
            *const libc::regex_t,
            *const libc::c_char,
            usize,
            *mut libc::regmatch_t,
            i32,
        ) -> i32;
        let gl_regcomp: RegcompFn =
            std::mem::transmute::<*mut c_void, RegcompFn>(libc::dlsym(h, b"regcomp\0".as_ptr().cast()));
        let gl_regexec: RegexecFn =
            std::mem::transmute::<*mut c_void, RegexecFn>(libc::dlsym(h, b"regexec\0".as_ptr().cast()));

        let cases: [(&str, usize); 3] = [
            ("a*a*a*a*a*a*a*a*b", 40),
            ("(a*)*b", 26),
            ("(a|aa)*b", 26),
        ];
        let mut none: [regex::RegMatch; 0] = [];
        for &(pat, m) in cases.iter() {
            let text = "a".repeat(m); // no 'b' -> NO-MATCH
            let compiled = match regex::regex_compile(pat.as_bytes(), (libc::REG_EXTENDED | libc::REG_NOSUB)) {
                Ok(c) => c,
                Err(e) => {
                    println!("REGEX {pat:?} fl compile err {e}");
                    continue;
                }
            };
            let fl_r = regex::regex_exec(&compiled, text.as_bytes(), &mut none, 0);

            let mut re: libc::regex_t = std::mem::zeroed();
            let pat_c = CString::new(pat).unwrap();
            let rc = gl_regcomp(&mut re, pat_c.as_ptr(), (libc::REG_EXTENDED | libc::REG_NOSUB));
            if rc != 0 {
                println!("REGEX {pat:?} glibc compile err {rc}");
                continue;
            }
            let text_c = CString::new(text.clone()).unwrap();
            let gl_r = gl_regexec(&re, text_c.as_ptr(), 0, std::ptr::null_mut(), 0);
            assert!(fl_r != 0 && gl_r != 0, "regex {pat:?}: fl={fl_r} glibc={gl_r} (expected NO-MATCH)");

            let iters = 200usize;
            let t0 = Instant::now();
            for _ in 0..iters {
                black_box(regex::regex_exec(black_box(&compiled), black_box(text.as_bytes()), &mut none, 0));
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                black_box(gl_regexec(black_box(&re), black_box(text_c.as_ptr()), 0, std::ptr::null_mut(), 0));
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!("REGEX {pat:?} m={m} fl={fl:.0}ns glibc={gl:.0}ns fl/glibc={:.5}x", fl / gl);
        }

        // MATCHING input (required byte 'b' present, so the fast-reject passes and the NFA
        // still runs): confirms the per-byte memchr adds negligible overhead on the match
        // path (i.e. the no-match win is not bought with a match-path regression).
        {
            let pat = "a*a*a*a*a*a*a*a*b";
            let text = format!("{}b", "a".repeat(39)); // 39 'a' + 'b' -> MATCHES
            let compiled =
                regex::regex_compile(pat.as_bytes(), libc::REG_EXTENDED | libc::REG_NOSUB).unwrap();
            let fl_r = regex::regex_exec(&compiled, text.as_bytes(), &mut none, 0);
            let mut re: libc::regex_t = std::mem::zeroed();
            let pat_c = CString::new(pat).unwrap();
            gl_regcomp(&mut re, pat_c.as_ptr(), libc::REG_EXTENDED | libc::REG_NOSUB);
            let text_c = CString::new(text.clone()).unwrap();
            let gl_r = gl_regexec(&re, text_c.as_ptr(), 0, std::ptr::null_mut(), 0);
            assert!(fl_r == 0 && gl_r == 0, "match: fl={fl_r} glibc={gl_r} (expected MATCH)");
            let iters = 200usize;
            let t0 = Instant::now();
            for _ in 0..iters {
                black_box(regex::regex_exec(black_box(&compiled), black_box(text.as_bytes()), &mut none, 0));
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                black_box(gl_regexec(black_box(&re), black_box(text_c.as_ptr()), 0, std::ptr::null_mut(), 0));
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!("REGEX MATCH {pat:?} fl={fl:.0}ns glibc={gl:.0}ns fl/glibc={:.3}x", fl / gl);
        }
    }
}
