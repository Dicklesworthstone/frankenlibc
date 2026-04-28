#![cfg(target_os = "linux")]

//! Conformance test for `getopt()` and `getopt_long()`.
//!
//! Verifies FrankenLibC's getopt implementation against expected POSIX behavior.
//! Note: Differential testing against live host libc is not reliable due to
//! shared symbol space issues (both impls export optind/optarg and may have
//! conflicting internal state). Instead we test against known-correct results.
//!
//! Bead: CONFORMANCE: libc getopt+getopt_long conformance matrix.

use std::ffi::{CStr, CString, c_char, c_int};
use std::sync::Mutex;

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    static mut optind: c_int;
    static mut optarg: *mut c_char;
    static mut opterr: c_int;
}

#[repr(C)]
struct LongOpt {
    name: *const c_char,
    has_arg: c_int,
    flag: *mut c_int,
    val: c_int,
}

const NO_ARGUMENT: c_int = 0;
const REQUIRED_ARGUMENT: c_int = 1;
const OPTIONAL_ARGUMENT: c_int = 2;

static OPT_LOCK: Mutex<()> = Mutex::new(());

fn build_argv(args: &[&str]) -> (Vec<CString>, Vec<*mut c_char>) {
    let cs: Vec<CString> = args.iter().map(|s| CString::new(*s).unwrap()).collect();
    let mut ptrs: Vec<*mut c_char> = cs.iter().map(|c| c.as_ptr() as *mut c_char).collect();
    ptrs.push(std::ptr::null_mut()); // null-terminate for C convention
    (cs, ptrs)
}

fn run_getopt_loop(args: &[&str], optstr: &str) -> Vec<(c_int, Option<String>)> {
    let (_keep, argv) = build_argv(args);
    let argc = (argv.len() - 1) as c_int;
    let optstr_c = CString::new(optstr).unwrap();
    unsafe {
        optind = 1;
        opterr = 0; // suppress error messages
    }
    let mut out = Vec::new();
    loop {
        let r = unsafe { fl::getopt(argc, argv.as_ptr(), optstr_c.as_ptr()) };
        if r == -1 {
            break;
        }
        let arg = unsafe { optarg };
        let arg_str = if arg.is_null() {
            None
        } else {
            Some(
                unsafe { CStr::from_ptr(arg) }
                    .to_string_lossy()
                    .into_owned(),
            )
        };
        out.push((r, arg_str));
        if out.len() > 32 {
            break;
        }
    }
    out
}

#[test]
fn conformance_getopt_basic_short_opts() {
    let _g = OPT_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // Basic option parsing
    assert_eq!(
        run_getopt_loop(&["prog", "-a", "-b"], "ab"),
        vec![(b'a' as c_int, None), (b'b' as c_int, None)]
    );

    // Option with attached argument
    assert_eq!(
        run_getopt_loop(&["prog", "-aval", "-b"], "a:b"),
        vec![
            (b'a' as c_int, Some("val".to_string())),
            (b'b' as c_int, None)
        ]
    );

    // Option with separate argument
    assert_eq!(
        run_getopt_loop(&["prog", "-a", "val", "-b"], "a:b"),
        vec![
            (b'a' as c_int, Some("val".to_string())),
            (b'b' as c_int, None)
        ]
    );

    // Unknown option returns '?'
    let result = run_getopt_loop(&["prog", "-x"], "ab");
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, b'?' as c_int);

    // Missing required argument returns '?' (or ':' if optstring starts with ':')
    let result = run_getopt_loop(&["prog", "-a"], "a:");
    assert_eq!(result.len(), 1);
    assert!(result[0].0 == b'?' as c_int || result[0].0 == b':' as c_int);

    // No args
    assert_eq!(run_getopt_loop(&["prog"], "ab"), vec![]);

    // Stop at first non-option
    assert_eq!(
        run_getopt_loop(&["prog", "-a", "file", "-b"], "ab"),
        vec![(b'a' as c_int, None)]
    );

    // Double-dash ends options
    assert_eq!(
        run_getopt_loop(&["prog", "-a", "--", "-b"], "ab"),
        vec![(b'a' as c_int, None)]
    );
}

#[test]
fn conformance_getopt_long_basic() {
    let _g = OPT_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let name_help = CString::new("help").unwrap();
    let name_file = CString::new("file").unwrap();
    let opts = [
        LongOpt {
            name: name_help.as_ptr(),
            has_arg: NO_ARGUMENT,
            flag: std::ptr::null_mut(),
            val: b'h' as c_int,
        },
        LongOpt {
            name: name_file.as_ptr(),
            has_arg: REQUIRED_ARGUMENT,
            flag: std::ptr::null_mut(),
            val: b'f' as c_int,
        },
        LongOpt {
            name: std::ptr::null(),
            has_arg: 0,
            flag: std::ptr::null_mut(),
            val: 0,
        },
    ];
    let optstr = CString::new("hf:").unwrap();

    let run = |args: &[&str]| -> Vec<(c_int, Option<String>)> {
        let (_keep, argv) = build_argv(args);
        let argc = (argv.len() - 1) as c_int;
        unsafe {
            optind = 1;
            opterr = 0;
        }
        let mut idx: c_int = -1;
        let mut out = Vec::new();
        loop {
            let r = unsafe {
                fl::getopt_long(
                    argc,
                    argv.as_ptr(),
                    optstr.as_ptr(),
                    opts.as_ptr() as *const _,
                    &mut idx,
                )
            };
            if r == -1 {
                break;
            }
            let arg = unsafe { optarg };
            let s = if arg.is_null() {
                None
            } else {
                Some(
                    unsafe { CStr::from_ptr(arg) }
                        .to_string_lossy()
                        .into_owned(),
                )
            };
            out.push((r, s));
            if out.len() > 32 {
                break;
            }
        }
        out
    };

    // Long options
    assert_eq!(
        run(&["prog", "--help", "--file=foo.txt"]),
        vec![
            (b'h' as c_int, None),
            (b'f' as c_int, Some("foo.txt".to_string()))
        ]
    );

    // Long option with separate argument
    assert_eq!(
        run(&["prog", "--file", "bar.txt"]),
        vec![(b'f' as c_int, Some("bar.txt".to_string()))]
    );

    // Mixed short and long
    assert_eq!(
        run(&["prog", "-h", "--file=test.txt"]),
        vec![
            (b'h' as c_int, None),
            (b'f' as c_int, Some("test.txt".to_string()))
        ]
    );

    let _ = OPTIONAL_ARGUMENT;
}

#[test]
fn getopt_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"unistd.h(getopt+getopt_long)\",\"reference\":\"POSIX\",\"functions\":2,\"test_type\":\"conformance\"}}",
    );
}
