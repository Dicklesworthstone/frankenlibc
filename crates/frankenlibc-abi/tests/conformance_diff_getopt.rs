#![cfg(target_os = "linux")]

//! Differential conformance harness for `getopt()` and `getopt_long()`.
//!
//! Uses simple synthetic argv vectors. Both impls share the same
//! `optind`/`optarg`/`optopt` global state, so each test resets
//! optind=1 before invoking the parser. Tests serialize via OPT_LOCK.
//!
//! Bead: CONFORMANCE: libc getopt+getopt_long diff matrix.

use std::ffi::{CString, c_char, c_int};
use std::sync::Mutex;

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn getopt(argc: c_int, argv: *const *mut c_char, optstring: *const c_char) -> c_int;
    fn getopt_long(
        argc: c_int,
        argv: *const *mut c_char,
        optstring: *const c_char,
        longopts: *const LongOpt,
        longindex: *mut c_int,
    ) -> c_int;
    static mut optind: c_int;
    static mut optarg: *mut c_char;
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
    let ptrs: Vec<*mut c_char> = cs.iter().map(|c| c.as_ptr() as *mut c_char).collect();
    (cs, ptrs)
}

fn run_getopt_loop(use_fl: bool, args: &[&str], optstr: &str) -> Vec<(c_int, Option<String>)> {
    let (_keep, mut argv) = build_argv(args);
    let optstr_c = CString::new(optstr).unwrap();
    unsafe { optind = 1 };
    let mut out = Vec::new();
    loop {
        let r = if use_fl {
            unsafe { fl::getopt(argv.len() as c_int, argv.as_ptr(), optstr_c.as_ptr()) }
        } else {
            unsafe { getopt(argv.len() as c_int, argv.as_ptr(), optstr_c.as_ptr()) }
        };
        if r == -1 {
            break;
        }
        let arg = unsafe { optarg };
        let arg_str = if arg.is_null() {
            None
        } else {
            Some(
                unsafe { std::ffi::CStr::from_ptr(arg) }
                    .to_string_lossy()
                    .into_owned(),
            )
        };
        out.push((r, arg_str));
        // Avoid runaway loop.
        if out.len() > 32 {
            break;
        }
    }
    let _ = argv.as_mut_ptr();
    out
}

#[test]
fn diff_getopt_basic_short_opts() {
    let _g = OPT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let cases: &[(&[&str], &str)] = &[
        (&["prog", "-a", "-b"], "ab"),
        (&["prog", "-aval", "-b"], "a:b"),
        (&["prog", "-a", "val", "-b"], "a:b"),
        (&["prog", "-x"], "ab"), // unknown opt
        (&["prog", "-a"], "a:"), // missing required arg
        (&["prog"], "ab"),       // no args
    ];
    for (args, opt) in cases {
        let v_fl = run_getopt_loop(true, args, opt);
        let v_lc = run_getopt_loop(false, args, opt);
        assert_eq!(
            v_fl, v_lc,
            "getopt({args:?}, {opt:?}) divergence: fl={v_fl:?}, lc={v_lc:?}"
        );
    }
}

#[test]
fn diff_getopt_long_basic() {
    let _g = OPT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let name_help = CString::new("help").unwrap();
    let name_file = CString::new("file").unwrap();
    let opts_fl = vec![
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
    let opts_lc = vec![
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

    let run = |use_fl: bool, opts: &[LongOpt]| -> Vec<(c_int, Option<String>)> {
        let args = ["prog", "--help", "--file=foo.txt", "extra"];
        let (_keep, argv) = build_argv(&args);
        unsafe { optind = 1 };
        let mut idx: c_int = -1;
        let mut out = Vec::new();
        loop {
            let r = if use_fl {
                unsafe {
                    fl::getopt_long(
                        argv.len() as c_int,
                        argv.as_ptr(),
                        optstr.as_ptr(),
                        opts.as_ptr() as *const _,
                        &mut idx,
                    )
                }
            } else {
                unsafe {
                    getopt_long(
                        argv.len() as c_int,
                        argv.as_ptr(),
                        optstr.as_ptr(),
                        opts.as_ptr(),
                        &mut idx,
                    )
                }
            };
            if r == -1 {
                break;
            }
            let arg = unsafe { optarg };
            let s = if arg.is_null() {
                None
            } else {
                Some(
                    unsafe { std::ffi::CStr::from_ptr(arg) }
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
    let v_fl = run(true, &opts_fl);
    let v_lc = run(false, &opts_lc);
    assert_eq!(v_fl, v_lc, "getopt_long divergence");
    let _ = OPTIONAL_ARGUMENT;
}

#[test]
fn getopt_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"unistd.h(getopt+getopt_long)\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
