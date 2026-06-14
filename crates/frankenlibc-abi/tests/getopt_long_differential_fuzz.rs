#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc getopt_long oracle (shared optind/optarg)

//! Randomized differential fuzzer for `getopt_long` vs host glibc. The existing
//! `conformance_diff_getopt` is a fixed battery against hand-written expectations
//! (its header even says live differential testing is "not reliable"); it IS
//! reliable when both engines are driven sequentially with a full reset
//! (`optind = 0`) and a FRESH argv copy each run, since getopt permutes the argv
//! pointer array in place. This generates random optstrings (with `+`/`-`/`:`
//! mode prefixes and `:`/`::` argument specs), random long-option tables, and
//! random argv token streams, then compares the FULL per-call contract — return
//! value, `optopt`, `optind`, `longindex`, and `optarg` — across the whole parse
//! loop. `opterr` is forced to 0 so the (stderr) error text is out of scope.

use std::ffi::{CStr, CString, c_char, c_int};
use std::sync::Mutex;

use frankenlibc_abi::unistd_abi as fl;

/// `optind`/`optarg`/`optopt` are process-global symbols shared by fl and host
/// glibc. The two tests in this file would otherwise race when cargo runs them
/// on parallel threads, corrupting each other's scan state. Serialize every
/// `run()` so each full parse loop observes a clean, exclusive global state.
static GETOPT_GLOBALS: Mutex<()> = Mutex::new(());

unsafe extern "C" {
    fn getopt_long(
        argc: c_int,
        argv: *const *mut c_char,
        optstring: *const c_char,
        longopts: *const libc::option,
        longindex: *mut c_int,
    ) -> c_int;
    static mut optind: c_int;
    static mut optarg: *mut c_char;
    static mut optopt: c_int;
    static mut opterr: c_int;
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

/// One captured getopt_long return: the full observable contract.
#[derive(PartialEq, Eq, Debug)]
struct Step {
    ret: c_int,
    optopt: c_int,
    optind: c_int,
    longindex: c_int,
    optarg: Option<String>,
}

const NO_ARGUMENT: c_int = 0;
const REQUIRED_ARGUMENT: c_int = 1;

const LONG_NAMES: &[&str] = &["verbose", "version", "file", "force", "help", "output"];

fn gen_optstring(r: &mut Lcg) -> String {
    let mut s = String::new();
    match r.below(5) {
        0 => s.push('+'),
        1 => s.push('-'),
        2 => s.push(':'),
        _ => {}
    }
    let letters = b"abfhov";
    let n = 1 + r.below(letters.len());
    for _ in 0..n {
        s.push(letters[r.below(letters.len())] as char);
        match r.below(3) {
            0 => s.push(':'),
            1 => s.push_str("::"),
            _ => {}
        }
    }
    s
}

/// Build a long-option table (name CStrings kept alive in `keep`). flag is
/// always null so the return value is `val`; `val` is the name's first letter.
/// Names are a DISTINCT subset (duplicate long names are a separate ambiguity
/// edge tracked elsewhere).
fn gen_longopts(r: &mut Lcg, keep: &mut Vec<CString>) -> Vec<libc::option> {
    let mut pool: Vec<&str> = LONG_NAMES.to_vec();
    // Fisher-Yates partial shuffle for a distinct random subset.
    for i in 0..pool.len() {
        let j = i + r.below(pool.len() - i);
        pool.swap(i, j);
    }
    let count = r.below(LONG_NAMES.len() + 1);
    let mut opts = Vec::new();
    for &name in pool.iter().take(count) {
        let c = CString::new(name).unwrap();
        let val = name.as_bytes()[0] as c_int;
        let has_arg = r.below(3) as c_int; // 0 none, 1 required, 2 optional
        let ptr = c.as_ptr();
        keep.push(c);
        opts.push(libc::option {
            name: ptr,
            has_arg,
            flag: std::ptr::null_mut(),
            val,
        });
    }
    opts.push(libc::option {
        name: std::ptr::null(),
        has_arg: 0,
        flag: std::ptr::null_mut(),
        val: 0,
    });
    opts
}

fn gen_argv(r: &mut Lcg) -> Vec<String> {
    let mut v = vec!["prog".to_string()];
    let n = r.below(7);
    for _ in 0..n {
        let tok = match r.below(13) {
            0 => "-a".to_string(),
            1 => "-f".to_string(),
            2 => "-fval".to_string(),
            3 => "-ab".to_string(), // bundled
            4 => format!("--{}", LONG_NAMES[r.below(LONG_NAMES.len())]),
            5 => format!("--{}=x", LONG_NAMES[r.below(LONG_NAMES.len())]),
            6 => "--ver".to_string(), // abbreviation (ambiguous: verbose/version)
            7 => "--fi".to_string(),  // abbreviation -> file
            8 => "--".to_string(),
            9 => "operand".to_string(),
            // A bare "-" is a non-option operand (never an option/argument):
            // glibc permutes/leaves it. Now exercised after the exchange-model
            // rewrite (bd-1fw2a7).
            10 => "-".to_string(),
            11 => "--xyz".to_string(), // unknown long option
            _ => "-z".to_string(),     // unknown short option
        };
        v.push(tok);
    }
    v
}

/// Drive one engine over `args` to completion, returning the captured steps.
fn run(
    getopt_fn: unsafe extern "C" fn(
        c_int,
        *const *mut c_char,
        *const c_char,
        *const libc::option,
        *mut c_int,
    ) -> c_int,
    args: &[String],
    optstr: &CStr,
    longopts: &[libc::option],
) -> Vec<Step> {
    let _guard = GETOPT_GLOBALS.lock().unwrap_or_else(|e| e.into_inner());
    let cs: Vec<CString> = args
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();
    let mut argv: Vec<*mut c_char> = cs.iter().map(|c| c.as_ptr() as *mut c_char).collect();
    argv.push(std::ptr::null_mut());
    let argc = (argv.len() - 1) as c_int;

    unsafe {
        optind = 0; // full reinitialization (re-reads +/-/: mode prefixes)
        opterr = 0;
        optopt = 0;
        optarg = std::ptr::null_mut();
    }

    let mut steps = Vec::new();
    loop {
        let mut longindex: c_int = -1;
        let r = unsafe {
            getopt_fn(
                argc,
                argv.as_ptr(),
                optstr.as_ptr(),
                longopts.as_ptr(),
                &mut longindex,
            )
        };
        if r == -1 {
            break;
        }
        let oa = unsafe { optarg };
        let optarg_s = if oa.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(oa) }.to_string_lossy().into_owned())
        };
        // POSIX defines `optopt` only after a '?' or ':' return; on a successful
        // option it is unspecified (glibc leaves internal scratch state there,
        // e.g. after a `-W`-routed long option), so normalize it out otherwise.
        let optopt_significant = r == b'?' as c_int || r == b':' as c_int;
        steps.push(Step {
            ret: r,
            optopt: if optopt_significant {
                unsafe { optopt }
            } else {
                0
            },
            optind: unsafe { optind },
            longindex,
            optarg: optarg_s,
        });
        if steps.len() > 24 {
            break;
        }
    }
    // Record the final optind (where the operand tail begins).
    steps.push(Step {
        ret: -1,
        optopt: 0,
        optind: unsafe { optind },
        longindex: -1,
        optarg: None,
    });
    steps
}

/// Focused, deterministic differential test for the long-option ABBREVIATION
/// feature (GNU unambiguous-prefix matching). All argv put options before any
/// operand so NO permutation occurs — isolating abbreviation from the separate
/// permutation/`-` getopt bugs tracked in bd-1fw2a7. Compares fl vs live
/// glibc step-for-step.
#[test]
fn getopt_long_abbreviation_matches_glibc() {
    let no = NO_ARGUMENT;
    let req = REQUIRED_ARGUMENT;
    // (optstring, [(name, has_arg, val)], argv-after-prog)
    let cases: Vec<(&str, Vec<(&str, c_int, u8)>, Vec<&str>)> = vec![
        // Unique prefix -> matches.
        ("", vec![("verbose", no, b'v')], vec!["--verb"]),
        ("", vec![("verbose", no, b'v')], vec!["--v"]),
        // Required-arg long option via abbreviation takes the next argv.
        ("", vec![("file", req, b'f')], vec!["--fi", "data"]),
        ("", vec![("file", req, b'f')], vec!["--fi=data"]),
        // Exact match wins over a longer option sharing the prefix.
        (
            "",
            vec![("ver", no, b'x'), ("verbose", no, b'v')],
            vec!["--ver"],
        ),
        // Ambiguous: same val but DIFFERENT has_arg -> '?'.
        (
            "",
            vec![("verbose", no, b'v'), ("version", req, b'v')],
            vec!["--ver"],
        ),
        // Ambiguous: different val -> '?'.
        (
            "",
            vec![("verbose", no, b'v'), ("version", no, b's')],
            vec!["--ver"],
        ),
        // Not ambiguous: identical has_arg+flag+val -> matches first.
        (
            "",
            vec![("verbose", no, b'v'), ("verbose", no, b'v')],
            vec!["--ver"],
        ),
        // Unknown long option -> '?'.
        ("", vec![("verbose", no, b'v')], vec!["--zzz"]),
        // Abbreviation alongside a short option.
        ("a", vec![("verbose", no, b'v')], vec!["-a", "--verb"]),
        // --- GNU `W;` extension: `-W foo` is processed as `--foo`. ---
        // Separated form, required-arg long takes the following argv.
        ("W;", vec![("file", req, b'f')], vec!["-W", "file", "data"]),
        // Inline `-Wname=value`.
        ("W;", vec![("file", req, b'f')], vec!["-Wfile=q"]),
        // Separated form, no-argument long option.
        ("W;", vec![("verbose", no, b'v')], vec!["-W", "verbose"]),
        // Abbreviation through `-W`.
        ("W;", vec![("verbose", no, b'v')], vec!["-W", "verb"]),
        // Unknown long via `-W` -> '?'.
        ("W;", vec![("verbose", no, b'v')], vec!["-W", "zzz"]),
        // Required-arg long via `-W` with no argument available -> '?'.
        ("W;", vec![("file", req, b'f')], vec!["-W", "file"]),
        // Leading ':' makes the missing W-routed required arg report ':'.
        (":W;", vec![("file", req, b'f')], vec!["-W", "file"]),
        // Ambiguous abbreviation through `-W` -> '?'.
        (
            "W;",
            vec![("verbose", no, b'v'), ("version", no, b's')],
            vec!["-W", "ver"],
        ),
        // `-W` alongside an ordinary short option.
        (
            "W;a",
            vec![("file", req, b'f')],
            vec!["-a", "-W", "file", "x"],
        ),
        // `-aW foo` — `-W` mid-bundle after a short option.
        (
            "W;a",
            vec![("verbose", no, b'v')],
            vec!["-aW", "verbose"],
        ),
        // `--name=value` on a no-arg long routed via `-W` -> '?'.
        ("W;", vec![("verbose", no, b'v')], vec!["-Wverbose=x"]),
        // A literal `-;` is NOT a selectable option even with `W;` present:
        // glibc forces `c == ';'` to the unknown-option path.
        ("W;ab", vec![("verbose", no, b'v')], vec!["-;"]),
    ];

    for (i, (optstr, longs, argv)) in cases.iter().enumerate() {
        let _keep: Vec<CString> = longs
            .iter()
            .map(|(n, _, _)| CString::new(*n).unwrap())
            .collect();
        let mut opts: Vec<libc::option> = longs
            .iter()
            .zip(_keep.iter())
            .map(|(&(_, ha, v), c)| libc::option {
                name: c.as_ptr(),
                has_arg: ha,
                flag: std::ptr::null_mut(),
                val: v as c_int,
            })
            .collect();
        opts.push(libc::option {
            name: std::ptr::null(),
            has_arg: 0,
            flag: std::ptr::null_mut(),
            val: 0,
        });
        let cstr = CString::new(*optstr).unwrap();
        let args: Vec<String> = std::iter::once("prog".to_string())
            .chain(argv.iter().map(|s| s.to_string()))
            .collect();
        let fl_steps = run(fl::getopt_long, &args, &cstr, &opts);
        let lc_steps = run(getopt_long, &args, &cstr, &opts);
        assert_eq!(
            fl_steps, lc_steps,
            "case {i}: optstr={optstr:?} argv={argv:?}"
        );
    }
}

#[test]
fn getopt_long_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x9e37_79b9_0907_d1ee);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..60_000 {
        let optstr = CString::new(gen_optstring(&mut r)).unwrap();
        let mut keep = Vec::new();
        let longopts = gen_longopts(&mut r, &mut keep);
        let args = gen_argv(&mut r);

        let mut fl_steps = run(fl::getopt_long, &args, &optstr, &longopts);
        let mut lc_steps = run(getopt_long, &args, &optstr, &longopts);
        // `optopt` is only specified on a `?`/`:` return; `longindex` only on a
        // successful long-option match. Normalize the unspecified slots away so
        // the comparison pins the defined contract, not internal artifacts.
        let normalize = |steps: &mut Vec<Step>| {
            for s in steps {
                let err = s.ret == b'?' as c_int || s.ret == b':' as c_int;
                if !err {
                    s.optopt = 0;
                } else {
                    s.longindex = -1;
                }
            }
        };
        normalize(&mut fl_steps);
        normalize(&mut lc_steps);
        compared += 1;

        if fl_steps != lc_steps && divs.len() < 30 {
            let lnames: Vec<String> = keep
                .iter()
                .map(|c| c.to_string_lossy().into_owned())
                .collect();
            let msg = format!(
                "optstr={:?} longs={:?} argv={:?}\n    fl   ={fl_steps:?}\n    glibc={lc_steps:?}",
                optstr.to_string_lossy(),
                lnames,
                &args[1..],
            );
            eprintln!("DIV: {msg}");
            divs.push(msg);
        }
    }

    assert!(
        divs.is_empty(),
        "getopt_long diverged from host glibc on some of {compared} cases (showing up to 30):\n{}",
        divs.join("\n")
    );
    eprintln!("getopt_long differential fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
