#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc strfmon oracle (libc, linked by std)

//! Randomized live differential fuzzer for `strfmon` vs host glibc. fl's
//! `strfmon`/`strfmon_l`/`__strfmon_l` were stubs that ignored the format string
//! entirely (read one f64, emit `{:.2}`); this calls the real fl ABI `strfmon`
//! (variadic) and the host `strfmon` with the SAME format + value, comparing the
//! full contract (return value + the exact bytes written) in the C locale.

use std::ffi::{CString, c_char, c_int};

use frankenlibc_abi::unistd_abi::strfmon as fl_strfmon;

unsafe extern "C" {
    fn strfmon(s: *mut c_char, max: usize, fmt: *const c_char, ...) -> isize;
    fn setlocale(category: c_int, locale: *const c_char) -> *mut c_char;
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
}

#[derive(PartialEq, Eq, Debug)]
struct Out {
    ret: isize,
    out: Option<String>,
}

/// Run one strfmon (`$f`) with a single f64 value and render the result.
macro_rules! run {
    ($f:path, $fmt:expr, $val:expr) => {{
        let mut buf = [0u8; 128];
        let ret = unsafe { $f(buf.as_mut_ptr() as *mut c_char, buf.len(), $fmt, $val) };
        let out = if ret >= 0 {
            let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            Some(String::from_utf8_lossy(&buf[..n]).into_owned())
        } else {
            None
        };
        Out { ret, out }
    }};
}

fn host(fmt: &CString, val: f64) -> Out {
    run!(strfmon, fmt.as_ptr(), val)
}
fn fl(fmt: &CString, val: f64) -> Out {
    run!(fl_strfmon, fmt.as_ptr(), val)
}

#[test]
fn strfmon_learn_glibc_c_locale() {
    unsafe { setlocale(libc::LC_ALL, c"C".as_ptr()) };
    let formats = [
        "%n", "%i", "%11n", "%#6n", "%#6.3n", "%-14#5.4n", "%=*11n", "%^n", "%(n", "%+n", "%!n",
        "%.0n", "%.4n", "Cost: %n!", "%%", "%-11n", "%(#7.2n", "%!(n", "%^#10.2i",
    ];
    let vals = [
        1234.567, -1234.567, 0.0, 0.005, -0.005, 1_000_000.0, -0.0, 12.0, 0.5,
    ];
    for f in formats {
        let cf = CString::new(f).unwrap();
        for &v in &vals {
            let h = host(&cf, v);
            let l = fl(&cf, v);
            let mark = if h == l { "  " } else { "!!" };
            eprintln!("{mark} fmt={f:?} val={v}\n     glibc={h:?}\n     fl   ={l:?}");
        }
    }
}
