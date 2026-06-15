#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc asprintf oracle

//! Differential test for `asprintf` vs host glibc: the return value (byte count,
//! excluding the NUL) and the allocated buffer contents (binary-safe through an
//! embedded NUL produced by `%c`), including the empty-format case and a large
//! string that forces buffer growth. Each engine allocates with its own malloc;
//! buffers are read in-process and leaked (the test process exits).

use std::ffi::CString;

use frankenlibc_abi::stdio_abi as fl;

unsafe extern "C" {
    fn asprintf(strp: *mut *mut libc::c_char, fmt: *const libc::c_char, ...) -> libc::c_int;
}

#[derive(Debug, PartialEq, Eq)]
struct Out {
    ret: i32,
    bytes: Vec<u8>,
}

fn read_out(ret: i32, p: *mut libc::c_char) -> Out {
    let bytes = if ret >= 0 && !p.is_null() {
        unsafe { std::slice::from_raw_parts(p as *const u8, ret as usize) }.to_vec()
    } else {
        Vec::new()
    };
    Out { ret, bytes }
}

#[test]
#[allow(clippy::approx_constant)]
fn asprintf_matches_glibc() {
    let mut fails = Vec::new();

    macro_rules! case {
        ($label:expr, $fmt:expr $(, $arg:expr)*) => {{
            let cf = CString::new($fmt).unwrap();
            let mut pf: *mut libc::c_char = std::ptr::null_mut();
            let rf = unsafe { fl::asprintf(&mut pf, cf.as_ptr() $(, $arg)*) };
            let f = read_out(rf, pf);
            let mut pg: *mut libc::c_char = std::ptr::null_mut();
            let rg = unsafe { asprintf(&mut pg, cf.as_ptr() $(, $arg)*) };
            let g = read_out(rg, pg);
            if f != g {
                fails.push(format!(
                    "{}: fl=(ret={}, {:?}) glibc=(ret={}, {:?})",
                    $label, f.ret, String::from_utf8_lossy(&f.bytes),
                    g.ret, String::from_utf8_lossy(&g.bytes)
                ));
            }
        }};
    }

    // Bind string args to locals so the CStrings outlive both engine calls
    // (the macro evaluates each arg expression once per engine).
    let big_cs = CString::new("A".repeat(2000)).unwrap();
    let k_cs = CString::new("k").unwrap();

    case!("int", "hello %d", 42i32);
    case!("empty", "");
    case!("plain", "no specifiers here");
    case!("nul-via-c", "%c%c%c", 'a' as i32, 0i32, 'b' as i32);
    case!("big", "%s", big_cs.as_ptr());
    case!("mixed", "%s=%d (%x)", k_cs.as_ptr(), -5i32, 255u32);
    case!("pct", "100%% done");
    case!("float", "%.3f", 3.14159f64);

    assert!(
        fails.is_empty(),
        "asprintf diverged from glibc:\n{}",
        fails.join("\n")
    );
}
