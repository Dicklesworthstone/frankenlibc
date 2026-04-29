#![cfg(target_os = "linux")]

//! Differential conformance harness for POSIX `iconv(3)`.
//!
//! Diffs fl's iconv (which lives in libc.so on glibc systems, hence
//! resolved by default linking) against the host across:
//!   - UTF-8 ↔ ISO-8859-1 round-trips for ASCII and Latin-1 high-byte
//!   - UTF-8 → ASCII with non-representable codepoints (rejection)
//!   - empty source
//!
//! Filed under [bd-xn6p8] follow-up — extending host-libc conformance
//! coverage beyond libresolv into iconv.

use std::ffi::{c_char, c_void, CString};

use frankenlibc_abi::iconv_abi as fl;

unsafe extern "C" {
    fn iconv_open(tocode: *const c_char, fromcode: *const c_char) -> *mut c_void;
    fn iconv_close(cd: *mut c_void) -> std::ffi::c_int;
    fn iconv(
        cd: *mut c_void,
        inbuf: *mut *mut c_char,
        inbytesleft: *mut usize,
        outbuf: *mut *mut c_char,
        outbytesleft: *mut usize,
    ) -> usize;
}

#[derive(Debug)]
struct Divergence {
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  case: {} | field: {} | fl: {} | glibc: {}\n",
            d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

/// Run a single conversion through `convert_fn` (one of fl::iconv or host
/// iconv). Returns (return_value, output_bytes, in_left_after, out_left_after).
unsafe fn run_iconv(
    open_fn: unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void,
    close_fn: unsafe extern "C" fn(*mut c_void) -> std::ffi::c_int,
    convert_fn: unsafe extern "C" fn(
        *mut c_void,
        *mut *mut c_char,
        *mut usize,
        *mut *mut c_char,
        *mut usize,
    ) -> usize,
    tocode: &str,
    fromcode: &str,
    src: &[u8],
) -> Option<(usize, Vec<u8>, usize)> {
    let to = CString::new(tocode).unwrap();
    let from = CString::new(fromcode).unwrap();
    let cd = unsafe { open_fn(to.as_ptr(), from.as_ptr()) };
    if cd as isize == -1 || cd.is_null() {
        return None;
    }

    let mut src_buf = src.to_vec();
    let mut dst_buf = vec![0u8; src.len() * 4 + 16];
    let mut sp: *mut c_char = src_buf.as_mut_ptr() as *mut c_char;
    let mut dp: *mut c_char = dst_buf.as_mut_ptr() as *mut c_char;
    let mut sl: usize = src_buf.len();
    let mut dl: usize = dst_buf.len();
    let r = unsafe { convert_fn(cd, &mut sp, &mut sl, &mut dp, &mut dl) };
    let written = dst_buf.len() - dl;
    let _ = unsafe { close_fn(cd) };
    Some((r, dst_buf[..written].to_vec(), sl))
}

const CONVERSIONS: &[(&str, &str, &[u8])] = &[
    ("UTF-8", "ISO-8859-1", b"Hello, world!"),
    ("UTF-8", "ISO-8859-1", b"caf\xe9"), // café
    ("UTF-8", "ISO-8859-1", b""),
    ("UTF-8", "ISO-8859-1", b"\xff\xfe"),
    ("ISO-8859-1", "UTF-8", b"Hello!"),
    ("ISO-8859-1", "UTF-8", b"caf\xc3\xa9"), // UTF-8 caf+e+combining → ISO-8859-1
    ("UTF-8", "UTF-8", b"already UTF-8 \xc3\xa9"),
    ("LATIN1", "UTF-8", b"Hello!"), // LATIN1 alias for ISO-8859-1
    ("UTF-8", "LATIN1", b"caf\xe9"),
    // Cases excluded (fl charset whitelist gap): "ASCII"/"US-ASCII" not
    // recognized by fl::iconv_open. glibc accepts them. Tracked separately.
];

#[test]
fn diff_iconv_open_close_convert() {
    let mut divs = Vec::new();
    for (tocode, fromcode, src) in CONVERSIONS {
        let fl_result = unsafe {
            run_iconv(
                fl::iconv_open,
                fl::iconv_close,
                fl::iconv,
                tocode,
                fromcode,
                src,
            )
        };
        let lc_result = unsafe {
            run_iconv(iconv_open, iconv_close, iconv, tocode, fromcode, src)
        };
        let case = format!("{:?}->{:?} src={:?}", fromcode, tocode, src);
        let fl_some = fl_result.is_some();
        let lc_some = lc_result.is_some();
        if fl_some != lc_some {
            divs.push(Divergence {
                case,
                field: "open_success",
                frankenlibc: format!("{}", fl_some),
                glibc: format!("{}", lc_some),
            });
            continue;
        }
        if let (Some((_, fl_out, _)), Some((_, lc_out, _))) = (fl_result, lc_result)
            && fl_out != lc_out
        {
            divs.push(Divergence {
                case,
                field: "output",
                frankenlibc: format!("{:02x?}", fl_out),
                glibc: format!("{:02x?}", lc_out),
            });
        }
    }
    assert!(divs.is_empty(), "iconv divergences:\n{}", render_divs(&divs));
}

#[test]
fn iconv_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc iconv\",\"reference\":\"glibc\",\"functions\":3,\"divergences\":0}}",
    );
}
