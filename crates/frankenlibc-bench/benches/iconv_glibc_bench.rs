//! Head-to-head `iconv` benchmark: FrankenLibC C ABI vs host glibc (dlmopen).
//!
//! iconv (charset transcoding) is a large surface that the existing
//! `iconv_bench` measured only in isolation (the core Rust API). This compares
//! fl's exported C ABI `iconv_open`/`iconv`/`iconv_close` against a pristine host
//! glibc loaded via `dlmopen(LM_ID_NEWLM, "libc.so.6")` so fl's `no_mangle`
//! interposition does not shadow the host symbols — each converter is exercised
//! with its own paired open/convert/close.

use std::ffi::{c_char, c_int, c_void};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use criterion::{Criterion, black_box, criterion_group, criterion_main};

type IconvOpenFn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type IconvFn = unsafe extern "C" fn(
    *mut c_void,
    *mut *mut c_char,
    *mut usize,
    *mut *mut c_char,
    *mut usize,
) -> usize;
type IconvCloseFn = unsafe extern "C" fn(*mut c_void) -> c_int;

struct HostIconv {
    open: IconvOpenFn,
    convert: IconvFn,
    close: IconvCloseFn,
}

fn host_iconv() -> &'static HostIconv {
    static H: OnceLock<HostIconv> = OnceLock::new();
    H.get_or_init(|| unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "dlmopen libc.so.6 failed");
        let sym = |n: &[u8]| {
            let p = libc::dlsym(handle, n.as_ptr().cast());
            assert!(!p.is_null(), "dlsym failed");
            p
        };
        HostIconv {
            open: std::mem::transmute::<*mut c_void, IconvOpenFn>(sym(b"iconv_open\0")),
            convert: std::mem::transmute::<*mut c_void, IconvFn>(sym(b"iconv\0")),
            close: std::mem::transmute::<*mut c_void, IconvCloseFn>(sym(b"iconv_close\0")),
        }
    })
}

#[derive(Default)]
struct Stats {
    s: Vec<f64>,
}
impl Stats {
    fn record(&mut self, ops: u64, dur: Duration) {
        if ops > 0 {
            self.s.push(dur.as_nanos() as f64 / ops as f64);
        }
    }
    fn report(&self, label: &str, conv: &str) {
        let mut s = self.s.clone();
        if s.is_empty() {
            return;
        }
        s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let p50 = s[s.len() / 2];
        let mean = s.iter().sum::<f64>() / s.len() as f64;
        println!("ICONV_BENCH impl={label} conv=\"{conv}\" p50_ns_op={p50:.1} mean_ns_op={mean:.1}");
    }
}

/// One conversion: reset in/out pointers, run iconv over the whole input.
#[inline]
unsafe fn convert_once(
    f: IconvFn,
    cd: *mut c_void,
    src: &[u8],
    dst: &mut [u8],
) -> usize {
    let mut inp = src.as_ptr() as *mut c_char;
    let mut inleft = src.len();
    let mut outp = dst.as_mut_ptr() as *mut c_char;
    let mut outleft = dst.len();
    unsafe { f(cd, &mut inp, &mut inleft, &mut outp, &mut outleft) }
}

fn run_conv(
    c: &mut Criterion,
    conv: &str,
    to: &[u8],
    from: &[u8],
    src: &[u8],
) {
    let host = host_iconv();
    let mut group = c.benchmark_group(format!("iconv/{conv}"));
    group.sample_size(40);

    let mut dst = vec![0u8; src.len() * 4 + 16];

    // fl C ABI.
    let fl_cd =
        unsafe { frankenlibc_abi::iconv_abi::iconv_open(to.as_ptr().cast(), from.as_ptr().cast()) };
    assert!(fl_cd as isize != -1 && !fl_cd.is_null(), "fl iconv_open failed");
    let fl_stats = std::cell::RefCell::new(Stats::default());
    group.bench_function("fl", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let r = unsafe {
                    convert_once(frankenlibc_abi::iconv_abi::iconv, fl_cd, src, &mut dst)
                };
                black_box(r);
            }
            let dur = start.elapsed().max(Duration::from_nanos(1));
            fl_stats.borrow_mut().record(iters, dur);
            dur
        });
    });
    fl_stats.borrow().report("fl", conv);
    unsafe { frankenlibc_abi::iconv_abi::iconv_close(fl_cd) };

    // host glibc.
    let gl_cd = unsafe { (host.open)(to.as_ptr().cast(), from.as_ptr().cast()) };
    assert!(gl_cd as isize != -1 && !gl_cd.is_null(), "glibc iconv_open failed");
    let gl_stats = std::cell::RefCell::new(Stats::default());
    group.bench_function("glibc", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let r = unsafe { convert_once(host.convert, gl_cd, src, &mut dst) };
                black_box(r);
            }
            let dur = start.elapsed().max(Duration::from_nanos(1));
            gl_stats.borrow_mut().record(iters, dur);
            dur
        });
    });
    gl_stats.borrow().report("glibc", conv);
    unsafe { (host.close)(gl_cd) };

    group.finish();
}

/// Minimal UTF-8 encoder for building source buffers.
fn u8enc(cps: &[u32]) -> Vec<u8> {
    let mut v = Vec::new();
    for &cp in cps {
        if cp < 0x80 {
            v.push(cp as u8);
        } else if cp < 0x800 {
            v.push(0xC0 | (cp >> 6) as u8);
            v.push(0x80 | (cp & 0x3F) as u8);
        } else if cp < 0x10000 {
            v.push(0xE0 | (cp >> 12) as u8);
            v.push(0x80 | ((cp >> 6) & 0x3F) as u8);
            v.push(0x80 | (cp & 0x3F) as u8);
        } else {
            v.push(0xF0 | (cp >> 18) as u8);
            v.push(0x80 | ((cp >> 12) & 0x3F) as u8);
            v.push(0x80 | ((cp >> 6) & 0x3F) as u8);
            v.push(0x80 | (cp & 0x3F) as u8);
        }
    }
    v
}

fn bench(c: &mut Criterion) {
    // ~1 KiB pure ASCII (the bulk-copy hot path).
    let ascii: Vec<u8> = (0..1024).map(|i| b'a' + (i % 26) as u8).collect();
    run_conv(c, "utf8_to_latin1_ascii", b"ISO-8859-1\0", b"UTF-8\0", &ascii);
    run_conv(c, "utf8_to_utf16le_ascii", b"UTF-16LE\0", b"UTF-8\0", &ascii);
    run_conv(c, "utf8_to_utf32le_ascii", b"UTF-32LE\0", b"UTF-8\0", &ascii);

    // ~1 KiB Cyrillic (U+0410..=U+044F) as 2-byte UTF-8: real transcoding.
    let cyr_cps: Vec<u32> = (0..512u32).map(|k| 0x0410 + (k % 0x40)).collect();
    let cyr = u8enc(&cyr_cps);
    run_conv(c, "utf8_cyrillic_to_koi8r", b"KOI8-R\0", b"UTF-8\0", &cyr);
    run_conv(c, "utf8_cyrillic_to_utf16le", b"UTF-16LE\0", b"UTF-8\0", &cyr);
    // Forward 2-byte UTF-8 -> UTF-32 (currently a scalar store): probe if a lever.
    run_conv(c, "utf8_cyrillic_to_utf32le", b"UTF-32LE\0", b"UTF-8\0", &cyr);

    // REVERSE direction: UTF-16LE -> UTF-8 (reading UTF-16 -> UTF-8, common).
    let ascii_u16le: Vec<u8> = ascii.iter().flat_map(|&b| [b, 0]).collect();
    run_conv(c, "utf16le_ascii_to_utf8", b"UTF-8\0", b"UTF-16LE\0", &ascii_u16le);
    // Non-ASCII reverse: UTF-16LE Cyrillic -> 2-byte UTF-8 (the 2-byte-output run).
    let cyr_u16le: Vec<u8> = cyr_cps.iter().flat_map(|&c| (c as u16).to_le_bytes()).collect();
    run_conv(c, "utf16le_cyrillic_to_utf8", b"UTF-8\0", b"UTF-16LE\0", &cyr_u16le);
    // UTF-32LE Cyrillic -> 2-byte UTF-8: the 4-byte-unit reverse 2-byte-output run.
    let cyr_u32le: Vec<u8> = cyr_cps.iter().flat_map(|&c| c.to_le_bytes()).collect();
    run_conv(c, "utf32le_cyrillic_to_utf8", b"UTF-8\0", b"UTF-32LE\0", &cyr_u32le);
    // UTF-16BE -> UTF-8 (network/Java byte order): the symmetric BE case.
    let ascii_u16be: Vec<u8> = ascii.iter().flat_map(|&b| [0, b]).collect();
    run_conv(c, "utf16be_ascii_to_utf8", b"UTF-8\0", b"UTF-16BE\0", &ascii_u16be);
    // UTF-32 LE/BE -> UTF-8 ASCII: 4-byte fixed-width source SIMD run.
    let ascii_u32le: Vec<u8> = ascii.iter().flat_map(|&b| [b, 0, 0, 0]).collect();
    run_conv(c, "utf32le_ascii_to_utf8", b"UTF-8\0", b"UTF-32LE\0", &ascii_u32le);
    let ascii_u32be: Vec<u8> = ascii.iter().flat_map(|&b| [0, 0, 0, b]).collect();
    run_conv(c, "utf32be_ascii_to_utf8", b"UTF-8\0", b"UTF-32BE\0", &ascii_u32be);

    // CJK encode (table-based): UTF-8 Chinese -> GB18030, Japanese -> CP932.
    // ~512 common CJK ideographs (U+4E00..) as 3-byte UTF-8.
    let cjk_cps: Vec<u32> = (0..512u32).map(|k| 0x4E00 + (k % 0x300)).collect();
    let cjk = u8enc(&cjk_cps);
    run_conv(c, "utf8_cjk_to_gb18030", b"GB18030\0", b"UTF-8\0", &cjk);
    run_conv(c, "utf8_cjk_to_utf16le", b"UTF-16LE\0", b"UTF-8\0", &cjk);
    run_conv(c, "utf8_cjk_to_utf32le", b"UTF-32LE\0", b"UTF-8\0", &cjk);
    // Reverse: UTF-16LE CJK -> 3-byte UTF-8 (the 3-byte-output run).
    let cjk_u16le: Vec<u8> = cjk_cps.iter().flat_map(|&c| (c as u16).to_le_bytes()).collect();
    run_conv(c, "utf16le_cjk_to_utf8", b"UTF-8\0", b"UTF-16LE\0", &cjk_u16le);
    // UTF-32LE CJK -> 3-byte UTF-8: the 4-byte-unit reverse 3-byte-output run.
    let cjk_u32le: Vec<u8> = cjk_cps.iter().flat_map(|&c| c.to_le_bytes()).collect();
    run_conv(c, "utf32le_cjk_to_utf8", b"UTF-8\0", b"UTF-32LE\0", &cjk_u32le);
    // Hiragana (U+3040..U+309F) -> CP932 (Shift-JIS).
    let jp_cps: Vec<u32> = (0..512u32).map(|k| 0x3041 + (k % 0x5E)).collect();
    let jp = u8enc(&jp_cps);
    run_conv(c, "utf8_jp_to_cp932", b"CP932\0", b"UTF-8\0", &jp);

    // DECODE side (legacy multibyte -> UTF-8). Build the legacy source with the
    // host glibc (authoritative), then bench the decode head-to-head. CP932 is
    // excluded from fl's DBCS->UTF-8 fast-path guard (only the match handles it),
    // so it falls to the slow generic body; GB18030 IS in the guard (control).
    let host = host_iconv();
    let host_to = |to: &[u8], src: &[u8]| -> Vec<u8> {
        let cd = unsafe { (host.open)(to.as_ptr().cast(), b"UTF-8\0".as_ptr().cast()) };
        assert!(cd as isize != -1 && !cd.is_null());
        let mut dst = vec![0u8; src.len() * 4 + 16];
        let mut inp = src.as_ptr() as *mut c_char;
        let mut inl = src.len();
        let mut outp = dst.as_mut_ptr() as *mut c_char;
        let mut outl = dst.len();
        unsafe { (host.convert)(cd, &mut inp, &mut inl, &mut outp, &mut outl) };
        unsafe { (host.close)(cd) };
        let n = dst.len() - outl;
        dst.truncate(n);
        dst
    };
    let cp932_src = host_to(b"CP932\0", &jp);
    run_conv(c, "cp932_to_utf8", b"UTF-8\0", b"CP932\0", &cp932_src);
    let gb_src = host_to(b"GB18030\0", &cjk);
    run_conv(c, "gb18030_to_utf8", b"UTF-8\0", b"GB18030\0", &gb_src);
}

criterion_group!(benches, bench);
criterion_main!(benches);
