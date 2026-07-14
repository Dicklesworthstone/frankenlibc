//! Head-to-head `iconv` benchmark: FrankenLibC C ABI vs host glibc (dlmopen).
//!
//! iconv (charset transcoding) is a large surface that the existing
//! `iconv_bench` measured only in isolation (the core Rust API). This compares
//! fl's exported C ABI `iconv_open`/`iconv`/`iconv_close` against a pristine host
//! glibc loaded via `dlmopen(LM_ID_NEWLM, "libc.so.6")` so fl's `no_mangle`
//! interposition does not shadow the host symbols — each converter is exercised
//! with its own paired open/convert/close.

use std::ffi::{c_char, c_int, c_void};
use std::hint::black_box;
use std::sync::OnceLock;
use std::time::Instant;

// Manual-timing harness (harness = false): rch executes a plain `fn main()` remotely and
// returns its stdout, whereas a criterion `criterion_main!` harness is built-but-not-run
// under `rch exec -- cargo bench` (see NEGATIVE_EVIDENCE cc-iconv-probe-2026-07-11). `Bencher`
// is a zero-cost placeholder so the ~35 `run_conv(c, ...)` call sites stay unchanged.
struct Bencher;

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

/// Median (p50) ns per whole-buffer conversion over `samples` samples of `iters` conversions.
fn measure(samples: usize, iters: u64, mut op: impl FnMut()) -> f64 {
    let mut per = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        for _ in 0..iters {
            op();
        }
        per.push(start.elapsed().as_nanos() as f64 / iters.max(1) as f64);
    }
    per.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    per[per.len() / 2]
}

/// One conversion: reset in/out pointers, run iconv over the whole input.
#[inline]
unsafe fn convert_once(f: IconvFn, cd: *mut c_void, src: &[u8], dst: &mut [u8]) -> usize {
    let mut inp = src.as_ptr() as *mut c_char;
    let mut inleft = src.len();
    let mut outp = dst.as_mut_ptr() as *mut c_char;
    let mut outleft = dst.len();
    unsafe { f(cd, &mut inp, &mut inleft, &mut outp, &mut outleft) }
}

fn run_conv(_c: &mut Bencher, conv: &str, to: &[u8], from: &[u8], src: &[u8]) {
    let host = host_iconv();
    // *12 (not *4): TSCII decodes one byte to up to 4 Tamil scalars = 12 UTF-8 bytes,
    // so the tscii single-pass fast path needs outbuf >= input*12. Harmless for the
    // other codecs (bigger scratch, same written region).
    let mut dst = vec![0u8; src.len() * 12 + 16];

    // Iteration count scaled to keep each sample ~cheap even for the catastrophic converters.
    const ITERS: u64 = 200;
    const SAMPLES: usize = 41;
    const WARMUP: u64 = 400;

    // fl C ABI.
    let fl_cd =
        unsafe { frankenlibc_abi::iconv_abi::iconv_open(to.as_ptr().cast(), from.as_ptr().cast()) };
    assert!(
        fl_cd as isize != -1 && !fl_cd.is_null(),
        "fl iconv_open failed"
    );
    for _ in 0..WARMUP {
        black_box(unsafe { convert_once(frankenlibc_abi::iconv_abi::iconv, fl_cd, src, &mut dst) });
    }
    let fl_p50 = measure(SAMPLES, ITERS, || {
        black_box(unsafe { convert_once(frankenlibc_abi::iconv_abi::iconv, fl_cd, src, &mut dst) });
    });
    unsafe { frankenlibc_abi::iconv_abi::iconv_close(fl_cd) };

    // host glibc.
    let gl_cd = unsafe { (host.open)(to.as_ptr().cast(), from.as_ptr().cast()) };
    assert!(
        gl_cd as isize != -1 && !gl_cd.is_null(),
        "glibc iconv_open failed"
    );
    for _ in 0..WARMUP {
        black_box(unsafe { convert_once(host.convert, gl_cd, src, &mut dst) });
    }
    let gl_p50 = measure(SAMPLES, ITERS, || {
        black_box(unsafe { convert_once(host.convert, gl_cd, src, &mut dst) });
    });
    unsafe { (host.close)(gl_cd) };

    let ratio = if gl_p50 > 0.0 { fl_p50 / gl_p50 } else { 0.0 };
    println!(
        "ICONV conv=\"{conv}\" fl_ns={fl_p50:.1} glibc_ns={gl_p50:.1} fl_over_glibc={ratio:.3}"
    );
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

fn main() {
    let c = &mut Bencher;
    // ~1 KiB pure ASCII (the bulk-copy hot path).
    let ascii: Vec<u8> = (0..1024).map(|i| b'a' + (i % 26) as u8).collect();
    run_conv(
        c,
        "utf8_to_latin1_ascii",
        b"ISO-8859-1\0",
        b"UTF-8\0",
        &ascii,
    );
    run_conv(
        c,
        "utf8_to_utf16le_ascii",
        b"UTF-16LE\0",
        b"UTF-8\0",
        &ascii,
    );
    run_conv(
        c,
        "utf8_to_utf32le_ascii",
        b"UTF-32LE\0",
        b"UTF-8\0",
        &ascii,
    );

    // ~1 KiB Cyrillic (U+0410..=U+044F) as 2-byte UTF-8: real transcoding.
    let cyr_cps: Vec<u32> = (0..512u32).map(|k| 0x0410 + (k % 0x40)).collect();
    let cyr = u8enc(&cyr_cps);
    run_conv(c, "utf8_cyrillic_to_koi8r", b"KOI8-R\0", b"UTF-8\0", &cyr);
    run_conv(
        c,
        "utf8_cyrillic_to_utf16le",
        b"UTF-16LE\0",
        b"UTF-8\0",
        &cyr,
    );
    // Forward 2-byte UTF-8 -> UTF-32 (currently a scalar store): probe if a lever.
    run_conv(
        c,
        "utf8_cyrillic_to_utf32le",
        b"UTF-32LE\0",
        b"UTF-8\0",
        &cyr,
    );

    // REVERSE direction: UTF-16LE -> UTF-8 (reading UTF-16 -> UTF-8, common).
    let ascii_u16le: Vec<u8> = ascii.iter().flat_map(|&b| [b, 0]).collect();
    run_conv(
        c,
        "utf16le_ascii_to_utf8",
        b"UTF-8\0",
        b"UTF-16LE\0",
        &ascii_u16le,
    );
    // Non-ASCII reverse: UTF-16LE Cyrillic -> 2-byte UTF-8 (the 2-byte-output run).
    let cyr_u16le: Vec<u8> = cyr_cps
        .iter()
        .flat_map(|&c| (c as u16).to_le_bytes())
        .collect();
    run_conv(
        c,
        "utf16le_cyrillic_to_utf8",
        b"UTF-8\0",
        b"UTF-16LE\0",
        &cyr_u16le,
    );
    // UTF-32LE Cyrillic -> 2-byte UTF-8: the 4-byte-unit reverse 2-byte-output run.
    let cyr_u32le: Vec<u8> = cyr_cps.iter().flat_map(|&c| c.to_le_bytes()).collect();
    run_conv(
        c,
        "utf32le_cyrillic_to_utf8",
        b"UTF-8\0",
        b"UTF-32LE\0",
        &cyr_u32le,
    );
    // UTF-16BE -> UTF-8 (network/Java byte order): the symmetric BE case.
    let ascii_u16be: Vec<u8> = ascii.iter().flat_map(|&b| [0, b]).collect();
    run_conv(
        c,
        "utf16be_ascii_to_utf8",
        b"UTF-8\0",
        b"UTF-16BE\0",
        &ascii_u16be,
    );
    // UTF-32 LE/BE -> UTF-8 ASCII: 4-byte fixed-width source SIMD run.
    let ascii_u32le: Vec<u8> = ascii.iter().flat_map(|&b| [b, 0, 0, 0]).collect();
    run_conv(
        c,
        "utf32le_ascii_to_utf8",
        b"UTF-8\0",
        b"UTF-32LE\0",
        &ascii_u32le,
    );
    let ascii_u32be: Vec<u8> = ascii.iter().flat_map(|&b| [0, 0, 0, b]).collect();
    run_conv(
        c,
        "utf32be_ascii_to_utf8",
        b"UTF-8\0",
        b"UTF-32BE\0",
        &ascii_u32be,
    );

    // CJK encode (table-based): UTF-8 Chinese -> GB18030, Japanese -> CP932.
    // ~512 common CJK ideographs (U+4E00..) as 3-byte UTF-8.
    let cjk_cps: Vec<u32> = (0..512u32).map(|k| 0x4E00 + (k % 0x300)).collect();
    let cjk = u8enc(&cjk_cps);
    run_conv(c, "utf8_cjk_to_gb18030", b"GB18030\0", b"UTF-8\0", &cjk);
    run_conv(c, "utf8_cjk_to_utf16le", b"UTF-16LE\0", b"UTF-8\0", &cjk);
    run_conv(c, "utf8_cjk_to_utf32le", b"UTF-32LE\0", b"UTF-8\0", &cjk);
    // Reverse: UTF-16LE CJK -> 3-byte UTF-8 (the 3-byte-output run).
    let cjk_u16le: Vec<u8> = cjk_cps
        .iter()
        .flat_map(|&c| (c as u16).to_le_bytes())
        .collect();
    run_conv(
        c,
        "utf16le_cjk_to_utf8",
        b"UTF-8\0",
        b"UTF-16LE\0",
        &cjk_u16le,
    );
    // UTF-32LE CJK -> 3-byte UTF-8: the 4-byte-unit reverse 3-byte-output run.
    let cjk_u32le: Vec<u8> = cjk_cps.iter().flat_map(|&c| c.to_le_bytes()).collect();
    run_conv(
        c,
        "utf32le_cjk_to_utf8",
        b"UTF-8\0",
        b"UTF-32LE\0",
        &cjk_u32le,
    );
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
    // Reverse of host_to: decode `from`-encoded bytes to UTF-8 via host glibc. Used to
    // derive a guaranteed-encodable UTF-8 corpus for a codec (round-trip: build valid
    // legacy bytes -> host_from -> UTF-8 that host_to can then re-encode fully).
    let host_from = |from: &[u8], src: &[u8]| -> Vec<u8> {
        let cd = unsafe { (host.open)(b"UTF-8\0".as_ptr().cast(), from.as_ptr().cast()) };
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
    // Build a VALID, non-degenerate DBCS source for codecs whose code points are a
    // scattered subset (Big5/EucTw/Gb2312): enumerate lead/trail pairs and keep only
    // those glibc decodes cleanly (fully consumes the 2 bytes). Defeats the
    // "contiguous-Unicode-range host_to gives a near-empty buffer" source block.
    let build_dbcs_source = |codec: &[u8],
                             leads: std::ops::RangeInclusive<u8>,
                             trails: std::ops::RangeInclusive<u8>,
                             target: usize|
     -> Vec<u8> {
        let cd = unsafe { (host.open)(b"UTF-8\0".as_ptr().cast(), codec.as_ptr().cast()) };
        assert!(
            cd as isize != -1 && !cd.is_null(),
            "build_dbcs_source open failed"
        );
        let mut out = Vec::new();
        'outer: for lead in leads.clone() {
            for trail in trails.clone() {
                let src = [lead, trail];
                let mut dst = [0u8; 8];
                let mut inp = src.as_ptr() as *mut c_char;
                let mut inl = 2usize;
                let mut outp = dst.as_mut_ptr() as *mut c_char;
                let mut outl = 8usize;
                let r = unsafe { (host.convert)(cd, &mut inp, &mut inl, &mut outp, &mut outl) };
                if r != usize::MAX && inl == 0 {
                    out.push(lead);
                    out.push(trail);
                    if out.len() >= target * 2 {
                        break 'outer;
                    }
                }
            }
        }
        unsafe { (host.close)(cd) };
        out
    };
    // Single-byte-source variant: enumerate 0x00..=0xFF, keep the bytes glibc decodes
    // cleanly (1 byte in, >=1 byte out), repeat to `target`. For codecs (TSCII, EBCDIC)
    // where a contiguous-Unicode-range host_to truncates on the first unencodable cp,
    // giving a bogus tiny-source ratio.
    let build_sbcs_source = |codec: &[u8], target: usize| -> Vec<u8> {
        let cd = unsafe { (host.open)(b"UTF-8\0".as_ptr().cast(), codec.as_ptr().cast()) };
        assert!(cd as isize != -1 && !cd.is_null(), "build_sbcs_source open failed");
        let mut valid = Vec::new();
        for bv in 0u16..=0xFF {
            let b = bv as u8;
            let src = [b];
            let mut dst = [0u8; 8];
            let mut inp = src.as_ptr() as *mut c_char;
            let mut inl = 1usize;
            let mut outp = dst.as_mut_ptr() as *mut c_char;
            let mut outl = 8usize;
            let r = unsafe { (host.convert)(cd, &mut inp, &mut inl, &mut outp, &mut outl) };
            if r != usize::MAX && inl == 0 && (8 - outl) > 0 {
                valid.push(b);
            }
        }
        unsafe { (host.close)(cd) };
        let mut out = Vec::with_capacity(target);
        if !valid.is_empty() {
            for i in 0..target {
                out.push(valid[i % valid.len()]);
            }
        }
        out
    };
    let cp932_src = host_to(b"CP932\0", &jp);
    run_conv(c, "cp932_to_utf8", b"UTF-8\0", b"CP932\0", &cp932_src);
    // EUC-JP (Japanese) -> UTF-8: probe glibc speed + source validity (Hiragana is 2-byte).
    // `jp` (U+3041 + k%0x5E) cycles into the UNASSIGNED U+3097/U+3098, so host_to(EUC-JP,jp)
    // TRUNCATES there (~86 chars) and yields a bogus tiny-source ratio. Use a fully-assigned
    // Hiragana range (U+3041..=U+3096, 86 cps, all JIS X 0208) for an honest full-length source.
    let jp_full_cps: Vec<u32> = (0..512u32).map(|k| 0x3041 + (k % 86)).collect();
    let jp_full = u8enc(&jp_full_cps);
    let eucjp_src = host_to(b"EUC-JP\0", &jp_full);
    run_conv(c, "eucjp_to_utf8", b"UTF-8\0", b"EUC-JP\0", &eucjp_src);
    // ENCODE direction: UTF-8 -> EUC-JP (Japanese). `jp` is Hiragana (2-byte JIS X 0208 in EUC-JP).
    run_conv(c, "utf8_to_eucjp", b"EUC-JP\0", b"UTF-8\0", &jp);
    // EUC-JP-MS (MS EUC-JP variant, same SS structure) -> UTF-8: gather generalization.
    let eucjpms_src = host_to(b"EUC-JP-MS\0", &jp_full);
    run_conv(
        c,
        "eucjpms_to_utf8",
        b"UTF-8\0",
        b"EUC-JP-MS\0",
        &eucjpms_src,
    );
    let gb_src = host_to(b"GB18030\0", &cjk);
    run_conv(c, "gb18030_to_utf8", b"UTF-8\0", b"GB18030\0", &gb_src);
    // GBK (Simplified Chinese, 2-byte DBCS) -> UTF-8: the gather-SIMD generalization.
    let gbk_src = host_to(b"GBK\0", &cjk);
    run_conv(c, "gbk_to_utf8", b"UTF-8\0", b"GBK\0", &gbk_src);
    // CP949/UHC (Korean Hangul) -> UTF-8: probe glibc speed (Korean codec, full Hangul source).
    let hangul_cps: Vec<u32> = (0..512u32).map(|k| 0xAC00 + (k % 0x800)).collect();
    let hangul = u8enc(&hangul_cps);
    let cp949_src = host_to(b"CP949\0", &hangul);
    run_conv(c, "cp949_to_utf8", b"UTF-8\0", b"CP949\0", &cp949_src);
    // EUC-KR (Korean, common on Unix) -> UTF-8: pure 2-byte DBCS decode, NOT yet in the SIMD gather.
    // Source = EUC-KR Hangul rows (leads 0xB0..=0xC8 = Wansung Hangul, cp >= U+AC00 = 3-byte UTF-8,
    // real Korean text) so the gather actually fires; rows 0xA1.. are symbols (many cp < 0x800 that
    // fall to scalar) and don't represent Korean text.
    let euckr_src = build_dbcs_source(b"EUC-KR\0", 0xB0..=0xC8, 0xA1..=0xFE, 512);
    run_conv(c, "euckr_to_utf8", b"UTF-8\0", b"EUC-KR\0", &euckr_src);
    // JOHAB (Korean, full Hangul coverage like UHC) -> UTF-8: cache-bound gather.
    let johab_src = host_to(b"JOHAB\0", &hangul);
    run_conv(c, "johab_to_utf8", b"UTF-8\0", b"JOHAB\0", &johab_src);
    // BIG5 (Traditional Chinese) -> UTF-8: valid source built by enumerating glibc-
    // accepted Level-1/2 lead/trail pairs (defeats the contiguous-range source block).
    let big5_src = build_dbcs_source(b"BIG5\0", 0xA4..=0xF9, 0xA1..=0xFE, 512);
    run_conv(c, "big5_to_utf8", b"UTF-8\0", b"BIG5\0", &big5_src);
    // EUC-TW (Traditional Chinese, CNS-11643 plane 1) -> UTF-8: 2-byte pairs, lead/trail
    // 0xA1..=0xFE. Exercises decode_euctw's scalar 2-byte path (now an O(1) direct table,
    // was a binary_search over 5867 sorted pairs). EUC-TW is excluded from the SIMD gather.
    let euctw_src = build_dbcs_source(b"EUC-TW\0", 0xA1..=0xFE, 0xA1..=0xFE, 512);
    run_conv(c, "euctw_to_utf8", b"UTF-8\0", b"EUC-TW\0", &euctw_src);
    // ENCODE-DIRECTION SCAN (fresh honest re-scan of the UNBENCHED encode paths — the
    // string-wide/iconv notes flag encode as far less explored than decode). Each source
    // is a fully-encodable UTF-8 corpus derived by round-tripping the codec's own valid
    // bytes through host glibc (host_from), so host_to never truncates (the tiny-source
    // artifact). Baselines whether the O(log n) encode search loses to glibc's O(1) reverse.
    //   utf8_to_euctw:  EUC_TW_ENC 55569-entry binary_search (~16 probes/char).
    let euctw_utf8 = host_from(b"EUC-TW\0", &euctw_src);
    run_conv(c, "utf8_to_euctw", b"EUC-TW\0", b"UTF-8\0", &euctw_utf8);
    //   utf8_to_cp037:  encode_sbcs_full EBCDIC (~256-entry binary_search).
    let cp037_bytes = build_sbcs_source(b"CP037\0", 512);
    let cp037_utf8 = host_from(b"CP037\0", &cp037_bytes);
    run_conv(c, "utf8_to_cp037", b"CP037\0", b"UTF-8\0", &cp037_utf8);
    //   utf8_to_cp037_text: realistic ASCII-heavy English text -> CP037 (the dominant
    //   real EBCDIC-encode workload; the enumerate-all-bytes source above interleaves
    //   1-byte ASCII with 2-byte Latin-1 so its ASCII runs are short). Exercises the
    //   SIMD ASCII-run gather for low-remapping single-byte targets.
    let cp037_text: Vec<u8> = b"The quick brown fox jumps over the lazy dog 0123456789, "
        .iter()
        .copied()
        .cycle()
        .take(1024)
        .collect();
    run_conv(c, "utf8_to_cp037_text", b"CP037\0", b"UTF-8\0", &cp037_text);
    //   utf8_to_cp1258: encode_sbcs_mb Vietnamese (precomposed -> base+combining decompose).
    let cp1258_bytes = build_sbcs_source(b"CP1258\0", 512);
    let cp1258_utf8 = host_from(b"CP1258\0", &cp1258_bytes);
    run_conv(c, "utf8_to_cp1258", b"CP1258\0", b"UTF-8\0", &cp1258_utf8);
    // BIG5-HKSCS (Hong Kong Traditional Chinese) -> UTF-8: routed to the dedicated
    // dbcs_x_decode per-char converter (Vec<char>+Vec<u8> two-pass), same slow-body
    // class as EUC-TW was. Level-1/2 Big5 leads 0xA4..=0xF9, trails 0x40..=0xFE
    // (build_dbcs_source keeps only glibc-accepted pairs).
    let big5hkscs_src = build_dbcs_source(b"BIG5-HKSCS\0", 0xA4..=0xF9, 0x40..=0xFE, 512);
    run_conv(
        c,
        "big5hkscs_to_utf8",
        b"UTF-8\0",
        b"BIG5-HKSCS\0",
        &big5hkscs_src,
    );
    // EUC-JISX0213 (Japanese JIS X 0213 plane 1) -> UTF-8: dedicated eucjisx0213_decode
    // per-char converter, same two-pass slow-body class. Plane-1 leads/trails 0xA1..=0xFE.
    let eucjisx_src = build_dbcs_source(b"EUC-JISX0213\0", 0xA1..=0xFE, 0xA1..=0xFE, 512);
    run_conv(
        c,
        "eucjisx0213_to_utf8",
        b"UTF-8\0",
        b"EUC-JISX0213\0",
        &eucjisx_src,
    );
    // ENCODE-DIRECTION SCAN of the dbcs_x converters (utf8 -> big5hkscs / eucjisx0213):
    // their ->UTF-8 DECODE side was ~6x before single-passing; the ENCODE side is
    // UNBENCHED (dbcs_x_convert Vec-two-pass? binary-search enc?). Round-trip a codec-
    // valid corpus via host_from so host_to never truncates.
    let big5hkscs_utf8 = host_from(b"BIG5-HKSCS\0", &big5hkscs_src);
    run_conv(
        c,
        "utf8_to_big5hkscs",
        b"BIG5-HKSCS\0",
        b"UTF-8\0",
        &big5hkscs_utf8,
    );
    let eucjisx_utf8 = host_from(b"EUC-JISX0213\0", &eucjisx_src);
    run_conv(
        c,
        "utf8_to_eucjisx0213",
        b"EUC-JISX0213\0",
        b"UTF-8\0",
        &eucjisx_utf8,
    );
    // PROBE the remaining dedicated Vec-two-pass decoders (-> UTF-8) for negative ledger.
    // Stateful ISO-2022-* built authoritatively by host glibc from real script sources.
    let iso2022jp_src = host_to(b"ISO-2022-JP\0", &jp_full);
    run_conv(c, "iso2022jp_to_utf8", b"UTF-8\0", b"ISO-2022-JP\0", &iso2022jp_src);
    // ENCODE direction: UTF-8 -> ISO-2022-JP. `jp_full` Hiragana is JIS X 0208, so the
    // stateful encoder emits ESC $ B ... runs. Probes iso2022jp_convert (was Vec-two-pass).
    run_conv(c, "utf8_to_iso2022jp", b"ISO-2022-JP\0", b"UTF-8\0", &jp_full);
    // ISO-2022-JP-2 / JP-3 (supersets, still Vec-two-pass decoders). Hiragana is JIS X 0208
    // (JP-2) / JIS X 0213 plane 1 (JP-3), so host_to yields a full-length source.
    let iso2022jp2_src = host_to(b"ISO-2022-JP-2\0", &jp_full);
    run_conv(c, "iso2022jp2_to_utf8", b"UTF-8\0", b"ISO-2022-JP-2\0", &iso2022jp2_src);
    // ENCODE direction: UTF-8 -> ISO-2022-JP-2. `jp_full` Hiragana is JIS X 0208 (G0 set 2).
    // Probes iso2022jp2_convert (was Vec-two-pass, now single-pass).
    run_conv(c, "utf8_to_iso2022jp2", b"ISO-2022-JP-2\0", b"UTF-8\0", &jp_full);
    let iso2022jp3_src = host_to(b"ISO-2022-JP-3\0", &jp_full);
    run_conv(c, "iso2022jp3_to_utf8", b"UTF-8\0", b"ISO-2022-JP-3\0", &iso2022jp3_src);
    // ENCODE direction: UTF-8 -> ISO-2022-JP-3. `jp_full` Hiragana is JIS X 0208.
    // Probes iso2022jp3_convert (was Vec-two-pass, now single-pass).
    run_conv(c, "utf8_to_iso2022jp3", b"ISO-2022-JP-3\0", b"UTF-8\0", &jp_full);
    // IBM930 (EBCDIC Japanese Katakana+Kanji, SO/SI DBCS) -> UTF-8. cjk = U+4E00 Kanji.
    let ibm930_src = build_sbcs_source(b"IBM930\0", 512);
    run_conv(c, "ibm930_to_utf8", b"UTF-8\0", b"IBM930\0", &ibm930_src);
    // ISO-2022-KR uses KSC 5601 = the EUC-KR charset. Build a KSC-encodable UTF-8 corpus
    // by round-tripping valid EUC-KR Wansung Hangul (host_from), so host_to yields a full
    // ISO-2022-KR source (plain `hangul` has non-KSC syllables that truncate the encode).
    let euckr_valid = build_dbcs_source(b"EUC-KR\0", 0xB0..=0xC8, 0xA1..=0xFE, 512);
    let ksc_utf8 = host_from(b"EUC-KR\0", &euckr_valid);
    let iso2022kr_src = host_to(b"ISO-2022-KR\0", &ksc_utf8);
    run_conv(c, "iso2022kr_to_utf8", b"UTF-8\0", b"ISO-2022-KR\0", &iso2022kr_src);
    // ENCODE direction: UTF-8 -> ISO-2022-KR. `ksc_utf8` is Wansung Hangul (KSC 5601),
    // so the stateful encoder emits SO + double-byte cells. Probes iso2022kr_convert
    // (was Vec-two-pass, now single-pass).
    run_conv(c, "utf8_to_iso2022kr", b"ISO-2022-KR\0", b"UTF-8\0", &ksc_utf8);
    // ISO-2022-CN's default G1 is GB2312; round-trip a GB2312-encodable UTF-8 corpus so
    // host_to yields a full source (plain `cjk` has U+4E00 cps outside GB2312 that truncate).
    let gb2312_valid = build_dbcs_source(b"GB2312\0", 0xB0..=0xF7, 0xA1..=0xFE, 512);
    let gb_utf8 = host_from(b"GB2312\0", &gb2312_valid);
    let iso2022cn_src = host_to(b"ISO-2022-CN\0", &gb_utf8);
    run_conv(c, "iso2022cn_to_utf8", b"UTF-8\0", b"ISO-2022-CN\0", &iso2022cn_src);
    // ENCODE direction: UTF-8 -> ISO-2022-CN. `gb_utf8` is GB2312 Hanzi, so the stateful
    // encoder emits ESC $ ) A designator + SO + double-byte cells. Probes iso2022cn_convert
    // (was Vec-two-pass, now single-pass).
    run_conv(c, "utf8_to_iso2022cn", b"ISO-2022-CN\0", b"UTF-8\0", &gb_utf8);
    // TSCII (Tamil, visual-order maximal-munch decode): honest single-byte source
    // (a contiguous Tamil host_to truncated on unassigned/non-TSCII cps).
    let tscii_src = build_sbcs_source(b"TSCII\0", 512);
    run_conv(c, "tscii_to_utf8", b"UTF-8\0", b"TSCII\0", &tscii_src);
    // ENCODE-DIRECTION SCAN of the remaining dedicated Vec-two-pass converters
    // (tscii_convert / ibm_ebcdic_convert). Round-trip codec-valid bytes via host_from
    // so host_to never truncates.
    let tscii_utf8 = host_from(b"TSCII\0", &tscii_src);
    run_conv(c, "utf8_to_tscii", b"TSCII\0", b"UTF-8\0", &tscii_utf8);
    let ibm930_utf8 = host_from(b"IBM930\0", &ibm930_src);
    run_conv(c, "utf8_to_ibm930", b"IBM930\0", b"UTF-8\0", &ibm930_utf8);
    // ENCODE-DIRECTION SCAN #3: the last unbenched encode paths — iso2022cnext_convert
    // (Vec-two-pass, flagged "likely false-gap glibc-CN-slow"), + encode_sbcs_mb (TCVN /
    // CP1255, multibyte-decompose; cp1258 was loop-floor — confirm TCVN/CP1255).
    run_conv(c, "utf8_to_iso2022cnext", b"ISO-2022-CN-EXT\0", b"UTF-8\0", &gb_utf8);
    let tcvn_bytes = build_sbcs_source(b"TCVN\0", 512);
    let tcvn_utf8 = host_from(b"TCVN\0", &tcvn_bytes);
    run_conv(c, "utf8_to_tcvn", b"TCVN\0", b"UTF-8\0", &tcvn_utf8);
    let cp1255_bytes = build_sbcs_source(b"CP1255\0", 512);
    let cp1255_utf8 = host_from(b"CP1255\0", &cp1255_bytes);
    run_conv(c, "utf8_to_cp1255", b"CP1255\0", b"UTF-8\0", &cp1255_utf8);
    // DECODE-DIRECTION SCAN (->UTF-16): the dedicated decoders (dbcs_x_decode /
    // eucjisx0213_decode / tscii_decode) single-pass ONLY for to==UTF-8; a UTF-16
    // target falls to the Vec<char>+Vec<u8> two-pass body (the ~6x class the ->UTF-8
    // single-pass cleared). Probe whether ->UTF-16 is still catastrophic + fixable.
    run_conv(c, "big5hkscs_to_utf16", b"UTF-16LE\0", b"BIG5-HKSCS\0", &big5hkscs_src);
    run_conv(c, "eucjisx0213_to_utf16", b"UTF-16LE\0", b"EUC-JISX0213\0", &eucjisx_src);
    run_conv(c, "tscii_to_utf16", b"UTF-16LE\0", b"TSCII\0", &tscii_src);
    // ENCODE direction: UTF-8 -> BIG5. Source = big5_src decoded back to UTF-8 (host BIG5->UTF-8),
    // so every char is guaranteed Big5-encodable; exercises the SIMD encode gather for Big5.
    let big5_utf8 = {
        let cd = unsafe { (host.open)(b"UTF-8\0".as_ptr().cast(), b"BIG5\0".as_ptr().cast()) };
        assert!(
            cd as isize != -1 && !cd.is_null(),
            "BIG5->UTF-8 open failed"
        );
        let mut dst = vec![0u8; big5_src.len() * 4 + 16];
        let mut inp = big5_src.as_ptr() as *mut c_char;
        let mut inl = big5_src.len();
        let mut outp = dst.as_mut_ptr() as *mut c_char;
        let mut outl = dst.len();
        unsafe { (host.convert)(cd, &mut inp, &mut inl, &mut outp, &mut outl) };
        unsafe { (host.close)(cd) };
        let n = dst.len() - outl;
        dst.truncate(n);
        dst
    };
    run_conv(c, "utf8_to_big5", b"BIG5\0", b"UTF-8\0", &big5_utf8);
    // GB2312/EUC-CN (Simplified Chinese, common on Unix) -> UTF-8: generic source.
    let gb2312_src = build_dbcs_source(b"GB2312\0", 0xB0..=0xF7, 0xA1..=0xFE, 512);
    run_conv(c, "gb2312_to_utf8", b"UTF-8\0", b"GB2312\0", &gb2312_src);
    // ENCODE direction: UTF-8 Hangul -> CP949 (cp->byte enc_direct lookup). `hangul`
    // is CONTIGUOUS cps (0xAC00..) = a warm encode table (not cache-bound).
    run_conv(c, "utf8_to_cp949", b"CP949\0", b"UTF-8\0", &hangul);
    // DIVERSE cps scattered across the full Hangul block (U+AC00..U+D7A3) = a
    // cache-bound encode table, matching real Korean text (and the decode wins).
    let hangul_div_cps: Vec<u32> = (0..512u32).map(|k| 0xAC00 + (k * 21) % 0x2B9C).collect();
    let hangul_div = u8enc(&hangul_div_cps);
    run_conv(
        c,
        "utf8_to_cp949_diverse",
        b"CP949\0",
        b"UTF-8\0",
        &hangul_div,
    );
    // ENCODE ASCII probe: UTF-8 ASCII (1 KiB) -> CP949 (ASCII passes through 1:1).
    // The UTF-8->DBCS encode runs the general per-char loop with NO ASCII SIMD fast
    // path (unlike mbstowcs) — probe whether ASCII-heavy encode is un-dominated.
    run_conv(c, "utf8_ascii_to_cp949", b"CP949\0", b"UTF-8\0", &ascii);
    // SBCS DECODE probe: KOI8-R Cyrillic (all high bytes 0xC0..) -> UTF-8 (2-byte/cp).
    // Each byte -> cp (256-table) -> 2-byte UTF-8. Probe if the high-byte SBCS decode
    // is SIMD or scalar per-byte (un-benched until now).
    let koi8r_src = host_to(b"KOI8-R\0", &cyr);
    run_conv(c, "koi8r_to_utf8", b"UTF-8\0", b"KOI8-R\0", &koi8r_src);
    // Latin-1 (ISO-8859-1, the most common SBCS) high bytes 0xA0..=0xFF -> 2-byte
    // UTF-8 (U+00A0..U+00FF): confirms the SBCS->UTF-8 SIMD win generalizes to the
    // highest-value codec (shares the same from_decode 2-byte fast path).
    let latin1_src: Vec<u8> = (0..1024).map(|i| 0xA0u8 + (i % 0x60) as u8).collect();
    run_conv(
        c,
        "latin1_to_utf8",
        b"UTF-8\0",
        b"ISO-8859-1\0",
        &latin1_src,
    );
    // SBCS -> UTF-16 probe: Latin-1 high bytes -> UTF-16LE (byte -> cp(BMP) -> 1 u16).
    // The from_decode->UTF-16/32 path is scalar single-unit — probe if un-dominated.
    run_conv(
        c,
        "latin1_to_utf16le",
        b"UTF-16LE\0",
        b"ISO-8859-1\0",
        &latin1_src,
    );
    // DBCS -> UTF-16 probe: Shift-JIS (CP932) -> UTF-16LE. The DBCS legacy->UTF-16/32
    // path decodes each char then writes a unit — probe if un-dominated (un-benched).
    run_conv(c, "cp932_to_utf16le", b"UTF-16LE\0", b"CP932\0", &cp932_src);
    // Same vpgatherdd-vs-scalar question for the fast-glibc EUC-JP/-MS -> UTF-16 path.
    run_conv(c, "eucjp_to_utf16le", b"UTF-16LE\0", b"EUC-JP\0", &eucjp_src);
    run_conv(
        c,
        "eucjpms_to_utf16le",
        b"UTF-16LE\0",
        b"EUC-JP-MS\0",
        &eucjpms_src,
    );
    // SBCS -> UTF-32 probe: Latin-1 high bytes -> UTF-32LE (the tw==4 leg left scalar
    // by the SBCS->UTF-16 SIMD fix) — probe if un-dominated.
    run_conv(
        c,
        "latin1_to_utf32le",
        b"UTF-32LE\0",
        b"ISO-8859-1\0",
        &latin1_src,
    );
}
