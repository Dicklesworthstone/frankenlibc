#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc iconv oracle for offline table generation

//! GENERATOR (`#[ignore]`): emits glibc-exact DBCS<->Unicode mapping tables for
//! the 2-byte CJK codecs (Shift-JIS, BIG5) by probing the host glibc `iconv(3)`,
//! the same offline-table-generation pattern used for wcwidth / log2 / codepage
//! tables. Run with:
//!   cargo test -p frankenlibc-abi --test cjk_table_gen -- --ignored --nocapture
//! then paste each emitted block into the generated table module. Runtime stays
//! 100% safe Rust (array index + binary search). See bd-2g7oyh.195.

use std::ffi::{CString, c_char, c_void};

unsafe extern "C" {
    fn iconv_open(to: *const c_char, from: *const c_char) -> *mut c_void;
    fn iconv_close(cd: *mut c_void) -> libc::c_int;
    fn iconv(
        cd: *mut c_void,
        inbuf: *mut *mut c_char,
        inbytesleft: *mut usize,
        outbuf: *mut *mut c_char,
        outbytesleft: *mut usize,
    ) -> usize;
}

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

/// Decode `bytes` under codec `from` to UTF-8 via host glibc. Returns
/// Ok((codepoint, consumed)) for a single decoded scalar, or Err(errno).
unsafe fn dec(from: &CString, utf8: &CString, bytes: &[u8]) -> Result<(u32, usize), i32> {
    let cd = unsafe { iconv_open(utf8.as_ptr(), from.as_ptr()) };
    assert!(cd as isize != -1, "iconv_open failed");
    let mut src = bytes.to_vec();
    let mut out = [0u8; 32];
    let mut sp = src.as_mut_ptr() as *mut c_char;
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut sl = src.len();
    let mut ol = out.len();
    unsafe { *libc::__errno_location() = 0 };
    let r = unsafe { iconv(cd, &mut sp, &mut sl, &mut op, &mut ol) };
    let e = errno();
    let consumed = bytes.len() - sl;
    let written = out.len() - ol;
    unsafe { iconv_close(cd) };
    if r == usize::MAX {
        return Err(e);
    }
    let s = std::str::from_utf8(&out[..written]).map_err(|_| -2)?;
    let mut chars = s.chars();
    let c = chars.next().ok_or(-3)?;
    if chars.next().is_some() {
        return Err(-4); // more than one char — shouldn't happen for one sequence
    }
    Ok((c as u32, consumed))
}

/// Encode codepoint `cp` to codec `to` via host glibc. Returns the codec bytes.
unsafe fn enc(to: &CString, utf8: &CString, cp: u32) -> Option<Vec<u8>> {
    let c = char::from_u32(cp)?;
    let mut buf = [0u8; 4];
    let s = c.encode_utf8(&mut buf);
    let cd = unsafe { iconv_open(to.as_ptr(), utf8.as_ptr()) };
    assert!(cd as isize != -1);
    let mut src = s.as_bytes().to_vec();
    let mut out = [0u8; 8];
    let mut sp = src.as_mut_ptr() as *mut c_char;
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut sl = src.len();
    let mut ol = out.len();
    let r = unsafe { iconv(cd, &mut sp, &mut sl, &mut op, &mut ol) };
    let written = out.len() - ol;
    unsafe { iconv_close(cd) };
    if r == usize::MAX {
        return None;
    }
    Some(out[..written].to_vec())
}

#[test]
#[ignore = "offline generator for CJK iconv tables (bd-2g7oyh.195); run with --ignored --nocapture"]
fn cjk_table_gen() {
    let utf8 = CString::new("UTF-8").unwrap();
    for codec in ["SHIFT_JIS", "BIG5", "GBK", "EUC-KR"] {
        let from = CString::new(codec).unwrap();
        let ident = codec.to_ascii_uppercase().replace('-', "_");

        let mut one_byte = [-1i32; 256]; // 1-byte char codepoint, or -1
        let mut is_lead = [false; 256]; // b0 is a (incomplete) multibyte lead
        for b0 in 0u16..256 {
            match unsafe { dec(&from, &utf8, &[b0 as u8]) } {
                Ok((cp, 1)) => one_byte[b0 as usize] = cp as i32,
                Ok(_) => {}
                Err(e) if e == libc::EINVAL => is_lead[b0 as usize] = true,
                Err(_) => {}
            }
        }

        // 2-byte table for each lead byte.
        let mut dbcs: Vec<(u16, u32)> = Vec::new();
        for b0 in 0u16..256 {
            if !is_lead[b0 as usize] {
                continue;
            }
            for b1 in 0u16..256 {
                if let Ok((cp, 2)) = unsafe { dec(&from, &utf8, &[b0 as u8, b1 as u8]) } {
                    dbcs.push((((b0 << 8) | b1), cp));
                }
            }
        }
        dbcs.sort_by_key(|&(k, _)| k);

        // Encode table: glibc's canonical encoding for EVERY BMP code point it
        // can represent (swept directly, not inverted from decode — so it is
        // exact even where the codec is asymmetric, e.g. SHIFT_JIS 0x5C<->U+00A5
        // yen / U+005C unrepresentable, and includes the ASCII range so there is
        // no identity shortcut at runtime). DBCS code points are all BMP for
        // these codecs, so 0x0000..=0xFFFF covers them.
        let mut enct: Vec<(u32, u32)> = Vec::new();
        for cp in 0u32..=0xFFFF {
            if let Some(b) = unsafe { enc(&from, &utf8, cp) } {
                let packed = match b.len() {
                    1 => b[0] as u32,
                    2 => ((b[0] as u32) << 8) | b[1] as u32,
                    _ => continue,
                };
                enct.push((cp, packed));
            }
        }
        enct.sort_by_key(|&(cp, _)| cp);

        eprintln!("CJK_GEN codec={ident} one_byte_set={} dbcs={} enc={}",
            one_byte.iter().filter(|&&v| v >= 0).count(), dbcs.len(), enct.len());
        eprintln!("CJK_GEN_BEGIN {ident}");
        let mut s = String::new();
        s.push_str(&format!("// @generated by cjk_table_gen from host glibc iconv ({codec}).\n"));
        // ONE_BYTE
        s.push_str(&format!("pub(crate) static {ident}_ONE_BYTE: [i32; 256] = [\n"));
        for chunk in one_byte.chunks(16) {
            s.push_str("    ");
            for v in chunk { s.push_str(&format!("{v},")); }
            s.push('\n');
        }
        s.push_str("];\n");
        // IS_LEAD
        s.push_str(&format!("pub(crate) static {ident}_IS_LEAD: [bool; 256] = [\n"));
        for chunk in is_lead.chunks(16) {
            s.push_str("    ");
            for v in chunk { s.push_str(&format!("{v},")); }
            s.push('\n');
        }
        s.push_str("];\n");
        // DBCS decode (sorted by 2-byte key)
        s.push_str(&format!("pub(crate) static {ident}_DBCS: [(u16, u32); {}] = [\n", dbcs.len()));
        for chunk in dbcs.chunks(8) {
            s.push_str("    ");
            for (k, cp) in chunk { s.push_str(&format!("({k:#x},{cp:#x}),")); }
            s.push('\n');
        }
        s.push_str("];\n");
        // ENCODE (sorted by cp); packed<0x100 => 1 byte, else (b0<<8|b1).
        s.push_str(&format!("pub(crate) static {ident}_ENC: [(u32, u32); {}] = [\n", enct.len()));
        for chunk in enct.chunks(8) {
            s.push_str("    ");
            for (cp, p) in chunk { s.push_str(&format!("({cp:#x},{p:#x}),")); }
            s.push('\n');
        }
        s.push_str("];\n");
        eprint!("{s}");
        eprintln!("CJK_GEN_END {ident}");
    }

    // --- EUC-JP: variable length (1-byte ASCII; 2-byte 0x8E half-width kana +
    //     0xA1-0xFE JIS X 0208; 3-byte 0x8F JIS X 0212). ---
    {
        let from = CString::new("EUC-JP").unwrap();
        let mut one_byte = [-1i32; 256];
        for b0 in 0u16..256 {
            if let Ok((cp, 1)) = unsafe { dec(&from, &utf8, &[b0 as u8]) } {
                one_byte[b0 as usize] = cp as i32;
            }
        }
        // EUC-JP has a fixed code structure (single-probe length detection is
        // unreliable because JIS X 0212 row 1 is sparse): 0x8E => 2-byte
        // half-width kana, 0x8F => 3-byte JIS X 0212 (SS3), 0xA1-0xFE => 2-byte
        // JIS X 0208. The actual mappings are still swept from glibc below.
        let mut lead_len = [0u8; 256];
        lead_len[0x8E] = 2;
        lead_len[0x8F] = 3;
        for b0 in 0xA1..=0xFE {
            lead_len[b0] = 2;
        }
        let mut dbcs2: Vec<(u16, u32)> = Vec::new();
        for b0 in 0u16..256 {
            if lead_len[b0 as usize] != 2 {
                continue;
            }
            for b1 in 0u16..256 {
                if let Ok((cp, 2)) = unsafe { dec(&from, &utf8, &[b0 as u8, b1 as u8]) } {
                    dbcs2.push(((b0 << 8) | b1, cp));
                }
            }
        }
        dbcs2.sort_by_key(|&(k, _)| k);
        // 3-byte (0x8F): trails are in the EUC code-set range; sweep 0xA0..=0xFF.
        let mut dbcs3: Vec<(u16, u32)> = Vec::new();
        for b0 in 0u16..256 {
            if lead_len[b0 as usize] != 3 {
                continue;
            }
            for b1 in 0xA0u16..256 {
                for b2 in 0xA0u16..256 {
                    if let Ok((cp, 3)) =
                        unsafe { dec(&from, &utf8, &[b0 as u8, b1 as u8, b2 as u8]) }
                    {
                        dbcs3.push(((b1 << 8) | b2, cp));
                    }
                }
            }
        }
        dbcs3.sort_by_key(|&(k, _)| k);
        // glibc's incomplete-vs-invalid classification, probed directly (exact):
        //  - SS3_ROW_VALID[b1]: [0x8F,b1] returns EINVAL (a valid JIS X 0212 row
        //    awaiting its cell byte) vs EILSEQ (out-of-range row) — so a truncated
        //    valid row is EINVAL while an out-of-range row is EILSEQ.
        //  - LEAD2_DEFER[b0]: a lone high byte [b0] returns EINVAL (glibc defers
        //    its lead validation, awaiting a 2nd byte) vs EILSEQ (always illegal,
        //    e.g. 0xFF).
        let mut ss3_row_valid = [false; 256];
        for b1 in 0u16..256 {
            if let Err(e) = unsafe { dec(&from, &utf8, &[0x8F, b1 as u8]) } {
                if e == libc::EINVAL {
                    ss3_row_valid[b1 as usize] = true;
                }
            }
        }
        let mut lead2_defer = [false; 256];
        for b0 in 0x80u16..256 {
            if b0 == 0x8F {
                continue;
            }
            if let Err(e) = unsafe { dec(&from, &utf8, &[b0 as u8]) } {
                if e == libc::EINVAL {
                    lead2_defer[b0 as usize] = true;
                }
            }
        }
        // Encode (full BMP). packed: <0x100 => 1 byte, <0x10000 => 2, else 3.
        let mut enct: Vec<(u32, u32)> = Vec::new();
        for cp in 0u32..=0xFFFF {
            if let Some(b) = unsafe { enc(&from, &utf8, cp) } {
                let packed = match b.len() {
                    1 => b[0] as u32,
                    2 => ((b[0] as u32) << 8) | b[1] as u32,
                    3 => ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32,
                    _ => continue,
                };
                enct.push((cp, packed));
            }
        }
        enct.sort_by_key(|&(cp, _)| cp);

        eprintln!(
            "CJK_GEN codec=EUC_JP one_byte_set={} dbcs2={} dbcs3={} enc={}",
            one_byte.iter().filter(|&&v| v >= 0).count(),
            dbcs2.len(),
            dbcs3.len(),
            enct.len()
        );
        eprintln!("CJK_GEN_BEGIN EUC_JP");
        let mut s = String::new();
        s.push_str("// @generated by cjk_table_gen from host glibc iconv (EUC-JP).\n");
        s.push_str("pub(crate) static EUC_JP_ONE_BYTE: [i32; 256] = [\n");
        for chunk in one_byte.chunks(16) {
            s.push_str("    ");
            for v in chunk { s.push_str(&format!("{v},")); }
            s.push('\n');
        }
        s.push_str("];\n");
        s.push_str("pub(crate) static EUC_JP_LEAD_LEN: [u8; 256] = [\n");
        for chunk in lead_len.chunks(16) {
            s.push_str("    ");
            for v in chunk { s.push_str(&format!("{v},")); }
            s.push('\n');
        }
        s.push_str("];\n");
        s.push_str("pub(crate) static EUC_JP_SS3_ROW_VALID: [bool; 256] = [\n");
        for chunk in ss3_row_valid.chunks(16) {
            s.push_str("    ");
            for v in chunk { s.push_str(&format!("{v},")); }
            s.push('\n');
        }
        s.push_str("];\n");
        s.push_str("pub(crate) static EUC_JP_LEAD2_DEFER: [bool; 256] = [\n");
        for chunk in lead2_defer.chunks(16) {
            s.push_str("    ");
            for v in chunk { s.push_str(&format!("{v},")); }
            s.push('\n');
        }
        s.push_str("];\n");
        s.push_str(&format!("pub(crate) static EUC_JP_DBCS2: [(u16, u32); {}] = [\n", dbcs2.len()));
        for chunk in dbcs2.chunks(8) {
            s.push_str("    ");
            for (k, cp) in chunk { s.push_str(&format!("({k:#x},{cp:#x}),")); }
            s.push('\n');
        }
        s.push_str("];\n");
        s.push_str(&format!("pub(crate) static EUC_JP_DBCS3: [(u16, u32); {}] = [\n", dbcs3.len()));
        for chunk in dbcs3.chunks(8) {
            s.push_str("    ");
            for (k, cp) in chunk { s.push_str(&format!("({k:#x},{cp:#x}),")); }
            s.push('\n');
        }
        s.push_str("];\n");
        s.push_str(&format!("pub(crate) static EUC_JP_ENC: [(u32, u32); {}] = [\n", enct.len()));
        for chunk in enct.chunks(8) {
            s.push_str("    ");
            for (cp, p) in chunk { s.push_str(&format!("({cp:#x},{p:#x}),")); }
            s.push('\n');
        }
        s.push_str("];\n");
        eprint!("{s}");
        eprintln!("CJK_GEN_END EUC_JP");
    }
}
