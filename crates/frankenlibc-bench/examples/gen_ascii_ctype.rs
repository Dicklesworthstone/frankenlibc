//! Generator: print `const ASCII_CTYPE: [u16; 128]` = the wide-ctype class mask for each
//! ASCII codepoint, reconstructed from fl's 12 isw* predicates (which are ctype_mask & bit).
//! Bit layout MUST match wctype_table.rs: ALNUM=0 ALPHA=1 BLANK=2 CNTRL=3 DIGIT=4 GRAPH=5
//! LOWER=6 PRINT=7 PUNCT=8 SPACE=9 UPPER=10 XDIGIT=11.
use frankenlibc_abi::wchar_abi as wa;
fn main() {
    let mut out = String::from("const ASCII_CTYPE: [u16; 128] = [\n");
    for cp in 0..128u32 {
        let mut m = 0u16;
        unsafe {
            if wa::iswalnum(cp) != 0 {
                m |= 1 << 0;
            }
            if wa::iswalpha(cp) != 0 {
                m |= 1 << 1;
            }
            if wa::iswblank(cp) != 0 {
                m |= 1 << 2;
            }
            if wa::iswcntrl(cp) != 0 {
                m |= 1 << 3;
            }
            if wa::iswdigit(cp) != 0 {
                m |= 1 << 4;
            }
            if wa::iswgraph(cp) != 0 {
                m |= 1 << 5;
            }
            if wa::iswlower(cp) != 0 {
                m |= 1 << 6;
            }
            if wa::iswprint(cp) != 0 {
                m |= 1 << 7;
            }
            if wa::iswpunct(cp) != 0 {
                m |= 1 << 8;
            }
            if wa::iswspace(cp) != 0 {
                m |= 1 << 9;
            }
            if wa::iswupper(cp) != 0 {
                m |= 1 << 10;
            }
            if wa::iswxdigit(cp) != 0 {
                m |= 1 << 11;
            }
        }
        if cp % 8 == 0 {
            out.push_str("    ");
        }
        out.push_str(&format!("0x{m:04x},"));
        if cp % 8 == 7 {
            out.push('\n');
        } else {
            out.push(' ');
        }
    }
    out.push_str("];\n");
    eprint!("{out}");
}
