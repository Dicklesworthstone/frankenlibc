//! Differential probe: frankenlibc printf integer formatting (format_signed /
//! format_unsigned) vs glibc, covering the classic edge cases: precision-0 of
//! zero -> empty string, precision zero-padding, zero-flag ignored when a
//! precision is given, sign flags (+/space), "+.0" of zero -> "+", alt-form
//! (#) for hex/octal incl. of zero (no prefix), width/precision/zero-pad
//! interaction, and INT64_MIN / UINT64_MAX. glibc reference captured from a C
//! snprintf probe (using ll length so the full 64-bit value is formatted).

use frankenlibc_core::stdio::printf::{
    FormatSegment, format_signed, format_unsigned, parse_format_string,
};

fn spec_of(fmt: &str) -> frankenlibc_core::stdio::printf::FormatSpec {
    parse_format_string(fmt.as_bytes())
        .as_slice()
        .iter()
        .find_map(|s| match s {
            FormatSegment::Spec(spec) => Some(*spec),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no spec in {fmt:?}"))
}

fn rs(fmt: &str, v: i64) -> String {
    let spec = spec_of(fmt);
    let mut buf = Vec::new();
    format_signed(v, &spec, &mut buf);
    String::from_utf8(buf).unwrap()
}
fn ru(fmt: &str, v: u64) -> String {
    let spec = spec_of(fmt);
    let mut buf = Vec::new();
    format_unsigned(v, &spec, &mut buf);
    String::from_utf8(buf).unwrap()
}

#[test]
fn printf_int_differential_battery() {
    let mut d = Vec::new();
    let mut cs = |label: &str, got: String, exp: &str| {
        if got != exp {
            d.push(format!("{label}: frankenlibc={got:?} glibc={exp:?}"));
        }
    };

    // signed
    cs("%lld/0", rs("%lld", 0), "0");
    cs("%.0lld/0", rs("%.0lld", 0), "");
    cs("%5lld/42", rs("%5lld", 42), "   42");
    cs("%-5lld/42", rs("%-5lld", 42), "42   ");
    cs("%05lld/42", rs("%05lld", 42), "00042");
    cs("%+lld/42", rs("%+lld", 42), "+42");
    cs("% lld/42", rs("% lld", 42), " 42");
    cs("%+lld/-42", rs("%+lld", -42), "-42");
    cs("%.5lld/42", rs("%.5lld", 42), "00042");
    cs("%8.5lld/42", rs("%8.5lld", 42), "   00042");
    cs("%-8.5lld/42", rs("%-8.5lld", 42), "00042   ");
    cs("%05.3lld/42", rs("%05.3lld", 42), "  042");
    cs("%lld/MIN", rs("%lld", i64::MIN), "-9223372036854775808");
    cs("%+.0lld/0", rs("%+.0lld", 0), "+");
    // unsigned
    cs("%llu/0", ru("%llu", 0), "0");
    cs("%llx/255", ru("%llx", 255), "ff");
    cs("%llX/255", ru("%llX", 255), "FF");
    cs("%#llx/255", ru("%#llx", 255), "0xff");
    cs("%#llx/0", ru("%#llx", 0), "0");
    cs("%#llo/0", ru("%#llo", 0), "0");
    cs("%#llo/8", ru("%#llo", 8), "010");
    cs("%llo/8", ru("%llo", 8), "10");
    cs("%.0llu/0", ru("%.0llu", 0), "");
    cs("%#010llx/255", ru("%#010llx", 255), "0x000000ff");
    cs("%5llx/255", ru("%5llx", 255), "   ff");
    cs("%#llX/255", ru("%#llX", 255), "0XFF");
    cs("%llx/MAX", ru("%llx", u64::MAX), "ffffffffffffffff");

    assert!(
        d.is_empty(),
        "printf integer formatting diverges from glibc in {} case(s):\n{}",
        d.len(),
        d.join("\n")
    );
}
