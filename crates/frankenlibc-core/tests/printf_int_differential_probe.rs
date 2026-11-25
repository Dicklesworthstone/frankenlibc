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

// Native-thread admission is process-wide and irreversible. Isolate these
// regressions so the ordinary differential cases retain their hosted setup.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn isolated_native_admission_case(name: &str) -> bool {
    const CHILD: &str = "FRANKENLIBC_PRINTF_NATIVE_ADMISSION_CHILD";
    if std::env::var_os(CHILD).is_some() {
        return false;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains("1 passed;"),
        "isolated {name} failed: {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
    true
}

#[test]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn native_admission_preserves_numeric_locale_through_hosted_thread_churn() {
    if isolated_native_admission_case(
        "native_admission_preserves_numeric_locale_through_hosted_thread_churn",
    ) {
        return;
    }
    frankenlibc_core::pthread::tls::disable_tid_cache();
    for generation in 0..2048 {
        let formatted = std::thread::spawn(|| {
            use frankenlibc_core::stdio::printf::{format_float, set_thread_numeric};
            set_thread_numeric(b";", b"_", &[3]);
            let mut output = Vec::new();
            format_signed(12_345, &spec_of("%'d"), &mut output);
            output.push(b' ');
            format_float(1.5, &spec_of("%.1f"), &mut output);
            // Thread exit owns cleanup; callers need not reset uselocale.
            output
        })
        .join()
        .unwrap();
        assert_eq!(
            formatted, b"12_345 1;5",
            "LC_NUMERIC lost after hosted thread generation {generation}"
        );
    }
}

#[test]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn native_admission_preserves_simultaneous_errors_after_thread_churn() {
    if isolated_native_admission_case(
        "native_admission_preserves_simultaneous_errors_after_thread_churn",
    ) {
        return;
    }
    use frankenlibc_core::errno::{EINVAL, ENOMEM, EOVERFLOW};
    use frankenlibc_core::stdio::printf::{note_render_failure, take_render_failure};
    use std::sync::{Arc, Barrier};

    frankenlibc_core::pthread::tls::disable_tid_cache();
    for _ in 0..2048 {
        std::thread::spawn(|| {
            // A thread may exit with a pending error; it must not consume a
            // process-wide slot forever or affect later owners' failures.
            note_render_failure(ENOMEM);
        })
        .join()
        .unwrap();
    }
    let ready = Arc::new(Barrier::new(2));
    let workers: Vec<_> = [EINVAL, EOVERFLOW]
        .into_iter()
        .map(|expected| {
            let ready = Arc::clone(&ready);
            std::thread::spawn(move || {
                note_render_failure(expected);
                ready.wait();
                (expected, take_render_failure(), take_render_failure())
            })
        })
        .collect();
    for worker in workers {
        let (expected, actual, consumed) = worker.join().unwrap();
        assert_eq!(actual, expected, "another owner overwrote a pending failure");
        assert_eq!(consumed, 0, "a consumed failure was replayed");
    }
}

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
