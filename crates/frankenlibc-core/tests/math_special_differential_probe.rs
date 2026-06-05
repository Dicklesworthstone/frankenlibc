//! Differential probe: frankenlibc math vs glibc libm on C99 Annex F
//! mandated-exact special cases (inf/nan/±0 handling, exact integer powers,
//! signed-zero atan2 quadrants, round-half-to-even remainder, hypot(inf,nan),
//! nextafter steps). Compared via exact IEEE-754 bits, EXCEPT NaN results which
//! are compared as "is NaN" (NaN sign/payload is unspecified by the standard).
//! glibc reference bits captured from a C probe linked against -lm.

use frankenlibc_core::math::{
    atan2, cbrt, copysign, exp, fmod, hypot, ldexp, log, nextafter, pow, remainder, scalbn,
};

fn check(label: &str, got: f64, glibc_hex: &str, diffs: &mut Vec<String>) {
    let g = u64::from_str_radix(glibc_hex, 16).expect("hex");
    let ref_val = f64::from_bits(g);
    let ok = if ref_val.is_nan() {
        got.is_nan()
    } else {
        got.to_bits() == g
    };
    if !ok {
        diffs.push(format!(
            "{label}: frankenlibc=0x{:016x} ({got:?}) glibc=0x{g:016x} ({ref_val:?})",
            got.to_bits()
        ));
    }
}

#[test]
fn math_special_value_differential_battery() {
    let inf = f64::INFINITY;
    let ninf = f64::NEG_INFINITY;
    let nan = f64::NAN;
    let mut d = Vec::new();

    // (label, frankenlibc result, glibc bits)
    check("pow_p0_n2", pow(0.0, -2.0), "7ff0000000000000", &mut d);
    check("pow_n0_n3", pow(-0.0, -3.0), "fff0000000000000", &mut d);
    check("pow_p0_3", pow(0.0, 3.0), "0000000000000000", &mut d);
    check("pow_n0_3", pow(-0.0, 3.0), "8000000000000000", &mut d);
    check("pow_n1_inf", pow(-1.0, inf), "3ff0000000000000", &mut d);
    check("pow_n1_ninf", pow(-1.0, ninf), "3ff0000000000000", &mut d);
    check("pow_1_nan", pow(1.0, nan), "3ff0000000000000", &mut d);
    check("pow_nan_0", pow(nan, 0.0), "3ff0000000000000", &mut d);
    check("pow_inf_0", pow(inf, 0.0), "3ff0000000000000", &mut d);
    check("pow_2_10", pow(2.0, 10.0), "4090000000000000", &mut d);
    check("pow_n2_3", pow(-2.0, 3.0), "c020000000000000", &mut d);
    check("pow_0_0", pow(0.0, 0.0), "3ff0000000000000", &mut d);
    check("pow_ninf_n1", pow(ninf, -1.0), "8000000000000000", &mut d);
    check("pow_ninf_2", pow(ninf, 2.0), "7ff0000000000000", &mut d);
    check("pow_half_ninf", pow(0.5, ninf), "7ff0000000000000", &mut d);
    check("pow_2_ninf", pow(2.0, ninf), "0000000000000000", &mut d);

    check("fmod_5_3", fmod(5.0, 3.0), "4000000000000000", &mut d);
    check("fmod_n5_3", fmod(-5.0, 3.0), "c000000000000000", &mut d);
    check("fmod_5_n3", fmod(5.0, -3.0), "4000000000000000", &mut d);
    check("fmod_5_0", fmod(5.0, 0.0), "fff8000000000000", &mut d);
    check("fmod_inf_1", fmod(inf, 1.0), "fff8000000000000", &mut d);
    check("fmod_1_inf", fmod(1.0, inf), "3ff0000000000000", &mut d);
    check("fmod_n0_5", fmod(-0.0, 5.0), "8000000000000000", &mut d);

    check("rem_5_3", remainder(5.0, 3.0), "bff0000000000000", &mut d);
    check("rem_5_2", remainder(5.0, 2.0), "3ff0000000000000", &mut d);
    check("rem_7_2", remainder(7.0, 2.0), "bff0000000000000", &mut d);
    check("rem_n5_3", remainder(-5.0, 3.0), "3ff0000000000000", &mut d);

    check("atan2_p0_p0", atan2(0.0, 0.0), "0000000000000000", &mut d);
    check("atan2_n0_p0", atan2(-0.0, 0.0), "8000000000000000", &mut d);
    check("atan2_p0_n0", atan2(0.0, -0.0), "400921fb54442d18", &mut d);
    check("atan2_n0_n0", atan2(-0.0, -0.0), "c00921fb54442d18", &mut d);
    check("atan2_p0_n1", atan2(0.0, -1.0), "400921fb54442d18", &mut d);
    check("atan2_1_0", atan2(1.0, 0.0), "3ff921fb54442d18", &mut d);
    check("atan2_n1_0", atan2(-1.0, 0.0), "bff921fb54442d18", &mut d);
    check("atan2_inf_inf", atan2(inf, inf), "3fe921fb54442d18", &mut d);
    check(
        "atan2_inf_ninf",
        atan2(inf, ninf),
        "4002d97c7f3321d2",
        &mut d,
    );

    check(
        "copysign_3_n0",
        copysign(3.0, -0.0),
        "c008000000000000",
        &mut d,
    );
    check(
        "copysign_3_n1",
        copysign(3.0, -1.0),
        "c008000000000000",
        &mut d,
    );

    check("cbrt_n8", cbrt(-8.0), "c000000000000000", &mut d);
    check("cbrt_n0", cbrt(-0.0), "8000000000000000", &mut d);
    check("cbrt_inf", cbrt(inf), "7ff0000000000000", &mut d);

    check("hypot_3_4", hypot(3.0, 4.0), "4014000000000000", &mut d);
    check("hypot_inf_nan", hypot(inf, nan), "7ff0000000000000", &mut d);
    check("hypot_nan_inf", hypot(nan, inf), "7ff0000000000000", &mut d);

    check(
        "nextafter_1_2",
        nextafter(1.0, 2.0),
        "3ff0000000000001",
        &mut d,
    );
    check(
        "nextafter_0_1",
        nextafter(0.0, 1.0),
        "0000000000000001",
        &mut d,
    );
    check(
        "nextafter_0_n1",
        nextafter(0.0, -1.0),
        "8000000000000001",
        &mut d,
    );
    check(
        "nextafter_1_1",
        nextafter(1.0, 1.0),
        "3ff0000000000000",
        &mut d,
    );
    check(
        "nextafter_inf_0",
        nextafter(inf, 0.0),
        "7fefffffffffffff",
        &mut d,
    );

    check("log_1", log(1.0), "0000000000000000", &mut d);
    check("log_0", log(0.0), "fff0000000000000", &mut d);
    check("log_n1", log(-1.0), "fff8000000000000", &mut d);
    check("log_inf", log(inf), "7ff0000000000000", &mut d);
    check("exp_0", exp(0.0), "3ff0000000000000", &mut d);
    check("exp_ninf", exp(ninf), "0000000000000000", &mut d);
    check("exp_inf", exp(inf), "7ff0000000000000", &mut d);
    check("scalbn_1_3", scalbn(1.0, 3), "4020000000000000", &mut d);
    check("ldexp_3_4", ldexp(3.0, 4), "4048000000000000", &mut d);

    assert!(
        d.is_empty(),
        "math special-value results diverge from glibc in {} case(s):\n{}",
        d.len(),
        d.join("\n")
    );
}
