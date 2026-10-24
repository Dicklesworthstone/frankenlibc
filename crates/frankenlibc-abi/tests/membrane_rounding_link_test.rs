//! The ABI and membrane must share the no-self-interposition rounding helpers.
use frankenlibc_membrane::util::{ceil_f64, floor_f64, round_f64, trunc_f64};

#[test]
fn shared_rounding_is_callable_across_the_crate_boundary() {
    for (x, truncated, floor, ceil, rounded) in [
        (0.25, 0.0, 0.0, 1.0, 0.0),
        (-0.25, -0.0, -1.0, -0.0, -0.0),
        (0.5, 0.0, 0.0, 1.0, 1.0),
        (-0.5, -0.0, -1.0, -0.0, -1.0),
        (1.75, 1.0, 1.0, 2.0, 2.0),
        (-1.75, -1.0, -2.0, -1.0, -2.0),
    ] {
        let actual: [f64; 4] = [trunc_f64(x), floor_f64(x), ceil_f64(x), round_f64(x)];
        let expected: [f64; 4] = [truncated, floor, ceil, rounded];
        for (actual, expected) in actual.into_iter().zip(expected) {
            assert_eq!(actual.to_bits(), expected.to_bits(), "input {x}");
        }
    }
}

#[test]
fn shared_rounding_preserves_zeros_nonfinites_and_large_integral_values() {
    for helper in [trunc_f64, floor_f64, ceil_f64, round_f64] {
        for x in [0.0, -0.0, f64::INFINITY, f64::NEG_INFINITY,
                  4_503_599_627_370_496.0, -4_503_599_627_370_496.0, f64::MAX] {
            assert_eq!(helper(x).to_bits(), x.to_bits());
        }
        let nan = f64::from_bits(0x7ff8_0000_0000_1234);
        assert_eq!(helper(nan).to_bits(), nan.to_bits());
    }
}
