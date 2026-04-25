//! Locale support.

pub mod catgets;

/// POSIX locale category: character classification and conversion.
pub const LC_CTYPE: i32 = 0;
/// POSIX locale category: numeric formatting.
pub const LC_NUMERIC: i32 = 1;
/// POSIX locale category: date and time formatting.
pub const LC_TIME: i32 = 2;
/// POSIX locale category: string collation.
pub const LC_COLLATE: i32 = 3;
/// POSIX locale category: monetary formatting.
pub const LC_MONETARY: i32 = 4;
/// POSIX locale category: informational and diagnostic messages.
pub const LC_MESSAGES: i32 = 5;
/// POSIX locale category: all categories.
pub const LC_ALL: i32 = 6;

/// Minimum valid locale category value.
pub const LC_MIN: i32 = 0;
/// Maximum valid locale category value.
pub const LC_MAX: i32 = 6;

/// Value used for unspecified numeric fields in `LocaleConv` (POSIX `CHAR_MAX`).
const CHAR_MAX: i8 = 127;

/// Returns `true` if `cat` is a valid POSIX locale category.
#[inline]
pub fn valid_category(cat: i32) -> bool {
    (LC_MIN..=LC_MAX).contains(&cat)
}

/// Numeric and monetary formatting conventions (mirrors POSIX `struct lconv`).
#[derive(Debug, Clone, Default)]
pub struct LocaleConv {
    /// Decimal-point character.
    pub decimal_point: Vec<u8>,
    /// Thousands separator.
    pub thousands_sep: Vec<u8>,
    /// Grouping specification.
    pub grouping: Vec<u8>,
    /// International currency symbol.
    pub int_curr_symbol: Vec<u8>,
    /// Local currency symbol.
    pub currency_symbol: Vec<u8>,
    /// Monetary decimal-point character.
    pub mon_decimal_point: Vec<u8>,
    /// Monetary thousands separator.
    pub mon_thousands_sep: Vec<u8>,
    /// Monetary grouping specification.
    pub mon_grouping: Vec<u8>,
    /// Positive-value sign.
    pub positive_sign: Vec<u8>,
    /// Negative-value sign.
    pub negative_sign: Vec<u8>,
    /// International fractional digits.
    pub int_frac_digits: i8,
    /// Local fractional digits.
    pub frac_digits: i8,
    /// 1 if currency_symbol precedes positive value.
    pub p_cs_precedes: i8,
    /// 1 if space separates currency_symbol from positive value.
    pub p_sep_by_space: i8,
    /// 1 if currency_symbol precedes negative value.
    pub n_cs_precedes: i8,
    /// 1 if space separates currency_symbol from negative value.
    pub n_sep_by_space: i8,
    /// Positioning of positive_sign for positive values.
    pub p_sign_posn: i8,
    /// Positioning of negative_sign for negative values.
    pub n_sign_posn: i8,
}

/// Returns the `LocaleConv` for the POSIX "C" locale.
///
/// String fields that are unspecified in the "C" locale are set to empty
/// byte vectors, except `decimal_point` which is `b"."`. All numeric flag
/// fields are set to `CHAR_MAX` (127) per POSIX.
pub fn c_locale_conv() -> LocaleConv {
    LocaleConv {
        decimal_point: b".".to_vec(),
        thousands_sep: b"".to_vec(),
        grouping: b"".to_vec(),
        int_curr_symbol: b"".to_vec(),
        currency_symbol: b"".to_vec(),
        mon_decimal_point: b"".to_vec(),
        mon_thousands_sep: b"".to_vec(),
        mon_grouping: b"".to_vec(),
        positive_sign: b"".to_vec(),
        negative_sign: b"".to_vec(),
        int_frac_digits: CHAR_MAX,
        frac_digits: CHAR_MAX,
        p_cs_precedes: CHAR_MAX,
        p_sep_by_space: CHAR_MAX,
        n_cs_precedes: CHAR_MAX,
        n_sep_by_space: CHAR_MAX,
        p_sign_posn: CHAR_MAX,
        n_sign_posn: CHAR_MAX,
    }
}

/// Returns the canonical name of the "C" locale as a byte slice.
#[inline]
pub fn c_locale_name() -> &'static [u8] {
    b"C"
}

/// Returns the canonical name of the "POSIX" locale as a byte slice.
#[inline]
pub fn posix_locale_name() -> &'static [u8] {
    b"POSIX"
}

/// Returns `true` if `name` refers to the minimal POSIX "C" locale.
///
/// The "C" locale can be identified by the names `b"C"`, `b"POSIX"`, or
/// the empty string `b""`.
#[inline]
pub fn is_c_locale(name: &[u8]) -> bool {
    matches!(name, b"C" | b"POSIX" | b"")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── valid_category tests ────────────────────────────────────────

    #[test]
    fn valid_category_accepts_all_defined_categories() {
        assert!(valid_category(LC_CTYPE));
        assert!(valid_category(LC_NUMERIC));
        assert!(valid_category(LC_TIME));
        assert!(valid_category(LC_COLLATE));
        assert!(valid_category(LC_MONETARY));
        assert!(valid_category(LC_MESSAGES));
        assert!(valid_category(LC_ALL));
    }

    #[test]
    fn valid_category_rejects_out_of_range() {
        assert!(!valid_category(-1));
        assert!(!valid_category(7));
        assert!(!valid_category(i32::MIN));
        assert!(!valid_category(i32::MAX));
    }

    #[test]
    fn valid_category_boundary_values() {
        assert!(valid_category(LC_MIN));
        assert!(valid_category(LC_MAX));
        assert!(!valid_category(LC_MIN - 1));
        assert!(!valid_category(LC_MAX + 1));
    }

    // ── c_locale_conv tests ─────────────────────────────────────────

    #[test]
    fn c_locale_conv_decimal_point_is_dot() {
        let lc = c_locale_conv();
        assert_eq!(lc.decimal_point, b".");
    }

    #[test]
    fn c_locale_conv_string_fields_empty() {
        let lc = c_locale_conv();
        assert!(lc.thousands_sep.is_empty());
        assert!(lc.grouping.is_empty());
        assert!(lc.int_curr_symbol.is_empty());
        assert!(lc.currency_symbol.is_empty());
        assert!(lc.mon_decimal_point.is_empty());
        assert!(lc.mon_thousands_sep.is_empty());
        assert!(lc.mon_grouping.is_empty());
        assert!(lc.positive_sign.is_empty());
        assert!(lc.negative_sign.is_empty());
    }

    #[test]
    fn c_locale_conv_numeric_fields_are_char_max() {
        let lc = c_locale_conv();
        assert_eq!(lc.int_frac_digits, 127);
        assert_eq!(lc.frac_digits, 127);
        assert_eq!(lc.p_cs_precedes, 127);
        assert_eq!(lc.p_sep_by_space, 127);
        assert_eq!(lc.n_cs_precedes, 127);
        assert_eq!(lc.n_sep_by_space, 127);
        assert_eq!(lc.p_sign_posn, 127);
        assert_eq!(lc.n_sign_posn, 127);
    }

    #[test]
    fn c_locale_conv_clone_equals_original() {
        let lc = c_locale_conv();
        let lc2 = lc.clone();
        assert_eq!(lc.decimal_point, lc2.decimal_point);
        assert_eq!(lc.int_frac_digits, lc2.int_frac_digits);
    }

    // ── locale name tests ───────────────────────────────────────────

    #[test]
    fn c_locale_name_returns_c() {
        assert_eq!(c_locale_name(), b"C");
    }

    #[test]
    fn posix_locale_name_returns_posix() {
        assert_eq!(posix_locale_name(), b"POSIX");
    }

    // ── is_c_locale tests ───────────────────────────────────────────

    #[test]
    fn is_c_locale_recognises_c() {
        assert!(is_c_locale(b"C"));
    }

    #[test]
    fn is_c_locale_recognises_posix() {
        assert!(is_c_locale(b"POSIX"));
    }

    #[test]
    fn is_c_locale_recognises_empty() {
        assert!(is_c_locale(b""));
    }

    #[test]
    fn is_c_locale_rejects_other_names() {
        assert!(!is_c_locale(b"en_US.UTF-8"));
        assert!(!is_c_locale(b"c")); // case-sensitive
        assert!(!is_c_locale(b"posix"));
        assert!(!is_c_locale(b"C.UTF-8"));
    }

    // ── constant value tests ────────────────────────────────────────

    #[test]
    fn category_constants_have_expected_values() {
        assert_eq!(LC_CTYPE, 0);
        assert_eq!(LC_NUMERIC, 1);
        assert_eq!(LC_TIME, 2);
        assert_eq!(LC_COLLATE, 3);
        assert_eq!(LC_MONETARY, 4);
        assert_eq!(LC_MESSAGES, 5);
        assert_eq!(LC_ALL, 6);
        assert_eq!(LC_MIN, 0);
        assert_eq!(LC_MAX, 6);
    }
}
