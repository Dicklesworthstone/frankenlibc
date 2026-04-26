//! NetBSD/FreeBSD libutil `fmtcheck` — printf-format compatibility check.
//!
//! Pure-safe Rust port of the byte-level logic. The C ABI shim in
//! `frankenlibc-abi::stdlib_abi` returns the user-supplied pointer
//! when [`compatible`] is `true`, else the default-supplied pointer
//! — matching the BSD contract.
//!
//! ## Semantics
//!
//! Two format strings are "compatible" iff they declare the same
//! sequence of variadic conversion specifiers, where each specifier
//! is normalized to a [`ConvShape`] capturing its type-class and
//! length-modifier class. The body of the format (literal text,
//! flags, width, precision) doesn't matter — only the **types** of
//! arguments the format consumes from `va_arg`.
//!
//! ### Equivalence classes
//!
//! - **Integers**: `d` ≡ `i`; `o` ≡ `u` ≡ `x` ≡ `X`. Length modifiers
//!   matter (`%d` vs `%ld` do **not** match — they consume different
//!   amounts of data from the va_list).
//! - **Floats**: `f` ≡ `F` ≡ `e` ≡ `E` ≡ `g` ≡ `G` ≡ `a` ≡ `A`.
//!   Length modifier matters (`%f` vs `%Lf` differ).
//! - **`%c`**: argument-promoted to `int`; treated as a distinct
//!   class from plain `INT` so callers can't quietly swap a `%d`
//!   for a `%c` even though both are int-shaped.
//! - **`%s`**: distinct class for `char *`.
//! - **`%p`**: distinct class for `void *`.
//! - **`%n`**: distinct class for `int *` (with length modifier).
//! - **`%%`**: literal percent — consumes no argument; ignored.

use crate::stdio::ValueArgKind;
use crate::stdio::printf::{FormatSegment, FormatSpec, parse_format_string};

/// Normalized conversion shape used to compare two `FormatSpec`s.
///
/// Each variant carries its length-modifier class so `%d` and `%ld`
/// can be distinguished even though both are signed integers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConvShape {
    /// `d`, `i` — signed integer.
    SignedInt(LenClass),
    /// `o`, `u`, `x`, `X` — unsigned integer.
    UnsignedInt(LenClass),
    /// `f`, `F`, `e`, `E`, `g`, `G`, `a`, `A` — floating point.
    Float(LenClass),
    /// `c` — character (promoted to int, but a distinct class).
    Char(LenClass),
    /// `s` — string.
    String_(LenClass),
    /// `p` — pointer.
    Pointer,
    /// `n` — store count via int*.
    StoreCount(LenClass),
}

/// Length-modifier equivalence class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LenClass {
    /// No length modifier (default `int` / `double`).
    Default,
    /// `h` or `hh` — short / signed-char.
    Short,
    /// `l` — long.
    Long,
    /// `ll` or `j` — long long / intmax_t.
    LongLong,
    /// `z` or `t` — size_t / ptrdiff_t.
    Size,
    /// `L` — long double.
    LongDouble,
}

impl ConvShape {
    /// Map a parsed `FormatSpec` to its compatibility shape, or
    /// `None` for non-consuming entries (literal `%`, parse errors).
    pub fn from_spec(spec: &FormatSpec) -> Option<Self> {
        let len = LenClass::from_length(spec.length);
        match spec.conversion {
            b'd' | b'i' => Some(Self::SignedInt(len)),
            b'o' | b'u' | b'x' | b'X' => Some(Self::UnsignedInt(len)),
            b'f' | b'F' | b'e' | b'E' | b'g' | b'G' | b'a' | b'A' => Some(Self::Float(len)),
            b'c' | b'C' => Some(Self::Char(len)),
            b's' | b'S' => Some(Self::String_(len)),
            b'p' => Some(Self::Pointer),
            b'n' => Some(Self::StoreCount(len)),
            // %%, %m (glibc strerror), and anything else don't consume
            // a va_arg, so they don't affect the compatibility verdict.
            _ => None,
        }
    }
}

impl LenClass {
    fn from_length(m: crate::stdio::printf::LengthMod) -> Self {
        use crate::stdio::printf::LengthMod;
        match m {
            LengthMod::None => Self::Default,
            LengthMod::H | LengthMod::Hh => Self::Short,
            LengthMod::L => Self::Long,
            LengthMod::Ll | LengthMod::J => Self::LongLong,
            LengthMod::Z | LengthMod::T => Self::Size,
            LengthMod::BigL => Self::LongDouble,
        }
    }
}

/// Walk `fmt`, collecting the [`ConvShape`] of each
/// variadic-consuming specifier in order.
pub fn shape_list(fmt: &[u8]) -> Vec<ConvShape> {
    parse_format_string(fmt)
        .iter()
        .filter_map(|seg| match seg {
            FormatSegment::Spec(spec) => ConvShape::from_spec(spec),
            _ => None,
        })
        .collect()
}

/// Returns `true` iff `user` and `default_fmt` declare exactly the
/// same sequence of variadic conversion specifiers (per the
/// equivalence classes documented at the module level).
pub fn compatible(user: &[u8], default_fmt: &[u8]) -> bool {
    shape_list(user) == shape_list(default_fmt)
}

/// Convenience: returns the [`ValueArgKind`] sequence consumed by
/// `fmt`. Coarser than [`shape_list`] (only Gp vs Fp), but useful
/// for callers that only care about the va_list register class.
pub fn arg_kind_list(fmt: &[u8]) -> Vec<ValueArgKind> {
    parse_format_string(fmt)
        .iter()
        .filter_map(|seg| match seg {
            FormatSegment::Spec(spec) => spec.value_arg_kind(),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- shape_list ----

    #[test]
    fn shape_empty_format_has_no_conversions() {
        assert!(shape_list(b"").is_empty());
        assert!(shape_list(b"plain text").is_empty());
        assert!(shape_list(b"100%% complete").is_empty());
    }

    #[test]
    fn shape_signed_int() {
        let s = shape_list(b"%d");
        assert_eq!(s, vec![ConvShape::SignedInt(LenClass::Default)]);

        let s = shape_list(b"%i");
        assert_eq!(s, vec![ConvShape::SignedInt(LenClass::Default)]);
    }

    #[test]
    fn shape_unsigned_int_family() {
        for c in [b"%o", b"%u", b"%x", b"%X"].iter() {
            let s = shape_list(*c);
            assert_eq!(s, vec![ConvShape::UnsignedInt(LenClass::Default)]);
        }
    }

    #[test]
    fn shape_floats_all_collapse_to_float() {
        for c in [b"%f", b"%F", b"%e", b"%E", b"%g", b"%G", b"%a", b"%A"].iter() {
            let s = shape_list(*c);
            assert_eq!(s, vec![ConvShape::Float(LenClass::Default)]);
        }
    }

    #[test]
    fn shape_string_pointer_char() {
        assert_eq!(
            shape_list(b"%s"),
            vec![ConvShape::String_(LenClass::Default)]
        );
        assert_eq!(shape_list(b"%p"), vec![ConvShape::Pointer]);
        assert_eq!(shape_list(b"%c"), vec![ConvShape::Char(LenClass::Default)]);
    }

    #[test]
    fn shape_length_modifiers_normalize() {
        assert_eq!(
            shape_list(b"%hd"),
            vec![ConvShape::SignedInt(LenClass::Short)]
        );
        assert_eq!(
            shape_list(b"%hhd"),
            vec![ConvShape::SignedInt(LenClass::Short)]
        );
        assert_eq!(
            shape_list(b"%ld"),
            vec![ConvShape::SignedInt(LenClass::Long)]
        );
        assert_eq!(
            shape_list(b"%lld"),
            vec![ConvShape::SignedInt(LenClass::LongLong)]
        );
        assert_eq!(
            shape_list(b"%jd"),
            vec![ConvShape::SignedInt(LenClass::LongLong)]
        );
        assert_eq!(
            shape_list(b"%zd"),
            vec![ConvShape::SignedInt(LenClass::Size)]
        );
        assert_eq!(
            shape_list(b"%td"),
            vec![ConvShape::SignedInt(LenClass::Size)]
        );
        assert_eq!(
            shape_list(b"%Lf"),
            vec![ConvShape::Float(LenClass::LongDouble)]
        );
    }

    #[test]
    fn shape_skips_literal_percent() {
        let s = shape_list(b"100%% done in %d seconds");
        assert_eq!(s, vec![ConvShape::SignedInt(LenClass::Default)]);
    }

    #[test]
    fn shape_handles_multiple_conversions_in_order() {
        let s = shape_list(b"%d %s %f");
        assert_eq!(
            s,
            vec![
                ConvShape::SignedInt(LenClass::Default),
                ConvShape::String_(LenClass::Default),
                ConvShape::Float(LenClass::Default),
            ]
        );
    }

    // ---- compatible ----

    #[test]
    fn compatible_identical_formats() {
        assert!(compatible(b"%d %s", b"%d %s"));
        assert!(compatible(b"", b""));
        assert!(compatible(b"plain", b"different plain"));
    }

    #[test]
    fn compatible_d_and_i_interchange() {
        assert!(compatible(b"%d", b"%i"));
        assert!(compatible(b"%i %d", b"%d %i"));
    }

    #[test]
    fn compatible_unsigned_family_interchange() {
        assert!(compatible(b"%o", b"%u"));
        assert!(compatible(b"%x", b"%X"));
        assert!(compatible(b"%u", b"%X"));
    }

    #[test]
    fn compatible_floats_all_match() {
        assert!(compatible(b"%f", b"%g"));
        assert!(compatible(b"%e", b"%G"));
        assert!(compatible(b"%a", b"%E"));
    }

    #[test]
    fn incompatible_signed_vs_unsigned() {
        assert!(!compatible(b"%d", b"%u"));
        assert!(!compatible(b"%i", b"%x"));
    }

    #[test]
    fn incompatible_int_vs_float() {
        assert!(!compatible(b"%d", b"%f"));
        assert!(!compatible(b"%s", b"%d"));
    }

    #[test]
    fn incompatible_different_length_modifiers() {
        assert!(!compatible(b"%d", b"%ld"));
        assert!(!compatible(b"%ld", b"%lld"));
        assert!(!compatible(b"%f", b"%Lf"));
    }

    #[test]
    fn incompatible_different_conversion_count() {
        assert!(!compatible(b"%d", b"%d %d"));
        assert!(!compatible(b"%d %s", b"%d"));
    }

    #[test]
    fn incompatible_reordered_conversions() {
        assert!(!compatible(b"%d %s", b"%s %d"));
    }

    #[test]
    fn compatible_ignores_literal_text_differences() {
        assert!(compatible(b"User said: %s (errno=%d)", b"%s|%d"));
    }

    #[test]
    fn compatible_ignores_flags_width_precision() {
        assert!(compatible(b"%d", b"%5d"));
        assert!(compatible(b"%d", b"%-10.3d"));
        assert!(compatible(b"%s", b"%.20s"));
        assert!(compatible(b"%f", b"%+#15.6f"));
    }

    #[test]
    fn compatible_with_percent_literal_in_one() {
        assert!(compatible(b"100%% %d", b"%d"));
    }

    #[test]
    fn incompatible_char_vs_int_not_swappable() {
        // c is its own class even though it's int-shaped — fmtcheck
        // is conservative about the type label.
        assert!(!compatible(b"%c", b"%d"));
    }

    #[test]
    fn compatible_pointer_class_distinct() {
        assert!(!compatible(b"%p", b"%s"));
        assert!(!compatible(b"%p", b"%d"));
        assert!(compatible(b"%p", b"%p"));
    }

    // ---- arg_kind_list (coarse Gp/Fp categorisation) ----

    #[test]
    fn arg_kind_list_groups_int_string_pointer_as_gp() {
        use ValueArgKind::*;
        assert_eq!(arg_kind_list(b"%d %s %p %f"), vec![Gp, Gp, Gp, Fp]);
        assert_eq!(arg_kind_list(b"%lld %Lf"), vec![Gp, Fp]);
    }
}
