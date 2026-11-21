//! IDNA (Internationalized Domain Names in Applications) primitives.
//!
//! Safe Rust Punycode and native Unicode 16 IDNA processing. Forward lookup
//! uses nontransitional UTS #46 mapping, NFC, Bidi and ContextJ validation,
//! followed by the IDNA2008 derived-property restrictions used by GNU.
//! Locale decoding belongs to the ABI layer, before these UTF-8 operations.

pub mod punycode;

mod properties;

use std::borrow::Cow;

use idna::uts46::{AsciiDenyList, Hyphens, Uts46};

/// A name cannot be represented as a GNU-compatible DNS name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdnaError;

/// Convert a Unicode name to its ASCII DNS representation.
///
/// GNU preserves wholly ASCII input verbatim, including its case and existing
/// A-labels. Once Unicode processing is needed, it maps all labels, validates
/// each label independently, and enforces encoded DNS lengths. Empty labels
/// remain permitted: resolver policy, rather than IDNA, decides whether those
/// names can be looked up. ContextO code points are permitted, matching GNU's
/// lookup profile; ContextJ and the RFC 5893 Bidi rules are still enforced.
pub fn to_dns_encoding(name: &str) -> Result<Cow<'_, str>, IdnaError> {
    if name.is_ascii() {
        return Ok(Cow::Borrowed(name));
    }

    // These are the UTS #46 domain-separator mappings. Split after mapping so
    // Bidi validation is label-local, as in GNU, and a numeric ASCII label in
    // a domain containing a right-to-left label remains usable.
    let separated: String = name
        .chars()
        .map(|character| match character {
            '\u{3002}' | '\u{ff0e}' | '\u{ff61}' => '.',
            other => other,
        })
        .collect();
    let processor = Uts46::new();
    let mut output = String::with_capacity(separated.len());
    for (index, label) in separated.split('.').enumerate() {
        if index != 0 {
            output.push('.');
        }
        if label.is_empty() {
            continue;
        }
        let (mapped, validity) =
            processor.to_unicode(label.as_bytes(), AsciiDenyList::EMPTY, Hyphens::Check);
        validity.map_err(|_| IdnaError)?;
        // GNU's lookup profile does not accept DNS presentation escapes.
        if mapped.contains('\\') {
            return Err(IdnaError);
        }
        // Each mapped scalar needs at least one encoded byte. Bound the
        // encoder's quadratic work before considering attacker-sized labels;
        // normalization and ignored-character removal have already happened.
        if mapped.chars().take(64).count() > 63 {
            return Err(IdnaError);
        }
        let start = output.len();
        if mapped.is_ascii() {
            output.push_str(&mapped);
        } else {
            // UTS #46 alone also accepts symbols such as emoji. GNU applies
            // IDNA2008 restrictions after mapping. Use the complete normative
            // derived-property table, with GNU's non-STD3 underscore allowance.
            if !mapped
                .chars()
                .all(|character| character == '_' || properties::allowed(character))
            {
                return Err(IdnaError);
            }
            let codepoints: Vec<u32> = mapped.chars().map(u32::from).collect();
            let encoded = punycode::encode(&codepoints).ok_or(IdnaError)?;
            output.push_str("xn--");
            output.extend(encoded.into_iter().map(char::from));
        }
        if output.len() - start > 63 {
            return Err(IdnaError);
        }
    }
    let wire_name_length = output.len() - usize::from(output.ends_with('.'));
    if wire_name_length > 253 {
        return Err(IdnaError);
    }
    Ok(Cow::Owned(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_idna_maps_normalizes_and_validates_general_unicode() {
        for (input, expected) in [
            ("BÜCHER.test", "xn--bcher-kva.test"),
            ("bu\u{308}cher.test", "xn--bcher-kva.test"),
            ("例え。テスト", "xn--r8jz45g.xn--zckzah"),
            ("例え．テスト", "xn--r8jz45g.xn--zckzah"),
            ("例え｡テスト", "xn--r8jz45g.xn--zckzah"),
            ("faß.test", "xn--fa-hia.test"),
            ("Σςσ.test", "xn--3xabb.test"),
            ("Ⅳ.test", "iv.test"),
            ("Ｆｏｏ.test", "foo.test"),
            ("ü.AsCii.TeST", "xn--tda.ascii.test"),
            ("ü_foo.test", "xn--_foo-zra.test"),
            ("a·b.test", "xn--ab-0ea.test"),
            ("123.א.test", "123.xn--4db.test"),
            ("1a.א.test", "1a.xn--4db.test"),
            ("_srv.א.test", "_srv.xn--4db.test"),
            ("क्\u{200d}ष.test", "xn--11b2ezcw70k.test"),
            ("نامه\u{200c}ای.test", "xn--mgba3gch31f060k.test"),
            ("ü..test", "xn--tda..test"),
            ("ü.test..", "xn--tda.test.."),
            ("ü.\u{ad}.test", "xn--tda..test"),
            ("ü.a b.test", "xn--tda.a b.test"),
            ("＄.test", "$.test"),
            ("ü.xn--bcher-kva.test", "xn--tda.xn--bcher-kva.test"),
        ] {
            assert_eq!(to_dns_encoding(input).unwrap(), expected, "{input:?}");
        }
        for input in [
            "😀.test",
            "☃.test",
            "\u{378}.test",
            "\u{308}a.test",
            "ü-.test",
            "-ü.test",
            "ab--ü.test",
            "ü.ab--cd.test",
            "ü.-ascii.test",
            "ü.ascii-.test",
            "a\u{200d}b.test",
            "a\u{200c}b.test",
            "אa.test",
            "ü!.test",
            "ü.a\\foo.test",
            "ü.xn--bad_.test",
            "ü.xn--hello-.test",
        ] {
            assert_eq!(to_dns_encoding(input), Err(IdnaError), "{input:?}");
        }
    }

    #[test]
    fn forward_idna_preserves_ascii_and_checks_encoded_lengths() {
        for input in ["AsCii.CaSe", "xn--bad_.test", "xn--", "a..b", "a\\b"] {
            assert!(matches!(to_dns_encoding(input), Ok(Cow::Borrowed(value)) if value == input));
        }
        let label_limit = format!("{}ü.test", "u".repeat(55));
        assert_eq!(
            to_dns_encoding(&label_limit)
                .unwrap()
                .split('.')
                .next()
                .unwrap()
                .len(),
            63
        );
        assert_eq!(to_dns_encoding(&format!("u{label_limit}")), Err(IdnaError));
        assert_eq!(to_dns_encoding(&"ü".repeat(57)).unwrap().len(), 63);
        assert_eq!(to_dns_encoding(&"ü".repeat(58)), Err(IdnaError));
        assert_eq!(to_dns_encoding(&"ü".repeat(4096)), Err(IdnaError));
        assert!(to_dns_encoding(&format!("ü.{}", "a".repeat(63))).is_ok());
        assert_eq!(
            to_dns_encoding(&format!("ü.{}", "a".repeat(64))),
            Err(IdnaError)
        );

        let domain_limit = format!("ü.{}a", "a.".repeat(122));
        assert_eq!(to_dns_encoding(&domain_limit).unwrap().len(), 253);
        assert_eq!(
            to_dns_encoding(&format!("{domain_limit}.")).unwrap().len(),
            254
        );
        assert_eq!(to_dns_encoding(&format!("{domain_limit}a")), Err(IdnaError));
        assert_eq!(
            to_dns_encoding(&format!("{domain_limit}a.")),
            Err(IdnaError)
        );
    }
}
