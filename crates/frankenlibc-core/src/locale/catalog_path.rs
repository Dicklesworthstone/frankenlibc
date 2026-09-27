//! Byte-preserving XSI message-catalog search paths.
//!
//! This module neither reads the environment nor opens files. The ABI supplies
//! the selected LC_MESSAGES name (NL_CAT_LOCALE) or LANG (other flags), and
//! opens candidates in order. Expansion is deliberately single-pass: '%' and
//! ':' in a substituted catalog name are data, not more template syntax.

/// GNU installation layout with the normal `/usr` prefix. Explicit NLSPATH
/// candidates precede these implementation-defined fallback locations.
pub const DEFAULT_NLSPATH: &[u8] =
    b"/usr/share/locale/%L/%N:/usr/share/locale/%L/LC_MESSAGES/%N";

/// Linux's pathname limit, excluding the terminating NUL. Oversized paths are
/// rejected, never truncated to a different (potentially valid) catalog name.
pub const MAX_CATALOG_PATH_BYTES: usize = 4095;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogPathError {
    InvalidName,
    InvalidTemplate,
    PathTooLong,
    OutOfMemory,
}

#[derive(Clone, Copy)]
struct LocaleParts<'a> {
    whole: &'a [u8],
    language: &'a [u8],
    territory: &'a [u8],
    codeset: &'a [u8],
}

impl<'a> LocaleParts<'a> {
    fn new(locale: &'a [u8]) -> Self {
        // GNU catopen substitutes LANG byte-for-byte, including dots and
        // slashes; it is not the locale loader's name-normalization routine.
        // Empty/unset LANG selects C. The ABI ignores untrusted LANG entirely
        // when AT_SECURE is set.
        let whole = if locale.is_empty() { &b"C"[..] } else { locale };
        let language_end = whole
            .iter()
            .position(|&b| b == b'_' || b == b'.')
            .unwrap_or(whole.len());
        let mut rest = &whole[language_end..];
        let mut territory = &b""[..];
        if let Some(after_underscore) = rest.strip_prefix(b"_") {
            let end = after_underscore
                .iter()
                .position(|&b| b == b'.')
                .unwrap_or(after_underscore.len());
            territory = &after_underscore[..end];
            rest = &after_underscore[end..];
        }
        // GNU catopen retains an @modifier in this tail. This differs from
        // stripping modifiers for locale-directory fallback in gettext.
        let codeset = rest.strip_prefix(b".").unwrap_or(b"");
        Self {
            whole,
            language: &whole[..language_end],
            territory,
            codeset,
        }
    }
}

/// Lazily expands one candidate at a time. Memory is bounded by one pathname,
/// not by the total NLSPATH length or the number of its substitutions.
///
/// A slash in `name` selects exactly that pathname, with no substitutions or
/// environment/default fallback. Empty/unset NLSPATH uses only the defaults;
/// an empty component *inside a nonempty NLSPATH* means `%N`.
pub struct CatalogPaths<'a> {
    name: &'a [u8],
    locale: LocaleParts<'a>,
    explicit: Option<&'a [u8]>,
    defaults: Option<&'static [u8]>,
    direct: bool,
}

impl<'a> CatalogPaths<'a> {
    /// `secure` suppresses user-supplied path templates. The ABI supplies the
    /// active LC_MESSAGES name, or C instead of untrusted LANG in secure mode.
    pub fn new(
        name: &'a [u8],
        locale: &'a [u8],
        nlspath: Option<&'a [u8]>,
        secure: bool,
    ) -> Result<Self, CatalogPathError> {
        if name.is_empty() || name.contains(&0) {
            return Err(CatalogPathError::InvalidName);
        }
        let direct = name.contains(&b'/');
        Ok(Self {
            name,
            locale: LocaleParts::new(locale),
            explicit: if direct || secure {
                None
            } else {
                nlspath.filter(|path| !path.is_empty())
            },
            defaults: if direct { None } else { Some(DEFAULT_NLSPATH) },
            direct,
        })
    }

    fn expand(&self, template: &[u8]) -> Result<Vec<u8>, CatalogPathError> {
        let mut out = Vec::new();
        if template.is_empty() {
            append(&mut out, self.name)?;
            return Ok(out);
        }
        let mut rest = template;
        while !rest.is_empty() {
            let literal = rest.iter().position(|&b| b == b'%').unwrap_or(rest.len());
            append(&mut out, &rest[..literal])?;
            rest = &rest[literal..];
            if rest.is_empty() {
                break;
            }
            let token = *rest.get(1).ok_or(CatalogPathError::InvalidTemplate)?;
            let replacement = match token {
                b'N' => self.name,
                b'L' => self.locale.whole,
                b'l' => self.locale.language,
                b't' => self.locale.territory,
                b'c' => self.locale.codeset,
                b'%' => &b"%"[..],
                _ => return Err(CatalogPathError::InvalidTemplate),
            };
            append(&mut out, replacement)?;
            rest = &rest[2..];
        }
        Ok(out)
    }
}

fn append(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CatalogPathError> {
    if bytes.contains(&0) {
        return Err(CatalogPathError::InvalidTemplate);
    }
    let len = out
        .len()
        .checked_add(bytes.len())
        .ok_or(CatalogPathError::PathTooLong)?;
    if len > MAX_CATALOG_PATH_BYTES {
        return Err(CatalogPathError::PathTooLong);
    }
    out.try_reserve(bytes.len())
        .map_err(|_| CatalogPathError::OutOfMemory)?;
    out.extend_from_slice(bytes);
    Ok(())
}

fn component<'a>(cursor: &mut Option<&'a [u8]>) -> Option<&'a [u8]> {
    let rest = cursor.take()?;
    match rest.iter().position(|&b| b == b':') {
        Some(end) => {
            *cursor = Some(&rest[end + 1..]);
            Some(&rest[..end])
        }
        None => Some(rest),
    }
}

impl Iterator for CatalogPaths<'_> {
    type Item = Result<Vec<u8>, CatalogPathError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.direct {
            self.direct = false;
            let mut out = Vec::new();
            return Some(append(&mut out, self.name).map(|()| out));
        }
        let template = component(&mut self.explicit)
            .or_else(|| component(&mut self.defaults))?;
        Some(self.expand(template))
    }
}

impl std::iter::FusedIterator for CatalogPaths<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    fn first(template: &[u8], locale: &[u8]) -> Result<Vec<u8>, CatalogPathError> {
        CatalogPaths::new(b"app", locale, Some(template), false)
            .unwrap()
            .next()
            .unwrap()
    }

    #[test]
    fn expands_all_standard_substitutions() {
        assert_eq!(
            first(b"/%N/%L/%l/%t/%c/%%", b"fr_FR.UTF-8").unwrap(),
            b"/app/fr_FR.UTF-8/fr/FR/UTF-8/%"
        );
    }

    #[test]
    fn gnu_modifier_is_not_stripped_from_codeset_tail() {
        assert_eq!(first(b"%c", b"sr_RS.UTF-8@latin").unwrap(), b"UTF-8@latin");
        assert_eq!(first(b"%l", b"sr@latin").unwrap(), b"sr@latin");
        assert_eq!(first(b"%t", b"sr_RS@latin").unwrap(), b"RS@latin");
    }

    #[test]
    fn absent_components_expand_to_empty_strings() {
        assert_eq!(first(b"%l|%t|%c", b"C").unwrap(), b"C||");
        assert_eq!(first(b"%l|%t|%c", b"en.UTF-8").unwrap(), b"en||UTF-8");
        assert_eq!(first(b"%l|%t|%c", b"en_US").unwrap(), b"en|US|");
    }

    #[test]
    fn expands_components_before_adding_defaults() {
        let actual = CatalogPaths::new(b"app", b"C", Some(b":first/%N::last/%N:"), false)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let expected: Vec<Vec<u8>> = [
            &b"app"[..],
            b"first/app",
            b"app",
            b"last/app",
            b"app",
            b"/usr/share/locale/C/app",
            b"/usr/share/locale/C/LC_MESSAGES/app",
        ]
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn empty_or_unset_nlspath_does_not_search_the_working_directory() {
        for value in [None, Some(&b""[..])] {
            let actual = CatalogPaths::new(b"app", b"C", value, false)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(actual.len(), 2);
            assert_eq!(actual[0], b"/usr/share/locale/C/app");
        }
    }

    #[test]
    fn slash_selects_a_literal_path_and_disables_all_fallbacks() {
        for path in [&b"./%N:app"[..], b"/tmp/app", b"relative/app"] {
            let mut paths = CatalogPaths::new(path, b"C", Some(b"elsewhere/%N"), false).unwrap();
            assert_eq!(paths.next(), Some(Ok(path.to_vec())));
            assert_eq!(paths.next(), None);
            assert_eq!(paths.next(), None);
        }
    }

    #[test]
    fn substituted_percent_and_colon_bytes_are_never_reinterpreted() {
        let mut paths = CatalogPaths::new(b"%L:app", b"fr_FR", Some(b"/tmp/%N"), false).unwrap();
        assert_eq!(paths.next().unwrap().unwrap(), b"/tmp/%L:app");
    }

    #[test]
    fn non_utf8_filesystem_bytes_survive_expansion() {
        let mut paths = CatalogPaths::new(b"app\xff", b"C", Some(b"/tmp/\xfe/%N"), false).unwrap();
        assert_eq!(paths.next().unwrap().unwrap(), b"/tmp/\xfe/app\xff");
    }

    #[test]
    fn secure_search_ignores_user_path_templates() {
        let mut paths = CatalogPaths::new(b"app", b"C", Some(b":/untrusted/%N"), true).unwrap();
        assert_eq!(paths.next().unwrap().unwrap(), b"/usr/share/locale/C/app");
        assert_eq!(paths.count(), 1);
    }

    #[test]
    fn empty_locale_uses_c_but_nonempty_locale_is_substituted_verbatim() {
        assert_eq!(first(b"%L/%N", b"").unwrap(), b"C/app");
        for locale in [&b"."[..], b"..", b"../../tmp", b"x/y"] {
            let mut expected = locale.to_vec();
            expected.extend_from_slice(b"/app");
            assert_eq!(first(b"%L/%N", locale).unwrap(), expected);
        }
        assert_eq!(first(b"%L/%N", b"en\0US"), Err(CatalogPathError::InvalidTemplate));
    }

    #[test]
    fn rejects_empty_and_embedded_nul_catalog_names() {
        for name in [&b""[..], b"app\0other", b"./app\0other"] {
            assert!(matches!(
                CatalogPaths::new(name, b"C", None, false),
                Err(CatalogPathError::InvalidName)
            ));
        }
    }

    #[test]
    fn unsupported_or_incomplete_tokens_do_not_alias_valid_files() {
        for template in [&b"prefix/%q"[..], b"prefix/%", b"prefix\0/%N"] {
            assert_eq!(first(template, b"C"), Err(CatalogPathError::InvalidTemplate));
        }
    }

    #[test]
    fn an_invalid_component_does_not_consume_later_components() {
        let mut paths = CatalogPaths::new(b"app", b"C", Some(b"%q:ok/%N"), false).unwrap();
        assert_eq!(paths.next(), Some(Err(CatalogPathError::InvalidTemplate)));
        assert_eq!(paths.next(), Some(Ok(b"ok/app".to_vec())));
    }

    #[test]
    fn exactly_maximum_length_is_accepted_but_never_truncated() {
        let exact = vec![b'a'; MAX_CATALOG_PATH_BYTES];
        assert_eq!(first(&exact, b"C").unwrap(), exact);
        let too_long = vec![b'a'; MAX_CATALOG_PATH_BYTES + 1];
        assert_eq!(first(&too_long, b"C"), Err(CatalogPathError::PathTooLong));
    }

    #[test]
    fn repeated_expansion_obeys_the_same_length_budget() {
        let name = vec![b'x'; 2048];
        let mut paths = CatalogPaths::new(&name, b"C", Some(b"%N%N:ok"), false).unwrap();
        assert_eq!(paths.next(), Some(Err(CatalogPathError::PathTooLong)));
        assert_eq!(paths.next(), Some(Ok(b"ok".to_vec())));
    }

    #[test]
    fn iterator_remains_exhausted() {
        let mut paths = CatalogPaths::new(b"app", b"C", None, false).unwrap();
        assert!(paths.next().is_some());
        assert!(paths.next().is_some());
        assert!(paths.next().is_none());
        assert!(paths.next().is_none());
    }
}
