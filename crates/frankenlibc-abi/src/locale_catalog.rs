//! Native filesystem half of XSI catalog lookup.
//!
//! The parent ABI snapshots locale/environment inputs. No registry lock is
//! held across filesystem I/O, and path expansion stays in the safe core.

use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use frankenlibc_core::locale::catgets::path::{CatalogPathError, CatalogPaths};
use frankenlibc_core::locale::catgets::{MessageCatalog, parse_catalog_bytes};

fn path_errno(error: CatalogPathError) -> libc::c_int {
    match error {
        CatalogPathError::InvalidName | CatalogPathError::InvalidTemplate => libc::EINVAL,
        CatalogPathError::PathTooLong => libc::ENAMETOOLONG,
        CatalogPathError::OutOfMemory => libc::ENOMEM,
    }
}

/// Open the first accessible candidate, not the first *valid* catalog.
/// GNU catopen continues after open failures, but an opened malformed file or
/// directory is a terminal EINVAL, even when a later candidate is valid.
pub(super) fn open(
    name: &[u8],
    locale: &[u8],
    nlspath: Option<&[u8]>,
    secure: bool,
) -> Result<MessageCatalog, libc::c_int> {
    let candidates = CatalogPaths::new(name, locale, nlspath, secure).map_err(path_errno)?;
    let mut last_error = libc::ENOENT;
    for candidate in candidates {
        let path = match candidate {
            Ok(path) => path,
            Err(CatalogPathError::OutOfMemory) => return Err(libc::ENOMEM),
            Err(error) => {
                last_error = path_errno(error);
                continue;
            }
        };
        let mut file = match File::open(Path::new(OsStr::from_bytes(&path))) {
            Ok(file) => file,
            Err(error) => {
                last_error = error.raw_os_error().unwrap_or(libc::EIO);
                continue;
            }
        };
        // Inspect the opened descriptor rather than checking the pathname and
        // opening it again: a rename must not change which file we validate.
        let metadata = file
            .metadata()
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        if !metadata.is_file() {
            return Err(libc::EINVAL);
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        return parse_catalog_bytes(bytes).map_err(|_| libc::EINVAL);
    }
    Err(last_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            loop {
                let path = std::env::temp_dir().join(format!(
                    "frankenlibc-catalog-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => panic!("create catalog fixture: {e}"),
                }
            }
        }

        fn path(&self, name: &[u8]) -> Vec<u8> {
            self.0
                .join(OsStr::from_bytes(name))
                .as_os_str()
                .as_bytes()
                .to_vec()
        }

        fn catalog(&self, name: &[u8], message: &[u8]) -> Vec<u8> {
            let path = self.path(name);
            let path_ref = Path::new(OsStr::from_bytes(&path));
            std::fs::create_dir_all(path_ref.parent().unwrap()).unwrap();
            // GNU gencat layout: one slot in each endian table, then strings.
            // The (set=1, message=1) entry has stored_set=2.
            let mut bytes = Vec::new();
            for word in [0x9604_08de_u32, 1, 1, 2, 1, 0] {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            for word in [2_u32, 1, 0] {
                bytes.extend_from_slice(&word.to_be_bytes());
            }
            bytes.extend_from_slice(message);
            bytes.push(0);
            std::fs::write(path_ref, bytes).unwrap();
            path
        }

        fn search(&self, parts: &[&[u8]]) -> Vec<u8> {
            let mut paths = Vec::new();
            for (index, part) in parts.iter().enumerate() {
                if index != 0 {
                    paths.push(b':');
                }
                paths.extend_from_slice(&self.path(part));
            }
            paths
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn loads_substituted_locale_after_missing_candidate() {
        let f = Fixture::new();
        f.catalog(b"fr_FR.UTF-8/app", b"bonjour");
        let paths = f.search(&[b"missing/%N", b"%L/%N"]);
        let cat = open(b"app", b"fr_FR.UTF-8", Some(&paths), false).unwrap();
        assert_eq!(cat.message_bytes(1, 1), Some(b"bonjour".as_slice()));
    }

    #[test]
    fn first_opened_catalog_wins() {
        let f = Fixture::new();
        f.catalog(b"first/app", b"first");
        f.catalog(b"second/app", b"second");
        let paths = f.search(&[b"first/%N", b"second/%N"]);
        let cat = open(b"app", b"C", Some(&paths), false).unwrap();
        assert_eq!(cat.message_bytes(1, 1), Some(b"first".as_slice()));
    }

    #[test]
    fn malformed_opened_catalog_does_not_fall_through() {
        let f = Fixture::new();
        std::fs::write(OsStr::from_bytes(&f.path(b"bad")), b"invalid").unwrap();
        f.catalog(b"good", b"good");
        let paths = f.search(&[b"bad", b"good"]);
        assert_eq!(open(b"app", b"C", Some(&paths), false), Err(libc::EINVAL));
    }

    #[test]
    fn opened_directory_does_not_fall_through() {
        let f = Fixture::new();
        std::fs::create_dir(f.0.join("directory")).unwrap();
        f.catalog(b"good", b"good");
        let paths = f.search(&[b"directory", b"good"]);
        assert_eq!(open(b"app", b"C", Some(&paths), false), Err(libc::EINVAL));
    }

    #[test]
    fn literal_path_bypasses_substitutions_and_search() {
        let f = Fixture::new();
        let literal = f.catalog(b"%N:literal", b"literal");
        f.catalog(b"other", b"wrong");
        let paths = f.search(&[b"other"]);
        let cat = open(&literal, b"C", Some(&paths), false).unwrap();
        assert_eq!(cat.message_bytes(1, 1), Some(b"literal".as_slice()));
        assert_eq!(
            open(&f.path(b"missing"), b"C", Some(&paths), false),
            Err(libc::ENOENT)
        );
    }

    #[test]
    fn filesystem_bytes_are_not_lossily_decoded() {
        let f = Fixture::new();
        f.catalog(b"\xff/app\xfe", b"bytes");
        let paths = f.search(&[b"\xff/%N"]);
        let cat = open(b"app\xfe", b"C", Some(&paths), false).unwrap();
        assert_eq!(cat.message_bytes(1, 1), Some(b"bytes".as_slice()));
    }

    #[test]
    fn secure_search_ignores_environment_but_allows_explicit_paths() {
        let f = Fixture::new();
        let literal = f.catalog(b"secure-catalog-test", b"explicit");
        let paths = f.search(&[b"secure-catalog-test"]);
        let name = format!("frankenlibc-not-installed-{}", std::process::id());
        assert_eq!(
            open(name.as_bytes(), b"C", Some(&paths), true),
            Err(libc::ENOENT)
        );
        let cat = open(&literal, b"C", Some(&paths), true).unwrap();
        assert_eq!(cat.message_bytes(1, 1), Some(b"explicit".as_slice()));
    }

    #[test]
    fn overlong_literal_path_is_not_truncated() {
        let mut path = vec![b'x'; 4096];
        path[0] = b'/';
        assert_eq!(open(&path, b"C", None, false), Err(libc::ENAMETOOLONG));
    }
}
