//! Bounded ELF dependency search, shared by the native group loader.
//!
//! Implements DT_RPATH inheritance, direct-only DT_RUNPATH, $ORIGIN and
//! ${ORIGIN}, initial LD_LIBRARY_PATH, native-ABI ld.so.cache entries and
//! conventional Linux paths. Hardware-capability directories and $LIB/$PLATFORM
//! remain unsupported; the cache decoder only selects baseline entries.

use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use frankenlibc_core::elf::{LoadedObject, ProgramType};

#[path = "dlfcn_cache.rs"]
mod cache;

// Use one architecture-specific definition for fallback lookup and NODEFLIB
// filtering of cache entries. In particular, AArch64 must not inherit x86 paths.
const DEFAULT_DIRECTORIES: &[&str] = if cfg!(target_arch = "aarch64") {
    &[
        "/lib/aarch64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
        "/lib64",
        "/usr/lib64",
        "/lib",
        "/usr/lib",
    ]
} else {
    &[
        "/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu",
        "/lib64",
        "/usr/lib64",
        "/lib",
        "/usr/lib",
    ]
};

#[derive(Default)]
pub(super) struct SearchPaths {
    rpath: Vec<PathBuf>,
    runpath: Option<Vec<PathBuf>>,
    no_default: bool,
}

pub(super) struct SearchContext {
    pub(super) secure: bool,
    environment: Vec<PathBuf>,
    cache: Option<cache::Cache>,
}

fn bounded_file(path: &str, limit: usize) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path).ok()?.take((limit + 1) as u64).read_to_end(&mut bytes).ok()?;
    (bytes.len() <= limit).then_some(bytes)
}

impl SearchContext {
    pub(super) fn process() -> Self {
        // Unknown security state is secure, never permission to use LD_*.
        let secure = bounded_file("/proc/self/auxv", 65536)
            .and_then(|bytes| {
                for entry in bytes.chunks_exact(16) {
                    let tag = u64::from_ne_bytes(entry[..8].try_into().ok()?);
                    let value = u64::from_ne_bytes(entry[8..].try_into().ok()?);
                    if tag == 23 { return Some(value != 0); } // AT_SECURE
                    if tag == 0 { break; } // AT_NULL
                }
                None
            }).unwrap_or(true);
        let mut environment = Vec::new();
        if !secure {
            // /proc exposes the initial environment, not later setenv edits.
            // Do not consult mutable process environment during concurrent loads.
            if let Some(bytes) = bounded_file("/proc/self/environ", 1 << 20) {
                if let Some(value) = bytes.split(|byte| *byte == 0)
                    .find_map(|entry| entry.strip_prefix(b"LD_LIBRARY_PATH="))
                {
                    let executable = std::fs::read_link("/proc/self/exe").ok();
                    let origin = executable.as_deref().and_then(Path::parent);
                    environment = split_paths(value, origin, true);
                }
            }
        }
        // A load group sees one immutable snapshot, including in secure mode:
        // the administrator-maintained cache is independent of LD_* variables.
        // Missing, oversized, or malformed files leave ordinary search intact.
        let cache = bounded_file("/etc/ld.so.cache", cache::MAX_CACHE_BYTES)
            .and_then(cache::Cache::from_bytes);
        Self { secure, environment, cache }
    }
}

fn dynamic_string(strings: &[u8], offset: u64) -> Option<&[u8]> {
    let offset = usize::try_from(offset).ok()?;
    let tail = strings.get(offset..)?;
    let length = tail.iter().position(|byte| *byte == 0)?;
    Some(&tail[..length])
}

impl SearchPaths {
    pub(super) fn parse(bytes: &[u8], object: &LoadedObject, origin: &Path, secure: bool) -> Option<Self> {
        let mut paths = Self::default();
        let origin = (!secure).then_some(origin);
        for header in &object.program_headers {
            if header.p_type != ProgramType::Dynamic { continue; }
            let start = usize::try_from(header.p_offset).ok()?;
            let length = usize::try_from(header.p_filesz).ok()?;
            let entries = bytes.get(start..start.checked_add(length)?)?;
            if entries.len() % 16 != 0 { return None; }
            let mut terminated = false;
            for entry in entries.chunks_exact(16) {
                let tag = i64::from_le_bytes(entry[..8].try_into().ok()?);
                let value = u64::from_le_bytes(entry[8..].try_into().ok()?);
                match tag {
                    0 => { terminated = true; break; }
                    15 => paths.rpath = split_paths(dynamic_string(&object.dynstr, value)?, origin, false),
                    29 => paths.runpath = Some(split_paths(dynamic_string(&object.dynstr, value)?, origin, false)),
                    0x6fff_fffb => paths.no_default = value & 0x800 != 0, // DF_1_NODEFLIB
                    _ => {}
                }
            }
            if !terminated { return None; }
        }
        Some(paths)
    }

    pub(super) fn child_rpaths(&self, inherited: &[PathBuf]) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if self.runpath.is_none() { append_unique(&mut paths, &self.rpath); }
        append_unique(&mut paths, inherited);
        paths
    }

    pub(super) fn candidates(&self, name: &[u8], origin: &Path, inherited: &[PathBuf], context: &SearchContext) -> Option<Vec<PathBuf>> {
        let name = expand_origin(name, (!context.secure).then_some(origin))?;
        if name.as_os_str().as_bytes().contains(&b'/') {
            // Path-bearing dependencies are exact paths, relative to cwd when
            // relative, and do not use RUNPATH as an implicit parent directory.
            return Some(vec![name]);
        }
        if name.as_os_str().is_empty() { return None; }
        let mut directories = Vec::new();
        if self.runpath.is_none() {
            directories = self.child_rpaths(inherited);
        }
        if !context.secure {
            append_unique(&mut directories, &context.environment);
        }
        if let Some(runpath) = &self.runpath { append_unique(&mut directories, runpath); }
        let mut candidates: Vec<PathBuf> = directories
            .into_iter()
            .map(|directory| directory.join(&name))
            .collect();
        // Cache entries are complete pathnames, not additional directories.
        // They rank after RUNPATH and before the default directory fallback.
        if let Some(cache) = &context.cache {
            for path in cache.candidates(name.as_os_str().as_bytes()) {
                if self.no_default
                    && DEFAULT_DIRECTORIES.iter().any(|directory| path.starts_with(directory))
                {
                    continue;
                }
                if !candidates.contains(&path) {
                    candidates.push(path);
                }
            }
        }
        if !self.no_default {
            for directory in DEFAULT_DIRECTORIES {
                let path = Path::new(directory).join(&name);
                if !candidates.contains(&path) {
                    candidates.push(path);
                }
            }
        }
        Some(candidates)
    }
}

fn append_unique(output: &mut Vec<PathBuf>, paths: &[PathBuf]) {
    for path in paths {
        if !output.contains(path) { output.push(path.clone()); }
    }
}

fn split_paths(value: &[u8], origin: Option<&Path>, environment: bool) -> Vec<PathBuf> {
    value.split(|byte| *byte == b':' || (environment && *byte == b';'))
        .filter_map(|component| {
            if component.is_empty() { Some(PathBuf::from(".")) }
            else { expand_origin(component, origin) }
        }).collect()
}

fn expand_origin(value: &[u8], origin: Option<&Path>) -> Option<PathBuf> {
    let mut result = Vec::new();
    let mut cursor = 0;
    while cursor < value.len() {
        if value[cursor] != b'$' {
            result.push(value[cursor]);
            cursor += 1;
            continue;
        }
        let remaining = &value[cursor..];
        let length = if remaining.starts_with(b"${ORIGIN}") { 9 }
            else if remaining.starts_with(b"$ORIGIN")
                && !remaining.get(7).is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_') { 7 }
            else { return None; };
        result.extend_from_slice(origin?.as_os_str().as_bytes());
        cursor += length;
    }
    Some(PathBuf::from(OsStr::from_bytes(&result)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_expansion_preserves_non_utf8_and_rejects_unknown_tokens() {
        let origin = Path::new(OsStr::from_bytes(b"/tmp/lib-\xff"));
        assert_eq!(expand_origin(b"${ORIGIN}/child", Some(origin)).unwrap().as_os_str().as_bytes(), b"/tmp/lib-\xff/child");
        assert_eq!(expand_origin(b"$ORIGIN/child", Some(origin)).unwrap().as_os_str().as_bytes(), b"/tmp/lib-\xff/child");
        assert!(expand_origin(b"$ORIGIN_EXTRA/child", Some(origin)).is_none());
        assert!(expand_origin(b"$PLATFORM/child", Some(origin)).is_none());
        assert!(expand_origin(b"$ORIGIN/child", None).is_none());
    }

    #[test]
    fn runpath_does_not_inherit_and_overrides_own_rpath() {
        let paths = SearchPaths { rpath: vec!["/rpath".into()], runpath: Some(vec!["/runpath".into()]), no_default: true };
        let context = SearchContext { secure: false, environment: vec!["/environment".into()], cache: None };
        let inherited = vec![PathBuf::from("/ancestor")];
        assert_eq!(paths.candidates(b"libx.so", Path::new("/origin"), &inherited, &context).unwrap(), vec![PathBuf::from("/environment/libx.so"), PathBuf::from("/runpath/libx.so")]);
        assert_eq!(paths.child_rpaths(&inherited), inherited);
    }

    #[test]
    fn rpath_search_precedes_environment_and_inherits() {
        let paths = SearchPaths { rpath: vec!["/rpath".into()], runpath: None, no_default: true };
        let context = SearchContext { secure: false, environment: vec!["/environment".into()], cache: None };
        let inherited = vec![PathBuf::from("/ancestor")];
        assert_eq!(paths.candidates(b"libx.so", Path::new("/origin"), &inherited, &context).unwrap(), vec![PathBuf::from("/rpath/libx.so"), PathBuf::from("/ancestor/libx.so"), PathBuf::from("/environment/libx.so")]);
        assert_eq!(paths.candidates(b"sub/libx.so", Path::new("/origin"), &inherited, &context).unwrap(), vec![PathBuf::from("sub/libx.so")]);
    }

    fn context_with_cache(paths: &[&[u8]], secure: bool) -> SearchContext {
        let start = 48 + 24 * paths.len();
        let mut bytes = vec![0u8; start];
        bytes[..20].copy_from_slice(b"glibc-ld.so.cache1.1");
        bytes[20..24].copy_from_slice(&(paths.len() as u32).to_ne_bytes());
        for (i, path) in paths.iter().enumerate() {
            let entry = 48 + 24 * i;
            let key = bytes.len() as u32;
            bytes.extend_from_slice(b"libx.so\0");
            let value = bytes.len() as u32;
            bytes.extend_from_slice(path);
            bytes.push(0);
            bytes[entry..entry + 4].copy_from_slice(&cache::native_flags().to_ne_bytes());
            bytes[entry + 4..entry + 8].copy_from_slice(&key.to_ne_bytes());
            bytes[entry + 8..entry + 12].copy_from_slice(&value.to_ne_bytes());
        }
        let length = (bytes.len() - start) as u32;
        bytes[24..28].copy_from_slice(&length.to_ne_bytes());
        SearchContext {
            secure,
            environment: vec!["/environment".into()],
            cache: Some(cache::Cache::from_bytes(bytes).unwrap()),
        }
    }

    #[test]
    fn cache_is_after_runpath_before_defaults_and_is_not_a_directory() {
        let paths = SearchPaths {
            runpath: Some(vec!["/runpath".into()]),
            ..SearchPaths::default()
        };
        let context = context_with_cache(&[b"/vendor/libx.so"], false);
        let candidates = paths.candidates(b"libx.so", Path::new("/origin"), &[], &context).unwrap();
        assert_eq!(&candidates[..3], &[
            PathBuf::from("/environment/libx.so"),
            PathBuf::from("/runpath/libx.so"),
            PathBuf::from("/vendor/libx.so"),
        ]);
        assert_eq!(candidates[3], Path::new(DEFAULT_DIRECTORIES[0]).join("libx.so"));
        assert!(!candidates.contains(&PathBuf::from("/vendor/libx.so/libx.so")));
    }

    #[test]
    fn nodeflib_skips_default_cache_entries_but_keeps_vendor_entries() {
        let paths = SearchPaths { no_default: true, ..SearchPaths::default() };
        let context = context_with_cache(&[
            b"/lib/libx.so",
            b"/lib64/libx.so",
            b"/usr/lib/nested/libx.so",
            b"/vendor/libx.so",
            b"/liberal/libx.so",
        ], false);
        assert_eq!(paths.candidates(b"libx.so", Path::new("/origin"), &[], &context).unwrap(), vec![
            PathBuf::from("/environment/libx.so"),
            PathBuf::from("/vendor/libx.so"),
            PathBuf::from("/liberal/libx.so"),
        ]);
    }

    #[test]
    fn cache_preserves_rpath_inheritance_and_exact_path_bypass() {
        let paths = SearchPaths {
            rpath: vec!["/rpath".into()],
            no_default: true,
            ..SearchPaths::default()
        };
        let context = context_with_cache(&[b"/vendor/libx.so"], false);
        let inherited = [PathBuf::from("/ancestor")];
        assert_eq!(paths.candidates(b"libx.so", Path::new("/origin"), &inherited, &context).unwrap(), vec![
            PathBuf::from("/rpath/libx.so"),
            PathBuf::from("/ancestor/libx.so"),
            PathBuf::from("/environment/libx.so"),
            PathBuf::from("/vendor/libx.so"),
        ]);
        assert_eq!(paths.candidates(b"sub/libx.so", Path::new("/origin"), &inherited, &context).unwrap(), vec![PathBuf::from("sub/libx.so")]);
    }

    #[test]
    fn secure_mode_uses_system_cache_but_never_environment_or_origin() {
        let paths = SearchPaths { no_default: true, ..SearchPaths::default() };
        let context = context_with_cache(&[b"/vendor/libx.so"], true);
        assert_eq!(paths.candidates(b"libx.so", Path::new("/origin"), &[], &context).unwrap(), vec![PathBuf::from("/vendor/libx.so")]);
        assert!(paths.candidates(b"$ORIGIN/libx.so", Path::new("/origin"), &[], &context).is_none());
    }

    #[test]
    fn duplicate_cache_paths_do_not_change_precedence_or_fallbacks() {
        let paths = SearchPaths::default();
        let context = context_with_cache(&[b"/environment/libx.so", b"/vendor/libx.so"], false);
        let candidates = paths.candidates(b"libx.so", Path::new("/origin"), &[], &context).unwrap();
        assert_eq!(candidates.iter().filter(|path| **path == Path::new("/environment/libx.so")).count(), 1);
        let mut missing = context;
        missing.cache = None;
        let without_cache = paths.candidates(b"libx.so", Path::new("/origin"), &[], &missing).unwrap();
        assert_eq!(candidates.into_iter().filter(|path| path != Path::new("/vendor/libx.so")).collect::<Vec<_>>(), without_cache);
    }
}
