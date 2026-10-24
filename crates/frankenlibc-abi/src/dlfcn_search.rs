//! Bounded ELF dependency search, shared by the native group loader.
//!
//! Implements DT_RPATH inheritance, direct-only DT_RUNPATH, $ORIGIN and
//! ${ORIGIN}, initial LD_LIBRARY_PATH, native-ABI ld.so.cache entries and
//! conventional Linux paths. CPU/OS-validated glibc-hwcaps variants precede
//! the baseline WITHIN each search directory, never across directory order.
//! $LIB/$PLATFORM token expansion remains unsupported.

use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use frankenlibc_core::elf::{LoadedObject, ProgramType};

#[path = "dlfcn_cache.rs"]
mod cache;
use cache::hwcaps::Capabilities;

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
    capabilities: Capabilities,
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
        Self { secure, environment, cache, capabilities: Capabilities::detect() }
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
        let mut candidates = Vec::new();
        for directory in directories {
            append_directory(&mut candidates, &directory, &name, context.capabilities);
        }
        // Cache entries are complete pathnames, not additional directories.
        // They rank after RUNPATH and before the default directory fallback.
        if let Some(cache) = &context.cache {
            for path in cache.candidates_with_capabilities(name.as_os_str().as_bytes(), context.capabilities) {
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
                append_directory(&mut candidates, Path::new(directory), &name, context.capabilities);
            }
        }
        Some(candidates)
    }
}

/// Preserve directory precedence, including each directory's baseline, before
/// advancing to the next RPATH/environment/RUNPATH/default entry. A CPU's best
/// variant in a later directory must not displace an earlier baseline DSO.
fn append_directory(output: &mut Vec<PathBuf>, directory: &Path, name: &Path, capabilities: Capabilities) {
    for capability in capabilities.names() {
        let path = directory.join("glibc-hwcaps").join(capability).join(name);
        if !output.contains(&path) { output.push(path); }
    }
    let path = directory.join(name);
    if !output.contains(&path) { output.push(path); }
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
        let context = SearchContext { secure: false, environment: vec!["/environment".into()], cache: None, capabilities: Capabilities::default() };
        let inherited = vec![PathBuf::from("/ancestor")];
        assert_eq!(paths.candidates(b"libx.so", Path::new("/origin"), &inherited, &context).unwrap(), vec![PathBuf::from("/environment/libx.so"), PathBuf::from("/runpath/libx.so")]);
        assert_eq!(paths.child_rpaths(&inherited), inherited);
    }

    #[test]
    fn rpath_search_precedes_environment_and_inherits() {
        let paths = SearchPaths { rpath: vec!["/rpath".into()], runpath: None, no_default: true };
        let context = SearchContext { secure: false, environment: vec!["/environment".into()], cache: None, capabilities: Capabilities::default() };
        let inherited = vec![PathBuf::from("/ancestor")];
        assert_eq!(paths.candidates(b"libx.so", Path::new("/origin"), &inherited, &context).unwrap(), vec![PathBuf::from("/rpath/libx.so"), PathBuf::from("/ancestor/libx.so"), PathBuf::from("/environment/libx.so")]);
        assert_eq!(paths.candidates(b"sub/libx.so", Path::new("/origin"), &inherited, &context).unwrap(), vec![PathBuf::from("sub/libx.so")]);
    }

    fn cache_fixture(paths: &[&[u8]], capability: Option<&[u8]>) -> Vec<u8> {
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
        let capability_offset = bytes.len() as u32;
        if let Some(capability) = capability {
            bytes.extend_from_slice(capability);
            bytes.push(0);
            for index in 0..paths.len() {
                let field = 48 + 24 * index + 16;
                bytes[field..field + 8].copy_from_slice(&(1u64 << 62).to_ne_bytes());
            }
        }
        let length = (bytes.len() - start) as u32;
        bytes[24..28].copy_from_slice(&length.to_ne_bytes());
        if capability.is_some() {
            let extension = (bytes.len() + 3) & !3;
            let data = extension + 24;
            bytes.resize(data + 4, 0);
            for (offset, value) in [
                (32, extension as u32), (extension, 0xeaa4_2174),
                (extension + 4, 1), (extension + 8, 1),
                (extension + 16, data as u32), (extension + 20, 4),
                (data, capability_offset),
            ] {
                bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
            }
        }
        bytes
    }

    fn context_with_cache(paths: &[&[u8]], secure: bool) -> SearchContext {
        SearchContext {
            secure,
            environment: vec!["/environment".into()],
            cache: Some(cache::Cache::from_bytes(cache_fixture(paths, None)).unwrap()),
            capabilities: Capabilities::default(),
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

    fn capable_context(level: u8) -> SearchContext {
        SearchContext {
            secure: false,
            environment: Vec::new(),
            cache: None,
            capabilities: Capabilities::for_x86_level(level),
        }
    }

    #[test]
    fn hwcaps_are_ordered_within_each_directory_not_across_directories() {
        let paths = SearchPaths {
            runpath: Some(vec!["/first".into(), "/second".into()]),
            no_default: true,
            ..SearchPaths::default()
        };
        assert_eq!(paths.candidates(b"libx.so", Path::new("/origin"), &[], &capable_context(3)).unwrap(), vec![
            PathBuf::from("/first/glibc-hwcaps/x86-64-v3/libx.so"),
            PathBuf::from("/first/glibc-hwcaps/x86-64-v2/libx.so"),
            PathBuf::from("/first/libx.so"),
            PathBuf::from("/second/glibc-hwcaps/x86-64-v3/libx.so"),
            PathBuf::from("/second/glibc-hwcaps/x86-64-v2/libx.so"),
            PathBuf::from("/second/libx.so"),
        ]);
    }

    #[test]
    fn hwcaps_preserve_rpath_inheritance_and_runpath_environment_order() {
        let inherited = [PathBuf::from("/ancestor")];
        let mut context = capable_context(2);
        context.environment.push("/environment".into());
        let mut paths = SearchPaths {
            rpath: vec!["/rpath".into()],
            no_default: true,
            ..SearchPaths::default()
        };
        let candidates = paths.candidates(b"libx.so", Path::new("/origin"), &inherited, &context).unwrap();
        assert_eq!(candidates.len(), 6);
        assert_eq!(candidates[0], Path::new("/rpath/glibc-hwcaps/x86-64-v2/libx.so"));
        assert_eq!(candidates[1], Path::new("/rpath/libx.so"));
        assert_eq!(candidates[2], Path::new("/ancestor/glibc-hwcaps/x86-64-v2/libx.so"));
        assert_eq!(candidates[4], Path::new("/environment/glibc-hwcaps/x86-64-v2/libx.so"));
        paths.runpath = Some(vec!["/runpath".into()]);
        let candidates = paths.candidates(b"libx.so", Path::new("/origin"), &inherited, &context).unwrap();
        assert_eq!(candidates.len(), 4);
        assert_eq!(candidates[0], Path::new("/environment/glibc-hwcaps/x86-64-v2/libx.so"));
        assert_eq!(candidates[2], Path::new("/runpath/glibc-hwcaps/x86-64-v2/libx.so"));
        assert_eq!(paths.child_rpaths(&inherited), inherited);
    }

    #[test]
    fn capable_exact_paths_still_bypass_all_search_and_expansion() {
        let paths = SearchPaths { runpath: Some(vec!["/runpath".into()]), ..SearchPaths::default() };
        for name in [b"/absolute/libx.so".as_slice(), b"relative/libx.so"] {
            assert_eq!(paths.candidates(name, Path::new("/origin"), &[], &capable_context(4)).unwrap(), vec![PathBuf::from(OsStr::from_bytes(name))]);
        }
        assert_eq!(paths.candidates(b"$ORIGIN/libx.so", Path::new("/origin"), &[], &capable_context(4)).unwrap(), vec![PathBuf::from("/origin/libx.so")]);
    }

    #[test]
    fn capable_search_preserves_non_utf8_bytes_and_deduplicates_candidates() {
        let directory = PathBuf::from(OsStr::from_bytes(b"/vendor/\xff"));
        let paths = SearchPaths {
            runpath: Some(vec![directory.clone(), directory]),
            no_default: true,
            ..SearchPaths::default()
        };
        let candidates = paths.candidates(b"lib\xfe.so", Path::new("/origin"), &[], &capable_context(2)).unwrap();
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].as_os_str().as_bytes(), b"/vendor/\xff/glibc-hwcaps/x86-64-v2/lib\xfe.so");
        assert_eq!(candidates[1].as_os_str().as_bytes(), b"/vendor/\xff/lib\xfe.so");
    }

    #[test]
    fn capable_secure_search_never_reintroduces_environment_or_origin() {
        let mut context = capable_context(4);
        context.secure = true;
        context.environment.push("/untrusted".into());
        let paths = SearchPaths { no_default: true, ..SearchPaths::default() };
        assert!(paths.candidates(b"libx.so", Path::new("/origin"), &[], &context).unwrap().is_empty());
        assert!(paths.candidates(b"$ORIGIN/libx.so", Path::new("/origin"), &[], &context).is_none());
    }

    #[test]
    fn capable_defaults_follow_cache_and_nodeflib_filters_optimized_system_paths() {
        let bytes = cache_fixture(&[
            b"/lib/glibc-hwcaps/x86-64-v2/libx.so",
            b"/vendor/libx.so",
        ], Some(b"x86-64-v2"));
        let context = SearchContext {
            secure: true,
            environment: Vec::new(),
            cache: Some(cache::Cache::from_bytes(bytes).unwrap()),
            capabilities: Capabilities::for_x86_level(2),
        };
        let mut paths = SearchPaths::default();
        let candidates = paths.candidates(b"libx.so", Path::new("/origin"), &[], &context).unwrap();
        assert_eq!(candidates[0], Path::new("/lib/glibc-hwcaps/x86-64-v2/libx.so"));
        assert_eq!(candidates[1], Path::new("/vendor/libx.so"));
        assert_eq!(candidates[2], Path::new(DEFAULT_DIRECTORIES[0]).join("glibc-hwcaps/x86-64-v2/libx.so"));
        assert_eq!(candidates[3], Path::new(DEFAULT_DIRECTORIES[0]).join("libx.so"));
        paths.no_default = true;
        assert_eq!(paths.candidates(b"libx.so", Path::new("/origin"), &[], &context).unwrap(), vec![PathBuf::from("/vendor/libx.so")]);
    }
}
