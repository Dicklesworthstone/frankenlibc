#![cfg(all(target_os = "linux", target_arch = "x86_64", not(feature = "standalone")))]

use frankenlibc_abi::dlfcn_abi::{
    dlclose, dlerror, dlopen, dlsym, dlvsym, native_dso_handle_for_tests,
};
use frankenlibc_core::elf::{ElfLoader, LoadedObject, ProgramType};
use std::ffi::{CStr, CString, c_void};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, OnceLock};

// Both native tests publish the same SONAME globally. Do not let libtest run
// their separate load scenarios in the same native scope at the same time.
static NATIVE_TEST_LOCK: Mutex<()> = Mutex::new(());

// The ABI library excludes its exported modules in cfg(test) builds. Include
// the actual safe parser here so its malformed-input gates really execute.
#[path = "../src/dlfcn_versions.rs"]
mod versions;
use versions::{Lookup, Table};

fn success(output: &Output) {
    assert!(output.status.success(), "status={}\nstdout={}\nstderr={}",
        output.status, String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr));
}

fn fixtures() -> &'static Path {
    static DIRECTORY: OnceLock<PathBuf> = OnceLock::new();
    DIRECTORY.get_or_init(|| {
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .expect("fixture clock").as_nanos();
        let output = std::env::temp_dir().join(format!("frankenlibc-versions-{}-{nonce}", std::process::id()));
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/elf_versions/build.sh");
        success(&Command::new("timeout").args(["90", "bash"]).arg(script).arg(&output)
            .env_remove("LD_PRELOAD").env_remove("LD_LIBRARY_PATH")
            .output().expect("compile version fixtures under watchdog"));
        // Retain compiler-produced DSOs on failure for direct replay.
        output
    })
}

fn cases() -> Vec<PathBuf> {
    ["gnu", "sysv", "both"].into_iter().flat_map(|hash| {
        ["full", "sectionless"].into_iter().map(move |form| fixtures().join(hash).join(form))
    }).collect()
}

fn oracle(probe: &str, directory: &Path, case: Option<&str>, expected: &str) {
    let mut command = Command::new("timeout");
    command.arg("15").arg(fixtures().join(probe)).arg(directory)
        .env_remove("LD_PRELOAD").env_remove("LD_LIBRARY_PATH");
    if let Some(case) = case { command.arg(case); }
    let output = command.output().expect("independent host-loader probe");
    success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), expected);
}

fn error() -> Option<String> {
    // SAFETY: dlerror owns the thread-local NUL-terminated result until its
    // next invocation. Copy it before any subsequent loader operation.
    unsafe {
        let message = dlerror();
        (!message.is_null()).then(|| CStr::from_ptr(message).to_string_lossy().into_owned())
    }
}

struct Open(*mut c_void);
impl Open {
    fn new(path: &Path, flags: i32) -> Self {
        let name = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        let _ = error();
        // SAFETY: trusted, compiler-built fixture and valid C pathname.
        let handle = unsafe { dlopen(name.as_ptr(), libc::RTLD_NOW | flags) };
        assert!(!handle.is_null(), "{}: {:?}", path.display(), error());
        let result = Self(handle);
        assert!(native_dso_handle_for_tests(handle), "host fallback is not native version support");
        result
    }

    fn close(mut self) {
        // SAFETY: all fixture calls and workers have completed.
        assert_eq!(unsafe { dlclose(self.0) }, 0, "{:?}", error());
        self.0 = std::ptr::null_mut();
    }
}
impl Drop for Open {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this guard owns one open reference, also on test failure.
            let _ = unsafe { dlclose(self.0) };
        }
    }
}

fn symbol(handle: *mut c_void, name: &CStr, version: Option<&CStr>) -> *mut c_void {
    let _ = error();
    // SAFETY: test callers retain the owning native handle; names are valid.
    let address = unsafe {
        match version {
            Some(version) => dlvsym(handle, name.as_ptr(), version.as_ptr()),
            None => dlsym(handle, name.as_ptr()),
        }
    };
    let error = error();
    assert!(error.is_none() && !address.is_null(), "{name:?}/{version:?}: {error:?}");
    address
}

fn absent(handle: *mut c_void, name: &CStr, version: Option<&CStr>) {
    let _ = error();
    // SAFETY: same retained handles and valid names as successful lookups.
    let address = unsafe {
        match version {
            Some(version) => dlvsym(handle, name.as_ptr(), version.as_ptr()),
            None => dlsym(handle, name.as_ptr()),
        }
    };
    assert!(address.is_null(), "{name:?}/{version:?} must not bind");
    assert!(error().is_some(), "failed lookup must set dlerror");
    assert!(error().is_none(), "dlerror is consumed exactly once");
}

fn call(handle: *mut c_void, name: &CStr, version: Option<&CStr>) -> i32 {
    let address = symbol(handle, name, version);
    // SAFETY: every tested function (including an IFUNC's resolved target) is
    // int(void) in the checked-in C fixture, and its DSO is retained.
    unsafe { std::mem::transmute::<*mut c_void, extern "C" fn() -> i32>(address)() }
}

fn value(handle: *mut c_void, name: &CStr, version: Option<&CStr>) -> i32 {
    // SAFETY: these fixture symbols are aligned int data or this thread's TLS.
    unsafe { *symbol(handle, name, version).cast::<i32>() }
}

#[test]
fn native_default_versions_exact_versions_and_legacy_relocations_match_host() {
    let _serial = NATIVE_TEST_LOCK.lock().expect("native test lock");
    for directory in cases() {
        oracle("host_probe", &directory, None, "versioned lookup, relocations, IFUNC and TLS: PASS\n");
        let provider = Open::new(&directory.join("libversions.so"), libc::RTLD_GLOBAL);
        for (name, public, previous) in [(c"api", 22, 11), (c"dispatch", 66, 55)] {
            assert_eq!(call(provider.0, name, None), public);
            assert_eq!(call(provider.0, name, Some(c"VERS_1")), previous);
            assert_eq!(call(provider.0, name, Some(c"VERS_2")), public);
            absent(provider.0, name, Some(c"NOT_PRESENT"));
        }
        assert_eq!(call(provider.0, c"retired", Some(c"VERS_1")), 33);
        assert_eq!(call(provider.0, c"recent", Some(c"VERS_2")), 44);
        absent(provider.0, c"retired", None);
        absent(provider.0, c"recent", None);
        absent(provider.0, c"unversioned", Some(c"NOT_PRESENT"));
        assert_eq!(call(provider.0, c"unversioned", None), 77);
        assert_eq!(value(provider.0, c"data", None), 202);
        assert_eq!(value(provider.0, c"data", Some(c"VERS_1")), 101);
        let id = provider.0 as usize;
        std::thread::spawn(move || {
            let handle = id as *mut c_void;
            assert_eq!(value(handle, c"tls_value", None), 404);
            assert_eq!(value(handle, c"tls_value", Some(c"VERS_1")), 303);
            let current = symbol(handle, c"tls_value", None).cast::<i32>();
            let previous = symbol(handle, c"tls_value", Some(c"VERS_1")).cast::<i32>();
            assert_ne!(current, previous);
            // SAFETY: this worker exclusively owns these two TLS instances.
            unsafe { *current = 901; *previous = 902; }
        }).join().expect("native versioned TLS worker");
        assert_eq!(value(provider.0, c"tls_value", None), 404);
        assert_eq!(value(provider.0, c"tls_value", Some(c"VERS_1")), 303);
        let consumer = Open::new(&directory.join("consumer.so"), libc::RTLD_LOCAL);
        assert_eq!(call(consumer.0, c"current_values", None), 694);
        assert_eq!(call(consumer.0, c"previous_values", None), 470);
        let legacy = Open::new(&directory.join("legacy.so"), libc::RTLD_LOCAL);
        assert_eq!(call(legacy.0, c"legacy_values", None), 470);
        let plain = Open::new(&directory.join("unversioned.so"), libc::RTLD_LOCAL);
        assert_eq!(call(plain.0, c"plain", Some(c"ARBITRARY")), 88);
        plain.close();
        legacy.close();
        consumer.close();
        let id = provider.0;
        provider.close();
        assert!(!native_dso_handle_for_tests(id), "version metadata must not pin a closed group");
    }
}

#[test]
fn native_dependency_contracts_are_checked_even_without_versioned_relocations() {
    let _serial = NATIVE_TEST_LOCK.lock().expect("native test lock");
    for directory in cases() {
        for case in ["strong", "weak", "unversioned"] {
            let directory = directory.join(format!("contract_{case}"));
            oracle("contract_probe", &directory, Some(case), "dependency version contract: PASS\n");
            let provider = Open::new(&directory.join("libversions.so"), libc::RTLD_GLOBAL);
            let path = directory.join("contract.so");
            if case == "strong" {
                let name = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                // SAFETY: valid path to the deliberately incompatible fixture.
                let _ = error();
                let handle = unsafe { dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
                assert!(handle.is_null(), "missing strong VERNEED must fail before publication");
                assert!(error().is_some());
                let handle = unsafe { dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) };
                assert!(handle.is_null(), "failed version contract must not publish a partial handle");
                let _ = error();
            } else {
                let consumer = Open::new(&path, libc::RTLD_LOCAL);
                assert_eq!(call(consumer.0, c"current_values", None), 470);
                assert_eq!(call(consumer.0, c"previous_values", None), 470);
                consumer.close();
            }
            assert!(native_dso_handle_for_tests(provider.0), "failure must preserve the resident provider");
            assert!(!symbol(provider.0, c"api", None).is_null());
            provider.close();
        }
    }
}

fn parsed(path: &Path) -> (Vec<u8>, LoadedObject, Table) {
    let bytes = std::fs::read(path).unwrap();
    let object = ElfLoader::new(0).parse(&bytes).expect("core parses compiler fixture");
    let table = Table::parse(&bytes, &object).expect("native parses runtime version metadata");
    (bytes, object, table)
}

fn tag(bytes: &[u8], object: &LoadedObject, wanted: i64) -> (usize, u64) {
    let dynamic = object.program_headers.iter().find(|header| header.p_type == ProgramType::Dynamic).unwrap();
    for offset in (dynamic.p_offset as usize..(dynamic.p_offset + dynamic.p_filesz) as usize).step_by(16) {
        if i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()) == wanted {
            return (offset + 8, u64::from_le_bytes(bytes[offset + 8..offset + 16].try_into().unwrap()));
        }
    }
    panic!("missing fixture dynamic tag {wanted:#x}")
}

fn offset(object: &LoadedObject, address: u64) -> usize {
    let header = object.program_headers.iter().find(|header| header.is_load()
        && header.p_vaddr <= address && address < header.p_vaddr + header.p_filesz).unwrap();
    (header.p_offset + address - header.p_vaddr) as usize
}

#[test]
fn runtime_version_selection_preserves_default_hidden_and_relocation_contracts() {
    for directory in cases() {
        let (bytes, object, table) = parsed(&directory.join("libversions.so"));
        let old = table.lookup(&object, "api", Some("VERS_1"), Lookup::Public).unwrap();
        let new = table.lookup(&object, "api", Some("VERS_2"), Lookup::Public).unwrap();
        assert_ne!(old.st_value, new.st_value);
        assert!(std::ptr::eq(table.lookup(&object, "api", None, Lookup::Public).unwrap(), new));
        assert!(std::ptr::eq(table.lookup(&object, "api", None, Lookup::Relocation { hidden: false }).unwrap(), old));
        for name in ["retired", "recent"] {
            assert!(table.lookup(&object, name, None, Lookup::Public).is_none());
        }
        assert!(table.lookup(&object, "unversioned", Some("VERS_1"), Lookup::Public).is_none());
        assert!(table.lookup(&object, "unversioned", Some("VERS_1"), Lookup::Relocation { hidden: false }).is_some());
        assert!(table.lookup(&object, "unversioned", Some("VERS_1"), Lookup::Relocation { hidden: true }).is_none());
        let slot = object.dynsym.iter().position(|symbol| std::ptr::eq(symbol, old)).unwrap();
        let versym = offset(&object, tag(&bytes, &object, 0x6fff_fff0).1);
        let mut ambiguous = bytes.clone();
        ambiguous[versym + slot * 2..versym + slot * 2 + 2].copy_from_slice(&2u16.to_le_bytes());
        let ambiguous = Table::parse(&ambiguous, &object).unwrap();
        assert!(ambiguous.lookup(&object, "api", None, Lookup::Public).is_none(), "two public versions are ambiguous");
        assert!(ambiguous.lookup(&object, "api", Some("VERS_2"), Lookup::Public).is_some());
    }
}

#[test]
fn dependency_metadata_distinguishes_strong_weak_and_unversioned_providers() {
    for directory in cases() {
        for (case, expected) in [("strong", false), ("weak", true), ("unversioned", true)] {
            let directory = directory.join(format!("contract_{case}"));
            let (_, _, provider) = parsed(&directory.join("libversions.so"));
            let (_, consumer, required) = parsed(&directory.join("contract.so"));
            assert_eq!(required.requirements.len(), 1);
            assert_eq!(required.requirements[0].library, "libversions.so");
            assert_eq!(provider.satisfies(&required.requirements[0]), expected);
            for relocation in consumer.rela_dyn.iter().chain(&consumer.rela_plt) {
                if relocation.symbol_index() != 0 {
                    assert!(required.name(relocation.symbol_index() as usize).is_none(),
                        "fixture must isolate declarations from symbol-version matching");
                }
            }
        }
    }
}

#[test]
fn malformed_version_records_fail_closed_without_section_header_assumptions() {
    for directory in cases() {
        for filename in ["libversions.so", "consumer.so"] {
            let (bytes, object, _) = parsed(&directory.join(filename));
            let (count_tag, table_tag, next_field, hash_field, aux_field) = if filename == "libversions.so" {
                (0x6fff_fffd, 0x6fff_fffc, 16, 8, 12)
            } else { (0x6fff_ffff, 0x6fff_fffe, 12, 0, 8) };
            let (count_offset, _) = tag(&bytes, &object, count_tag);
            let (_, address) = tag(&bytes, &object, table_tag);
            let base = offset(&object, address);
            let (versym_pointer, _) = tag(&bytes, &object, 0x6fff_fff0);
            let mut mutations = Vec::new();
            for position in [count_offset, versym_pointer] {
                let mut corrupt = bytes.clone();
                corrupt[position..position + 8].copy_from_slice(&u64::MAX.to_le_bytes());
                mutations.push(corrupt);
            }
            let mut corrupt = bytes.clone();
            corrupt[base..base + 2].copy_from_slice(&2u16.to_le_bytes());
            mutations.push(corrupt);
            let mut corrupt = bytes.clone();
            corrupt[base + next_field..base + next_field + 4].copy_from_slice(&4u32.to_le_bytes());
            mutations.push(corrupt);
            let mut corrupt = bytes.clone();
            corrupt[base + aux_field..base + aux_field + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            mutations.push(corrupt);
            if filename == "libversions.so" {
                let mut corrupt = bytes.clone();
                corrupt[base + hash_field] ^= 1;
                mutations.push(corrupt);
            }
            for (index, corrupt) in mutations.iter().enumerate() {
                assert!(Table::parse(corrupt, &object).is_none(), "{} {filename} mutation {index}", directory.display());
            }
        }
    }
}
