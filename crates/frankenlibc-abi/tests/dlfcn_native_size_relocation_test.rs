//! Real linked DSOs, not synthetic addresses: SIZE uses the selected provider's
//! versioned metadata, and PC64 uses the place of the relocated full word.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_int, c_void};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenlibc_abi::dlfcn_abi as native;
use frankenlibc_core::elf::ElfLoader;

fn checked(command: &mut Command) {
    let output = command.output().expect("execute required fixture tool");
    assert!(
        output.status.success(),
        "{command:?}: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn compile(root: &Path, name: &str, source: &str, extra: &[&str]) {
    fs::write(root.join(format!("{name}.S")), source).unwrap();
    let mut command = Command::new("cc");
    command
        .current_dir(root)
        .args([
            "-shared",
            "-nostdlib",
            "-Wl,--hash-style=both",
            "-Wl,-z,now",
            "-Wl,-z,relro",
            "-Wl,-rpath,$ORIGIN",
        ])
        .arg(format!("-Wl,-soname,lib{name}.so"))
        .arg(format!("{name}.S"))
        .args(extra)
        .arg("-o")
        .arg(format!("lib{name}.so"));
    checked(&mut command);
}

fn provider(size: usize) -> String {
    format!(
        ".data\n.globl rs_blob\n.type rs_blob,@object\nrs_blob:\n.zero {size}\n.size rs_blob,.-rs_blob\n.section .note.GNU-stack,\"\",@progbits\n"
    )
}

fn consumer(symbol: &str) -> String {
    format!(
        r#"
.data
.globl rs_size64
.type rs_size64,@object
rs_size64:
.Lsize64: .quad {symbol}@SIZE + 5
.size rs_size64,.-rs_size64
.globl rs_size32
.type rs_size32,@object
rs_size32: .long {symbol}@SIZE + 3
.size rs_size32,.-rs_size32
.globl rs_minus
.type rs_minus,@object
rs_minus: .quad {symbol}@SIZE - 7
.size rs_minus,.-rs_minus
.text
.globl rs_observe
.type rs_observe,@function
rs_observe:
    endbr64
    mov .Lsize64(%rip),%rax
    ret
.size rs_observe,.-rs_observe
.section .note.GNU-stack,"",@progbits
"#
    )
}

fn fixtures(root: &Path) {
    fs::create_dir_all(root).unwrap();
    fs::write(root.join("v1.map"), "RS_1 { global: rs_*; local: *; };\n").unwrap();
    fs::write(root.join("v2.map"), "RS_2 { global: rs_*; local: *; };\n").unwrap();
    compile(
        root,
        "rs_provider",
        &provider(37),
        &["-Wl,--version-script=v1.map"],
    );
    compile(
        root,
        "rs_preempt",
        &provider(73),
        &["-Wl,--version-script=v1.map"],
    );
    compile(
        root,
        "rs_wrong_version",
        &provider(91),
        &["-Wl,--version-script=v2.map"],
    );
    compile(
        root,
        "rs_consumer",
        &consumer("rs_blob"),
        &["-Wl,--no-as-needed", "-L.", "-lrs_provider"],
    );
    let bytes = fs::read(root.join("librs_consumer.so")).unwrap();
    let object = ElfLoader::new(0).parse(&bytes).unwrap();
    let entries: Vec<_> = object.rela_dyn.iter().chain(&object.rela_plt).collect();
    for kind in [32, 33] {
        assert!(
            entries
                .iter()
                .any(|entry| entry.reloc_type().to_u32() == kind),
            "the toolchain must emit SIZE{kind}, not fold the fixture away"
        );
    }
    let mut stripped = bytes.clone();
    stripped[40..48].fill(0); // e_shoff
    stripped[58..64].fill(0); // e_shentsize, e_shnum, e_shstrndx
    fs::write(root.join("librs_stripped.so"), &stripped).unwrap();

    // Move one SIZE64 target four bytes before the end of its PT_LOAD: writing
    // eight bytes must reject the transaction, even if mmap's page has room.
    let entry = entries
        .iter()
        .find(|entry| entry.reloc_type().to_u32() == 33)
        .unwrap();
    let limit = object
        .program_headers
        .iter()
        .filter(|header| header.is_load())
        .map(|header| header.p_vaddr + header.p_memsz)
        .max()
        .unwrap();
    let mut needle = Vec::new();
    needle.extend_from_slice(&entry.r_offset.to_le_bytes());
    needle.extend_from_slice(&entry.r_info.to_le_bytes());
    needle.extend_from_slice(&entry.r_addend.to_le_bytes());
    let locations: Vec<_> = bytes
        .windows(24)
        .enumerate()
        .filter_map(|(index, data)| (data == needle.as_slice()).then_some(index))
        .collect();
    assert_eq!(locations.len(), 1, "unambiguous relocation edit");
    let mut bad = bytes;
    bad[locations[0]..locations[0] + 8].copy_from_slice(&(limit - 4).to_le_bytes());
    fs::write(root.join("librs_bad_target.so"), bad).unwrap();

    let pc = r#"
.data
.globl rs_relative
.type rs_relative,@object
rs_relative: .quad rs_blob - . + 7
.size rs_relative,.-rs_relative
.section .note.GNU-stack,"",@progbits
"#;
    compile(
        root,
        "rs_pc64",
        pc,
        &["-Wl,--no-as-needed", "-L.", "-lrs_provider"],
    );
    let pc = ElfLoader::new(0)
        .parse(&fs::read(root.join("librs_pc64.so")).unwrap())
        .unwrap();
    assert!(
        pc.rela_dyn
            .iter()
            .any(|entry| entry.reloc_type().to_u32() == 24)
    );

    compile(
        root,
        "rs_weak",
        &format!(
            ".weak rs_absent\n.type rs_absent,@object\n{}",
            consumer("rs_absent")
        ),
        &[],
    );
    compile(root, "rs_missing", &consumer("rs_absent"), &[]);
    // Reading IFUNC SIZE is metadata-only. Executing this resolver is a bug.
    compile(
        root,
        "rs_ifunc",
        ".text\n.globl rs_indirect\n.type rs_indirect,@gnu_indirect_function\nrs_indirect: ud2\n.size rs_indirect,23\n.section .note.GNU-stack,\"\",@progbits\n",
        &[],
    );
    compile(
        root,
        "rs_ifunc_size",
        &consumer("rs_indirect"),
        &["-Wl,--no-as-needed", "-L.", "-lrs_ifunc"],
    );
}

struct Loader(bool);
impl Loader {
    fn try_open(&self, root: &Path, name: &str, flags: c_int) -> *mut c_void {
        let path = CString::new(root.join(format!("lib{name}.so")).as_os_str().as_bytes()).unwrap();
        // SAFETY: terminated pathname, valid flags; handles are consumed once.
        unsafe {
            if self.0 {
                native::dlopen(path.as_ptr(), flags)
            } else {
                libc::dlopen(path.as_ptr(), flags)
            }
        }
    }
    fn open(&self, root: &Path, name: &str, flags: c_int) -> *mut c_void {
        let handle = self.try_open(root, name, flags);
        assert!(!handle.is_null(), "load {name} (native={})", self.0);
        assert_eq!(
            native::native_dso_handle_for_tests(handle),
            self.0,
            "a native load must not be rescued by host fallback"
        );
        handle
    }
    fn symbol(&self, handle: *mut c_void, name: &CStr) -> *mut c_void {
        // SAFETY: live handle and terminated fixture symbol name.
        let pointer = unsafe {
            if self.0 {
                native::dlsym(handle, name.as_ptr())
            } else {
                libc::dlsym(handle, name.as_ptr())
            }
        };
        assert!(!pointer.is_null(), "lookup {name:?}");
        pointer
    }
    fn value64(&self, handle: *mut c_void, name: &CStr) -> u64 {
        // SAFETY: named fixture objects hold eight bytes; assembly permits
        // unaligned slots, so never use an aligned Rust load here.
        unsafe { self.symbol(handle, name).cast::<u64>().read_unaligned() }
    }
    fn sizes(&self, handle: *mut c_void, size: u64) {
        assert_eq!(self.value64(handle, c"rs_size64"), size.wrapping_add(5));
        assert_eq!(self.value64(handle, c"rs_minus"), size.wrapping_sub(7));
        // SAFETY: this exported fixture object holds exactly four bytes.
        let narrow = unsafe {
            self.symbol(handle, c"rs_size32")
                .cast::<u32>()
                .read_unaligned()
        };
        assert_eq!(narrow, size.wrapping_add(3) as u32);
        // SAFETY: fixture-defined function returning one unsigned 64-bit word.
        let function: unsafe extern "C" fn() -> u64 =
            unsafe { std::mem::transmute(self.symbol(handle, c"rs_observe")) };
        assert_eq!(unsafe { function() }, size.wrapping_add(5));
    }
    fn close(&self, handle: *mut c_void) {
        // SAFETY: consume one successful open after all uses of its symbols.
        let status = unsafe {
            if self.0 {
                native::dlclose(handle)
            } else {
                libc::dlclose(handle)
            }
        };
        assert_eq!(status, 0);
    }
}

fn scenario(loader: Loader, root: &Path, case: &str) {
    let now = libc::RTLD_NOW | libc::RTLD_LOCAL;
    match case {
        "plain" | "stripped" => {
            let name = if case == "plain" {
                "rs_consumer"
            } else {
                "rs_stripped"
            };
            let handle = loader.open(root, name, now);
            loader.sizes(handle, 37);
            loader.close(handle);
        }
        "preempt" | "deepbind" | "version" => {
            let name = if case == "version" {
                "rs_wrong_version"
            } else {
                "rs_preempt"
            };
            let provider = loader.open(root, name, libc::RTLD_NOW | libc::RTLD_GLOBAL);
            let flags = now
                | if case == "deepbind" {
                    libc::RTLD_DEEPBIND
                } else {
                    0
                };
            let handle = loader.open(root, "rs_consumer", flags);
            // The chosen provider must remain valid after its public handle is
            // closed; the relocation dependency is not a second public open.
            loader.close(provider);
            loader.sizes(handle, if case == "preempt" { 73 } else { 37 });
            loader.close(handle);
        }
        "pc64" => {
            let handle = loader.open(root, "rs_pc64", now);
            let slot = loader.symbol(handle, c"rs_relative") as u64;
            let target = loader.symbol(handle, c"rs_blob") as u64;
            assert_eq!(
                loader
                    .value64(handle, c"rs_relative")
                    .wrapping_add(slot)
                    .wrapping_sub(7),
                target
            );
            loader.close(handle);
        }
        "weak" | "ifunc" => {
            let name = if case == "weak" {
                "rs_weak"
            } else {
                "rs_ifunc_size"
            };
            let handle = loader.open(root, name, now);
            loader.sizes(handle, if case == "weak" { 0 } else { 23 });
            loader.close(handle);
        }
        "reject" => {
            for name in ["rs_bad_target", "rs_missing"] {
                assert!(loader.try_open(root, name, now).is_null(), "reject {name}");
            }
            let handle = loader.open(root, "rs_consumer", now);
            loader.sizes(handle, 37); // failed transactions did not poison later loads
            loader.close(handle);
        }
        _ => panic!("unknown scenario {case}"),
    }
}

#[test]
fn native_size_and_pc64_relocations() {
    if let Ok(case) = std::env::var("FRANKENLIBC_RELOC_CASE") {
        let root = PathBuf::from(std::env::var_os("FRANKENLIBC_RELOC_ROOT").unwrap());
        scenario(
            Loader(std::env::var("FRANKENLIBC_RELOC_BACKEND").unwrap() == "native"),
            &root,
            &case,
        );
        return;
    }
    let root = std::env::temp_dir().join(format!(
        "frankenlibc-relocations-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fixtures(&root);
    // Each backend/scenario gets a fresh process and link map. Some glibc
    // versions reject dynamic PC64 or fault on weak/IFUNC SIZE: those are
    // native/spec contracts, not claims of glibc differential equivalence.
    for backend in ["host", "native"] {
        let cases: &[&str] = if backend == "host" {
            &["plain", "stripped", "preempt", "deepbind", "version"]
        } else {
            &[
                "plain", "stripped", "preempt", "deepbind", "version", "pc64", "weak", "ifunc",
                "reject",
            ]
        };
        for case in cases {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "native_size_and_pc64_relocations",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("FRANKENLIBC_RELOC_ROOT", &root)
                .env("FRANKENLIBC_RELOC_BACKEND", backend)
                .env("FRANKENLIBC_RELOC_CASE", case);
            checked(&mut command);
            println!("{backend}/{case}: passed");
        }
    }
    println!("relocation contracts: 5 host and 9 native scenarios passed");
}
