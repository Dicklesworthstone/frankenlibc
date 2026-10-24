//! Real DSO dependency search through the native loader, not host dlopen.
//! Each case runs in a new process so initial LD_LIBRARY_PATH is authoritative.

#[path = "../src/dlfcn_candidate.rs"]
mod candidate;

use frankenlibc_abi::dlfcn_abi as dl;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::process::Command;

const CHILD: &str = "FRANKENLIBC_CANDIDATE_CHILD";

fn compile(source: &Path, output: &Path, extra: &[String]) {
    let mut command = Command::new(std::env::var_os("CC").unwrap_or_else(|| "cc".into()));
    command
        .args(["-shared", "-fPIC", "-nostdlib"])
        .arg(source)
        .args(extra)
        .arg("-o")
        .arg(output);
    let result = command.output().expect("execute C compiler");
    assert!(
        result.status.success(),
        "compiler failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

unsafe fn open(path: &Path) -> *mut std::ffi::c_void {
    use std::os::unix::ffi::OsStrExt;
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    unsafe { dl::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) }
}

fn check_child() {
    let path = PathBuf::from(std::env::var_os(CHILD).unwrap());
    let succeeds = std::env::var("FRANKENLIBC_CANDIDATE_EXPECT").unwrap() == "success";
    unsafe {
        let handle = open(&path);
        if !succeeds {
            assert!(
                handle.is_null(),
                "malformed first native candidate must stop search"
            );
            assert!(!dl::dlerror().is_null());
            return;
        }
        assert!(!handle.is_null(), "compatible later candidate must load");
        assert!(
            dl::native_dso_handle_for_tests(handle),
            "host fallback cannot satisfy this test"
        );
        let symbol = dl::dlsym(handle, c"candidate_entry".as_ptr());
        assert!(!symbol.is_null());
        let entry: unsafe extern "C" fn() -> i32 = std::mem::transmute(symbol);
        assert_eq!(entry(), 74);
        if std::env::var_os("FRANKENLIBC_CANDIDATE_RESIDENT").is_some() {
            // Same opened inode, now with an incompatible on-disk header.
            // An already-owned image must still reopen by identity.
            let mut bytes = std::fs::read(&path).unwrap();
            bytes[4] = 1;
            std::fs::write(&path, bytes).unwrap();
            let reopened = open(&path);
            assert_eq!(reopened, handle);
            assert!(dl::native_dso_handle_for_tests(reopened));
            assert_eq!(entry(), 74);
            assert_eq!(dl::dlclose(reopened), 0);
        }
        assert_eq!(dl::dlclose(handle), 0);
    }
}

#[test]
fn native_candidate_search() {
    if std::env::var_os(CHILD).is_some() {
        check_child();
        return;
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "frankenlibc-candidate-search-{}-{stamp}",
        std::process::id()
    ));
    let bad = root.join("bad");
    let good = root.join("good");
    std::fs::create_dir_all(&bad).unwrap();
    std::fs::create_dir_all(&good).unwrap();
    let provider = root.join("provider.c");
    let consumer = root.join("consumer.c");
    std::fs::write(&provider, "int candidate_value(void) { return 73; }\n").unwrap();
    std::fs::write(&consumer, "extern int candidate_value(void);\nint candidate_entry(void) { return candidate_value() + 1; }\n").unwrap();
    let soname = "libfrankenlibc_candidate_probe.so";
    let library = good.join(soname);
    compile(&provider, &library, &[format!("-Wl,-soname,{soname}")]);
    let native = std::fs::read(&library).unwrap();
    assert_eq!(&native[..7], b"\x7fELF\x02\x01\x01");
    let machine = u16::from_le_bytes([native[18], native[19]]);
    let foreign: u16 = if machine == 62 { 183 } else { 62 };
    let mut wrong_class = native.clone();
    wrong_class[4] = 1;
    let mut wrong_machine = native.clone();
    wrong_machine[18..20].copy_from_slice(&foreign.to_le_bytes());
    let mut broken_magic = native.clone();
    broken_magic[0] = 0;
    let mut broken_version = native.clone();
    broken_version[20..24].copy_from_slice(&2u32.to_le_bytes());
    let modified = |edits: &[(usize, &[u8])]| {
        let mut bytes = native.clone();
        for &(offset, value) in edits {
            bytes[offset..offset + value.len()].copy_from_slice(value);
        }
        bytes
    };
    let cases = [
        ("wrong-class", wrong_class, true),
        ("wrong-machine", wrong_machine, true),
        ("bad-magic", broken_magic, false),
        ("bad-version", broken_version, false),
        ("short-header", native[..63].to_vec(), false),
        ("native", native.clone(), true),
        ("ident-zero", modified(&[(6, &[0])]), false),
        ("ident-two", modified(&[(6, &[2])]), false),
        ("ident-max", modified(&[(6, &[255])]), false),
        ("file-zero", modified(&[(20, &0u32.to_le_bytes())]), false),
        (
            "file-max",
            modified(&[(20, &u32::MAX.to_le_bytes())]),
            false,
        ),
        (
            "file-high-byte",
            modified(&[(20, &257u32.to_le_bytes())]),
            false,
        ),
        (
            "foreign-bad-version",
            modified(&[(18, &foreign.to_le_bytes()), (20, &2u32.to_le_bytes())]),
            false,
        ),
        (
            "foreign-bad-ident",
            modified(&[(18, &foreign.to_le_bytes()), (6, &[2])]),
            true,
        ),
        (
            "class-bad-version",
            modified(&[(4, &[1]), (20, &2u32.to_le_bytes())]),
            true,
        ),
        ("class-bad-ident", modified(&[(4, &[1]), (6, &[2])]), true),
    ];
    let exe = std::env::current_exe().unwrap();
    let environment = std::env::join_paths([&bad, &good]).unwrap();
    let mut invocations = 0;
    for search in ["runpath", "rpath", "environment"] {
        let parent = root.join(format!("parent-{search}.so"));
        let mut extra = vec![format!("-L{}", good.display()), format!("-l:{}", soname)];
        if search != "environment" {
            extra.push("-Wl,-rpath,$ORIGIN/bad:$ORIGIN/good".into());
            extra.push(if search == "rpath" {
                "-Wl,--disable-new-dtags".into()
            } else {
                "-Wl,--enable-new-dtags".into()
            });
        }
        compile(&consumer, &parent, &extra);
        for (case, bytes, succeeds) in &cases {
            std::fs::write(bad.join(soname), bytes).unwrap();
            let mut command = Command::new(&exe);
            command
                .args([
                    "--exact",
                    "native_candidate_search",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env_remove("LD_PRELOAD")
                .env(CHILD, &parent)
                .env(
                    "FRANKENLIBC_CANDIDATE_EXPECT",
                    if *succeeds { "success" } else { "failure" },
                );
            if search == "environment" {
                command.env("LD_LIBRARY_PATH", &environment);
            } else {
                command.env_remove("LD_LIBRARY_PATH");
            }
            let result = command.output().unwrap();
            assert!(
                result.status.success(),
                "{search}/{case}\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed;"));
            invocations += 1;
        }
    }
    // Reuse must not be defeated by a changed backing file of the same inode.
    std::fs::write(bad.join(soname), &native).unwrap();
    let parent = root.join("parent-runpath.so");
    let result = Command::new(&exe)
        .args([
            "--exact",
            "native_candidate_search",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_remove("LD_PRELOAD")
        .env(CHILD, &parent)
        .env("FRANKENLIBC_CANDIDATE_EXPECT", "success")
        .env("FRANKENLIBC_CANDIDATE_RESIDENT", "1")
        .env_remove("LD_LIBRARY_PATH")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "resident image\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed;"));
    invocations += 1;
    assert_eq!(invocations, 49);
    eprintln!(
        "native candidate search: {invocations} isolated cases; fixtures {}",
        root.display()
    );
}
