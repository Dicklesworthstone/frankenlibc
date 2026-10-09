//! Classify an opened ELF candidate before committing library search to it.
//!
//! Wrong-class and foreign-machine objects are search misses, not a reason
//! to discard later directories. Everything else stays with the full loader:
//! a malformed native object must not silently select a different library.
//! Positional reads preserve both the opened inode and the caller's cursor.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

const ELF64_HEADER_SIZE: usize = 64;
const NATIVE_MACHINE: u16 = if cfg!(target_arch = "x86_64") {
    62 // EM_X86_64
} else if cfg!(target_arch = "aarch64") {
    183 // EM_AARCH64
} else {
    0 // Unsupported build targets must not classify arbitrary files as misses.
};

/// True only for an incompatible ELF candidate. False is NOT validation:
/// the original descriptor must still pass the ordinary complete ELF parser.
pub(super) fn incompatible(file: &File) -> bool {
    let mut header = [0u8; ELF64_HEADER_SIZE];
    let mut read = 0;
    while read < header.len() {
        match file.read_at(&mut header[read..], read as u64) {
            Ok(0) => return false,
            Ok(count) => read += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
    incompatible_header(&header, NATIVE_MACHINE)
}

/// Load admission is stricter than candidate classification. The general ELF
/// reader exposes version fields as metadata, so the native execution path
/// must explicitly reject formats it does not implement. Incompatible files
/// are skipped before this gate; resident images reopen without reparsing.
pub(super) fn versions_supported(header: &[u8]) -> bool {
    header.len() >= ELF64_HEADER_SIZE
        && header[6] == 1 // EI_VERSION == EV_CURRENT
        && header[20..24] == [1, 0, 0, 0] // e_version, full little-endian word
}

fn incompatible_header(header: &[u8], machine: u16) -> bool {
    if machine == 0 || header.len() < ELF64_HEADER_SIZE || &header[..4] != b"\x7fELF" {
        return false;
    }
    // The ELF64 loader needs a complete native-sized header before reporting
    // a class mismatch. In particular, a short file with EI_CLASS=1 is still
    // malformed, not permission to fall through to a later search directory.
    if header[4] != 2 {
        return true;
    }
    // Preserve the file-version error before architecture selection. Decode
    // native-endian words: this loader supports little-endian x86_64/AArch64.
    // An incompatible machine is a miss; other ident/type/header errors in a
    // native-machine file remain terminal in the complete parser.
    let version = u32::from_le_bytes(header[20..24].try_into().expect("bounded header"));
    let candidate = u16::from_le_bytes([header[18], header[19]]);
    version == 1 && candidate != machine
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(machine: u16) -> [u8; ELF64_HEADER_SIZE] {
        let mut bytes = [0u8; ELF64_HEADER_SIZE];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes
    }

    #[test]
    fn accepts_native_class_and_machine_without_claiming_validation() {
        for machine in [62, 183] {
            assert!(!incompatible_header(&header(machine), machine));
        }
        assert!(!incompatible_header(&header(62), 0));
    }

    #[test]
    fn skips_foreign_classes_and_architectures() {
        for native in [62, 183] {
            for class in [0, 1, 3, 255] {
                let mut bytes = header(native);
                bytes[4] = class;
                assert!(incompatible_header(&bytes, native));
            }
            for foreign in [0, 3, 40, 62, 183, 243, 65535] {
                assert_eq!(
                    incompatible_header(&header(foreign), native),
                    foreign != native
                );
            }
        }
    }

    #[test]
    fn malformed_native_headers_are_not_search_misses() {
        let native = header(62);
        for length in 0..ELF64_HEADER_SIZE {
            assert!(!incompatible_header(&native[..length], 62));
        }
        for (offset, value) in [
            (0, 0),
            (5, 2),
            (6, 2),
            (7, 255),
            (8, 255),
            (16, 2),
            (20, 2),
            (54, 1),
        ] {
            let mut bytes = native;
            bytes[offset] = value;
            assert!(!incompatible_header(&bytes, 62), "offset {offset}");
        }
    }

    #[test]
    fn mismatch_order_does_not_hide_magic_short_file_or_file_version_errors() {
        let mut bytes = header(183);
        bytes[20] = 2;
        assert!(!incompatible_header(&bytes, 62));
        bytes[4] = 1;
        assert!(incompatible_header(&bytes, 62));
        bytes[0] = 0;
        assert!(!incompatible_header(&bytes, 62));
        bytes[0] = 0x7f;
        for length in 0..ELF64_HEADER_SIZE {
            assert!(!incompatible_header(&bytes[..length], 62));
        }
    }

    #[test]
    fn admission_checks_both_version_fields_without_narrowing() {
        for machine in [62, 183] {
            let native = header(machine);
            assert!(versions_supported(&native));
            for ident_version in 0u8..=255 {
                let mut bytes = native;
                bytes[6] = ident_version;
                assert_eq!(versions_supported(&bytes), ident_version == 1);
            }
            for file_version in [0u32, 1, 2, 255, 256, 257, 1 << 24, u32::MAX] {
                let mut bytes = native;
                bytes[20..24].copy_from_slice(&file_version.to_le_bytes());
                assert_eq!(versions_supported(&bytes), file_version == 1);
            }
        }
    }

    #[test]
    fn admission_requires_a_complete_header_but_leaves_body_validation_to_loader() {
        let mut bytes = header(62).to_vec();
        for length in 0..ELF64_HEADER_SIZE {
            assert!(!versions_supported(&bytes[..length]));
        }
        bytes.extend_from_slice(&[0xa5; 128]);
        assert!(versions_supported(&bytes));
        bytes[6] = 0;
        assert!(!versions_supported(&bytes));
    }

    #[test]
    fn positional_probe_does_not_consume_the_selected_file() {
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "frankenlibc-elf-candidate-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let bytes = header(NATIVE_MACHINE);
        file.write_all(&bytes).unwrap();
        file.seek(SeekFrom::Start(7)).unwrap();
        assert!(!incompatible(&file));
        assert_eq!(file.stream_position().unwrap(), 7);
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut actual = Vec::new();
        file.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, bytes);
        // The fixture is intentionally retained in the process temporary
        // directory; no repository or caller-owned pathname is removed.
    }
}
