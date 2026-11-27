//! Keyed NSS ethers lookups. The files format uses its own GNU parser,
//! which accepts forms that the public ether_line converter rejects.

use super::{
    EtherAddrBytes, NSS_STATUS_NOTFOUND, NSS_STATUS_SUCCESS, NSS_STATUS_TRYAGAIN,
    NSS_STATUS_UNAVAIL, NssParsedEther, current_abi_errno, nss_set_errnop, set_abi_errno,
    tracked_object_fits, tracked_output_capacity,
};
use frankenlibc_core::resolv::{NssNetdbKind, NssNetdbValue, parse_nss_netdb_line};
use std::ffi::{c_char, c_int, c_void};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek};
use std::path::Path;

#[derive(Clone, Copy)]
pub(super) enum Key<'a> {
    Name(&'a [u8]),
    Address([u8; 6]),
}

fn open_source(path: &Path) -> io::Result<File> {
    let mut file = File::open(path)?;
    // A GNU files provider must be able to reread a record on ERANGE.
    // Reject nonseekable sources before the first read or buffer preflight.
    file.rewind()
        .map_err(|_| io::Error::from_raw_os_error(libc::ESPIPE))?;
    Ok(file)
}

fn scan(
    mut reader: impl BufRead,
    key: Key<'_>,
    capacity: usize,
) -> Result<Option<([u8; 6], Vec<u8>)>, c_int> {
    if capacity < 3 {
        return Err(libc::ERANGE);
    }
    let mut line = Vec::new();
    loop {
        line.clear();
        // GNU reserves space for the NUL and a truncation sentinel. Even an
        // unmatched or comment line must fit before parsing can continue.
        let count = (&mut reader)
            .take((capacity - 1) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))?;
        if count == 0 {
            return Ok(None);
        }
        if count == capacity - 1 {
            return Err(libc::ERANGE);
        }
        let parsed = parse_nss_netdb_line(NssNetdbKind::Ether, &line);
        let Some(record) = parsed.record else {
            continue;
        };
        let NssNetdbValue::Ether(address) = record.value else {
            unreachable!("ethers parser returned another record kind");
        };
        let name = &line[record.name];
        let matches = match key {
            Key::Name(needle) => name.eq_ignore_ascii_case(needle),
            Key::Address(needle) => needle == address,
        };
        if matches {
            return Ok(Some((address, name.to_vec())));
        }
    }
}

/// Look up one record without touching a process-wide enumeration cursor.
///
/// # Safety
/// The NSS caller supplies output objects and a buffer of the given capacity.
pub(super) unsafe fn lookup(
    key: Key<'_>,
    result: *mut c_void,
    buffer: *mut c_char,
    buflen: usize,
    errnop: *mut c_int,
) -> c_int {
    let saved_errno = current_abi_errno();
    if !tracked_object_fits(result.cast::<NssParsedEther>()) || buffer.is_null() {
        unsafe { nss_set_errnop(errnop, libc::EINVAL) };
        return NSS_STATUS_UNAVAIL;
    }
    let file = match open_source(Path::new("/etc/ethers")) {
        Ok(file) => file,
        Err(error) => {
            let code = error.raw_os_error().unwrap_or(libc::EIO);
            unsafe { set_abi_errno(code) };
            return if code == libc::EAGAIN {
                NSS_STATUS_TRYAGAIN
            } else {
                NSS_STATUS_UNAVAIL
            };
        }
    };
    let capacity = tracked_output_capacity(buffer, buflen);
    match scan(BufReader::new(file), key, capacity) {
        Ok(Some((octet, name))) => {
            // The accepted physical line fits in the caller's buffer with two
            // spare bytes. The name is an owned substring of that line.
            unsafe {
                std::ptr::copy_nonoverlapping(name.as_ptr(), buffer.cast::<u8>(), name.len());
                buffer.add(name.len()).write(0);
                result.cast::<NssParsedEther>().write(NssParsedEther {
                    name: buffer,
                    address: EtherAddrBytes { octet },
                });
                set_abi_errno(saved_errno);
            }
            NSS_STATUS_SUCCESS
        }
        Ok(None) => {
            unsafe { set_abi_errno(saved_errno) };
            NSS_STATUS_NOTFOUND
        }
        Err(error) => {
            unsafe {
                set_abi_errno(if capacity < 2 { saved_errno } else { error });
                nss_set_errnop(errnop, error);
            }
            if error == libc::ERANGE {
                NSS_STATUS_TRYAGAIN
            } else {
                NSS_STATUS_UNAVAIL
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn source_open_requires_a_seekable_descriptor() {
        use std::os::fd::AsRawFd;

        let (reader, _writer) = io::pipe().unwrap();
        let source = format!("/proc/self/fd/{}", reader.as_raw_fd());
        let error = open_source(Path::new(&source)).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ESPIPE));

        let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let mut file = open_source(&manifest).unwrap();
        assert_eq!(file.stream_position().unwrap(), 0);
    }

    #[test]
    fn lookup_uses_files_grammar_case_folding_and_first_match() {
        let rows = b"# header\ninvalid\n  0xa:00:1:2:3:4\tExample # first\n1:2:3:4:5:6 EXAMPLE";
        let first = ([10, 0, 1, 2, 3, 4], b"Example".to_vec());
        assert_eq!(
            scan(&rows[..], Key::Name(b"exAmple"), 128),
            Ok(Some(first.clone()))
        );
        assert_eq!(scan(&rows[..], Key::Address(first.0), 128), Ok(Some(first)));
        assert_eq!(scan(&rows[..], Key::Name(b"ample"), 128), Ok(None));
    }

    #[test]
    fn lookup_preserves_complete_names_and_physical_line_capacity() {
        let name = vec![b'a'; 400];
        let mut row = b"1:2:3:4:5:6 ".to_vec();
        row.extend_from_slice(&name);
        row.push(b'\n');
        let size = row.len();
        let key = Key::Address([1, 2, 3, 4, 5, 6]);
        assert_eq!(
            scan(row.as_slice(), key, size + 2),
            Ok(Some(([1, 2, 3, 4, 5, 6], name)))
        );
        assert_eq!(scan(row.as_slice(), key, size + 1), Err(libc::ERANGE));
        row.extend_from_slice(b"0:0:0:0:0:0 next");
        assert_eq!(
            scan(row.as_slice(), Key::Name(b"next"), size + 1),
            Err(libc::ERANGE)
        );
        assert_eq!(
            scan(row.as_slice(), Key::Name(b"next"), size + 2),
            Ok(Some(([0; 6], b"next".to_vec())))
        );
    }
}
