//! Deadline-bounded DNS transaction IDs without a filesystem or host RNG.
//!
//! GRND_NONBLOCK refuses an uninitialized kernel pool instead of waiting past
//! a query's budget. Errors never select a clock, counter, hash or device-file
//! fallback. Keep the unsafe slice-to-syscall conversion in the syscall veneer.

use std::io::{self, ErrorKind};
use std::time::Instant;

const GRND_NONBLOCK: u32 = 1;

pub(super) fn query_id(deadline: Instant) -> io::Result<u16> {
    query_id_with(
        || super::remaining(deadline).map(|_| ()),
        |bytes| {
            crate::syscall::sys_getrandom_slice(bytes, GRND_NONBLOCK)
                .map_err(io::Error::from_raw_os_error)
        },
    )
}

fn query_id_with(
    mut check_deadline: impl FnMut() -> io::Result<()>,
    mut read: impl FnMut(&mut [u8]) -> io::Result<usize>,
) -> io::Result<u16> {
    let mut bytes = [0; 2];
    let mut filled = 0;
    while filled < bytes.len() {
        check_deadline()?;
        let available = bytes.len() - filled;
        match read(&mut bytes[filled..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "empty kernel entropy read",
                ));
            }
            Ok(n) if n <= available => filled += n,
            Ok(_) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "oversized kernel entropy read",
                ));
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    // DNS permits all 65536 values, including zero. Do not bias the sample
    // by rejecting a valid value or claim randomness from a statistical test.
    Ok(u16::from_ne_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn kernel_entropy_partial_reads_and_interruptions_complete_the_same_id() {
        let checks = Cell::new(0);
        let mut calls = 0;
        let id = query_id_with(
            || {
                checks.set(checks.get() + 1);
                Ok(())
            },
            |bytes| {
                calls += 1;
                match calls {
                    1 => {
                        assert_eq!(bytes.len(), 2);
                        bytes[0] = 0x12;
                        Ok(1)
                    }
                    2 => {
                        assert_eq!(bytes.len(), 1);
                        Err(ErrorKind::Interrupted.into())
                    }
                    3 => {
                        assert_eq!(bytes.len(), 1);
                        bytes[0] = 0x34;
                        Ok(1)
                    }
                    _ => panic!("unexpected entropy read"),
                }
            },
        )
        .unwrap();
        assert_eq!(id, u16::from_ne_bytes([0x12, 0x34]));
        assert_eq!(calls, 3);
        assert_eq!(checks.get(), 3);
    }

    #[test]
    fn kernel_entropy_zero_is_a_valid_complete_id() {
        let id = query_id_with(
            || Ok(()),
            |bytes| {
                bytes.fill(0);
                Ok(bytes.len())
            },
        )
        .unwrap();
        assert_eq!(id, 0);
    }

    #[test]
    fn kernel_entropy_expired_budget_prevents_the_first_read() {
        let error = query_id_with(
            || Err(ErrorKind::TimedOut.into()),
            |_| panic!("an expired query must not request entropy"),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
    }

    #[test]
    fn kernel_entropy_interruptions_cannot_extend_the_deadline() {
        let checks = Cell::new(0);
        let reads = Cell::new(0);
        let error = query_id_with(
            || {
                checks.set(checks.get() + 1);
                if checks.get() == 3 {
                    Err(ErrorKind::TimedOut.into())
                } else {
                    Ok(())
                }
            },
            |_| {
                reads.set(reads.get() + 1);
                Err(ErrorKind::Interrupted.into())
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert_eq!(reads.get(), 2);
    }

    #[test]
    fn kernel_entropy_short_read_does_not_publish_a_partial_id_after_failure() {
        let mut calls = 0;
        let error = query_id_with(
            || Ok(()),
            |bytes| {
                calls += 1;
                if calls == 1 {
                    bytes[0] = 0xab;
                    Ok(1)
                } else {
                    Err(ErrorKind::PermissionDenied.into())
                }
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert_eq!(calls, 2);
    }

    #[test]
    fn kernel_entropy_empty_read_is_an_error_not_an_infinite_retry() {
        let mut calls = 0;
        let error = query_id_with(
            || Ok(()),
            |_| {
                calls += 1;
                Ok(0)
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
        assert_eq!(calls, 1);
    }

    #[test]
    fn kernel_entropy_overreported_length_is_rejected() {
        let error = query_id_with(|| Ok(()), |bytes| Ok(bytes.len() + 1)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn kernel_entropy_failures_are_not_replaced_with_predictable_ids() {
        // EPERM, EIO, EAGAIN, ENOSYS on supported Linux targets.
        for code in [1, 5, 11, 38] {
            let mut calls = 0;
            let error = query_id_with(
                || Ok(()),
                |_| {
                    calls += 1;
                    Err(io::Error::from_raw_os_error(code))
                },
            )
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(code));
            assert_eq!(calls, 1, "errors must not trigger a fallback");
        }
    }
}
