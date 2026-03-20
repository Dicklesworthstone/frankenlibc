//! POSIX I/O multiplexing.
//!
//! Implements constants and validators for `<poll.h>` and `<sys/select.h>`
//! functions: poll, ppoll, select, pselect.

// ---------------------------------------------------------------------------
// poll event flags
// ---------------------------------------------------------------------------

/// Data other than high-priority data may be read without blocking.
pub const POLLIN: i16 = 0x001;
/// Normal data may be written without blocking.
pub const POLLOUT: i16 = 0x004;
/// An error has occurred on the device or stream.
pub const POLLERR: i16 = 0x008;
/// The device has been disconnected.
pub const POLLHUP: i16 = 0x010;
/// The file descriptor is not open.
pub const POLLNVAL: i16 = 0x020;
/// Normal data (priority band 0) may be read without blocking.
pub const POLLRDNORM: i16 = 0x040;
/// Normal data may be written without blocking.
pub const POLLWRNORM: i16 = 0x100;
/// Priority data may be read without blocking.
pub const POLLPRI: i16 = 0x002;

// Linux specific poll flags
/// Priority band 0 data may be read without blocking.
pub const POLLRDBAND: i16 = 0x080;
/// Priority band data may be written without blocking.
pub const POLLWRBAND: i16 = 0x200;
/// Stream head hang up (Linux 2.6.17+).
pub const POLLRDHUP: i16 = 0x2000;
/// Ignored (compatibility).
pub const POLLMSG: i16 = 0x400;
/// Internal use.
pub const POLLREMOVE: i16 = 0x1000;
/// Internal use.
pub const POLLFREE: i16 = 0x4000;

/// Bitmask of input-requestable events.
const POLL_INPUT_MASK: i16 = POLLIN
    | POLLOUT
    | POLLPRI
    | POLLRDNORM
    | POLLWRNORM
    | POLLRDBAND
    | POLLWRBAND
    | POLLRDHUP
    | POLLMSG;

// ---------------------------------------------------------------------------
// select constants
// ---------------------------------------------------------------------------

/// Maximum number of file descriptors in an fd_set.
pub const FD_SETSIZE: i32 = 1024;

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/// Returns true if `events` contains only recognized input event bits.
#[must_use]
pub const fn valid_poll_events(events: i16) -> bool {
    (events & !POLL_INPUT_MASK) == 0
}

/// Returns true if `nfds` is within a reasonable range (at most 1M entries).
#[must_use]
pub const fn valid_nfds(nfds: u64) -> bool {
    nfds <= 1_048_576
}

/// Returns true if `nfds` is within FD_SETSIZE for select.
#[must_use]
pub const fn valid_select_nfds(nfds: i32) -> bool {
    nfds >= 0 && nfds <= FD_SETSIZE
}

/// Returns true if the poll timeout is not absurdly large (> 24h).
#[must_use]
pub const fn valid_poll_timeout(timeout_ms: i32) -> bool {
    // -1 means infinite wait (valid). Positive up to 24 hours.
    timeout_ms >= -1 && timeout_ms <= 86_400_000
}

/// Clamp nfds for poll to a safe maximum.
#[must_use]
pub const fn clamp_poll_nfds(nfds: u64) -> u64 {
    if nfds > 1_048_576 { 1_048_576 } else { nfds }
}

/// Clamp nfds for select to FD_SETSIZE.
#[must_use]
pub const fn clamp_select_nfds(nfds: i32) -> i32 {
    if nfds < 0 {
        0
    } else if nfds > FD_SETSIZE {
        FD_SETSIZE
    } else {
        nfds
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_constants_match_linux() {
        assert_eq!(POLLIN, 0x001);
        assert_eq!(POLLOUT, 0x004);
        assert_eq!(POLLERR, 0x008);
        assert_eq!(POLLHUP, 0x010);
        assert_eq!(POLLNVAL, 0x020);
        assert_eq!(POLLRDNORM, 0x040);
        assert_eq!(POLLWRNORM, 0x100);
        assert_eq!(POLLPRI, 0x002);
        assert_eq!(POLLRDHUP, 0x2000);
    }

    #[test]
    fn valid_poll_events_check() {
        assert!(valid_poll_events(POLLIN));
        assert!(valid_poll_events(POLLIN | POLLOUT));
        assert!(valid_poll_events(POLLIN | POLLPRI | POLLRDNORM));
        assert!(valid_poll_events(POLLRDHUP | POLLRDBAND | POLLWRBAND));
        assert!(valid_poll_events(0));
        // POLLERR is output-only, not valid as input request.
        assert!(!valid_poll_events(POLLERR));
        assert!(!valid_poll_events(POLLHUP));
        assert!(!valid_poll_events(POLLNVAL));
    }

    #[test]
    fn valid_nfds_check() {
        assert!(valid_nfds(0));
        assert!(valid_nfds(1));
        assert!(valid_nfds(1024));
        assert!(valid_nfds(1_048_576));
        assert!(!valid_nfds(1_048_577));
    }

    #[test]
    fn valid_select_nfds_check() {
        assert!(valid_select_nfds(0));
        assert!(valid_select_nfds(1));
        assert!(valid_select_nfds(FD_SETSIZE));
        assert!(!valid_select_nfds(FD_SETSIZE + 1));
        assert!(!valid_select_nfds(-1));
    }

    #[test]
    fn valid_poll_timeout_check() {
        assert!(valid_poll_timeout(-1)); // infinite
        assert!(valid_poll_timeout(0)); // immediate
        assert!(valid_poll_timeout(1000));
        assert!(valid_poll_timeout(86_400_000)); // 24h
        assert!(!valid_poll_timeout(86_400_001));
        assert!(!valid_poll_timeout(-2));
    }

    #[test]
    fn clamp_poll_nfds_check() {
        assert_eq!(clamp_poll_nfds(0), 0);
        assert_eq!(clamp_poll_nfds(100), 100);
        assert_eq!(clamp_poll_nfds(2_000_000), 1_048_576);
    }

    #[test]
    fn clamp_select_nfds_check() {
        assert_eq!(clamp_select_nfds(-5), 0);
        assert_eq!(clamp_select_nfds(512), 512);
        assert_eq!(clamp_select_nfds(2000), FD_SETSIZE);
    }
}
