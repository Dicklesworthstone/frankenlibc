//! Socket operations.
//!
//! Implements `<sys/socket.h>` constants and pure-logic validators. Actual
//! syscall invocations (`socket`, `bind`, `listen`, etc.) live in the ABI
//! crate.

// ---------------------------------------------------------------------------
// Address families (AF_*)
// ---------------------------------------------------------------------------

/// Unspecified address family.
pub const AF_UNSPEC: i32 = 0;
/// Unix domain sockets.
pub const AF_UNIX: i32 = 1;
/// IPv4 Internet protocols.
pub const AF_INET: i32 = 2;
/// IPv6 Internet protocols.
pub const AF_INET6: i32 = 10;
/// Kernel user interface device.
pub const AF_NETLINK: i32 = 16;

// ---------------------------------------------------------------------------
// Socket types (SOCK_*)
// ---------------------------------------------------------------------------

/// Byte-stream socket.
pub const SOCK_STREAM: i32 = 1;
/// Datagram socket.
pub const SOCK_DGRAM: i32 = 2;
/// Raw network protocol access.
pub const SOCK_RAW: i32 = 3;
/// Sequenced, reliable, connection-based datagrams.
pub const SOCK_SEQPACKET: i32 = 5;

// ---------------------------------------------------------------------------
// Socket type flags (ORed into `socket()` type argument)
// ---------------------------------------------------------------------------

/// Set O_NONBLOCK on the new socket.
pub const SOCK_NONBLOCK: i32 = 0x800;
/// Set FD_CLOEXEC on the new socket.
pub const SOCK_CLOEXEC: i32 = 0x80000;

/// Mask covering all known socket-type flags.
const SOCK_TYPE_FLAG_MASK: i32 = SOCK_NONBLOCK | SOCK_CLOEXEC;

// ---------------------------------------------------------------------------
// Shutdown modes
// ---------------------------------------------------------------------------

/// Shut down the reading side.
pub const SHUT_RD: i32 = 0;
/// Shut down the writing side.
pub const SHUT_WR: i32 = 1;
/// Shut down both reading and writing.
pub const SHUT_RDWR: i32 = 2;

// ---------------------------------------------------------------------------
// Socket levels
// ---------------------------------------------------------------------------

/// Socket-level options (for `getsockopt`/`setsockopt`).
pub const SOL_SOCKET: i32 = 1;

// ---------------------------------------------------------------------------
// Socket options (SO_*)
// ---------------------------------------------------------------------------

/// Allow local address reuse.
pub const SO_REUSEADDR: i32 = 2;
/// Enable keep-alive probes.
pub const SO_KEEPALIVE: i32 = 9;
/// Receive buffer size.
pub const SO_RCVBUF: i32 = 8;
/// Send buffer size.
pub const SO_SNDBUF: i32 = 7;
/// Receive timeout.
pub const SO_RCVTIMEO: i32 = 20;
/// Send timeout.
pub const SO_SNDTIMEO: i32 = 21;
/// Pending error (get only).
pub const SO_ERROR: i32 = 4;
/// Socket type (get only).
pub const SO_TYPE: i32 = 3;
/// Linger on close if unsent data is present.
pub const SO_LINGER: i32 = 13;

// ---------------------------------------------------------------------------
// Message flags (MSG_*)
// ---------------------------------------------------------------------------

/// Peek at incoming data without consuming it.
pub const MSG_PEEK: i32 = 2;
/// Block until the full amount of data is available.
pub const MSG_WAITALL: i32 = 256;
/// Non-blocking operation.
pub const MSG_DONTWAIT: i32 = 64;
/// Do not generate SIGPIPE on stream-oriented sockets.
pub const MSG_NOSIGNAL: i32 = 0x4000;

/// Mask covering all known MSG_* flags.
const MSG_KNOWN_MASK: i32 = MSG_PEEK | MSG_WAITALL | MSG_DONTWAIT | MSG_NOSIGNAL;

// ---------------------------------------------------------------------------
// Miscellaneous
// ---------------------------------------------------------------------------

/// Maximum length of the pending-connection queue for `listen()`.
pub const SOMAXCONN: i32 = 4096;

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/// Returns `true` if `af` is a recognized address family.
#[inline]
pub fn valid_address_family(af: i32) -> bool {
    matches!(af, AF_UNSPEC | AF_UNIX | AF_INET | AF_INET6 | AF_NETLINK)
}

/// Returns `true` if `stype` encodes a recognized base socket type, after
/// masking off the `SOCK_NONBLOCK` and `SOCK_CLOEXEC` modifier flags.
#[inline]
pub fn valid_socket_type(stype: i32) -> bool {
    let base = stype & !SOCK_TYPE_FLAG_MASK;
    matches!(base, SOCK_STREAM | SOCK_DGRAM | SOCK_RAW | SOCK_SEQPACKET)
}

/// Returns `true` if `how` is a valid shutdown mode.
#[inline]
pub fn valid_shutdown_how(how: i32) -> bool {
    matches!(how, SHUT_RD | SHUT_WR | SHUT_RDWR)
}

/// Clamps `backlog` into the range `[0, SOMAXCONN]`.
#[inline]
pub fn valid_backlog(backlog: i32) -> i32 {
    backlog.clamp(0, SOMAXCONN)
}

/// Returns `true` if `flags` contains only recognized MSG_* bits.
#[inline]
pub fn valid_msg_flags(flags: i32) -> bool {
    flags & !MSG_KNOWN_MASK == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Address family validation ------------------------------------------

    #[test]
    fn valid_af_known_families() {
        assert!(valid_address_family(AF_UNSPEC));
        assert!(valid_address_family(AF_UNIX));
        assert!(valid_address_family(AF_INET));
        assert!(valid_address_family(AF_INET6));
        assert!(valid_address_family(AF_NETLINK));
    }

    #[test]
    fn invalid_af_rejects_unknowns() {
        assert!(!valid_address_family(-1));
        assert!(!valid_address_family(3));
        assert!(!valid_address_family(42));
        assert!(!valid_address_family(i32::MAX));
        assert!(!valid_address_family(i32::MIN));
    }

    // -- Socket type validation ---------------------------------------------

    #[test]
    fn valid_socket_type_base_types() {
        assert!(valid_socket_type(SOCK_STREAM));
        assert!(valid_socket_type(SOCK_DGRAM));
        assert!(valid_socket_type(SOCK_RAW));
        assert!(valid_socket_type(SOCK_SEQPACKET));
    }

    #[test]
    fn valid_socket_type_with_flags() {
        assert!(valid_socket_type(SOCK_STREAM | SOCK_NONBLOCK));
        assert!(valid_socket_type(SOCK_DGRAM | SOCK_CLOEXEC));
        assert!(valid_socket_type(SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC));
        assert!(valid_socket_type(SOCK_SEQPACKET | SOCK_CLOEXEC));
    }

    #[test]
    fn invalid_socket_type_rejects_unknowns() {
        assert!(!valid_socket_type(0));
        assert!(!valid_socket_type(4)); // gap between RAW(3) and SEQPACKET(5)
        assert!(!valid_socket_type(6));
        assert!(!valid_socket_type(-1));
        assert!(!valid_socket_type(i32::MAX));
    }

    #[test]
    fn invalid_socket_type_flags_only() {
        // Flags without a valid base type should be rejected.
        assert!(!valid_socket_type(SOCK_NONBLOCK));
        assert!(!valid_socket_type(SOCK_CLOEXEC));
        assert!(!valid_socket_type(SOCK_NONBLOCK | SOCK_CLOEXEC));
    }

    // -- Shutdown how validation --------------------------------------------

    #[test]
    fn valid_shutdown_how_values() {
        assert!(valid_shutdown_how(SHUT_RD));
        assert!(valid_shutdown_how(SHUT_WR));
        assert!(valid_shutdown_how(SHUT_RDWR));
    }

    #[test]
    fn invalid_shutdown_how_values() {
        assert!(!valid_shutdown_how(-1));
        assert!(!valid_shutdown_how(3));
        assert!(!valid_shutdown_how(i32::MAX));
        assert!(!valid_shutdown_how(i32::MIN));
    }

    // -- Backlog clamping ---------------------------------------------------

    #[test]
    fn backlog_clamp_normal() {
        assert_eq!(valid_backlog(0), 0);
        assert_eq!(valid_backlog(1), 1);
        assert_eq!(valid_backlog(128), 128);
        assert_eq!(valid_backlog(SOMAXCONN), SOMAXCONN);
    }

    #[test]
    fn backlog_clamp_negative() {
        assert_eq!(valid_backlog(-1), 0);
        assert_eq!(valid_backlog(-100), 0);
        assert_eq!(valid_backlog(i32::MIN), 0);
    }

    #[test]
    fn backlog_clamp_above_max() {
        assert_eq!(valid_backlog(SOMAXCONN + 1), SOMAXCONN);
        assert_eq!(valid_backlog(100_000), SOMAXCONN);
        assert_eq!(valid_backlog(i32::MAX), SOMAXCONN);
    }

    // -- MSG flags validation -----------------------------------------------

    #[test]
    fn valid_msg_flags_known() {
        assert!(valid_msg_flags(0));
        assert!(valid_msg_flags(MSG_PEEK));
        assert!(valid_msg_flags(MSG_WAITALL));
        assert!(valid_msg_flags(MSG_DONTWAIT));
        assert!(valid_msg_flags(MSG_NOSIGNAL));
    }

    #[test]
    fn valid_msg_flags_combinations() {
        assert!(valid_msg_flags(MSG_PEEK | MSG_DONTWAIT));
        assert!(valid_msg_flags(MSG_WAITALL | MSG_NOSIGNAL));
        assert!(valid_msg_flags(
            MSG_PEEK | MSG_WAITALL | MSG_DONTWAIT | MSG_NOSIGNAL
        ));
    }

    #[test]
    fn invalid_msg_flags_unknown_bits() {
        assert!(!valid_msg_flags(1)); // bit 0 not in any known flag
        assert!(!valid_msg_flags(0x8000)); // unknown high bit
        assert!(!valid_msg_flags(MSG_PEEK | 0x1_0000));
        assert!(!valid_msg_flags(-1)); // all bits set
        assert!(!valid_msg_flags(i32::MIN));
    }

    // -- Constant value spot-checks -----------------------------------------

    #[test]
    fn constant_values() {
        assert_eq!(AF_UNSPEC, 0);
        assert_eq!(AF_UNIX, 1);
        assert_eq!(AF_INET, 2);
        assert_eq!(AF_INET6, 10);
        assert_eq!(AF_NETLINK, 16);

        assert_eq!(SOCK_STREAM, 1);
        assert_eq!(SOCK_DGRAM, 2);
        assert_eq!(SOCK_RAW, 3);
        assert_eq!(SOCK_SEQPACKET, 5);
        assert_eq!(SOCK_NONBLOCK, 0x800);
        assert_eq!(SOCK_CLOEXEC, 0x80000);

        assert_eq!(SHUT_RD, 0);
        assert_eq!(SHUT_WR, 1);
        assert_eq!(SHUT_RDWR, 2);

        assert_eq!(SOL_SOCKET, 1);

        assert_eq!(SO_REUSEADDR, 2);
        assert_eq!(SO_KEEPALIVE, 9);
        assert_eq!(SO_RCVBUF, 8);
        assert_eq!(SO_SNDBUF, 7);
        assert_eq!(SO_RCVTIMEO, 20);
        assert_eq!(SO_SNDTIMEO, 21);
        assert_eq!(SO_ERROR, 4);
        assert_eq!(SO_TYPE, 3);
        assert_eq!(SO_LINGER, 13);

        assert_eq!(MSG_PEEK, 2);
        assert_eq!(MSG_WAITALL, 256);
        assert_eq!(MSG_DONTWAIT, 64);
        assert_eq!(MSG_NOSIGNAL, 0x4000);

        assert_eq!(SOMAXCONN, 4096);
    }

    // ===== glibc parity tests =====
    // Verified against glibc <sys/socket.h>

    #[test]
    fn glibc_address_family_constants() {
        // AF_* constants must match glibc
        assert_eq!(AF_UNSPEC, 0);
        assert_eq!(AF_UNIX, 1);
        assert_eq!(AF_INET, 2);
        assert_eq!(AF_INET6, 10);
        assert_eq!(AF_NETLINK, 16);
    }

    #[test]
    fn glibc_socket_type_constants() {
        // SOCK_* type constants must match glibc
        assert_eq!(SOCK_STREAM, 1);
        assert_eq!(SOCK_DGRAM, 2);
        assert_eq!(SOCK_RAW, 3);
        assert_eq!(SOCK_SEQPACKET, 5);
        assert_eq!(SOCK_NONBLOCK, 0x800);
        assert_eq!(SOCK_CLOEXEC, 0x80000);
    }

    #[test]
    fn glibc_shutdown_constants() {
        // SHUT_* constants must match glibc
        assert_eq!(SHUT_RD, 0);
        assert_eq!(SHUT_WR, 1);
        assert_eq!(SHUT_RDWR, 2);
    }

    #[test]
    fn glibc_socket_option_constants() {
        // SOL_SOCKET and SO_* must match glibc
        assert_eq!(SOL_SOCKET, 1);
        assert_eq!(SO_REUSEADDR, 2);
        assert_eq!(SO_TYPE, 3);
        assert_eq!(SO_ERROR, 4);
        assert_eq!(SO_SNDBUF, 7);
        assert_eq!(SO_RCVBUF, 8);
        assert_eq!(SO_KEEPALIVE, 9);
        assert_eq!(SO_LINGER, 13);
        assert_eq!(SO_RCVTIMEO, 20);
        assert_eq!(SO_SNDTIMEO, 21);
    }

    #[test]
    fn glibc_msg_flag_constants() {
        // MSG_* constants must match glibc
        assert_eq!(MSG_PEEK, 2);
        assert_eq!(MSG_DONTWAIT, 64);
        assert_eq!(MSG_WAITALL, 256);
        assert_eq!(MSG_NOSIGNAL, 0x4000);
    }

    #[test]
    fn glibc_somaxconn() {
        // SOMAXCONN must match glibc (Linux 5.4+)
        assert_eq!(SOMAXCONN, 4096);
    }
}
