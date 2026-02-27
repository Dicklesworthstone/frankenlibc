//! Terminal I/O control.
//!
//! Implements `<termios.h>` constants, data structures, and validators for
//! terminal attribute manipulation.

// ---------------------------------------------------------------------------
// Optional actions for tcsetattr
// ---------------------------------------------------------------------------

/// Apply changes immediately.
pub const TCSANOW: i32 = 0;
/// Apply after all output has been transmitted.
pub const TCSADRAIN: i32 = 1;
/// Apply after all output has been transmitted; discard pending input.
pub const TCSAFLUSH: i32 = 2;

// ---------------------------------------------------------------------------
// Standard baud rates
// ---------------------------------------------------------------------------

pub const B0: u32 = 0;
pub const B50: u32 = 1;
pub const B75: u32 = 2;
pub const B110: u32 = 3;
pub const B134: u32 = 4;
pub const B150: u32 = 5;
pub const B200: u32 = 6;
pub const B300: u32 = 7;
pub const B600: u32 = 8;
pub const B1200: u32 = 9;
pub const B1800: u32 = 10;
pub const B2400: u32 = 11;
pub const B4800: u32 = 12;
pub const B9600: u32 = 13;
pub const B19200: u32 = 14;
pub const B38400: u32 = 15;

pub const B57600: u32 = 0o10001;
pub const B115200: u32 = 0o10002;
pub const B230400: u32 = 0o10003;
pub const B460800: u32 = 0o10004;
pub const B500000: u32 = 0o10005;
pub const B576000: u32 = 0o10006;
pub const B921600: u32 = 0o10007;
pub const B1000000: u32 = 0o10010;
pub const B1152000: u32 = 0o10011;
pub const B1500000: u32 = 0o10012;
pub const B2000000: u32 = 0o10013;
pub const B2500000: u32 = 0o10014;
pub const B3000000: u32 = 0o10015;
pub const B3500000: u32 = 0o10016;
pub const B4000000: u32 = 0o10017;

/// All recognized baud rate values.
const VALID_BAUDS: [u32; 31] = [
    B0, B50, B75, B110, B134, B150, B200, B300, B600, B1200, B1800, B2400, B4800, B9600, B19200,
    B38400, B57600, B115200, B230400, B460800, B500000, B576000, B921600, B1000000, B1152000,
    B1500000, B2000000, B2500000, B3000000, B3500000, B4000000,
];

// ---------------------------------------------------------------------------
// c_cc indices
// ---------------------------------------------------------------------------

pub const VINTR: usize = 0;
pub const VQUIT: usize = 1;
pub const VERASE: usize = 2;
pub const VKILL: usize = 3;
pub const VEOF: usize = 4;
pub const VTIME: usize = 5;
pub const VMIN: usize = 6;
pub const VSWTC: usize = 7;
pub const VSTART: usize = 8;
pub const VSTOP: usize = 9;
pub const VSUSP: usize = 10;
pub const VEOL: usize = 11;
pub const VREPRINT: usize = 12;
pub const VDISCARD: usize = 13;
pub const VWERASE: usize = 14;
pub const VLNEXT: usize = 15;
pub const VEOL2: usize = 16;
/// Number of control characters.
pub const NCCS: usize = 32;

// ---------------------------------------------------------------------------
// Input flags (c_iflag)
// ---------------------------------------------------------------------------

pub const IGNBRK: u32 = 0o1;
pub const BRKINT: u32 = 0o2;
pub const IGNPAR: u32 = 0o4;
pub const PARMRK: u32 = 0o10;
pub const INPCK: u32 = 0o20;
pub const ISTRIP: u32 = 0o40;
pub const INLCR: u32 = 0o100;
pub const IGNCR: u32 = 0o200;
pub const ICRNL: u32 = 0o400;
pub const IXON: u32 = 0o2000;
pub const IXOFF: u32 = 0o10000;

// ---------------------------------------------------------------------------
// Output flags (c_oflag)
// ---------------------------------------------------------------------------

pub const OPOST: u32 = 0o1;
pub const ONLCR: u32 = 0o4;

// ---------------------------------------------------------------------------
// Control flags (c_cflag)
// ---------------------------------------------------------------------------

/// Character size mask.
pub const CSIZE: u32 = 0o60;
pub const CS5: u32 = 0o0;
pub const CS6: u32 = 0o20;
pub const CS7: u32 = 0o40;
pub const CS8: u32 = 0o60;
pub const CSTOPB: u32 = 0o100;
pub const CREAD: u32 = 0o200;
pub const PARENB: u32 = 0o400;
pub const PARODD: u32 = 0o1000;
pub const HUPCL: u32 = 0o2000;
pub const CLOCAL: u32 = 0o4000;

/// Baud rate mask (lower bits of c_cflag on Linux).
pub const CBAUD: u32 = 0o10017;

// ---------------------------------------------------------------------------
// Local flags (c_lflag)
// ---------------------------------------------------------------------------

pub const ISIG: u32 = 0o1;
pub const ICANON: u32 = 0o2;
pub const ECHO: u32 = 0o10;
pub const ECHOE: u32 = 0o20;
pub const ECHOK: u32 = 0o40;
pub const ECHONL: u32 = 0o100;
pub const NOFLSH: u32 = 0o200;
pub const TOSTOP: u32 = 0o400;
pub const IEXTEN: u32 = 0o100000;

// ---------------------------------------------------------------------------
// Queue selector constants (for tcflush)
// ---------------------------------------------------------------------------

pub const TCIFLUSH: i32 = 0;
pub const TCOFLUSH: i32 = 1;
pub const TCIOFLUSH: i32 = 2;

// ---------------------------------------------------------------------------
// Flow action constants (for tcflow)
// ---------------------------------------------------------------------------

pub const TCOOFF: i32 = 0;
pub const TCOON: i32 = 1;
pub const TCIOFF: i32 = 2;
pub const TCION: i32 = 3;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Terminal attributes (like `struct termios`).
#[derive(Debug, Clone)]
pub struct Termios {
    /// Input mode flags.
    pub c_iflag: u32,
    /// Output mode flags.
    pub c_oflag: u32,
    /// Control mode flags.
    pub c_cflag: u32,
    /// Local mode flags.
    pub c_lflag: u32,
    /// Control characters.
    pub c_cc: [u8; NCCS],
}

impl Default for Termios {
    fn default() -> Self {
        Self {
            c_iflag: 0,
            c_oflag: 0,
            c_cflag: 0,
            c_lflag: 0,
            c_cc: [0u8; NCCS],
        }
    }
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/// Returns `true` if `act` is a valid optional-action value for `tcsetattr`.
///
/// Valid values: `TCSANOW` (0), `TCSADRAIN` (1), `TCSAFLUSH` (2).
pub fn valid_optional_actions(act: i32) -> bool {
    matches!(act, TCSANOW | TCSADRAIN | TCSAFLUSH)
}

/// Returns `true` if `speed` matches one of the defined `B*` baud rate constants.
pub fn valid_baud_rate(speed: u32) -> bool {
    VALID_BAUDS.contains(&speed)
}

/// Returns `true` if `sel` is a valid queue selector for `tcflush`.
///
/// Valid values: `TCIFLUSH` (0), `TCOFLUSH` (1), `TCIOFLUSH` (2).
pub fn valid_queue_selector(sel: i32) -> bool {
    matches!(sel, TCIFLUSH | TCOFLUSH | TCIOFLUSH)
}

/// Returns `true` if `act` is a valid flow-control action for `tcflow`.
///
/// Valid values: `TCOOFF` (0), `TCOON` (1), `TCIOFF` (2), `TCION` (3).
pub fn valid_flow_action(act: i32) -> bool {
    matches!(act, TCOOFF | TCOON | TCIOFF | TCION)
}

// ---------------------------------------------------------------------------
// Speed extraction / manipulation
// ---------------------------------------------------------------------------

/// Extract input speed from the terminal attributes.
///
/// On Linux, input and output speeds share the same `c_cflag` baud bits.
pub fn cfgetispeed(t: &Termios) -> u32 {
    t.c_cflag & CBAUD
}

/// Extract output speed from the terminal attributes.
///
/// On Linux, input and output speeds share the same `c_cflag` baud bits.
pub fn cfgetospeed(t: &Termios) -> u32 {
    t.c_cflag & CBAUD
}

/// Set the input speed in the terminal attributes.
///
/// Returns 0 on success. Returns -1 if `speed` is not a recognized baud rate.
pub fn cfsetispeed(t: &mut Termios, speed: u32) -> i32 {
    if !valid_baud_rate(speed) {
        return -1;
    }
    t.c_cflag = (t.c_cflag & !CBAUD) | (speed & CBAUD);
    0
}

/// Set the output speed in the terminal attributes.
///
/// Returns 0 on success. Returns -1 if `speed` is not a recognized baud rate.
pub fn cfsetospeed(t: &mut Termios, speed: u32) -> i32 {
    if !valid_baud_rate(speed) {
        return -1;
    }
    t.c_cflag = (t.c_cflag & !CBAUD) | (speed & CBAUD);
    0
}

/// Configure terminal attributes for raw (non-canonical, no echo) mode.
///
/// Equivalent to the `cfmakeraw` function:
/// - Clears `IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON` from `c_iflag`.
/// - Clears `OPOST` from `c_oflag`.
/// - Clears `ECHO | ECHONL | ICANON | ISIG | IEXTEN` from `c_lflag`.
/// - Clears `CSIZE | PARENB` from `c_cflag` and sets `CS8`.
/// - Sets `VMIN = 1` and `VTIME = 0` in `c_cc`.
pub fn cfmakeraw(t: &mut Termios) {
    // Input flags: clear processing bits.
    t.c_iflag &= !(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);

    // Output flags: disable post-processing.
    t.c_oflag &= !OPOST;

    // Local flags: disable echo, canonical, signals, extensions.
    t.c_lflag &= !(ECHO | ECHONL | ICANON | ISIG | IEXTEN);

    // Control flags: 8-bit characters, no parity.
    t.c_cflag &= !(CSIZE | PARENB);
    t.c_cflag |= CS8;

    // Non-canonical read: at least 1 byte, no timeout.
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;
}

// ---------------------------------------------------------------------------
// Stub syscall wrappers (kept for ABI compatibility, implementations pending)
// ---------------------------------------------------------------------------

/// Gets terminal attributes for the file descriptor.
///
/// Phase-1 deterministic placeholder: backend syscall transport lives in the
/// ABI layer today, so core returns `-1` without mutating the provided struct.
pub fn tcgetattr(_fd: i32, _termios: &mut Termios) -> i32 {
    -1
}

/// Sets terminal attributes for the file descriptor.
///
/// Phase-1 deterministic placeholder: validates the action selector and
/// returns `-1` while the backend syscall transport remains in ABI.
pub fn tcsetattr(_fd: i32, optional_actions: i32, _termios: &Termios) -> i32 {
    if !valid_optional_actions(optional_actions) {
        return -1;
    }
    -1
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Constant sanity checks
    // -----------------------------------------------------------------------

    #[test]
    fn test_tcsetattr_action_constants() {
        assert_eq!(TCSANOW, 0);
        assert_eq!(TCSADRAIN, 1);
        assert_eq!(TCSAFLUSH, 2);
    }

    #[test]
    fn test_standard_baud_rate_values() {
        assert_eq!(B0, 0);
        assert_eq!(B50, 1);
        assert_eq!(B75, 2);
        assert_eq!(B110, 3);
        assert_eq!(B134, 4);
        assert_eq!(B150, 5);
        assert_eq!(B200, 6);
        assert_eq!(B300, 7);
        assert_eq!(B600, 8);
        assert_eq!(B1200, 9);
        assert_eq!(B1800, 10);
        assert_eq!(B2400, 11);
        assert_eq!(B4800, 12);
        assert_eq!(B9600, 13);
        assert_eq!(B19200, 14);
        assert_eq!(B38400, 15);
    }

    #[test]
    fn test_extended_baud_rate_values() {
        assert_eq!(B57600, 0o10001);
        assert_eq!(B115200, 0o10002);
        assert_eq!(B230400, 0o10003);
        assert_eq!(B460800, 0o10004);
        assert_eq!(B500000, 0o10005);
        assert_eq!(B576000, 0o10006);
        assert_eq!(B921600, 0o10007);
        assert_eq!(B1000000, 0o10010);
        assert_eq!(B1152000, 0o10011);
        assert_eq!(B1500000, 0o10012);
        assert_eq!(B2000000, 0o10013);
        assert_eq!(B2500000, 0o10014);
        assert_eq!(B3000000, 0o10015);
        assert_eq!(B3500000, 0o10016);
        assert_eq!(B4000000, 0o10017);
    }

    #[test]
    fn test_cc_indices() {
        assert_eq!(VINTR, 0);
        assert_eq!(VQUIT, 1);
        assert_eq!(VERASE, 2);
        assert_eq!(VKILL, 3);
        assert_eq!(VEOF, 4);
        assert_eq!(VTIME, 5);
        assert_eq!(VMIN, 6);
        assert_eq!(VSWTC, 7);
        assert_eq!(VSTART, 8);
        assert_eq!(VSTOP, 9);
        assert_eq!(VSUSP, 10);
        assert_eq!(VEOL, 11);
        assert_eq!(VREPRINT, 12);
        assert_eq!(VDISCARD, 13);
        assert_eq!(VWERASE, 14);
        assert_eq!(VLNEXT, 15);
        assert_eq!(VEOL2, 16);
        assert_eq!(NCCS, 32);
    }

    #[test]
    fn test_input_flag_values() {
        assert_eq!(IGNBRK, 0o1);
        assert_eq!(BRKINT, 0o2);
        assert_eq!(IGNPAR, 0o4);
        assert_eq!(PARMRK, 0o10);
        assert_eq!(INPCK, 0o20);
        assert_eq!(ISTRIP, 0o40);
        assert_eq!(INLCR, 0o100);
        assert_eq!(IGNCR, 0o200);
        assert_eq!(ICRNL, 0o400);
        assert_eq!(IXON, 0o2000);
        assert_eq!(IXOFF, 0o10000);
    }

    #[test]
    fn test_output_flag_values() {
        assert_eq!(OPOST, 0o1);
        assert_eq!(ONLCR, 0o4);
    }

    #[test]
    fn test_control_flag_values() {
        assert_eq!(CSIZE, 0o60);
        assert_eq!(CS5, 0o0);
        assert_eq!(CS6, 0o20);
        assert_eq!(CS7, 0o40);
        assert_eq!(CS8, 0o60);
        assert_eq!(CSTOPB, 0o100);
        assert_eq!(CREAD, 0o200);
        assert_eq!(PARENB, 0o400);
        assert_eq!(PARODD, 0o1000);
        assert_eq!(HUPCL, 0o2000);
        assert_eq!(CLOCAL, 0o4000);
        assert_eq!(CBAUD, 0o10017);
    }

    #[test]
    fn test_local_flag_values() {
        assert_eq!(ISIG, 0o1);
        assert_eq!(ICANON, 0o2);
        assert_eq!(ECHO, 0o10);
        assert_eq!(ECHOE, 0o20);
        assert_eq!(ECHOK, 0o40);
        assert_eq!(ECHONL, 0o100);
        assert_eq!(NOFLSH, 0o200);
        assert_eq!(TOSTOP, 0o400);
        assert_eq!(IEXTEN, 0o100000);
    }

    #[test]
    fn test_queue_and_flow_constants() {
        assert_eq!(TCIFLUSH, 0);
        assert_eq!(TCOFLUSH, 1);
        assert_eq!(TCIOFLUSH, 2);
        assert_eq!(TCOOFF, 0);
        assert_eq!(TCOON, 1);
        assert_eq!(TCIOFF, 2);
        assert_eq!(TCION, 3);
    }

    // -----------------------------------------------------------------------
    // Termios struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_termios_default() {
        let t = Termios::default();
        assert_eq!(t.c_iflag, 0);
        assert_eq!(t.c_oflag, 0);
        assert_eq!(t.c_cflag, 0);
        assert_eq!(t.c_lflag, 0);
        assert_eq!(t.c_cc.len(), NCCS);
        assert!(t.c_cc.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_termios_clone() {
        let mut t = Termios {
            c_iflag: ICRNL,
            ..Termios::default()
        };
        t.c_cc[VEOF] = 4;
        let t2 = t.clone();
        assert_eq!(t2.c_iflag, ICRNL);
        assert_eq!(t2.c_cc[VEOF], 4);
    }

    // -----------------------------------------------------------------------
    // valid_optional_actions
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_optional_actions_accept_valid() {
        assert!(valid_optional_actions(TCSANOW));
        assert!(valid_optional_actions(TCSADRAIN));
        assert!(valid_optional_actions(TCSAFLUSH));
    }

    #[test]
    fn test_valid_optional_actions_reject_invalid() {
        assert!(!valid_optional_actions(-1));
        assert!(!valid_optional_actions(3));
        assert!(!valid_optional_actions(100));
        assert!(!valid_optional_actions(i32::MIN));
        assert!(!valid_optional_actions(i32::MAX));
    }

    // -----------------------------------------------------------------------
    // valid_baud_rate
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_baud_rate_standard() {
        for &rate in &[
            B0, B50, B75, B110, B134, B150, B200, B300, B600, B1200, B1800, B2400, B4800, B9600,
            B19200, B38400,
        ] {
            assert!(valid_baud_rate(rate), "B{rate} should be valid");
        }
    }

    #[test]
    fn test_valid_baud_rate_extended() {
        for &rate in &[
            B57600, B115200, B230400, B460800, B500000, B576000, B921600, B1000000, B1152000,
            B1500000, B2000000, B2500000, B3000000, B3500000, B4000000,
        ] {
            assert!(
                valid_baud_rate(rate),
                "extended rate {rate} should be valid"
            );
        }
    }

    #[test]
    fn test_valid_baud_rate_reject_invalid() {
        assert!(!valid_baud_rate(16));
        assert!(!valid_baud_rate(99));
        assert!(!valid_baud_rate(0o10000)); // gap between 15 and 0o10001
        assert!(!valid_baud_rate(u32::MAX));
    }

    // -----------------------------------------------------------------------
    // valid_queue_selector
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_queue_selector_accept_valid() {
        assert!(valid_queue_selector(TCIFLUSH));
        assert!(valid_queue_selector(TCOFLUSH));
        assert!(valid_queue_selector(TCIOFLUSH));
    }

    #[test]
    fn test_valid_queue_selector_reject_invalid() {
        assert!(!valid_queue_selector(-1));
        assert!(!valid_queue_selector(3));
        assert!(!valid_queue_selector(42));
    }

    // -----------------------------------------------------------------------
    // valid_flow_action
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_flow_action_accept_valid() {
        assert!(valid_flow_action(TCOOFF));
        assert!(valid_flow_action(TCOON));
        assert!(valid_flow_action(TCIOFF));
        assert!(valid_flow_action(TCION));
    }

    #[test]
    fn test_valid_flow_action_reject_invalid() {
        assert!(!valid_flow_action(-1));
        assert!(!valid_flow_action(4));
        assert!(!valid_flow_action(255));
    }

    // -----------------------------------------------------------------------
    // tcgetattr / tcsetattr placeholders
    // -----------------------------------------------------------------------

    #[test]
    fn test_tcgetattr_placeholder_returns_minus_one_without_mutation() {
        let mut t = Termios {
            c_iflag: ICRNL,
            c_oflag: OPOST,
            c_cflag: B9600 | CREAD,
            c_lflag: ICANON,
            c_cc: [0u8; NCCS],
        };
        let before = t.clone();
        let rc = tcgetattr(-1, &mut t);
        assert_eq!(rc, -1);
        assert_eq!(t.c_iflag, before.c_iflag);
        assert_eq!(t.c_oflag, before.c_oflag);
        assert_eq!(t.c_cflag, before.c_cflag);
        assert_eq!(t.c_lflag, before.c_lflag);
        assert_eq!(t.c_cc, before.c_cc);
    }

    #[test]
    fn test_tcsetattr_placeholder_returns_minus_one_for_valid_actions() {
        let t = Termios::default();
        for &act in &[TCSANOW, TCSADRAIN, TCSAFLUSH] {
            assert_eq!(tcsetattr(-1, act, &t), -1);
        }
    }

    #[test]
    fn test_tcsetattr_placeholder_rejects_invalid_action_values() {
        let t = Termios::default();
        for &act in &[-1, 3, 99, i32::MIN, i32::MAX] {
            assert_eq!(tcsetattr(-1, act, &t), -1);
        }
    }

    // -----------------------------------------------------------------------
    // cfgetispeed / cfgetospeed
    // -----------------------------------------------------------------------

    #[test]
    fn test_cfgetispeed_zero() {
        let t = Termios::default();
        assert_eq!(cfgetispeed(&t), B0);
    }

    #[test]
    fn test_cfgetospeed_zero() {
        let t = Termios::default();
        assert_eq!(cfgetospeed(&t), B0);
    }

    #[test]
    fn test_cfgetispeed_standard_rates() {
        for &rate in &[B0, B50, B9600, B38400] {
            let t = Termios {
                c_cflag: rate | CREAD,
                ..Termios::default()
            };
            assert_eq!(cfgetispeed(&t), rate);
        }
    }

    #[test]
    fn test_cfgetospeed_extended_rates() {
        for &rate in &[B57600, B115200, B4000000] {
            let t = Termios {
                c_cflag: rate | CREAD | CS8,
                ..Termios::default()
            };
            assert_eq!(cfgetospeed(&t), rate);
        }
    }

    #[test]
    fn test_cfget_speed_ignores_non_baud_bits() {
        // Set CREAD, CS8, PARENB alongside baud rate.
        let t = Termios {
            c_cflag: B9600 | CREAD | CS8 | PARENB,
            ..Termios::default()
        };
        assert_eq!(cfgetispeed(&t), B9600);
        assert_eq!(cfgetospeed(&t), B9600);
    }

    // -----------------------------------------------------------------------
    // cfsetispeed / cfsetospeed
    // -----------------------------------------------------------------------

    #[test]
    fn test_cfsetispeed_success() {
        let mut t = Termios::default();
        assert_eq!(cfsetispeed(&mut t, B9600), 0);
        assert_eq!(cfgetispeed(&t), B9600);
    }

    #[test]
    fn test_cfsetospeed_success() {
        let mut t = Termios::default();
        assert_eq!(cfsetospeed(&mut t, B115200), 0);
        assert_eq!(cfgetospeed(&t), B115200);
    }

    #[test]
    fn test_cfsetispeed_preserves_other_bits() {
        let mut t = Termios {
            c_cflag: CREAD | CS8 | PARENB | B9600,
            ..Termios::default()
        };
        assert_eq!(cfsetispeed(&mut t, B38400), 0);
        assert_eq!(cfgetispeed(&t), B38400);
        // Non-baud bits must be preserved.
        assert_ne!(t.c_cflag & CREAD, 0);
        assert_ne!(t.c_cflag & PARENB, 0);
        assert_eq!(t.c_cflag & CSIZE, CS8);
    }

    #[test]
    fn test_cfsetospeed_preserves_other_bits() {
        let mut t = Termios {
            c_cflag: CREAD | CS8 | B9600,
            ..Termios::default()
        };
        assert_eq!(cfsetospeed(&mut t, B57600), 0);
        assert_eq!(cfgetospeed(&t), B57600);
        assert_ne!(t.c_cflag & CREAD, 0);
        assert_eq!(t.c_cflag & CSIZE, CS8);
    }

    #[test]
    fn test_cfsetispeed_invalid_returns_minus_one() {
        let mut t = Termios::default();
        assert_eq!(cfsetispeed(&mut t, 999), -1);
        // Struct must be unchanged.
        assert_eq!(t.c_cflag, 0);
    }

    #[test]
    fn test_cfsetospeed_invalid_returns_minus_one() {
        let mut t = Termios {
            c_cflag: CREAD | B9600,
            ..Termios::default()
        };
        let before = t.c_cflag;
        assert_eq!(cfsetospeed(&mut t, 0xDEAD), -1);
        assert_eq!(t.c_cflag, before);
    }

    #[test]
    fn test_cfset_speed_b0_hangup() {
        let mut t = Termios {
            c_cflag: B9600 | CREAD,
            ..Termios::default()
        };
        assert_eq!(cfsetospeed(&mut t, B0), 0);
        assert_eq!(cfgetospeed(&t), B0);
        assert_ne!(t.c_cflag & CREAD, 0);
    }

    #[test]
    fn test_cfsetispeed_all_standard_rates() {
        let rates = [
            B0, B50, B75, B110, B134, B150, B200, B300, B600, B1200, B1800, B2400, B4800, B9600,
            B19200, B38400,
        ];
        for &rate in &rates {
            let mut t = Termios::default();
            assert_eq!(cfsetispeed(&mut t, rate), 0);
            assert_eq!(cfgetispeed(&t), rate);
        }
    }

    #[test]
    fn test_cfsetospeed_all_extended_rates() {
        let rates = [
            B57600, B115200, B230400, B460800, B500000, B576000, B921600, B1000000, B1152000,
            B1500000, B2000000, B2500000, B3000000, B3500000, B4000000,
        ];
        for &rate in &rates {
            let mut t = Termios::default();
            assert_eq!(cfsetospeed(&mut t, rate), 0);
            assert_eq!(cfgetospeed(&t), rate);
        }
    }

    // -----------------------------------------------------------------------
    // cfmakeraw
    // -----------------------------------------------------------------------

    #[test]
    fn test_cfmakeraw_from_default() {
        let mut t = Termios::default();
        cfmakeraw(&mut t);

        // Input flags: all specified bits must be cleared.
        let raw_iflag_mask = IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON;
        assert_eq!(t.c_iflag & raw_iflag_mask, 0);

        // Output flags: OPOST must be cleared.
        assert_eq!(t.c_oflag & OPOST, 0);

        // Local flags: all specified bits must be cleared.
        let raw_lflag_mask = ECHO | ECHONL | ICANON | ISIG | IEXTEN;
        assert_eq!(t.c_lflag & raw_lflag_mask, 0);

        // Control flags: CSIZE must be CS8, PARENB must be cleared.
        assert_eq!(t.c_cflag & CSIZE, CS8);
        assert_eq!(t.c_cflag & PARENB, 0);

        // VMIN=1, VTIME=0.
        assert_eq!(t.c_cc[VMIN], 1);
        assert_eq!(t.c_cc[VTIME], 0);
    }

    #[test]
    fn test_cfmakeraw_from_cooked() {
        // Start with a typical "cooked" terminal configuration.
        let mut t = Termios {
            c_iflag: ICRNL | IXON | BRKINT | IGNPAR,
            c_oflag: OPOST | ONLCR,
            c_cflag: B9600 | CREAD | CSIZE | PARENB,
            c_lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | IEXTEN,
            c_cc: [0u8; NCCS],
        };
        t.c_cc[VEOF] = 4; // Ctrl-D
        t.c_cc[VINTR] = 3; // Ctrl-C
        t.c_cc[VMIN] = 0;
        t.c_cc[VTIME] = 10;

        cfmakeraw(&mut t);

        // Input: ICRNL, IXON, BRKINT cleared; IGNPAR untouched.
        assert_eq!(t.c_iflag & ICRNL, 0);
        assert_eq!(t.c_iflag & IXON, 0);
        assert_eq!(t.c_iflag & BRKINT, 0);
        assert_ne!(t.c_iflag & IGNPAR, 0, "IGNPAR should be preserved");

        // Output: OPOST cleared; ONLCR untouched (cfmakeraw only clears OPOST).
        assert_eq!(t.c_oflag & OPOST, 0);
        assert_ne!(t.c_oflag & ONLCR, 0, "ONLCR not in cfmakeraw mask");

        // Local: ISIG, ICANON, ECHO, IEXTEN cleared; ECHOE, ECHOK untouched.
        assert_eq!(t.c_lflag & ISIG, 0);
        assert_eq!(t.c_lflag & ICANON, 0);
        assert_eq!(t.c_lflag & ECHO, 0);
        assert_eq!(t.c_lflag & IEXTEN, 0);
        assert_ne!(t.c_lflag & ECHOE, 0);
        assert_ne!(t.c_lflag & ECHOK, 0);

        // Control: CS8 set, PARENB cleared, CREAD + baud preserved.
        assert_eq!(t.c_cflag & CSIZE, CS8);
        assert_eq!(t.c_cflag & PARENB, 0);
        assert_ne!(t.c_cflag & CREAD, 0);
        assert_eq!(cfgetospeed(&t), B9600);

        // c_cc: VMIN=1, VTIME=0; other entries preserved.
        assert_eq!(t.c_cc[VMIN], 1);
        assert_eq!(t.c_cc[VTIME], 0);
        assert_eq!(t.c_cc[VEOF], 4);
        assert_eq!(t.c_cc[VINTR], 3);
    }

    #[test]
    fn test_cfmakeraw_idempotent() {
        let mut t = Termios::default();
        cfmakeraw(&mut t);
        let snapshot = t.clone();
        cfmakeraw(&mut t);
        assert_eq!(t.c_iflag, snapshot.c_iflag);
        assert_eq!(t.c_oflag, snapshot.c_oflag);
        assert_eq!(t.c_cflag, snapshot.c_cflag);
        assert_eq!(t.c_lflag, snapshot.c_lflag);
        assert_eq!(t.c_cc, snapshot.c_cc);
    }

    #[test]
    fn test_cfmakeraw_then_set_speed() {
        let mut t = Termios::default();
        cfmakeraw(&mut t);
        assert_eq!(cfsetospeed(&mut t, B115200), 0);
        assert_eq!(cfgetospeed(&t), B115200);
        // CS8 must still be set after speed change.
        assert_eq!(t.c_cflag & CSIZE, CS8);
    }

    // -----------------------------------------------------------------------
    // Combined / integration-style
    // -----------------------------------------------------------------------

    #[test]
    fn test_cbaud_mask_covers_all_baud_constants() {
        for &rate in &VALID_BAUDS {
            assert_eq!(
                rate & CBAUD,
                rate,
                "baud rate {rate:#o} must fit within CBAUD mask"
            );
        }
    }

    #[test]
    fn test_cc_indices_within_nccs() {
        let indices = [
            VINTR, VQUIT, VERASE, VKILL, VEOF, VTIME, VMIN, VSWTC, VSTART, VSTOP, VSUSP, VEOL,
            VREPRINT, VDISCARD, VWERASE, VLNEXT, VEOL2,
        ];
        for &idx in &indices {
            assert!(idx < NCCS, "c_cc index {idx} must be < NCCS ({NCCS})");
        }
    }

    #[test]
    fn test_csize_variants_within_mask() {
        assert_eq!(CS5 & CSIZE, CS5);
        assert_eq!(CS6 & CSIZE, CS6);
        assert_eq!(CS7 & CSIZE, CS7);
        assert_eq!(CS8 & CSIZE, CS8);
    }

    #[test]
    fn test_input_flags_no_overlap_with_other_categories() {
        // Sanity: input flag bits should not collide with local flag bits we use.
        // (Not exhaustive, just a spot check.)
        let all_iflag = IGNBRK
            | BRKINT
            | IGNPAR
            | PARMRK
            | INPCK
            | ISTRIP
            | INLCR
            | IGNCR
            | ICRNL
            | IXON
            | IXOFF;
        // IEXTEN is 0o100000 which is well above input flag range 0o1..0o10000
        assert_eq!(all_iflag & IEXTEN, 0);
    }
}
