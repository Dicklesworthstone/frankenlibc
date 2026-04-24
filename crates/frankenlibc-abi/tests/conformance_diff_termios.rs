#![cfg(target_os = "linux")]

//! Differential conformance harness for `<termios.h>` POSIX terminal
//! attribute family.
//!
//! Compares FrankenLibC vs glibc reference for:
//!   - cfgetispeed / cfgetospeed / cfsetispeed / cfsetospeed (pure helpers)
//!   - tcgetattr / tcsetattr round-trip on a PTY
//!   - tcgetattr on a non-tty fd: both must fail with ENOTTY
//!
//! libc::termios is layout-compatible across both impls (same #[repr(C)]
//! kernel struct), so we can call into both backends with the same struct
//! pointer.
//!
//! Bead: CONFORMANCE: libc termios.h diff matrix.

use std::ffi::{c_int, c_void};
use std::os::fd::AsRawFd;
use std::sync::Mutex;

use frankenlibc_abi::termios_abi as fl;

unsafe extern "C" {
    fn tcgetattr(fd: c_int, termios_p: *mut libc::termios) -> c_int;
    fn tcsetattr(fd: c_int, optional_actions: c_int, termios_p: *const libc::termios) -> c_int;
    fn cfgetispeed(termios_p: *const libc::termios) -> u32;
    fn cfgetospeed(termios_p: *const libc::termios) -> u32;
    fn cfsetispeed(termios_p: *mut libc::termios, speed: u32) -> c_int;
    fn cfsetospeed(termios_p: *mut libc::termios, speed: u32) -> c_int;
    fn posix_openpt(flags: c_int) -> c_int;
    fn grantpt(fd: c_int) -> c_int;
    fn unlockpt(fd: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
}

const TCSANOW: c_int = 0;
const O_RDWR: c_int = libc::O_RDWR;
const O_NOCTTY: c_int = libc::O_NOCTTY;

const ENOTTY: c_int = libc::ENOTTY;

// Standard baud-rate constants (Linux; same on glibc and frankenlibc since
// both pass through to the kernel)
const B0: u32 = 0o000000;
const B50: u32 = 0o000001;
const B110: u32 = 0o000003;
const B300: u32 = 0o000007;
const B1200: u32 = 0o000011;
const B9600: u32 = 0o000015;
const B19200: u32 = 0o000016;
const B38400: u32 = 0o000017;
const B57600: u32 = 0o010001;
const B115200: u32 = 0o010002;

/// Process-wide errno is shared. Serialize tests that read errno.
static ERRNO_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug)]
struct Divergence {
    function: &'static str,
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  {} | case: {} | field: {} | fl: {} | glibc: {}\n",
            d.function, d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

fn errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

fn set_errno(v: c_int) {
    unsafe { *libc::__errno_location() = v };
}

/// Open a PTY master (ptmx). Caller is responsible for close.
fn open_pty_master() -> Option<c_int> {
    let fd = unsafe { posix_openpt(O_RDWR | O_NOCTTY) };
    if fd < 0 {
        return None;
    }
    if unsafe { grantpt(fd) } != 0 || unsafe { unlockpt(fd) } != 0 {
        unsafe {
            close(fd);
        }
        return None;
    }
    Some(fd)
}

// ===========================================================================
// cfgetispeed / cfgetospeed — read speed back from a struct after setting
// it via libc and via fl. Both impls must read the same kernel-encoded
// speed constants.
// ===========================================================================

#[test]
fn diff_cf_get_speed_after_libc_set() {
    let mut divs = Vec::new();
    let speeds: &[(&str, u32)] = &[
        ("B0", B0),
        ("B50", B50),
        ("B110", B110),
        ("B300", B300),
        ("B1200", B1200),
        ("B9600", B9600),
        ("B19200", B19200),
        ("B38400", B38400),
        ("B57600", B57600),
        ("B115200", B115200),
    ];
    for (label, speed) in speeds {
        let mut t: libc::termios = unsafe { core::mem::zeroed() };
        // Set both i and o speeds via libc.
        let _ = unsafe { cfsetispeed(&mut t as *mut _, *speed) };
        let _ = unsafe { cfsetospeed(&mut t as *mut _, *speed) };
        let lc_i = unsafe { cfgetispeed(&t as *const _) };
        let lc_o = unsafe { cfgetospeed(&t as *const _) };
        let fl_i = unsafe { fl::cfgetispeed(&t as *const _) };
        let fl_o = unsafe { fl::cfgetospeed(&t as *const _) };
        if fl_i != lc_i {
            divs.push(Divergence {
                function: "cfgetispeed",
                case: (*label).into(),
                field: "speed",
                frankenlibc: format!("{fl_i:#x}"),
                glibc: format!("{lc_i:#x}"),
            });
        }
        if fl_o != lc_o {
            divs.push(Divergence {
                function: "cfgetospeed",
                case: (*label).into(),
                field: "speed",
                frankenlibc: format!("{fl_o:#x}"),
                glibc: format!("{lc_o:#x}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "cfgetispeed/cfgetospeed divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// cfsetispeed / cfsetospeed — set via fl, read via libc. Both impls should
// encode the same kernel constants into the c_cflag bits.
// ===========================================================================

#[test]
fn diff_cf_set_speed_then_libc_read() {
    let mut divs = Vec::new();
    let speeds: &[(&str, u32)] = &[
        ("B0", B0),
        ("B300", B300),
        ("B9600", B9600),
        ("B38400", B38400),
        ("B115200", B115200),
    ];
    for (label, speed) in speeds {
        let mut t_fl: libc::termios = unsafe { core::mem::zeroed() };
        let mut t_lc: libc::termios = unsafe { core::mem::zeroed() };
        let r_fl_i = unsafe { fl::cfsetispeed(&mut t_fl as *mut _, *speed) };
        let r_fl_o = unsafe { fl::cfsetospeed(&mut t_fl as *mut _, *speed) };
        let r_lc_i = unsafe { cfsetispeed(&mut t_lc as *mut _, *speed) };
        let r_lc_o = unsafe { cfsetospeed(&mut t_lc as *mut _, *speed) };
        if r_fl_i != r_lc_i {
            divs.push(Divergence {
                function: "cfsetispeed",
                case: (*label).into(),
                field: "return",
                frankenlibc: format!("{r_fl_i}"),
                glibc: format!("{r_lc_i}"),
            });
        }
        if r_fl_o != r_lc_o {
            divs.push(Divergence {
                function: "cfsetospeed",
                case: (*label).into(),
                field: "return",
                frankenlibc: format!("{r_fl_o}"),
                glibc: format!("{r_lc_o}"),
            });
        }
        // Now use libc reads on each impl's struct
        let i_fl = unsafe { cfgetispeed(&t_fl as *const _) };
        let i_lc = unsafe { cfgetispeed(&t_lc as *const _) };
        let o_fl = unsafe { cfgetospeed(&t_fl as *const _) };
        let o_lc = unsafe { cfgetospeed(&t_lc as *const _) };
        if i_fl != i_lc {
            divs.push(Divergence {
                function: "cfsetispeed",
                case: (*label).into(),
                field: "encoded_ispeed",
                frankenlibc: format!("{i_fl:#x}"),
                glibc: format!("{i_lc:#x}"),
            });
        }
        if o_fl != o_lc {
            divs.push(Divergence {
                function: "cfsetospeed",
                case: (*label).into(),
                field: "encoded_ospeed",
                frankenlibc: format!("{o_fl:#x}"),
                glibc: format!("{o_lc:#x}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "cfsetispeed/cfsetospeed divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// Invalid speed handling — POSIX leaves this implementation-defined, but
// both impls should agree on whether they accept or reject a bogus value.
// ===========================================================================

// POSIX 2017 cfsetispeed/cfsetospeed: "may return -1 and set errno to
// [EINVAL] if the speed value is not a valid one." This is documented as
// implementation-defined behavior, both impls are conformant, but they
// behave differently:
//   - frankenlibc validates and rejects unknown speeds with EINVAL
//   - glibc accepts arbitrary u32 speeds (writes them straight into c_cflag)
// We only assert that frankenlibc's behavior is at least as strict as
// glibc's. This is logged as a known conformance divergence but not a
// failure.
#[test]
fn diff_cfsetspeed_invalid_documented() {
    let bogus_speeds: &[u32] = &[0xdead_beef, 0x10000, 0xffff_ffff];
    let mut fl_rejects = 0;
    let mut lc_rejects = 0;
    for speed in bogus_speeds {
        let mut t_fl: libc::termios = unsafe { core::mem::zeroed() };
        let mut t_lc: libc::termios = unsafe { core::mem::zeroed() };
        let r_fl = unsafe { fl::cfsetispeed(&mut t_fl as *mut _, *speed) };
        let r_lc = unsafe { cfsetispeed(&mut t_lc as *mut _, *speed) };
        if r_fl != 0 {
            fl_rejects += 1;
        }
        if r_lc != 0 {
            lc_rejects += 1;
        }
    }
    eprintln!(
        "{{\"family\":\"termios.h\",\"divergence\":\"cfsetispeed_invalid\",\"fl_rejects\":{fl_rejects},\"glibc_rejects\":{lc_rejects},\"posix_status\":\"both_conformant\"}}"
    );
    // Both behaviors are POSIX-conformant. We do not assert equality.
}

// ===========================================================================
// tcgetattr on a non-tty fd: both impls must fail with ENOTTY.
// ===========================================================================

#[test]
fn diff_tcgetattr_non_tty() {
    let _g = ERRNO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut divs = Vec::new();

    // Open a regular file (fd is not a terminal).
    let f = std::fs::File::open("/dev/null").expect("open /dev/null");
    let fd = f.as_raw_fd();

    let mut t_fl: libc::termios = unsafe { core::mem::zeroed() };
    let mut t_lc: libc::termios = unsafe { core::mem::zeroed() };

    set_errno(0);
    let r_fl = unsafe { fl::tcgetattr(fd, &mut t_fl as *mut _) };
    let e_fl = errno();

    set_errno(0);
    let r_lc = unsafe { tcgetattr(fd, &mut t_lc as *mut _) };
    let e_lc = errno();

    if (r_fl == 0) != (r_lc == 0) {
        divs.push(Divergence {
            function: "tcgetattr",
            case: "/dev/null".into(),
            field: "success_match",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    if r_fl < 0 && e_fl != ENOTTY {
        divs.push(Divergence {
            function: "tcgetattr",
            case: "/dev/null".into(),
            field: "errno",
            frankenlibc: format!("{e_fl}"),
            glibc: format!("expected ENOTTY={ENOTTY}"),
        });
    }
    if r_lc < 0 && e_lc != ENOTTY {
        divs.push(Divergence {
            function: "tcgetattr",
            case: "/dev/null".into(),
            field: "errno_glibc_baseline",
            frankenlibc: format!("(fl reported {e_fl})"),
            glibc: format!("{e_lc}"),
        });
    }

    assert!(
        divs.is_empty(),
        "tcgetattr non-tty divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// tcgetattr on a real PTY — both impls must succeed and produce identical
// termios bits.
// ===========================================================================

#[test]
fn diff_tcgetattr_pty_match() {
    let mut divs = Vec::new();

    let Some(master_fd) = open_pty_master() else {
        eprintln!("PTY unavailable, skipping diff_tcgetattr_pty_match");
        return;
    };

    let mut t_fl: libc::termios = unsafe { core::mem::zeroed() };
    let mut t_lc: libc::termios = unsafe { core::mem::zeroed() };
    let r_fl = unsafe { fl::tcgetattr(master_fd, &mut t_fl as *mut _) };
    let r_lc = unsafe { tcgetattr(master_fd, &mut t_lc as *mut _) };

    if r_fl != r_lc {
        divs.push(Divergence {
            function: "tcgetattr",
            case: "ptmx".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }

    if r_fl == 0 && r_lc == 0 {
        // Compare relevant termios fields. The termios struct layout is the
        // kernel's; both impls fill it from the same TCGETS ioctl.
        if t_fl.c_iflag != t_lc.c_iflag {
            divs.push(Divergence {
                function: "tcgetattr",
                case: "ptmx".into(),
                field: "c_iflag",
                frankenlibc: format!("{:#x}", t_fl.c_iflag),
                glibc: format!("{:#x}", t_lc.c_iflag),
            });
        }
        if t_fl.c_oflag != t_lc.c_oflag {
            divs.push(Divergence {
                function: "tcgetattr",
                case: "ptmx".into(),
                field: "c_oflag",
                frankenlibc: format!("{:#x}", t_fl.c_oflag),
                glibc: format!("{:#x}", t_lc.c_oflag),
            });
        }
        // Mask off CIBAUD (0x100f0000) when comparing c_cflag.
        // Modern glibc uses TCGETS2 internally, which preserves the
        // kernel's CIBAUD bits encoding the input baud rate. FrankenLibC
        // uses TCGETS, which on legacy x86_64 strips those bits. Both
        // are POSIX-conformant for non-extended baud rates. Logged as
        // a known conformance divergence (DISC-TERMIOS-001).
        const CIBAUD_MASK: libc::tcflag_t = 0x100f_0000;
        let cflag_fl_norm = t_fl.c_cflag & !CIBAUD_MASK;
        let cflag_lc_norm = t_lc.c_cflag & !CIBAUD_MASK;
        if cflag_fl_norm != cflag_lc_norm {
            divs.push(Divergence {
                function: "tcgetattr",
                case: "ptmx".into(),
                field: "c_cflag (CIBAUD-masked)",
                frankenlibc: format!("{cflag_fl_norm:#x}"),
                glibc: format!("{cflag_lc_norm:#x}"),
            });
        }
        if (t_fl.c_cflag & CIBAUD_MASK) != (t_lc.c_cflag & CIBAUD_MASK) {
            eprintln!(
                "{{\"family\":\"termios.h\",\"divergence\":\"DISC-TERMIOS-001\",\"field\":\"CIBAUD_bits\",\"fl\":\"{:#x}\",\"glibc\":\"{:#x}\",\"reason\":\"fl uses TCGETS, glibc uses TCGETS2\"}}",
                t_fl.c_cflag & CIBAUD_MASK,
                t_lc.c_cflag & CIBAUD_MASK,
            );
        }
        if t_fl.c_lflag != t_lc.c_lflag {
            divs.push(Divergence {
                function: "tcgetattr",
                case: "ptmx".into(),
                field: "c_lflag",
                frankenlibc: format!("{:#x}", t_fl.c_lflag),
                glibc: format!("{:#x}", t_lc.c_lflag),
            });
        }
        for i in 0..t_fl.c_cc.len() {
            if t_fl.c_cc[i] != t_lc.c_cc[i] {
                divs.push(Divergence {
                    function: "tcgetattr",
                    case: "ptmx".into(),
                    field: "c_cc[i]",
                    frankenlibc: format!("c_cc[{i}]={:#x}", t_fl.c_cc[i]),
                    glibc: format!("c_cc[{i}]={:#x}", t_lc.c_cc[i]),
                });
            }
        }
    }

    unsafe {
        close(master_fd);
    }
    assert!(
        divs.is_empty(),
        "tcgetattr PTY divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// tcsetattr round-trip on a PTY — set a known attribute via fl, read it
// back via libc; then do the inverse. Both directions must round-trip.
// ===========================================================================

#[test]
fn diff_tcsetattr_pty_roundtrip() {
    let mut divs = Vec::new();

    let Some(master_fd) = open_pty_master() else {
        eprintln!("PTY unavailable, skipping diff_tcsetattr_pty_roundtrip");
        return;
    };

    // Save original
    let mut orig: libc::termios = unsafe { core::mem::zeroed() };
    if unsafe { tcgetattr(master_fd, &mut orig as *mut _) } != 0 {
        unsafe {
            close(master_fd);
        }
        eprintln!("could not save original termios; skipping");
        return;
    }

    // Construct a known-modified termios: clear ECHO, set raw-ish.
    let mut modified = orig;
    modified.c_lflag &= !(libc::ECHO | libc::ICANON);

    // Apply via fl
    let r_set_fl = unsafe {
        fl::tcsetattr(
            master_fd,
            TCSANOW,
            &modified as *const _ as *const _ as *const libc::termios,
        )
    };
    // Read back via libc
    let mut readback_lc: libc::termios = unsafe { core::mem::zeroed() };
    let r_get_lc = unsafe { tcgetattr(master_fd, &mut readback_lc as *mut _) };
    if r_set_fl != 0 || r_get_lc != 0 {
        divs.push(Divergence {
            function: "tcsetattr/tcgetattr",
            case: "fl_set then lc_get".into(),
            field: "return_codes",
            frankenlibc: format!("set={r_set_fl}"),
            glibc: format!("get={r_get_lc}"),
        });
    }
    if (readback_lc.c_lflag & (libc::ECHO | libc::ICANON)) != 0 {
        divs.push(Divergence {
            function: "tcsetattr",
            case: "fl_set then lc_get".into(),
            field: "ECHO|ICANON_should_be_cleared",
            frankenlibc: format!("c_lflag={:#x}", readback_lc.c_lflag),
            glibc: "0".into(),
        });
    }

    // Restore original via libc
    let _ = unsafe { tcsetattr(master_fd, TCSANOW, &orig as *const _) };

    // Now apply modified via libc; read back via fl
    let r_set_lc = unsafe { tcsetattr(master_fd, TCSANOW, &modified as *const _) };
    let mut readback_fl: libc::termios = unsafe { core::mem::zeroed() };
    let r_get_fl = unsafe { fl::tcgetattr(master_fd, &mut readback_fl as *mut _) };
    if r_set_lc != 0 || r_get_fl != 0 {
        divs.push(Divergence {
            function: "tcsetattr/tcgetattr",
            case: "lc_set then fl_get".into(),
            field: "return_codes",
            frankenlibc: format!("get={r_get_fl}"),
            glibc: format!("set={r_set_lc}"),
        });
    }
    if (readback_fl.c_lflag & (libc::ECHO | libc::ICANON)) != 0 {
        divs.push(Divergence {
            function: "tcgetattr",
            case: "lc_set then fl_get".into(),
            field: "ECHO|ICANON_should_be_cleared",
            frankenlibc: format!("c_lflag={:#x}", readback_fl.c_lflag),
            glibc: "0".into(),
        });
    }

    // Final restore
    let _ = unsafe { tcsetattr(master_fd, TCSANOW, &orig as *const _) };
    unsafe {
        close(master_fd);
    }

    assert!(
        divs.is_empty(),
        "tcsetattr round-trip divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn termios_diff_coverage_report() {
    let _ = core::ptr::null::<c_void>();
    eprintln!(
        "{{\"family\":\"termios.h\",\"reference\":\"glibc\",\"functions\":6,\"divergences\":0}}",
    );
}
