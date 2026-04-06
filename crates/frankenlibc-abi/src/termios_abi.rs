//! ABI layer for `<termios.h>` functions.
//!
//! Terminal attribute manipulation via `ioctl`/`libc` syscalls.
//! Pure-logic helpers (baud rate extraction, cfmakeraw) delegate
//! to `frankenlibc_core::termios`.

use std::collections::HashMap;
use std::ffi::c_int;
use std::sync::{LazyLock, Mutex};

use frankenlibc_core::errno;
use frankenlibc_core::syscall;
use frankenlibc_core::termios as termios_core;
use frankenlibc_membrane::rough_path::{RoughPathMonitor, SignatureState as RoughPathState};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::runtime_policy;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TerminalModeClass {
    Cooked,
    Cbreak,
    Raw,
    NonCanonical,
}

impl TerminalModeClass {
    const fn code(self) -> f64 {
        match self {
            Self::Cooked => 0.0,
            Self::Cbreak => 1.0 / 3.0,
            Self::Raw => 2.0 / 3.0,
            Self::NonCanonical => 1.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SpeedCoupling {
    Coupled,
    Diverged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ApplyDisposition {
    Immediate,
    Drain,
    Flush,
}

impl ApplyDisposition {
    const fn bit(self) -> u8 {
        match self {
            Self::Immediate => 0b001,
            Self::Drain => 0b010,
            Self::Flush => 0b100,
        }
    }

    const fn code(self) -> f64 {
        match self {
            Self::Immediate => 0.0,
            Self::Drain => 0.5,
            Self::Flush => 1.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TerminalSignatureClass {
    mode: TerminalModeClass,
    echo_enabled: bool,
    speed_coupling: SpeedCoupling,
}

impl TerminalSignatureClass {
    fn from_termios(termios: &libc::termios) -> Self {
        Self {
            mode: classify_mode(termios),
            echo_enabled: (termios.c_lflag & libc::ECHO) != 0,
            speed_coupling: classify_speed_coupling(termios),
        }
    }

    const fn is_legal(self) -> bool {
        !matches!(
            (self.mode, self.speed_coupling),
            (TerminalModeClass::Cooked, SpeedCoupling::Diverged)
        )
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalTransitionKind {
    Stable,
    ModeShift,
    EchoShift,
    SpeedShift,
    Composite,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TerminalTransitionReport {
    previous: TerminalSignatureClass,
    current: TerminalSignatureClass,
    kind: TerminalTransitionKind,
    apply: ApplyDisposition,
    mode_axis_changed: bool,
    echo_axis_changed: bool,
    speed_axis_changed: bool,
    is_legal: bool,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct TerminalSequenceSignature {
    final_class: Option<TerminalSignatureClass>,
    mode_axis_changes: u8,
    echo_axis_changes: u8,
    speed_axis_changes: u8,
    action_mask: u8,
}

impl TerminalSequenceSignature {
    fn observe(&mut self, report: TerminalTransitionReport) {
        self.final_class = Some(report.current);
        self.mode_axis_changes = self
            .mode_axis_changes
            .saturating_add(u8::from(report.mode_axis_changed));
        self.echo_axis_changes = self
            .echo_axis_changes
            .saturating_add(u8::from(report.echo_axis_changed));
        self.speed_axis_changes = self
            .speed_axis_changes
            .saturating_add(u8::from(report.speed_axis_changed));
        self.action_mask |= report.apply.bit();
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn equivalent_to(&self, other: &Self) -> bool {
        self.final_class == other.final_class
            && self.mode_axis_changes == other.mode_axis_changes
            && self.echo_axis_changes == other.echo_axis_changes
            && self.speed_axis_changes == other.speed_axis_changes
            && self.action_mask == other.action_mask
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq)]
struct TerminalTrackerSummary {
    current: TerminalSignatureClass,
    rough_path_state: RoughPathState,
    anomaly_score: f64,
    illegal_transition_count: u64,
    sequence_signature: TerminalSequenceSignature,
    is_legal: bool,
}

struct TerminalSignatureTracker {
    rough_path: RoughPathMonitor,
    sequence_signature: TerminalSequenceSignature,
    illegal_transition_count: u64,
    last_summary: Option<TerminalTrackerSummary>,
}

impl TerminalSignatureTracker {
    fn new() -> Self {
        Self {
            rough_path: RoughPathMonitor::new(),
            sequence_signature: TerminalSequenceSignature::default(),
            illegal_transition_count: 0,
            last_summary: None,
        }
    }

    fn observe(&mut self, report: TerminalTransitionReport) -> TerminalTrackerSummary {
        self.sequence_signature.observe(report);
        self.rough_path.observe(rough_path_observation(report));
        if !report.is_legal {
            self.illegal_transition_count = self.illegal_transition_count.saturating_add(1);
        }
        let rough_summary = self.rough_path.summary();
        let summary = TerminalTrackerSummary {
            current: report.current,
            rough_path_state: rough_summary.state,
            anomaly_score: rough_summary.anomaly_score,
            illegal_transition_count: self.illegal_transition_count,
            sequence_signature: self.sequence_signature,
            is_legal: report.is_legal,
        };
        self.last_summary = Some(summary);
        summary
    }

    #[cfg(test)]
    fn last_summary(&self) -> Option<TerminalTrackerSummary> {
        self.last_summary
    }
}

static FD_SIGNATURE_TRACKERS: LazyLock<Mutex<HashMap<c_int, TerminalSignatureTracker>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static PTR_SIGNATURE_TRACKERS: LazyLock<Mutex<HashMap<usize, TerminalSignatureTracker>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn apply_disposition(optional_actions: c_int) -> ApplyDisposition {
    match optional_actions {
        x if x == libc::TCSADRAIN => ApplyDisposition::Drain,
        x if x == libc::TCSAFLUSH => ApplyDisposition::Flush,
        _ => ApplyDisposition::Immediate,
    }
}

fn classify_mode(termios: &libc::termios) -> TerminalModeClass {
    let c_lflag = termios.c_lflag;
    if is_raw_like(termios) {
        TerminalModeClass::Raw
    } else if (c_lflag & libc::ICANON) != 0 {
        TerminalModeClass::Cooked
    } else if (c_lflag & libc::ISIG) != 0 {
        TerminalModeClass::Cbreak
    } else {
        TerminalModeClass::NonCanonical
    }
}

fn is_raw_like(termios: &libc::termios) -> bool {
    let c_iflag = termios.c_iflag;
    let c_oflag = termios.c_oflag;
    let c_cflag = termios.c_cflag;
    let c_lflag = termios.c_lflag;
    let raw_iflag_mask = termios_core::IGNBRK
        | termios_core::BRKINT
        | termios_core::PARMRK
        | termios_core::ISTRIP
        | termios_core::INLCR
        | termios_core::IGNCR
        | termios_core::ICRNL
        | termios_core::IXON;

    (c_lflag
        & (termios_core::ICANON | termios_core::ECHO | termios_core::ISIG | termios_core::IEXTEN))
        == 0
        && (c_iflag & raw_iflag_mask) == 0
        && (c_oflag & termios_core::OPOST) == 0
        && (c_cflag & termios_core::CSIZE) == termios_core::CS8
        && (c_cflag & termios_core::PARENB) == 0
}

fn classify_speed_coupling(termios: &libc::termios) -> SpeedCoupling {
    if effective_input_speed(termios) == effective_output_speed(termios) {
        SpeedCoupling::Coupled
    } else {
        SpeedCoupling::Diverged
    }
}

fn effective_input_speed(termios: &libc::termios) -> libc::speed_t {
    if termios.c_ispeed != 0 {
        termios.c_ispeed
    } else {
        (termios.c_cflag & termios_core::CBAUD as libc::tcflag_t) as libc::speed_t
    }
}

fn effective_output_speed(termios: &libc::termios) -> libc::speed_t {
    if termios.c_ospeed != 0 {
        termios.c_ospeed
    } else {
        (termios.c_cflag & termios_core::CBAUD as libc::tcflag_t) as libc::speed_t
    }
}

fn analyze_transition(
    before: &libc::termios,
    after: &libc::termios,
    optional_actions: c_int,
) -> TerminalTransitionReport {
    let previous = TerminalSignatureClass::from_termios(before);
    let current = TerminalSignatureClass::from_termios(after);
    let mode_axis_changed = previous.mode != current.mode;
    let echo_axis_changed = previous.echo_enabled != current.echo_enabled;
    let speed_axis_changed = previous.speed_coupling != current.speed_coupling;
    let changed_axes =
        u8::from(mode_axis_changed) + u8::from(echo_axis_changed) + u8::from(speed_axis_changed);
    let kind = match changed_axes {
        0 => TerminalTransitionKind::Stable,
        1 if mode_axis_changed => TerminalTransitionKind::ModeShift,
        1 if echo_axis_changed => TerminalTransitionKind::EchoShift,
        1 => TerminalTransitionKind::SpeedShift,
        _ => TerminalTransitionKind::Composite,
    };

    TerminalTransitionReport {
        previous,
        current,
        kind,
        apply: apply_disposition(optional_actions),
        mode_axis_changed,
        echo_axis_changed,
        speed_axis_changed,
        is_legal: current.is_legal(),
    }
}

fn rough_path_observation(report: TerminalTransitionReport) -> [f64; 4] {
    [
        report.current.mode.code(),
        if report.current.echo_enabled {
            1.0
        } else {
            0.0
        },
        if matches!(report.current.speed_coupling, SpeedCoupling::Diverged) {
            1.0
        } else {
            0.0
        },
        report.apply.code(),
    ]
}

fn observe_fd_transition(
    fd: c_int,
    before: &libc::termios,
    after: &libc::termios,
    optional_actions: c_int,
) -> TerminalTrackerSummary {
    let report = analyze_transition(before, after, optional_actions);
    let mut trackers = FD_SIGNATURE_TRACKERS
        .lock()
        .expect("termios fd signature tracker mutex poisoned");
    trackers
        .entry(fd)
        .or_insert_with(TerminalSignatureTracker::new)
        .observe(report)
}

fn observe_ptr_transition(
    ptr_key: usize,
    before: &libc::termios,
    after: &libc::termios,
    optional_actions: c_int,
) -> TerminalTrackerSummary {
    let report = analyze_transition(before, after, optional_actions);
    let mut trackers = PTR_SIGNATURE_TRACKERS
        .lock()
        .expect("termios pointer signature tracker mutex poisoned");
    trackers
        .entry(ptr_key)
        .or_insert_with(TerminalSignatureTracker::new)
        .observe(report)
}

// ---------------------------------------------------------------------------
// tcgetattr
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tcgetattr(fd: c_int, termios_p: *mut libc::termios) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Termios, fd as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
        return -1;
    }

    if termios_p.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
        return -1;
    }

    let rc = match unsafe { syscall::sys_ioctl(fd, libc::TCGETS as usize, termios_p as usize) } {
        Ok(_) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    let adverse = rc != 0;
    // libc sets errno on failure (EBADF, ENOTTY, etc.) — do not overwrite.
    runtime_policy::observe(ApiFamily::Termios, decision.profile, 10, adverse);
    rc
}

// ---------------------------------------------------------------------------
// tcsetattr
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tcsetattr(
    fd: c_int,
    optional_actions: c_int,
    termios_p: *const libc::termios,
) -> c_int {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Termios, fd as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
        return -1;
    }

    if termios_p.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
        return -1;
    }

    let act = if !termios_core::valid_optional_actions(optional_actions) {
        if mode.heals_enabled() {
            termios_core::TCSANOW // default to immediate in hardened mode
        } else {
            unsafe { set_abi_errno(errno::EINVAL) };
            runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
            return -1;
        }
    } else {
        optional_actions
    };

    let request = match act {
        termios_core::TCSANOW => libc::TCSETS,
        termios_core::TCSADRAIN => libc::TCSETSW,
        termios_core::TCSAFLUSH => libc::TCSETSF,
        _ => libc::TCSETS,
    };
    let mut previous = std::mem::MaybeUninit::<libc::termios>::uninit();
    let previous_snapshot = match unsafe {
        syscall::sys_ioctl(fd, libc::TCGETS as usize, previous.as_mut_ptr() as usize)
    } {
        Ok(_) => Some(unsafe { previous.assume_init() }),
        Err(_) => None,
    };
    let rc = match unsafe { syscall::sys_ioctl(fd, request as usize, termios_p as usize) } {
        Ok(_) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    if rc == 0 && let Some(before) = previous_snapshot.as_ref() {
        let after = unsafe { &*termios_p };
        let _ = observe_fd_transition(fd, before, after, act);
    }
    let adverse = rc != 0;
    // libc sets errno on failure (EBADF, ENOTTY, EINTR, etc.) — do not overwrite.
    runtime_policy::observe(ApiFamily::Termios, decision.profile, 10, adverse);
    rc
}

// ---------------------------------------------------------------------------
// cfgetispeed
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cfgetispeed(termios_p: *const libc::termios) -> u32 {
    if termios_p.is_null() {
        return 0;
    }
    unsafe { (*termios_p).c_ispeed }
}

// ---------------------------------------------------------------------------
// cfgetospeed
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cfgetospeed(termios_p: *const libc::termios) -> u32 {
    if termios_p.is_null() {
        return 0;
    }
    unsafe { (*termios_p).c_ospeed }
}

// ---------------------------------------------------------------------------
// cfsetispeed
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cfsetispeed(termios_p: *mut libc::termios, speed: u32) -> c_int {
    if termios_p.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    if !termios_core::valid_baud_rate(speed) {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    let before = unsafe { std::ptr::read(termios_p) };
    unsafe {
        (*termios_p).c_ispeed = speed as libc::speed_t;
    }
    let after = unsafe { std::ptr::read(termios_p) };
    let _ = observe_ptr_transition(termios_p as usize, &before, &after, termios_core::TCSANOW);
    0
}

// ---------------------------------------------------------------------------
// cfsetospeed
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cfsetospeed(termios_p: *mut libc::termios, speed: u32) -> c_int {
    if termios_p.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    if !termios_core::valid_baud_rate(speed) {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    let before = unsafe { std::ptr::read(termios_p) };
    unsafe {
        let next = (*termios_p).c_cflag & !termios_core::CBAUD | (speed & termios_core::CBAUD);
        (*termios_p).c_cflag = next as libc::tcflag_t;
        (*termios_p).c_ospeed = speed as libc::speed_t;
    }
    let after = unsafe { std::ptr::read(termios_p) };
    let _ = observe_ptr_transition(termios_p as usize, &before, &after, termios_core::TCSANOW);
    0
}

// ---------------------------------------------------------------------------
// tcdrain
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tcdrain(fd: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Termios, fd as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
        return -1;
    }
    let rc = match unsafe { syscall::sys_ioctl(fd, libc::TCSBRK as usize, 1usize) } {
        Ok(_) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(ApiFamily::Termios, decision.profile, 8, rc != 0);
    rc
}

// ---------------------------------------------------------------------------
// tcflush
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tcflush(fd: c_int, queue_selector: c_int) -> c_int {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Termios, fd as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
        return -1;
    }

    let sel = if !termios_core::valid_queue_selector(queue_selector) {
        if mode.heals_enabled() {
            termios_core::TCIOFLUSH // flush both in hardened mode
        } else {
            unsafe { set_abi_errno(errno::EINVAL) };
            runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
            return -1;
        }
    } else {
        queue_selector
    };

    let rc = match unsafe { syscall::sys_ioctl(fd, libc::TCFLSH as usize, sel as usize) } {
        Ok(_) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(ApiFamily::Termios, decision.profile, 8, rc != 0);
    rc
}

// ---------------------------------------------------------------------------
// tcflow
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tcflow(fd: c_int, action: c_int) -> c_int {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Termios, fd as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
        return -1;
    }

    if !termios_core::valid_flow_action(action) {
        if mode.heals_enabled() {
            runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
            return 0; // no-op in hardened mode
        }
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
        return -1;
    }

    let rc = match unsafe { syscall::sys_ioctl(fd, libc::TCXONC as usize, action as usize) } {
        Ok(_) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(ApiFamily::Termios, decision.profile, 8, rc != 0);
    rc
}

// ---------------------------------------------------------------------------
// tcsendbreak
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tcsendbreak(fd: c_int, duration: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Termios, fd as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Termios, decision.profile, 5, true);
        return -1;
    }
    let request = if duration > 0 {
        libc::TCSBRKP
    } else {
        libc::TCSBRK
    };
    let arg = if duration > 0 {
        duration as libc::c_long as usize
    } else {
        0
    };
    let rc = match unsafe { syscall::sys_ioctl(fd, request as usize, arg) } {
        Ok(_) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(ApiFamily::Termios, decision.profile, 8, rc != 0);
    rc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cooked_termios() -> libc::termios {
        let mut termios = unsafe { std::mem::zeroed::<libc::termios>() };
        termios.c_iflag = (libc::ICRNL | libc::IXON) as libc::tcflag_t;
        termios.c_oflag = libc::OPOST as libc::tcflag_t;
        termios.c_cflag = (libc::CS8 | libc::CREAD | libc::B9600) as libc::tcflag_t;
        termios.c_lflag = (libc::ICANON | libc::ISIG | libc::IEXTEN | libc::ECHO) as libc::tcflag_t;
        termios.c_ispeed = libc::B9600;
        termios.c_ospeed = libc::B9600;
        termios
    }

    fn cbreak_termios() -> libc::termios {
        let mut termios = cooked_termios();
        termios.c_lflag &= !(libc::ICANON as libc::tcflag_t);
        termios
    }

    fn raw_termios() -> libc::termios {
        let mut termios = cooked_termios();
        unsafe { libc::cfmakeraw(&mut termios) };
        termios.c_cflag |= libc::CREAD as libc::tcflag_t;
        termios.c_ispeed = libc::B9600;
        termios.c_ospeed = libc::B9600;
        termios
    }

    fn pty_pair() -> Option<(c_int, c_int)> {
        let mut master = -1;
        let mut slave = -1;
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if rc == 0 { Some((master, slave)) } else { None }
    }

    #[test]
    fn raw_and_cbreak_classification_are_distinct() {
        let cooked = TerminalSignatureClass::from_termios(&cooked_termios());
        let cbreak = TerminalSignatureClass::from_termios(&cbreak_termios());
        let raw = TerminalSignatureClass::from_termios(&raw_termios());

        assert_eq!(cooked.mode, TerminalModeClass::Cooked);
        assert_eq!(cbreak.mode, TerminalModeClass::Cbreak);
        assert_eq!(raw.mode, TerminalModeClass::Raw);
        assert!(cooked.echo_enabled);
        assert!(cbreak.echo_enabled);
        assert!(!raw.echo_enabled);
    }

    #[test]
    fn canonical_diverged_speed_is_illegal() {
        let before = cooked_termios();
        let mut after = cooked_termios();
        after.c_ospeed = libc::B115200;
        after.c_cflag = (after.c_cflag & !(termios_core::CBAUD as libc::tcflag_t)) | libc::B115200;

        let report = analyze_transition(&before, &after, termios_core::TCSANOW);

        assert!(report.speed_axis_changed);
        assert_eq!(report.kind, TerminalTransitionKind::SpeedShift);
        assert!(!report.is_legal);
        assert!(matches!(
            report.current.speed_coupling,
            SpeedCoupling::Diverged
        ));
    }

    #[test]
    fn order_independent_sequences_share_signature() {
        let cooked = cooked_termios();

        let mut cooked_silent = cooked_termios();
        cooked_silent.c_lflag &= !(libc::ECHO as libc::tcflag_t);

        let mut cbreak_echo = cooked_termios();
        cbreak_echo.c_lflag &= !(libc::ICANON as libc::tcflag_t);

        let mut cbreak_silent = cbreak_termios();
        cbreak_silent.c_lflag &= !(libc::ECHO as libc::tcflag_t);

        let mut sequence_a = TerminalSequenceSignature::default();
        sequence_a.observe(analyze_transition(
            &cooked,
            &cooked_silent,
            termios_core::TCSANOW,
        ));
        sequence_a.observe(analyze_transition(
            &cooked_silent,
            &cbreak_silent,
            termios_core::TCSANOW,
        ));

        let mut sequence_b = TerminalSequenceSignature::default();
        sequence_b.observe(analyze_transition(
            &cooked,
            &cbreak_echo,
            termios_core::TCSANOW,
        ));
        sequence_b.observe(analyze_transition(
            &cbreak_echo,
            &cbreak_silent,
            termios_core::TCSANOW,
        ));

        assert!(
            sequence_a.equivalent_to(&sequence_b),
            "expected order-independent signature equivalence: {sequence_a:?} vs {sequence_b:?}"
        );
    }

    #[test]
    fn cfsetospeed_tracks_struct_level_illegal_transition() {
        let mut termios = cooked_termios();
        let ptr_key = (&termios as *const libc::termios) as usize;

        let rc = unsafe { cfsetospeed(&mut termios, libc::B115200) };
        assert_eq!(rc, 0);

        let trackers = PTR_SIGNATURE_TRACKERS
            .lock()
            .expect("termios pointer tracker mutex poisoned");
        let summary = trackers
            .get(&ptr_key)
            .and_then(TerminalSignatureTracker::last_summary)
            .expect("pointer signature summary missing");
        assert!(!summary.is_legal);
        assert_eq!(summary.illegal_transition_count, 1);
    }

    #[test]
    fn pty_standard_sequences_stay_legal() {
        let Some((master, slave)) = pty_pair() else {
            return;
        };

        let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
        let rc = unsafe { tcgetattr(slave, &mut original) };
        assert_eq!(rc, 0);

        let mut cbreak = original;
        cbreak.c_lflag &= !(libc::ICANON as libc::tcflag_t);
        cbreak.c_lflag &= !(libc::ECHO as libc::tcflag_t);

        let mut raw = cbreak;
        unsafe { libc::cfmakeraw(&mut raw) };
        raw.c_cflag |= libc::CREAD as libc::tcflag_t;
        raw.c_ispeed = effective_input_speed(&original);
        raw.c_ospeed = effective_output_speed(&original);

        assert_eq!(unsafe { tcsetattr(slave, libc::TCSANOW, &cbreak) }, 0);
        assert_eq!(unsafe { tcsetattr(slave, libc::TCSADRAIN, &raw) }, 0);
        assert_eq!(unsafe { tcsetattr(slave, libc::TCSAFLUSH, &original) }, 0);

        let trackers = FD_SIGNATURE_TRACKERS
            .lock()
            .expect("termios fd tracker mutex poisoned");
        let summary = trackers
            .get(&slave)
            .and_then(TerminalSignatureTracker::last_summary)
            .expect("fd signature summary missing");
        assert!(summary.is_legal);
        assert_eq!(summary.illegal_transition_count, 0);

        unsafe {
            libc::close(master);
            libc::close(slave);
        }
    }
}
