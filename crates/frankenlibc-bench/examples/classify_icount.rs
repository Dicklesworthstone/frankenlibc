//! Instruction and branch-miss counts for `__fpclassify` / `__fpclassifyf`,
//! counted in-process with no external tool.
//!
//! WHY THIS EXISTS. Wall clock cannot answer the question these two claims ask.
//! L815 and L776 assert that fl "classifies from exponent and fraction bits",
//! which is a statement about MECHANISM — how much work, and how predictably —
//! not about speed. Timing them said what it could and then stopped: at 4M reps
//! the headline case measures 0.9996-0.9999 against a null half-width of 0.0004
//! to 0.0021, so the gate correctly refuses a direction and reports UNDECIDABLE.
//! That is a real equivalence bound, and it is the end of what a 2 ns function
//! yields to a timer.
//!
//! WHY NOT CALLGRIND, which is what the other icount drivers here use. Those are
//! run by hand under `valgrind --tool=callgrind`, and this fleet is driven through
//! `rch`, which refuses non-compilation commands — so the campaign's counted
//! instrument cannot be pointed at a worker at all. Counting from inside the
//! process fixes that: it is an ordinary `cargo run`, it needs no tool on the
//! host, and it does both arms in ONE invocation instead of two runs that have to
//! be trusted to be comparable.
//!
//! WHAT IT DOES NOT DO, inherited verbatim from `snprintf_icount.rs` and worth
//! repeating: it reports no ratio and no timing, and must not be used to claim a
//! speedup. Instructions retired are not cycles. It answers "how much work does
//! each implementation do, and how predictable is it" — and for a branch-ordered
//! classifier, the branch-miss column is the more interesting half.
//!
//! Counts are per-arm DIFFERENCES against a measured empty-loop baseline, because
//! an in-process counter necessarily includes the loop that drives the calls. The
//! baseline is measured, not assumed, and printed.

use std::ffi::{c_int, c_long, c_void};

#[cfg(target_arch = "x86_64")]
const SYS_PERF_EVENT_OPEN: c_long = 298;
#[cfg(target_arch = "aarch64")]
const SYS_PERF_EVENT_OPEN: c_long = 241;

const PERF_TYPE_HARDWARE: u32 = 0;
const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;
const PERF_COUNT_HW_BRANCH_MISSES: u64 = 5;

// _IO('$', n): ('$' << 8) | n.
const PERF_EVENT_IOC_ENABLE: c_ulong = 0x2400;
const PERF_EVENT_IOC_DISABLE: c_ulong = 0x2401;
const PERF_EVENT_IOC_RESET: c_ulong = 0x2403;

use std::ffi::c_ulong;

/// `struct perf_event_attr`, only as far as the fields this driver sets.
///
/// The kernel reads `size` and zero-fills anything beyond it, so declaring the
/// leading fields plus explicit tail padding is the same thing C programs do. The
/// bitfield at offset 40 is spelled as a `u64` of flags because Rust has no
/// bitfields: bit 0 is `disabled`, bit 5 `exclude_kernel`, bit 6 `exclude_hv`.
#[repr(C)]
#[derive(Default)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period_or_freq: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    bp_addr_or_config1: u64,
    bp_len_or_config2: u64,
    branch_sample_type: u64,
    sample_regs_user: u64,
    sample_stack_user: u32,
    clockid: i32,
    sample_regs_intr: u64,
    aux_watermark: u32,
    sample_max_stack: u16,
    reserved_2: u16,
    aux_sample_size: u32,
    reserved_3: u32,
}

const ATTR_DISABLED: u64 = 1 << 0;
const ATTR_EXCLUDE_KERNEL: u64 = 1 << 5;
const ATTR_EXCLUDE_HV: u64 = 1 << 6;

/// `syscall(2)` as a callable pointer, so the driver can choose WHOSE it uses.
///
/// This matters more than it looks. fl exports `syscall` with `no_mangle` in
/// release builds (`unistd_abi.rs`), and this example links frankenlibc-abi in
/// release — so a plain `libc::syscall` call here binds to FL's variadic wrapper,
/// not glibc's. The first run of this driver came back EACCES from
/// `perf_event_open`, which has two possible causes that look identical from the
/// outside: the host refusing to hand out counters, or fl's wrapper mishandling
/// the call. Resolving glibc's `syscall` on a fresh link map and trying both is
/// what separates them, so the driver asks instead of assuming.
type SyscallFn = unsafe extern "C" fn(c_long, ...) -> c_long;

/// glibc's own `syscall`, from a new link map that fl cannot interpose.
fn host_syscall() -> SyscallFn {
    // SAFETY: LM_ID_NEWLM with a NUL-terminated soname.
    let handle = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libc.so.6".as_ptr(),
            libc::RTLD_NOW | libc::RTLD_LOCAL,
        )
    };
    assert!(!handle.is_null(), "dlmopen libc.so.6");
    // SAFETY: handle from dlmopen; the name is NUL-terminated.
    let raw = unsafe { libc::dlsym(handle, c"syscall".as_ptr()) };
    assert!(!raw.is_null(), "dlsym syscall from libc.so.6");
    // SAFETY: the resolved symbol is C's variadic `syscall`.
    unsafe { std::mem::transmute::<*mut c_void, SyscallFn>(raw) }
}

/// One open hardware counter, scoped to this process on any CPU.
struct Counter {
    fd: c_int,
    name: &'static str,
}

impl Counter {
    fn open_with(config: u64, name: &'static str, syscall: SyscallFn) -> Result<Self, c_int> {
        let mut attr = PerfEventAttr {
            type_: PERF_TYPE_HARDWARE,
            size: u32::try_from(size_of::<PerfEventAttr>()).expect("attr fits u32"),
            config,
            flags: ATTR_DISABLED | ATTR_EXCLUDE_KERNEL | ATTR_EXCLUDE_HV,
            ..PerfEventAttr::default()
        };
        // SAFETY: `attr` is live and its `size` matches its layout; pid 0 is this
        // process, cpu -1 is any CPU, no group, no flags.
        let fd = unsafe {
            syscall(
                SYS_PERF_EVENT_OPEN,
                &mut attr as *mut PerfEventAttr as *mut c_void,
                0i32,
                -1i32,
                -1i32,
                0u64,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(0));
        }
        Ok(Self {
            fd: fd as c_int,
            name,
        })
    }

    #[allow(dead_code)] // kept as the documented shape; the driver uses open_with
    fn open(config: u64, name: &'static str) -> Option<Self> {
        let mut attr = PerfEventAttr {
            type_: PERF_TYPE_HARDWARE,
            size: u32::try_from(size_of::<PerfEventAttr>()).expect("attr fits u32"),
            config,
            // Count only this process's user-space work: kernel and hypervisor
            // time is not what either implementation is being asked about, and
            // including it would make the numbers depend on unrelated syscalls.
            flags: ATTR_DISABLED | ATTR_EXCLUDE_KERNEL | ATTR_EXCLUDE_HV,
            ..PerfEventAttr::default()
        };
        // SAFETY: `attr` is a live, fully-initialized struct whose `size` field
        // matches its own layout; pid 0 is this process and cpu -1 is any CPU.
        let fd = unsafe {
            libc::syscall(
                SYS_PERF_EVENT_OPEN,
                &mut attr as *mut PerfEventAttr as *mut c_void,
                0,
                -1,
                -1,
                0u64,
            )
        };
        if fd < 0 {
            return None;
        }
        Some(Self {
            fd: fd as c_int,
            name,
        })
    }

    fn reset_and_enable(&self) {
        // SAFETY: `self.fd` is an open perf event descriptor.
        unsafe {
            libc::ioctl(self.fd, PERF_EVENT_IOC_RESET, 0);
            libc::ioctl(self.fd, PERF_EVENT_IOC_ENABLE, 0);
        }
    }

    fn disable_and_read(&self) -> u64 {
        let mut value = 0u64;
        // SAFETY: `self.fd` is an open perf event descriptor and `value` is a
        // live 8-byte destination, which is what a non-grouped counter returns.
        unsafe {
            libc::ioctl(self.fd, PERF_EVENT_IOC_DISABLE, 0);
            let got = libc::read(
                self.fd,
                (&mut value as *mut u64).cast::<c_void>(),
                size_of::<u64>(),
            );
            assert_eq!(got, 8, "short read from perf counter {}", self.name);
        }
        value
    }
}

impl Drop for Counter {
    fn drop(&mut self) {
        // SAFETY: closing a descriptor this struct owns.
        unsafe { libc::close(self.fd) };
    }
}

type FpclassifyFn = unsafe extern "C" fn(f64) -> c_int;
type FpclassifyfFn = unsafe extern "C" fn(f32) -> c_int;

union ClassifySym {
    raw: *mut c_void,
    wide: FpclassifyFn,
    narrow: FpclassifyfFn,
}

const REPS_DEFAULT: usize = 2_000_000;

fn reps() -> usize {
    std::env::var("CLASSIFY_ICOUNT_REPS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(REPS_DEFAULT)
}

/// Resolve glibc's copy on a NEW link map, so fl's interposition cannot reach it.
fn host_symbol(name: &std::ffi::CStr, fl_address: usize) -> *mut c_void {
    // SAFETY: LM_ID_NEWLM with a NUL-terminated soname. libm is where both
    // __fpclassify and __fpclassifyf live on this host, not libc.
    let handle = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libm.so.6".as_ptr(),
            libc::RTLD_NOW | libc::RTLD_LOCAL,
        )
    };
    assert!(!handle.is_null(), "dlmopen libm.so.6");
    // SAFETY: handle from dlmopen, NUL-terminated name.
    let raw = unsafe { libc::dlsym(handle, name.as_ptr()) };
    assert!(!raw.is_null(), "dlsym {name:?} from libm.so.6");
    assert_ne!(
        raw as usize, fl_address,
        "the glibc arm resolved to fl's own {name:?} — this would compare fl \
         against itself"
    );
    raw
}

/// The five classification branches, one representative input each.
const WIDE_CASES: &[(&str, f64)] = &[
    ("normal", 1.234_567_890_123_45),
    ("zero", 0.0),
    ("subnormal", 5e-320),
    ("infinity", f64::INFINITY),
    ("nan", f64::NAN),
];

const NARROW_CASES: &[(&str, f32)] = &[
    ("normal", 1.234_567_9),
    ("zero", 0.0),
    ("subnormal", 7e-44),
    ("infinity", f32::INFINITY),
    ("nan", f32::NAN),
];

#[inline(never)]
fn drive_wide(f: FpclassifyFn, value: f64, n: usize) -> i64 {
    let mut sum = 0i64;
    for _ in 0..n {
        // SAFETY: a classification of a live f64; the callee reads no memory.
        sum = sum.wrapping_add(unsafe { f(std::hint::black_box(value)) } as i64);
    }
    std::hint::black_box(sum)
}

#[inline(never)]
fn drive_narrow(f: FpclassifyfFn, value: f32, n: usize) -> i64 {
    let mut sum = 0i64;
    for _ in 0..n {
        // SAFETY: as above, at f32.
        sum = sum.wrapping_add(unsafe { f(std::hint::black_box(value)) } as i64);
    }
    std::hint::black_box(sum)
}

/// The same loop with no call in it, so the driver's own cost can be subtracted.
#[inline(never)]
fn drive_empty(value: f64, n: usize) -> i64 {
    let mut sum = 0i64;
    for _ in 0..n {
        sum = sum.wrapping_add(std::hint::black_box(value) as i64);
    }
    std::hint::black_box(sum)
}

struct Measured {
    instructions: u64,
    branch_misses: u64,
    checksum: i64,
}

fn measure(instructions: &Counter, misses: &Counter, body: impl FnOnce() -> i64) -> Measured {
    instructions.reset_and_enable();
    misses.reset_and_enable();
    let checksum = body();
    let branch_misses = misses.disable_and_read();
    let instructions = instructions.disable_and_read();
    Measured {
        instructions,
        branch_misses,
        checksum,
    }
}

fn main() {
    let n = reps();

    // The host's own policy, read rather than guessed at. Turns a failure below
    // from "check your paranoid setting" into a recorded fact about this worker.
    println!(
        "CLASSIFY_ICOUNT_HOST perf_event_paranoid={} kernel_perf_event_support={}",
        std::fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")
            .map(|text| text.trim().to_owned())
            .unwrap_or_else(|error| format!("unreadable:{error}")),
        if std::path::Path::new("/proc/sys/kernel/perf_event_paranoid").exists() {
            "present"
        } else {
            "absent"
        }
    );

    // WHICH `syscall` DOES A PLAIN CALL REACH? Printed before anything depends on
    // it, because in a release build linking fl the answer is not obvious and it
    // decides how to read an EACCES below.
    let linked: SyscallFn = libc::syscall;
    let host = host_syscall();
    let fl_syscall_address = frankenlibc_abi::unistd_abi::syscall as usize;
    println!(
        "CLASSIFY_ICOUNT_SYSCALL_ARMS linked={:#x} host_libc={:#x} fl_export={:#x} \
         linked_is_fl={} linked_is_host={}",
        linked as usize,
        host as usize,
        fl_syscall_address,
        linked as usize == fl_syscall_address,
        linked as usize == host as usize,
    );

    // Try the host's syscall first, then the linked one, and report BOTH outcomes.
    // A host that refuses counters refuses them through either path; a wrapper
    // defect shows up as one path working where the other does not.
    let via_host = Counter::open_with(PERF_COUNT_HW_INSTRUCTIONS, "instructions", host);
    let via_linked = Counter::open_with(PERF_COUNT_HW_INSTRUCTIONS, "instructions", linked);
    println!(
        "CLASSIFY_ICOUNT_OPEN_PROBE via_host_libc={} via_linked={}",
        match &via_host {
            Ok(_) => "ok".to_owned(),
            Err(errno) => format!("errno={errno}"),
        },
        match &via_linked {
            Ok(_) => "ok".to_owned(),
            Err(errno) => format!("errno={errno}"),
        },
    );

    let instructions = match via_host.or(via_linked) {
        Ok(counter) => counter,
        Err(errno) => {
            // Not a silent skip: a missing counter is a property of the host, and a
            // driver that printed nothing would look exactly like one whose numbers
            // were all zero.
            println!(
                "CLASSIFY_ICOUNT_UNAVAILABLE counter=instructions \
                 reason=perf_event_open_failed_on_both_paths errno={errno} \
                 hint=perf_event_paranoid_or_missing_CAP_PERFMON_in_container"
            );
            std::process::exit(2);
        }
    };
    let misses = match Counter::open_with(PERF_COUNT_HW_BRANCH_MISSES, "branch_misses", host)
        .or_else(|_| Counter::open_with(PERF_COUNT_HW_BRANCH_MISSES, "branch_misses", linked))
    {
        Ok(counter) => counter,
        Err(errno) => {
            println!(
                "CLASSIFY_ICOUNT_UNAVAILABLE counter=branch_misses \
                 reason=perf_event_open_failed_on_both_paths errno={errno}"
            );
            std::process::exit(2);
        }
    };

    // POSITIVE CONTROL 1: the counter must respond to work at all. An empty loop
    // at n and at 2n must differ by roughly a factor of two; a counter stuck at
    // zero or pinned to a constant fails here rather than producing a tidy table
    // of meaningless deltas.
    let base_1 = measure(&instructions, &misses, || drive_empty(1.5, n));
    let base_2 = measure(&instructions, &misses, || drive_empty(1.5, 2 * n));
    let scaling = base_2.instructions as f64 / base_1.instructions.max(1) as f64;
    println!(
        "CLASSIFY_ICOUNT_CONTROL empty_loop_reps={n} instructions={} \
         doubled_reps_instructions={} scaling={scaling:.4} checksum={}",
        base_1.instructions, base_2.instructions, base_1.checksum
    );
    assert!(
        (1.8..2.2).contains(&scaling),
        "instruction counter did not scale with work (x{scaling:.4} for 2x the \
         reps); the counts below would be meaningless"
    );
    let baseline_instructions = base_1.instructions;
    let baseline_misses = base_1.branch_misses;

    let fl_wide: FpclassifyFn = frankenlibc_abi::math_abi::__fpclassify;
    let fl_narrow: FpclassifyfFn = frankenlibc_abi::math_abi::__fpclassifyf;
    // SAFETY: the resolved symbols have the documented signatures.
    let host_wide: FpclassifyFn = unsafe {
        ClassifySym {
            raw: host_symbol(c"__fpclassify", fl_wide as usize),
        }
        .wide
    };
    let host_narrow: FpclassifyfFn = unsafe {
        ClassifySym {
            raw: host_symbol(c"__fpclassifyf", fl_narrow as usize),
        }
        .narrow
    };

    println!(
        "CLASSIFY_ICOUNT_ARMS fl_wide={:#x} host_wide={:#x} fl_narrow={:#x} \
         host_narrow={:#x} reps={n}",
        fl_wide as usize, host_wide as usize, fl_narrow as usize, host_narrow as usize
    );

    for (label, value) in WIDE_CASES {
        for (arm, f) in [("fl", fl_wide), ("glibc", host_wide)] {
            let m = measure(&instructions, &misses, || drive_wide(f, *value, n));
            report("__fpclassify", arm, label, n, &m, baseline_instructions, baseline_misses);
        }
    }
    for (label, value) in NARROW_CASES {
        for (arm, f) in [("fl", fl_narrow), ("glibc", host_narrow)] {
            let m = measure(&instructions, &misses, || drive_narrow(f, *value, n));
            report("__fpclassifyf", arm, label, n, &m, baseline_instructions, baseline_misses);
        }
    }
}

fn report(
    symbol: &str,
    arm: &str,
    case: &str,
    n: usize,
    m: &Measured,
    baseline_instructions: u64,
    baseline_misses: u64,
) {
    let net_instructions = m.instructions.saturating_sub(baseline_instructions);
    let net_misses = m.branch_misses.saturating_sub(baseline_misses);
    println!(
        "CLASSIFY_ICOUNT symbol={symbol} arm={arm:<5} case={case:<9} \
         instr_total={} instr_net={} instr_per_call={:.3} \
         miss_total={} miss_net={} miss_per_1k_calls={:.3} checksum={}",
        m.instructions,
        net_instructions,
        net_instructions as f64 / n as f64,
        m.branch_misses,
        net_misses,
        net_misses as f64 * 1000.0 / n as f64,
        m.checksum,
    );
}
