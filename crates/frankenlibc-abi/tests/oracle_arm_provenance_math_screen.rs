#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(unsafe_code)] // dladdr provenance probe over live oracle arms
#![allow(invalid_runtime_symbol_definitions)]
#![allow(suspicious_runtime_symbol_definitions)]

//! SCREEN, not a fix: which link-time "glibc" arms in the math differentials
//! actually reach `libc.so.6`, and which are captured by a local provider?
//!
//! bd-v0388t measured 387 gates / 1546 symbols where the arm a differential
//! calls "glibc" names a symbol FrankenLibC also exports. That is the AT-RISK
//! population, not the defect count, and the difference matters for how the
//! bead gets worked: converting 387 gates by hand is weeks, converting the ones
//! that are actually hollow is an afternoon.
//!
//! ## Why the population is not the defect count
//!
//! fl's exports are debug-gated — every one carries
//! `#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]`, 608 of them in
//! `glibc_internal_abi.rs` alone — so in the debug profile these tests run in,
//! fl's symbols are NOT exported under their C names and a link-time reference
//! cannot bind to fl. The mechanism that actually bit `conformance_diff_fma` was
//! different and is recorded on the bead: it collapsed in a PLAIN DEBUG run
//! because **`compiler_builtins` supplies an `fma`**, with five sibling symbols
//! in the same binary resolving correctly to `libc.so`. A non-fl local provider
//! can capture a symbol regardless of profile.
//!
//! So the question this file answers is narrow and empirical: across the math
//! surface — the family `compiler_builtins` and Rust's own runtime are most
//! likely to provide — how many arms are captured, and by what?
//!
//! ## Why `dladdr` and not an address comparison
//!
//! A link-time reference goes through a PLT stub, so comparing the reference's
//! address against fl's function address can differ while both still reach the
//! same code. `dladdr` reports the object a code address actually lives in,
//! which is the question. A captured arm reports the test binary; a real one
//! reports `libc.so.6` or `libm.so.6`.
//!
//! This file PRINTS the census and PINS the captured set. The pin arrived only
//! after the set was measured and found stable across four extensions of the
//! screen; the per-gate `dlsym` conversions are the fix, and belong on the gates.

use std::ffi::{CStr, c_char, c_int, c_uint, c_ulong, c_void};

macro_rules! declare_mem_arms {
    ($($name:ident),* $(,)?) => {
        unsafe extern "C" {
            $(fn $name(a: *mut c_void, b: *const c_void, n: usize) -> *mut c_void;)*
        }
        /// `(symbol name, code address as the linker resolved it)`.
        fn mem_arm_addresses() -> Vec<(&'static str, *const c_void)> {
            vec![
                $((stringify!($name), $name as *const c_void)),*
            ]
        }
    };
}

macro_rules! declare_binary_arms {
    ($($name:ident),* $(,)?) => {
        unsafe extern "C" {
            $(fn $name(x: f64, y: f64) -> f64;)*
        }
        /// `(symbol name, code address as the linker resolved it)`.
        fn binary_arm_addresses() -> Vec<(&'static str, *const c_void)> {
            vec![
                $((stringify!($name), $name as *const c_void)),*
            ]
        }
    };
}

macro_rules! declare_more_arms {
    ($($name:ident),* $(,)?) => {
        unsafe extern "C" {
            $(fn $name() -> *const c_void;)*
        }
        /// `(symbol name, code address as the linker resolved it)`.
        fn other_arm_addresses() -> Vec<(&'static str, *const c_void)> {
            vec![
                $((stringify!($name), $name as *const c_void)),*
            ]
        }
    };
}

macro_rules! declare_math_arms {
    ($($name:ident),* $(,)?) => {
        unsafe extern "C" {
            $(fn $name(x: f64) -> f64;)*
        }
        /// `(symbol name, code address as the linker resolved it)`.
        fn math_arm_addresses() -> Vec<(&'static str, *const c_void)> {
            vec![
                $((stringify!($name), $name as *const c_void)),*
            ]
        }
    };
}

// The one-argument-double subset of the arms declared by
// `conformance_diff_math.rs` and `conformance_diff_fp_exceptions.rs`. The
// signature is deliberately uniform: this file never CALLS these, it only takes
// their addresses, so the declared prototype does not have to match the real one
// for `dladdr` to answer correctly. Nothing here is invoked.
/// The measured set of oracle arms a local provider captures in this binary.
///
/// ONE definition, used by both tests here: the ratchet that pins the measured
/// set, and the check that no differential binds one of these at link time.
/// They were briefly two literal copies and that is a silent-drift hazard --
/// updating the ratchet after a new measurement while leaving the other list
/// stale would quietly stop protecting the gates.
///
/// Every entry is MEASURED by `math_oracle_arms_report_their_owning_object`, not
/// predicted. Do not add one by reasoning about what an operation lowers to:
/// `nearbyint` is a roundsd lowering and is CLEAN, `cbrt` is not one and is
/// CAPTURED, and `lrint` returns an integer from the same operation as the
/// captured `rint` and is CLEAN.
///
/// The census now covers every symbol a no-dlsym differential declares that
/// libc/libm provides -- 853 arms, derived rather than sampled. Expanding it
/// from 151 took the captured set from 17 to 35, and the 18 new entries are
/// almost entirely f128: `compiler_builtins` supplies Rust's f128 math, so any
/// gate comparing FrankenLibC's f128 work against a link-time "glibc" arm is
/// measuring compiler_builtins.
const KNOWN_CAPTURED: &[&str] = &[
    "cbrt",
    "cbrtf",
    "ceil",
    "ceilf128",
    "copysign",
    "copysignf128",
    "fabs",
    "fabsf128",
    "fdim",
    "fdimf128",
    "floor",
    "floorf128",
    "fmaf128",
    "fmax",
    "fmaxf128",
    "fmaximum_numf128",
    "fmaximumf128",
    "fmin",
    "fminf128",
    "fminimum_numf128",
    "fminimumf128",
    "fmod",
    "fmodf128",
    "rint",
    "rintf",
    "rintf128",
    "round",
    "roundevenf128",
    "roundf",
    "roundf128",
    "sqrt",
    "sqrtf128",
    "trunc",
    "truncf",
    "truncf128",
];

declare_math_arms!(
    acos, acosh, asin, atanh, ceil, cos, cosh, erfc, exp, exp2, exp10, expm1, fabs, floor, ilogb,
    lgamma, log, log10, log1p, log2, logb, sin, sinh, sqrt, tan, tanh, tgamma, y0, y1,
    // Added because the captured set is exactly what LLVM lowers to a single
    // instruction and `compiler_builtins` defines non-weak -- roundsd for
    // ceil/floor, andpd for fabs, sqrtsd for sqrt. `round`, `trunc`, `rint` and
    // `nearbyint` are ALSO roundsd lowerings and were not in the census, so the
    // screen could not have seen them captured. `cbrt`, `atan`, `asinh`, `erf`,
    // `j0` and `j1` are ordinary libm calls added to widen the clean side, so a
    // capture result is not read off a list stacked with likely positives.
    round, trunc, rint, nearbyint, cbrt, atan, asinh, erf, j0, j1,
);

// `inet_net_ntop` / `inet_net_pton` are deliberately ABSENT: they live in
// `libresolv.so.2`, which this binary does not link, so declaring them here is
// an undefined symbol at link time rather than a census entry. That is a fact
// about this screen's link line, NOT about `conformance_diff_inet_net.rs` --
// that gate links them successfully and needs its own look.
//
// The NON-math surface, taken verbatim from the extern blocks of the twelve
// at-risk gates that assert on errno -- the order bd-v0388t asks for, because an
// errno-only divergence hides rather than crashes. Same rule as above: these are
// never called, only addressed, so one uniform prototype is enough for `dladdr`.
declare_more_arms!(
    // The f32 and integer-returning members of the round-to-integer family.
    // These belong here rather than in a typed macro because arms are never
    // CALLED, only addressed for `dladdr`, so one uniform prototype suffices --
    // the same reasoning this block already uses for the errno surface.
    //
    // Added because three differentials (conformance_diff_fe_rounding,
    // conformance_diff_round_mode, conformance_diff_math_exact) declare these
    // alongside `rint`, which IS captured. Converting `rint` while leaving its
    // siblings unmeasured would fix the symbol I happened to census and leave
    // the rest hollow for exactly the same reason.
    cbrtf,
    // Reached through `#[link_name]` aliases in their gates (host_setfsuid,
    // host_setfsgid), so a scan that reads the RUST name misses them. The
    // census derivation now resolves link_name and these are the only two
    // libc symbols it turned up that were previously invisible.
    setfsgid,
    setfsuid,
    // EVERY remaining symbol that a conformance_diff_* gate with no dlsym
    // anywhere declares at link time, and that libc.so.6 or libm.so.6 provides.
    // 702 names, derived rather than hand-picked: the check below can only
    // protect a gate whose symbol this census has MEASURED, so leaving the
    // population unmeasured left the check protecting the handful I had
    // thought to look at. 42 further symbols live in libresolv/libcrypt and
    // are deliberately absent -- declaring them here is an undefined symbol on
    // THIS binary's link line, the same reason inet_net_ntop is excluded above.
    // Arms are addressed, never called, so one uniform prototype is enough.
    __finite,
    __finitef128,
    __fpclassify,
    __fpclassifyf,
    __fpclassifyf128,
    __iseqsigf128,
    __isinf,
    __isinff128,
    __isnan,
    __isnanf128,
    __issignaling,
    __issignalingf128,
    __memcmpeq,
    __mempcpy,
    __nss_hash,
    __res_state,
    __signbit,
    __signbitf128,
    __stpcpy,
    __stpncpy,
    __xpg_strerror_r,
    _exit,
    acosf,
    acosf128,
    acoshf128,
    acospif128,
    addseverity,
    adjtimex,
    aio_cancel,
    aio_error,
    aio_read,
    aio_return,
    aio_write,
    alarm,
    aligned_alloc,
    arc4random,
    arc4random_buf,
    arc4random_uniform,
    argz_count,
    argz_create_sep,
    argz_next,
    argz_stringify,
    asctime_r,
    asinf,
    asinf128,
    asinhf,
    asinhf128,
    asinpif128,
    asprintf,
    atan2f,
    atan2f128,
    atan2pif128,
    atanf,
    atanf128,
    atanhf128,
    atanpif128,
    atof,
    basename,
    bcopy,
    bsd_signal,
    btowc,
    bzero,
    c16rtomb,
    cabs,
    cabsf128,
    cacosf128,
    cacoshf128,
    capget,
    capset,
    carg,
    cargf128,
    casinf128,
    casinhf128,
    catanf128,
    catanhf128,
    cbrtf128,
    ccosf128,
    ccoshf128,
    ceilf128,
    cexpf128,
    cfgetispeed,
    cfgetospeed,
    cfmakeraw,
    cfsetispeed,
    cfsetospeed,
    cimag,
    cimagf,
    cimagf128,
    clock_getres,
    clock_gettime,
    clock_nanosleep,
    clogf128,
    close,
    compoundnf128,
    conj,
    conjf128,
    copy_file_range,
    copysignf128,
    cosf,
    cosf128,
    coshf,
    coshf128,
    cospif128,
    cpowf128,
    cproj,
    cprojf128,
    creal,
    crealf,
    crealf128,
    csinf128,
    csinhf128,
    csqrtf128,
    ctanf128,
    ctanhf128,
    ctime_r,
    dcgettext,
    dcngettext,
    dgettext,
    dirname,
    dn_skipname,
    dngettext,
    dprintf,
    dup,
    dup2,
    endusershell,
    epoll_create,
    epoll_create1,
    epoll_ctl,
    epoll_pwait,
    epoll_wait,
    erfcf128,
    erff128,
    error,
    errx,
    eventfd,
    eventfd_read,
    eventfd_write,
    exp10f,
    exp10f128,
    exp10m1f128,
    exp2f,
    expf128,
    explicit_bzero,
    expm1f128,
    f32addf128,
    f32divf128,
    f32fmaf128,
    f32mulf128,
    f32sqrtf128,
    f32subf128,
    f32xaddf128,
    f32xdivf128,
    f32xfmaf128,
    f32xmulf128,
    f32xsqrtf128,
    f32xsubf128,
    f64addf128,
    f64divf128,
    f64fmaf128,
    f64mulf128,
    f64sqrtf128,
    f64subf128,
    fabsf128,
    fchmodat,
    fclose,
    fcntl,
    fdimf128,
    feclearexcept,
    fegetenv,
    fegetround,
    feraiseexcept,
    fesetenv,
    fesetround,
    fetestexcept,
    fgetwc,
    fgetws,
    fgetxattr,
    flock,
    floorf128,
    fmaf128,
    fmaxf128,
    fmaximum_mag_numf128,
    fmaximum_magf128,
    fmaximum_numf128,
    fmaximumf128,
    fmaxmagf128,
    fmemopen,
    fminf128,
    fminimum_mag_numf128,
    fminimum_magf128,
    fminimum_numf128,
    fminimumf128,
    fminmagf128,
    fmodf128,
    fmtmsg,
    fnmatch,
    fopen,
    fork,
    fpathconf,
    fputwc,
    fputws,
    free,
    freeaddrinfo,
    freelocale,
    frexpf128,
    fromfpf128,
    fromfpxf128,
    fstatat,
    fstatvfs,
    ftok,
    futimens,
    futimes,
    gai_strerror,
    gamma,
    gammaf,
    get_nprocs,
    get_nprocs_conf,
    get_phys_pages,
    getaddrinfo,
    getauxval,
    getdate_r,
    getdelim,
    getdomainname,
    getdtablesize,
    getegid,
    getentropy,
    getenv,
    geteuid,
    getgid,
    getgrouplist,
    gethostid,
    gethostname,
    getline,
    getloadavg,
    getlogin,
    getlogin_r,
    getnameinfo,
    getopt,
    getpayloadf128,
    getpgrp,
    getpid,
    getppid,
    getrandom,
    getresgid,
    getresuid,
    getsubopt,
    gettid,
    getuid,
    getusershell,
    getxattr,
    globfree,
    gmtime,
    gmtime_r,
    gnu_dev_major,
    gnu_dev_makedev,
    gnu_dev_minor,
    group_member,
    hasmntopt,
    hypot,
    hypotf,
    hypotf128,
    iconv,
    iconv_close,
    iconv_open,
    if_freenameindex,
    if_indextoname,
    if_nameindex,
    if_nametoindex,
    ilogbf128,
    index,
    inet_addr,
    inet_aton,
    inet_lnaof,
    inet_makeaddr,
    inet_netof,
    inet_network,
    inet_ntoa,
    inet_ntop,
    inet_pton,
    inotify_add_watch,
    inotify_init,
    inotify_init1,
    inotify_rm_watch,
    isalnum_l,
    isalpha_l,
    isascii,
    isblank_l,
    iscntrl_l,
    isdigit_l,
    isgraph_l,
    isinf,
    islower_l,
    isnan,
    isprint_l,
    ispunct_l,
    isspace_l,
    isupper_l,
    iswalnum,
    iswalpha,
    iswblank,
    iswcntrl,
    iswctype,
    iswdigit,
    iswgraph,
    iswlower,
    iswprint,
    iswpunct,
    iswspace,
    iswupper,
    iswxdigit,
    isxdigit_l,
    jn,
    jnf,
    kill,
    killpg,
    lchmod,
    ldexpf128,
    lgamma_r,
    linkat,
    listxattr,
    llogbf128,
    llrintf128,
    llroundf,
    llroundf128,
    localeconv,
    localtime_r,
    lockf,
    log10f128,
    log10p1f128,
    log1pf128,
    log2f128,
    log2p1f128,
    logbf128,
    logf128,
    logp1f128,
    lrintf128,
    lroundf128,
    lutimes,
    mblen,
    mbrlen,
    mbrtoc32,
    mbrtowc,
    mbsrtowcs,
    mbstowcs,
    mbtowc,
    memalign,
    memccpy,
    memfd_create,
    memfrob,
    memmem,
    mempcpy,
    mkdirat,
    mkfifo,
    mkfifoat,
    mknod,
    mknodat,
    modff128,
    mq_close,
    mq_open,
    mq_receive,
    mq_send,
    mq_unlink,
    nanf128,
    nanosleep,
    nearbyintf128,
    newlocale,
    nextafterf128,
    nextdownf128,
    nextupf128,
    nl_langinfo,
    nl_langinfo_l,
    ntp_adjtime,
    open,
    openat,
    pathconf,
    pclose,
    pipe,
    popen,
    posix_memalign,
    posix_spawn,
    posix_spawn_file_actions_addclose,
    posix_spawn_file_actions_adddup2,
    posix_spawn_file_actions_destroy,
    posix_spawn_file_actions_init,
    posix_spawnattr_destroy,
    posix_spawnattr_init,
    posix_spawnattr_setflags,
    posix_spawnp,
    powf,
    powf128,
    pownf128,
    powrf128,
    prctl,
    preadv,
    preadv2,
    prlimit,
    psiginfo,
    psignal,
    pthread_attr_destroy,
    pthread_attr_getdetachstate,
    pthread_attr_getguardsize,
    pthread_attr_getstacksize,
    pthread_attr_init,
    pthread_attr_setdetachstate,
    pthread_attr_setguardsize,
    pthread_attr_setstacksize,
    pthread_barrier_destroy,
    pthread_barrier_init,
    pthread_barrier_wait,
    pthread_getname_np,
    pthread_mutex_consistent,
    pthread_rwlockattr_getkind_np,
    pthread_rwlockattr_getpshared,
    pthread_rwlockattr_init,
    pthread_rwlockattr_setkind_np,
    pthread_rwlockattr_setpshared,
    pthread_self,
    pthread_setname_np,
    pthread_sigmask,
    pthread_spin_destroy,
    pthread_spin_init,
    pthread_spin_lock,
    pthread_spin_trylock,
    pthread_spin_unlock,
    putenv,
    pwritev,
    pwritev2,
    raise,
    rawmemchr,
    readlinkat,
    readv,
    recv,
    recvmsg,
    regcomp,
    regexec,
    regfree,
    remainderf128,
    removexattr,
    remquof,
    remquof128,
    renameat,
    res_dnok,
    res_hnok,
    res_mailok,
    res_ownok,
    rindex,
    rintf128,
    rootnf128,
    roundevenf128,
    roundf128,
    rsqrtf128,
    scalblnf128,
    scalbnf128,
    sched_get_priority_max,
    sched_get_priority_min,
    sched_getaffinity,
    sched_getparam,
    sched_getscheduler,
    sched_yield,
    secure_getenv,
    sem_destroy,
    sem_getvalue,
    sem_init,
    sem_post,
    sem_timedwait,
    sem_trywait,
    sem_wait,
    send,
    sendfile,
    sendmsg,
    setdomainname,
    setenv,
    sethostname,
    setlocale,
    setlogmask,
    setpayloadf128,
    setpayloadsigf128,
    setsid,
    setusershell,
    setxattr,
    shm_open,
    shm_unlink,
    sigabbrev_np,
    sigaction,
    sigaddset,
    sigaltstack,
    sigandset,
    sigdescr_np,
    sigemptyset,
    sigisemptyset,
    signalfd,
    sigorset,
    sigtimedwait,
    sigwaitinfo,
    sincos,
    sincosf128,
    sinf,
    sinf128,
    sinhf,
    sinhf128,
    sinpif128,
    snprintf,
    splice,
    sqrtf128,
    sscanf,
    statvfs,
    statx,
    stdc_bit_ceil_uc,
    stdc_bit_ceil_ui,
    stdc_bit_ceil_ull,
    stdc_bit_ceil_us,
    stdc_bit_floor_uc,
    stdc_bit_floor_ui,
    stdc_bit_floor_ull,
    stdc_bit_floor_us,
    stdc_bit_width_uc,
    stdc_bit_width_ui,
    stdc_bit_width_ull,
    stdc_bit_width_us,
    stdc_count_ones_uc,
    stdc_count_ones_ui,
    stdc_count_ones_ull,
    stdc_count_ones_us,
    stdc_count_zeros_uc,
    stdc_count_zeros_ui,
    stdc_count_zeros_ull,
    stdc_count_zeros_us,
    stdc_first_leading_one_uc,
    stdc_first_leading_one_ui,
    stdc_first_leading_one_ull,
    stdc_first_leading_one_us,
    stdc_first_leading_zero_uc,
    stdc_first_leading_zero_ui,
    stdc_first_leading_zero_ull,
    stdc_first_leading_zero_us,
    stdc_first_trailing_one_uc,
    stdc_first_trailing_one_ui,
    stdc_first_trailing_one_ull,
    stdc_first_trailing_one_us,
    stdc_first_trailing_zero_uc,
    stdc_first_trailing_zero_ui,
    stdc_first_trailing_zero_ull,
    stdc_first_trailing_zero_us,
    stdc_has_single_bit_uc,
    stdc_has_single_bit_ui,
    stdc_has_single_bit_ull,
    stdc_has_single_bit_us,
    stdc_leading_ones_uc,
    stdc_leading_ones_ui,
    stdc_leading_ones_ull,
    stdc_leading_ones_us,
    stdc_leading_zeros_uc,
    stdc_leading_zeros_ui,
    stdc_leading_zeros_ull,
    stdc_leading_zeros_us,
    stdc_trailing_ones_uc,
    stdc_trailing_ones_ui,
    stdc_trailing_ones_ull,
    stdc_trailing_ones_us,
    stdc_trailing_zeros_uc,
    stdc_trailing_zeros_ui,
    stdc_trailing_zeros_ull,
    stdc_trailing_zeros_us,
    stpcpy,
    stpncpy,
    strcasestr,
    strchrnul,
    strcoll,
    strerrordesc_np,
    strerrorname_np,
    strfmon,
    strfromd,
    strfromf,
    strfromf128,
    strftime,
    strftime_l,
    strlcat,
    strlcpy,
    strncpy,
    strptime,
    strrchr,
    strsep,
    strtod,
    strtod_l,
    strtof128,
    strtof_l,
    strtoimax,
    strtok_r,
    strtol_l,
    strtoll_l,
    strtoq,
    strtoul_l,
    strtoull_l,
    strtoumax,
    strtouq,
    strverscmp,
    strxfrm,
    swab,
    swprintf,
    swscanf,
    symlinkat,
    syscall,
    sysconf,
    sysinfo,
    tanf,
    tanf128,
    tanhf,
    tanhf128,
    tanpif128,
    tcgetattr,
    tcgetsid,
    tcsetattr,
    tdelete,
    tee,
    tfind,
    tgkill,
    timegm,
    timerfd_create,
    timerfd_gettime,
    timerfd_settime,
    timespec_get,
    timespec_getres,
    toascii,
    tolower_l,
    totalorder,
    totalorderf,
    totalorderf128,
    totalordermag,
    totalordermagf,
    totalordermagf128,
    toupper_l,
    towctrans,
    towlower,
    towupper,
    truncf128,
    tsearch,
    twalk,
    tzset,
    ufromfpf128,
    ufromfpxf128,
    uname,
    ungetwc,
    unlinkat,
    usleep,
    utime,
    utimensat,
    utimes,
    waitpid,
    warn,
    warnx,
    wcpcpy,
    wcpncpy,
    wcrtomb,
    wcscasecmp,
    wcscat,
    wcschr,
    wcschrnul,
    wcscmp,
    wcscpy,
    wcscspn,
    wcsdup,
    wcsftime,
    wcsftime_l,
    wcslen,
    wcsncasecmp,
    wcsncat,
    wcsncmp,
    wcsncpy,
    wcsnlen,
    wcspbrk,
    wcsrchr,
    wcsrtombs,
    wcsspn,
    wcsstr,
    wcstod,
    wcstof,
    wcstof128,
    wcstoimax,
    wcstok,
    wcstol,
    wcstoll,
    wcstombs,
    wcstoul,
    wcstoull,
    wcstoumax,
    wcswidth,
    wctob,
    wctomb,
    wctrans,
    wctype,
    wcwidth,
    wmemcmp,
    wmemcpy,
    wmemmove,
    wmempcpy,
    wmemset,
    wordexp,
    wordfree,
    write,
    writev,
    yn,
    ynf,
    llrint,
    llrintf,
    lrint,
    lrintf,
    // The remaining arms of conformance_diff_math_exact's extern block. Censused
    // as a set rather than one at a time, because that gate declares 33 symbols
    // and converting only the ones already measured would leave the rest hollow
    // for the same reason -- which is the mistake this bead exists to stop.
    frexp,
    frexpf,
    ilogbf,
    ldexp,
    ldexpf,
    llround,
    logbf,
    lround,
    lroundf,
    modf,
    modff,
    nextafter,
    nextafterf,
    remainder,
    remainderf,
    remquo,
    scalbn,
    scalbnf,
    significand,
    significandf,
    nearbyintf,
    rintf,
    roundf,
    truncf,
    __errno_location,
    __sched_get_priority_max,
    __sched_get_priority_min,
    __sched_getparam,
    __sched_getscheduler,
    __sched_setscheduler,
    __sched_yield,
    a64l,
    abs,
    alphasort,
    alphasort64,
    canonicalize_file_name,
    dirfd,
    div,
    ecvt,
    ecvt_r,
    fcvt,
    fcvt_r,
    fdopendir,
    ffs,
    ffsl,
    ffsll,
    ftw,
    ftw64,
    gcvt,
    getpriority,
    grantpt,
    hcreate,
    hcreate_r,
    hdestroy,
    hdestroy_r,
    hsearch,
    hsearch_r,
    imaxabs,
    isatty,
    l64a,
    labs,
    ldiv,
    lfind,
    llabs,
    lldiv,
    lsearch,
    nftw,
    nftw64,
    nice,
    pkey_alloc,
    pkey_free,
    pkey_get,
    pkey_mprotect,
    pkey_set,
    posix_openpt,
    ptsname_r,
    readdir64,
    readdir_r,
    realpath,
    scandir,
    scandir64,
    sched_getcpu,
    setpriority,
    sockatmark,
    ttyname,
    ttyname_r,
    ttyslot,
    unlockpt,
    versionsort
);

// TWO-ARGUMENT math, added after the one-arg census came back clean and a RED
// in `conformance_diff_math` turned out to point the other way. That gate
// reports `fmaxf(+0,-0)` as fl=-0.0 vs "glibc"=+0.0 -- but a live ctypes probe
// of libm.so.6 (glibc 2.42) returns **-0.0**, i.e. the SECOND operand, which is
// what fl returns. The gate's oracle therefore disagrees with real glibc, so the
// gate's oracle is not glibc. That is a captured arm producing a FALSE RED
// rather than the usual false green, and it is far more dangerous: acting on it
// means "fixing" fl to match a local provider and breaking real parity.
declare_binary_arms!(copysign, fdim, fmax, fmin, fmod, pow, atan2);

// The mem*/str* family. `compiler_builtins` supplies memcpy/memset/memmove/
// memcmp, and these are the symbols the fourth disguise reaches through
// `libc::<sym>`. Same rule as every other arm here: never called, only
// addressed, so one uniform prototype suffices for `dladdr`.
declare_mem_arms!(
    memcpy, memmove, memset, memcmp, memchr, strlen, strcmp, strncmp, strcpy, strchr, bcmp,
);

/// Which object does `addr` live in?
fn owning_object(addr: *const c_void) -> String {
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    // SAFETY: `addr` is a code address taken from a live function item and
    // `info` is a live local.
    if unsafe { libc::dladdr(addr, &mut info) } == 0 || info.dli_fname.is_null() {
        return "<dladdr failed>".to_owned();
    }
    // SAFETY: `dli_fname` is a NUL-terminated path owned by the loader.
    let path = unsafe { CStr::from_ptr(info.dli_fname) }.to_string_lossy();
    path.rsplit('/').next().unwrap_or(&path).to_owned()
}

/// Census the math oracle arms and print where each one actually resolves.
/// Arms that live in libresolv/libcrypt rather than libc, declared in their own
/// linked block.
///
/// These were the last known residual on bd-v0388t: 21 symbols that
/// conformance_diff_* gates declare and the census could not cover, because
/// naming them in the ordinary block is an undefined symbol on this binary's
/// link line. `#[link(name = ..)]` pulls the library in, which is the whole fix
/// -- the exclusion was never about these symbols being uninteresting.
#[link(name = "resolv")]
unsafe extern "C" {
    fn __b64_ntop(a: *const c_void, b: usize, c: *mut c_char, d: usize) -> c_int;
    fn __b64_pton(a: *const c_char, b: *mut c_void, c: usize) -> c_int;
    fn __dn_count_labels(a: *const c_char) -> c_int;
    fn __hostalias(a: *const c_char) -> *mut c_char;
    fn __p_class(a: c_int) -> *mut c_char;
    fn __p_option(a: c_ulong) -> *mut c_char;
    fn __p_rcode(a: c_int) -> *mut c_char;
    fn __p_time(a: c_uint) -> *mut c_char;
    fn __p_type(a: c_int) -> *mut c_char;
    fn __res_hostalias(a: *mut c_void, b: *const c_char, c: *mut c_char, d: usize) -> *mut c_char;
    fn __sym_ntop(a: *const c_void, b: c_int, c: *mut c_int) -> *mut c_char;
    fn __sym_ntos(a: *const c_void, b: c_int, c: *mut c_int) -> *mut c_char;
    fn __sym_ston(a: *const c_void, b: *const c_char, c: *mut c_int) -> c_int;
    fn inet_neta(a: c_uint, b: *mut c_char, c: usize) -> *mut c_char;
    fn ns_datetosecs(a: *const c_char, b: *mut c_int) -> c_ulong;
    fn ns_format_ttl(a: c_ulong, b: *mut c_char, c: usize) -> c_int;
    fn ns_get16(a: *const c_void) -> c_uint;
    fn ns_get32(a: *const c_void) -> c_ulong;
    fn ns_makecanon(a: *const c_char, b: *mut c_char, c: usize) -> c_int;
    fn ns_name_ntol(a: *const c_void, b: *mut c_void, c: usize) -> c_int;
}

#[link(name = "crypt")]
unsafe extern "C" {
    fn crypt_gensalt(a: *const c_char, b: c_ulong, c: *const c_char, d: c_int) -> *mut c_char;
}

/// `(symbol name, code address as the linker resolved it)` for the above.
fn foreign_lib_arm_addresses() -> Vec<(&'static str, *const c_void)> {
    vec![
        ("__b64_ntop", __b64_ntop as *const c_void),
        ("__b64_pton", __b64_pton as *const c_void),
        ("__dn_count_labels", __dn_count_labels as *const c_void),
        ("__hostalias", __hostalias as *const c_void),
        ("__p_class", __p_class as *const c_void),
        ("__p_option", __p_option as *const c_void),
        ("__p_rcode", __p_rcode as *const c_void),
        ("__p_time", __p_time as *const c_void),
        ("__p_type", __p_type as *const c_void),
        ("__res_hostalias", __res_hostalias as *const c_void),
        ("__sym_ntop", __sym_ntop as *const c_void),
        ("__sym_ntos", __sym_ntos as *const c_void),
        ("__sym_ston", __sym_ston as *const c_void),
        ("inet_neta", inet_neta as *const c_void),
        ("ns_datetosecs", ns_datetosecs as *const c_void),
        ("ns_format_ttl", ns_format_ttl as *const c_void),
        ("ns_get16", ns_get16 as *const c_void),
        ("ns_get32", ns_get32 as *const c_void),
        ("ns_makecanon", ns_makecanon as *const c_void),
        ("ns_name_ntol", ns_name_ntol as *const c_void),
        ("crypt_gensalt", crypt_gensalt as *const c_void),
    ]
}

#[test]
fn math_oracle_arms_report_their_owning_object() {
    let mut arms = math_arm_addresses();
    arms.extend(other_arm_addresses());
    arms.extend(binary_arm_addresses());
    arms.extend(mem_arm_addresses());
    arms.extend(foreign_lib_arm_addresses());
    assert!(
        !arms.is_empty(),
        "no arms declared; the macro did not expand"
    );

    let mut captured = Vec::new();
    let mut clean = Vec::new();
    for (name, addr) in &arms {
        let object = owning_object(*addr);
        // A real oracle lives in a shared library the loader mapped. Anything
        // resolving into this test binary is a local provider capturing the
        // symbol -- the `conformance_diff_fma` failure mode.
        if object.starts_with("lib") && object.contains(".so") {
            clean.push((*name, object));
        } else {
            captured.push((*name, object));
        }
    }

    println!(
        "ORACLE_ARM_CENSUS total={} clean={} captured={}",
        arms.len(),
        clean.len(),
        captured.len()
    );
    for (name, object) in &clean {
        println!("  CLEAN    {name:12} -> {object}");
    }
    for (name, object) in &captured {
        println!("  CAPTURED {name:12} -> {object}");
    }

    // dladdr must have placed every arm. A silent zero must never be readable
    // as "clean", which is the failure mode this whole bead is about.
    let unresolved: Vec<_> = arms
        .iter()
        .map(|(name, addr)| (*name, owning_object(*addr)))
        .filter(|(_, object)| object == "<dladdr failed>")
        .collect();
    assert!(
        unresolved.is_empty(),
        "dladdr could not place these arms, so the census is incomplete: {unresolved:?}"
    );

    // THE RATCHET. Earlier revisions of this file asserted nothing about the
    // capture count, because a GUESSED threshold that passes is exactly the
    // hollow gate bd-v0388t exists to stamp out. That held while the set was
    // unknown. It is now measured and stable across four extensions of this
    // screen -- 29, 94, 101 and 112 arms, the same nine every time -- so this
    // pins a measurement rather than a guess.
    //
    // The pin is the exact SET, not the count: a new capture displacing an old
    // one would leave the count at nine while changing what is hollow.
    //
    // If this fires, a symbol changed provider. Do NOT widen the list to make it
    // pass. Find the gates that declare the new symbol and give them a real
    // oracle -- `dlsym_oracle::host_fn` -- as conformance_diff_math,
    // conformance_diff_round_special, conformance_diff_copysign_fdim_special and
    // conformance_diff_fp_exceptions already do.
    //
    // THE "LLVM LOWERS IT TO roundsd" EXPLANATION IS INCOMPLETE. It was written
    // when the census covered 112 symbols and held for all nine then known. The
    // census now covers 122 and the extra ten refute it in both directions:
    //
    //   round, trunc, rint  -- roundsd lowerings, and CAPTURED, as it predicts
    //   nearbyint           -- also a roundsd lowering, and CLEAN
    //   cbrt                -- not a roundsd lowering at all, and CAPTURED
    //
    // So the lowering is not the discriminator; what `compiler_builtins` happens
    // to define NON-weak is. Do not extend this list by reasoning from the
    // instruction a symbol lowers to -- add the symbol to the census and measure
    // it, which is how the four new entries below were found.
    //
    // memcpy/memset/memmove/memcmp are declared weak there and correctly lose to
    // libc.so.6 -- measured, not assumed.
    //
    // The f32 round-family members behave like their f64 counterparts (rintf,
    // roundf, truncf captured) while the INTEGER-returning ones do not
    // (lrint, llrint clean), and neither nearbyint nor nearbyintf is captured.
    // Another reason not to predict from the lowering: the same operation is
    // captured at one return type and clean at another.

    let mut captured_names: Vec<&str> = captured.iter().map(|(name, _)| *name).collect();
    captured_names.sort_unstable();
    assert_eq!(
        captured_names, KNOWN_CAPTURED,
        "the set of locally-captured oracle arms changed. New captures are gates \
         that silently stopped testing glibc; disappearances mean an arm that was \
         converted no longer needs to be. Either way, investigate before editing \
         this list (bd-v0388t)."
    );
}

/// Every differential that DECLARES a captured symbol at link time must also
/// resolve it through `dlsym`, or its "glibc" arm is a local provider.
///
/// The screen above measures WHICH symbols are captured. This one closes the
/// loop by checking that no gate binds one of them at link time -- which is the
/// actual defect bd-v0388t is about, and which was previously found by hand.
/// Three gates were converted that way (conformance_diff_fe_rounding,
/// conformance_diff_round_mode, conformance_diff_math_exact) after censusing
/// their siblings one set at a time; this makes the next one fail loudly instead
/// of waiting for someone to think of looking.
///
/// The check is deliberately conservative: a file that mentions `dlsym` anywhere
/// is trusted, because pinpointing WHICH arm a shim resolves would mean parsing
/// Rust, and a false failure here would train people to edit the list rather
/// than the gate.
#[test]
fn no_differential_binds_a_captured_symbol_at_link_time() {
    let dir = std::path::Path::new("tests");
    let entries = std::fs::read_dir(dir).expect("read tests/ -- test CWD is the package root");
    let mut offenders: Vec<String> = Vec::new();
    let mut scanned = 0usize;

    for entry in entries.flatten() {
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if !name.starts_with("conformance_diff_") || !name.ends_with(".rs") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        scanned += 1;
        if text.contains("dlsym") {
            continue;
        }
        // Symbols declared inside an `extern "C" { ... }` block.
        let mut inside = false;
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("unsafe extern \"C\" {") || trimmed.starts_with("extern \"C\" {")
            {
                inside = true;
                continue;
            }
            if inside {
                if trimmed.starts_with('}') {
                    inside = false;
                    continue;
                }
                let declared = trimmed
                    .strip_prefix("fn ")
                    .or_else(|| trimmed.strip_prefix("pub fn "))
                    .and_then(|rest| rest.split(['(', '<', ' ']).next());
                if let Some(symbol) = declared
                    && KNOWN_CAPTURED.contains(&symbol)
                {
                    offenders.push(format!("{name} declares captured `{symbol}`"));
                }
            }
        }
    }

    assert!(
        scanned > 100,
        "only {scanned} differentials scanned; the glob is wrong"
    );
    assert!(
        offenders.is_empty(),
        "these gates bind a locally-captured symbol at link time, so their \
         \"glibc\" arm is not glibc. Give the arm dlsym_oracle::host_fn, as \
         conformance_diff_math_exact and conformance_diff_round_mode do. Do NOT \
         remove the symbol from CAPTURED to silence this (bd-v0388t):\n{}",
        offenders.join("\n")
    );
}
