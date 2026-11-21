// Real C++ landing pads and physical-stack forced unwinding. The owned E2E
// gate links this fixture without libgcc and verifies every _Unwind provider.

#include <csetjmp>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <signal.h>
#include <ucontext.h>
#include <unwind.h>

class TestException : public std::exception {
public:
    const char* what() const noexcept override {
        return "TestException from minimal_throw_catch";
    }
};

static volatile int caught_test_exception = 0;

namespace {

constexpr unsigned guard_count = 4;
constexpr unsigned max_stops = 64;
constexpr _Unwind_Exception_Class forced_class = 0x4652414e4b465243ULL;
constexpr uintptr_t seed_step = 0x13579bdfU;
static volatile uintptr_t runtime_seed = 0x2468ace1U;

struct Observations {
    unsigned events[guard_count + 1];
    unsigned event_count;
    unsigned search_calls;
    unsigned cleanup_calls;
    unsigned cleanup_installs;
    unsigned search_after_cleanup;
    unsigned stop_calls;
    unsigned end_calls;
    unsigned deletes;
    unsigned rethrows;
    unsigned boundary_equal_seen;
    unsigned boundary_stops;
    unsigned signal_deliveries;
    unsigned signal_contexts;
    unsigned failures;
    uintptr_t seed;
    uintptr_t frame_sp[guard_count];
    uintptr_t stopped_sp[max_stops];
    unsigned stopped_after_guards[max_stops];
    unsigned stopped_after_installs[max_stops];
    uintptr_t target_sp;
    uintptr_t boundary_sp;
    uintptr_t signal_registers[17];
    bool forced;
    bool stop_at_target;
    bool terminal_cleanup;
    bool stop_only_at_end;
    bool allow_stop_rewind;
    bool stop_at_boundary;
    bool signal_mode;
    bool signal_altstack;
    _Unwind_Reason_Code stop_result;
    _Unwind_Reason_Code returned;
};

static Observations observed;
static _Unwind_Exception forced_exception;
static std::jmp_buf destination;
static sigjmp_buf signal_destination;
alignas(16) static unsigned char alternate_signal_stack[128 * 1024];
// The potentially-unwinding indirect call must remain visible to the C++
// compiler. A direct call to libc's noexcept raise declaration has no cleanup
// landing pad at the interrupted call site.
static int (*volatile deliver_signal)(int) = raise;

__attribute__((always_inline)) inline uintptr_t stack_pointer() {
    uintptr_t result;
    asm volatile("mov %%rsp, %0" : "=r"(result));
    return result;
}

__attribute__((noinline)) void record_guard(unsigned id, uintptr_t a, uintptr_t b,
                                           uintptr_t c, uintptr_t d, uintptr_t e) {
#ifdef FRANKENLIBC_UNWIND_FIXTURE_TRACE
    std::fprintf(stderr, "guard=%u saved_sp=%p last_stop=%p\n", id,
                 (void*)(id < guard_count ? observed.frame_sp[id] : 0),
                 (void*)(observed.stop_calls == 0 ? 0 : observed.stopped_sp[observed.stop_calls - 1]));
#endif
    const uintptr_t expected = observed.seed + id * seed_step;
    if (id >= guard_count || a != expected + 1 || b != expected + 2 ||
        c != expected + 3 || d != expected + 4 || e != expected + 5) {
        ++observed.failures;
    }
    if (observed.forced &&
        (observed.stop_calls == 0 || id >= guard_count ||
         observed.stopped_sp[observed.stop_calls - 1] != observed.frame_sp[id])) {
        ++observed.failures;
    }
    if (observed.event_count < guard_count + 1) {
        observed.events[observed.event_count++] = id;
    } else {
        ++observed.failures;
    }
}

struct Guard {
    unsigned id;
    uintptr_t a, b, c, d, e;

    ~Guard() noexcept { record_guard(id, a, b, c, d, e); }
};

bool guards_match() {
    if (observed.event_count != guard_count) {
        return false;
    }
    for (unsigned id = 0; id < guard_count; ++id) {
        if (observed.events[id] != id) {
            return false;
        }
    }
    return true;
}

void exception_deleted(_Unwind_Reason_Code reason, _Unwind_Exception* exception) {
    if (exception != &forced_exception || reason != _URC_FOREIGN_EXCEPTION_CAUGHT) {
        ++observed.failures;
    }
    ++observed.deletes;
}

void reset_observations(bool forced) {
    observed = {};
    observed.seed = runtime_seed;
    observed.forced = forced;
    observed.stop_result = _URC_NO_REASON;
    forced_exception = {};
    forced_exception.exception_class = forced_class;
    forced_exception.exception_cleanup = exception_deleted;
}

_Unwind_Reason_Code forced_stop(int version, _Unwind_Action actions,
                               _Unwind_Exception_Class exception_class,
                               _Unwind_Exception* exception,
                               _Unwind_Context* context, void* argument) {
    const bool terminal = (actions & _UA_END_OF_STACK) != 0;
    const _Unwind_Action expected_actions =
        _UA_FORCE_UNWIND | _UA_CLEANUP_PHASE | (terminal ? _UA_END_OF_STACK : 0);
    if (version != 1 || actions != expected_actions ||
        exception_class != forced_class || exception != &forced_exception ||
        argument != &observed || context == nullptr) {
        ++observed.failures;
        return _URC_FATAL_PHASE2_ERROR;
    }
    const uintptr_t sp = _Unwind_GetCFA(context);
    const uintptr_t ip = _Unwind_GetIP(context);
    const bool interrupted_context = observed.signal_mode && ip == observed.signal_registers[16];
    if (interrupted_context) {
        ++observed.signal_contexts;
        int before = 0;
        if (_Unwind_GetIPInfo(context, &before) != ip || before != 1 ||
            sp != observed.signal_registers[7] || observed.signal_contexts != 1) {
            ++observed.failures;
        }
        for (int reg = 0; reg < 17; ++reg) {
            if (_Unwind_GetGR(context, reg) != observed.signal_registers[reg]) {
                ++observed.failures;
            }
        }
    }
#ifdef FRANKENLIBC_UNWIND_FIXTURE_TRACE
    std::fprintf(stderr, "stop=%u actions=%d ip=%p sp=%p target=%p\n",
                 observed.stop_calls, actions, (void*)ip, (void*)sp, (void*)observed.target_sp);
#endif
    if (terminal) {
        ++observed.end_calls;
        if (ip != 0 || observed.end_calls != 1 || observed.stop_at_target || observed.stop_at_boundary) {
            ++observed.failures;
        }
        if (observed.terminal_cleanup) {
            if (!guards_match()) {
                ++observed.failures;
            }
            _Unwind_DeleteException(exception);
            std::longjmp(destination, 1);
        }
        return observed.stop_result;
    }
    if (sp == 0 || ip == 0 || observed.stop_calls == max_stops ||
        (observed.stop_calls != 0 &&
         ((sp < observed.stopped_sp[observed.stop_calls - 1] &&
           !observed.allow_stop_rewind && !interrupted_context) ||
          (sp == observed.stopped_sp[observed.stop_calls - 1] &&
           observed.event_count != observed.stopped_after_guards[observed.stop_calls - 1] + 1 &&
           observed.cleanup_installs != observed.stopped_after_installs[observed.stop_calls - 1] + 1)))) {
        ++observed.failures;
        return _URC_FATAL_PHASE2_ERROR;
    }
    observed.allow_stop_rewind = false;
    observed.stopped_after_guards[observed.stop_calls] = observed.event_count;
    observed.stopped_after_installs[observed.stop_calls] = observed.cleanup_installs;
    observed.stopped_sp[observed.stop_calls++] = sp;
    if (observed.stop_at_boundary && observed.boundary_sp != 0) {
        if (sp == observed.boundary_sp) {
            ++observed.boundary_equal_seen;
        }
        if (sp > observed.boundary_sp) {
            ++observed.boundary_stops;
            if (!guards_match() || observed.boundary_equal_seen != 2 ||
                _Unwind_GetRegionStart(context) != 0 ||
                _Unwind_GetLanguageSpecificData(context) != 0) {
                ++observed.failures;
            }
            _Unwind_DeleteException(exception);
            std::longjmp(destination, 1);
        }
    }
    if (observed.stop_at_target && sp == observed.target_sp) {
        if (!guards_match()) {
            ++observed.failures;
        }
        _Unwind_DeleteException(exception);
        if (observed.signal_mode) {
            siglongjmp(signal_destination, 1);
        }
        std::longjmp(destination, 1);
    }
    if (observed.stop_at_target && sp > observed.target_sp) {
        ++observed.failures;
        return _URC_FATAL_PHASE2_ERROR;
    }
    return observed.stop_only_at_end ? _URC_NO_REASON : observed.stop_result;
}

void signal_unwind_handler(int signum, siginfo_t*, void* raw_context) {
    ++observed.signal_deliveries;
    if (signum != SIGUSR1 || raw_context == nullptr) {
        ++observed.failures;
        return;
    }
    const auto* context = static_cast<const ucontext_t*>(raw_context);
    constexpr int indices[17] = {
        REG_RAX, REG_RDX, REG_RCX, REG_RBX, REG_RSI, REG_RDI, REG_RBP, REG_RSP,
        REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15, REG_RIP
    };
    for (unsigned reg = 0; reg < 17; ++reg) {
        observed.signal_registers[reg] = static_cast<uintptr_t>(context->uc_mcontext.gregs[indices[reg]]);
    }
    if (observed.signal_altstack) {
        const uintptr_t sp = stack_pointer();
        const uintptr_t base = reinterpret_cast<uintptr_t>(alternate_signal_stack);
        if (sp < base || sp >= base + sizeof(alternate_signal_stack)) {
            ++observed.failures;
        }
    }
    observed.returned = _Unwind_ForcedUnwind(&forced_exception, forced_stop, &observed);
    ++observed.failures;
}

// Recursive calls deliberately share return PCs. Handler/cleanup identity must
// distinguish physical frames. Runtime-derived values keep callee-saved locals
// live across each call and make bad register restoration observable in cleanup.
__attribute__((noinline)) void guarded_frames(unsigned depth, bool forced) {
    const uintptr_t seed = observed.seed + depth * seed_step;
    register uintptr_t a asm("rbx") = seed + 1;
    register uintptr_t b asm("r12") = seed + 2;
    register uintptr_t c asm("r13") = seed + 3;
    register uintptr_t d asm("r14") = seed + 4;
    register uintptr_t e asm("r15") = seed + 5;
    asm volatile("" : "+r"(a), "+r"(b), "+r"(c), "+r"(d), "+r"(e));
    Guard guard{depth, a, b, c, d, e};
    observed.frame_sp[depth] = stack_pointer();
    if (depth != 0) {
        guarded_frames(depth - 1, forced);
    } else if (observed.signal_mode) {
        deliver_signal(SIGUSR1);
        ++observed.failures;
    } else if (forced) {
        observed.returned = _Unwind_ForcedUnwind(&forced_exception, forced_stop, &observed);
        ++observed.failures; // A successful forced cleanup leaves through stop.
    } else {
        throw TestException();
    }
}

int report(const char* label, bool result) {
    std::printf("%s: %s guards=%u search=%u cleanup=%u installs=%u stops=%u end=%u delete=%u rethrow=%u signal=%u interrupted=%u failures=%u\n",
                result ? "PASS" : "FAIL", label, observed.event_count,
                observed.search_calls, observed.cleanup_calls, observed.cleanup_installs,
                observed.stop_calls, observed.end_calls, observed.deletes,
                observed.rethrows, observed.signal_deliveries, observed.signal_contexts, observed.failures);
    return result ? 0 : 1;
}

bool personality_checks(bool forced) {
#ifdef FRANKENLIBC_WRAP_PERSONALITY
    return observed.cleanup_installs >= guard_count &&
           observed.search_after_cleanup == 0 &&
           (forced ? observed.search_calls == 0 : observed.search_calls >= guard_count + 1);
#else
    (void)forced;
    return true;
#endif
}

} // namespace

#ifdef FRANKENLIBC_WRAP_PERSONALITY
extern "C" _Unwind_Reason_Code __real___gxx_personality_v0(
    int, _Unwind_Action, _Unwind_Exception_Class, _Unwind_Exception*, _Unwind_Context*);

extern "C" _Unwind_Reason_Code __wrap___gxx_personality_v0(
    int version, _Unwind_Action actions, _Unwind_Exception_Class exception_class,
    _Unwind_Exception* exception, _Unwind_Context* context) {
    if ((actions & _UA_SEARCH_PHASE) != 0) {
        ++observed.search_calls;
        if (observed.cleanup_calls != 0) {
            ++observed.search_after_cleanup;
        }
    }
    if ((actions & _UA_CLEANUP_PHASE) != 0) {
        ++observed.cleanup_calls;
        if (observed.forced &&
            (actions != (_UA_FORCE_UNWIND | _UA_CLEANUP_PHASE) ||
             observed.stop_calls == 0 ||
             _Unwind_GetCFA(context) != observed.stopped_sp[observed.stop_calls - 1])) {
            ++observed.failures;
        }
    }
    const auto result = __real___gxx_personality_v0(
        version, actions, exception_class, exception, context);
    if (result == _URC_INSTALL_CONTEXT) {
        ++observed.cleanup_installs;
    }
    return result;
}
#endif

#ifdef FRANKENLIBC_WRAP_CXA_THROW
extern "C" [[noreturn]] void __real___cxa_throw(
    void* thrown_exception,
    void* type_info,
    void (*destructor)(void*)
);

extern "C" __attribute__((noinline, noreturn)) void __wrap___cxa_throw(
    void* thrown_exception,
    void* type_info,
    void (*destructor)(void*)
) {
    __real___cxa_throw(thrown_exception, type_info, destructor);
    __builtin_unreachable();
}
#endif

int throw_and_catch() {
    try {
        throw TestException();
    } catch (const TestException& e) {
        caught_test_exception = 1;
        printf("CAUGHT: %s\n", e.what());
        return 0; // Success
    } catch (...) {
        printf("CAUGHT: unknown exception\n");
        return 1;
    }
    return 2; // Should not reach
}

extern "C" int minimal_throw_catch_entry() {
    printf("minimal_throw_catch: starting\n");

    int result = throw_and_catch();
    if (caught_test_exception) {
        result = 0;
    }

    if (result == 0) {
        printf("PASS: exception caught correctly\n");
    } else {
        printf("FAIL: exception handling failed (code %d)\n", result);
    }

    if (result != 0) {
        return result;
    }

    reset_observations(false);
    caught_test_exception = 0;
    try {
        guarded_frames(guard_count - 1, false);
    } catch (const TestException&) {
        caught_test_exception = 1;
    } catch (...) {
        ++observed.failures;
    }
    return report("nested throw/cleanup/resume/catch",
                  caught_test_exception == 1 && observed.failures == 0 &&
                  guards_match() && personality_checks(false));
}

extern "C" int owned_forced_unwind_entry() {
    reset_observations(true);
    observed.stop_at_target = true;
    observed.target_sp = stack_pointer();
    if (setjmp(destination) == 0) {
        guarded_frames(guard_count - 1, true);
        ++observed.failures;
    }
    return report("forced cleanup/stop/resume",
                  observed.failures == 0 && guards_match() &&
                  observed.deletes == 1 && observed.end_calls == 0 &&
                  observed.stop_calls == 2 * guard_count + 1 && personality_checks(true));
}

extern "C" int owned_signal_unwind_entry(int alternate_stack) {
    reset_observations(true);
    observed.signal_mode = true;
    observed.signal_altstack = alternate_stack != 0;
    observed.stop_at_target = true;
    observed.target_sp = stack_pointer();
    struct sigaction action{}, previous_action{};
    stack_t previous_stack{};
    action.sa_sigaction = signal_unwind_handler;
    action.sa_flags = SA_SIGINFO | (alternate_stack ? SA_ONSTACK : 0);
    sigemptyset(&action.sa_mask);
    if (alternate_stack) {
        stack_t stack{};
        stack.ss_sp = alternate_signal_stack;
        stack.ss_size = sizeof(alternate_signal_stack);
        if (sigaltstack(&stack, &previous_stack) != 0) {
            return report("install alternate signal stack", false);
        }
    }
    if (sigaction(SIGUSR1, &action, &previous_action) != 0) {
        if (alternate_stack) { sigaltstack(&previous_stack, nullptr); }
        return report("install signal action", false);
    }
    if (sigsetjmp(signal_destination, 1) == 0) {
        guarded_frames(guard_count - 1, true);
        ++observed.failures;
    }
    if (sigaction(SIGUSR1, &previous_action, nullptr) != 0 ||
        (alternate_stack && sigaltstack(&previous_stack, nullptr) != 0)) {
        ++observed.failures;
    }
    return report(alternate_stack ? "signal unwind across alternate stack" : "signal unwind across interrupted frame",
                  observed.failures == 0 && guards_match() &&
                  observed.signal_deliveries == 1 && observed.signal_contexts == 1 &&
                  observed.deletes == 1 && observed.end_calls == 0 && personality_checks(true));
}

__attribute__((noinline)) static void forced_catching_frame() {
    try {
        guarded_frames(guard_count - 1, true);
    } catch (...) {
        // The C++ runtime enters _Unwind_Resume_or_Rethrow from its own frame.
        // It must retain forced state, not begin a fresh handler search.
        ++observed.rethrows;
        observed.allow_stop_rewind = true;
        throw;
    }
}

extern "C" int owned_forced_unwind_rethrow_entry() {
    reset_observations(true);
    observed.stop_at_target = true;
    observed.target_sp = stack_pointer();
    if (setjmp(destination) == 0) {
        forced_catching_frame();
        ++observed.failures;
    }
    return report("forced catch/rethrow keeps stop state",
                  observed.failures == 0 && guards_match() && observed.rethrows == 1 &&
                  observed.deletes == 1 && observed.end_calls == 0 &&
                  observed.stop_calls > 2 * guard_count + 1 && personality_checks(true));
}

// A real assembly call frame with an explicitly undefined return-address rule
// supplies a bounded physical stack root. This tests end-of-stack without
// unwinding the Python/dlopen driver or depending on host startup CFI details.
extern "C" __attribute__((visibility("hidden"))) void owned_force_terminal_root();
extern "C" __attribute__((visibility("hidden"))) void owned_force_missing_fde_root();
extern "C" __attribute__((visibility("hidden"))) void owned_force_boundary_root();
extern "C" __attribute__((visibility("hidden"), noinline)) void owned_force_terminal_body() {
    if (observed.terminal_cleanup) {
        guarded_frames(guard_count - 1, true);
        ++observed.failures;
    } else {
        observed.returned = _Unwind_ForcedUnwind(&forced_exception, forced_stop, &observed);
    }
}

extern "C" __attribute__((visibility("hidden"), noinline)) void owned_force_boundary_body() {
    constexpr unsigned id = guard_count - 1;
    const uintptr_t seed = observed.seed + id * seed_step;
    Guard guard{id, seed + 1, seed + 2, seed + 3, seed + 4, seed + 5};
    observed.frame_sp[id] = stack_pointer();
    observed.boundary_sp = observed.frame_sp[id];
    guarded_frames(id - 1, true);
    ++observed.failures;
}

asm(".text\n"
    ".p2align 4\n"
    ".hidden owned_force_terminal_root\n"
    ".type owned_force_terminal_root,@function\n"
    "owned_force_terminal_root:\n"
    ".cfi_startproc\n"
    ".cfi_undefined 16\n"
    "sub $8,%rsp\n"
    ".cfi_def_cfa_offset 16\n"
    "call owned_force_terminal_body\n"
    "add $8,%rsp\n"
    ".cfi_def_cfa_offset 8\n"
    "ret\n"
    ".cfi_endproc\n"
    ".size owned_force_terminal_root,.-owned_force_terminal_root\n"
    ".p2align 4\n"
    ".hidden owned_force_missing_fde_root\n"
    ".type owned_force_missing_fde_root,@function\n"
    "owned_force_missing_fde_root:\n"
    "sub $8,%rsp\n"
    "call owned_force_terminal_body\n"
    "add $8,%rsp\n"
    "ret\n"
    ".size owned_force_missing_fde_root,.-owned_force_missing_fde_root\n"
    ".p2align 4\n"
    ".hidden owned_force_boundary_root\n"
    ".type owned_force_boundary_root,@function\n"
    "owned_force_boundary_root:\n"
    "sub $8,%rsp\n"
    "call owned_force_boundary_body\n"
    "add $8,%rsp\n"
    "ret\n"
    ".size owned_force_boundary_root,.-owned_force_boundary_root\n");

extern "C" int owned_unwind_missing_fde_entry() {
    reset_observations(true);
    owned_force_missing_fde_root();
    // A nonzero PC with absent metadata is not an observed terminal frame.
    // This is the owned cursor's unsupported-input policy: some host unwinders
    // permissively treat this as stack end, so it is an owned-only assertion.
    int result = report("missing FDE fails without false terminal callback",
                        observed.failures == 0 && observed.stop_calls == 2 &&
                        observed.end_calls == 0 && observed.event_count == 0 &&
                        observed.returned == _URC_FATAL_PHASE2_ERROR && observed.deletes == 0);
    _Unwind_DeleteException(&forced_exception);
    return result | (observed.deletes != 1 || observed.failures != 0);
}

extern "C" int owned_forced_unwind_boundary_entry() {
    reset_observations(true);
    observed.terminal_cleanup = true;
    observed.stop_at_boundary = true;
    if (setjmp(destination) == 0) {
        owned_force_boundary_root();
        ++observed.failures;
    }
    // Native clone teardown uses this protocol: its valid outer frame still
    // runs at equality, then the stop callback consumes the recovered cursor
    // above the boundary without asking CFI to describe the synthetic caller.
    return report("external stop consumes a physical no-CFI boundary",
                  observed.failures == 0 && guards_match() &&
                  observed.boundary_equal_seen == 2 && observed.boundary_stops == 1 &&
                  observed.deletes == 1 && observed.end_calls == 0 &&
                  observed.stop_calls == 2 * guard_count + 1 && personality_checks(true));
}

extern "C" int owned_forced_unwind_end_entry() {
    reset_observations(true);
    observed.terminal_cleanup = true;
    if (setjmp(destination) == 0) {
        owned_force_terminal_root();
        ++observed.failures;
    }
    int result = report("forced cleanup to physical stack end",
                        observed.failures == 0 && guards_match() &&
                        observed.deletes == 1 && observed.end_calls == 1 &&
                        personality_checks(true));

    reset_observations(true);
    owned_force_terminal_root();
    result |= report("terminal stop returning zero",
                     observed.failures == 0 && observed.end_calls == 1 &&
                     observed.event_count == 0 && observed.search_calls == 0 &&
                     observed.returned == _URC_END_OF_STACK && observed.deletes == 0);
    _Unwind_DeleteException(&forced_exception);
    return result | (observed.deletes != 1 || observed.failures != 0);
}

extern "C" int owned_unwind_negative_entry() {
    const _Unwind_Reason_Code codes[] = {
        _URC_NORMAL_STOP, _URC_END_OF_STACK, _URC_FATAL_PHASE1_ERROR,
        _URC_FATAL_PHASE2_ERROR, _URC_CONTINUE_UNWIND
    };
    int result = 0;
    for (const auto code : codes) {
        reset_observations(true);
        observed.stop_result = code;
        observed.returned = _Unwind_ForcedUnwind(&forced_exception, forced_stop, &observed);
        result |= report("nonzero stop becomes fatal phase 2",
                         observed.failures == 0 && observed.stop_calls == 1 &&
                         observed.search_calls == 0 && observed.cleanup_calls == 0 &&
                         observed.end_calls == 0 && observed.deletes == 0 &&
                         observed.returned == _URC_FATAL_PHASE2_ERROR);
        _Unwind_DeleteException(&forced_exception);
        result |= observed.deletes != 1 || observed.failures != 0;
    }
    reset_observations(true);
    observed.stop_only_at_end = true;
    observed.stop_result = _URC_END_OF_STACK;
    owned_force_terminal_root();
    result |= report("nonzero terminal stop becomes fatal phase 2",
                     observed.failures == 0 && observed.end_calls == 1 &&
                     observed.returned == _URC_FATAL_PHASE2_ERROR && observed.deletes == 0);
    _Unwind_DeleteException(&forced_exception);
    result |= observed.deletes != 1 || observed.failures != 0;
    return result;
}

int main(int argc, char** argv) {
    if (argc == 2 && std::strcmp(argv[1], "signal") == 0) {
        return owned_signal_unwind_entry(0);
    }
    if (argc == 2 && std::strcmp(argv[1], "signal_altstack") == 0) {
        return owned_signal_unwind_entry(1);
    }
    if (argc == 2 && std::strcmp(argv[1], "forced") == 0) {
        return owned_forced_unwind_entry();
    }
    if (argc == 2 && std::strcmp(argv[1], "end") == 0) {
        return owned_forced_unwind_end_entry();
    }
    if (argc == 2 && std::strcmp(argv[1], "rethrow") == 0) {
        return owned_forced_unwind_rethrow_entry();
    }
    if (argc == 2 && std::strcmp(argv[1], "missing_fde") == 0) {
        return owned_unwind_missing_fde_entry();
    }
    if (argc == 2 && std::strcmp(argv[1], "boundary") == 0) {
        return owned_forced_unwind_boundary_entry();
    }
    if (argc == 2 && std::strcmp(argv[1], "negative") == 0) {
        return owned_unwind_negative_entry();
    }
    return minimal_throw_catch_entry();
}
