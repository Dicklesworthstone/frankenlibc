# frankenlibc Conformance Report

- Mode: strict+hardened
- Timestamp: 1970-01-01T00:00:00Z
- Total: 1817
- Passed: 1817
- Failed: 0

| Trace | Family | Symbol | Mode | Case | Spec | Status |
|-------|--------|--------|------|------|------|--------|
| `fixture-verify::allocator::calloc::strict::calloc_basic` | allocator | calloc | strict | calloc_basic | POSIX calloc | PASS |
| `fixture-verify::allocator::free::strict::free_null` | allocator | free | strict | free_null | POSIX free | PASS |
| `fixture-verify::allocator::malloc::strict::malloc_basic` | allocator | malloc | strict | malloc_basic | POSIX malloc | PASS |
| `fixture-verify::allocator::malloc::strict::malloc_zero` | allocator | malloc | strict | malloc_zero | POSIX malloc | PASS |
| `fixture-verify::allocator::realloc::strict::realloc_null_is_malloc` | allocator | realloc | strict | realloc_null_is_malloc | POSIX realloc | PASS |
| `fixture-verify::backtrace_ops::backtrace::hardened::backtrace_captures_frames_hardened` | backtrace_ops | backtrace | hardened | backtrace_captures_frames_hardened | GNU backtrace(3) | PASS |
| `fixture-verify::backtrace_ops::backtrace::hardened::backtrace_corrupted_stack_hardened` | backtrace_ops | backtrace | hardened | backtrace_corrupted_stack_hardened | FrankenLibC TSM repair | PASS |
| `fixture-verify::backtrace_ops::backtrace::strict::backtrace_captures_frames_strict` | backtrace_ops | backtrace | strict | backtrace_captures_frames_strict | GNU backtrace(3) | PASS |
| `fixture-verify::backtrace_ops::backtrace_symbols::strict::backtrace_symbols_strict` | backtrace_ops | backtrace_symbols | strict | backtrace_symbols_strict | GNU backtrace_symbols(3) | PASS |
| `fixture-verify::backtrace_ops::backtrace_symbols_fd::strict::backtrace_symbols_fd_strict` | backtrace_ops | backtrace_symbols_fd | strict | backtrace_symbols_fd_strict | GNU backtrace_symbols_fd(3) | PASS |
| `fixture-verify::c11threads/ops::call_once::hardened::call_once_three_invocations` | c11threads/ops | call_once | hardened | call_once_three_invocations [hardened] | ISO C11 7.26.2.1 | PASS |
| `fixture-verify::c11threads/ops::call_once::strict::call_once_three_invocations` | c11threads/ops | call_once | strict | call_once_three_invocations [strict] | ISO C11 7.26.2.1 | PASS |
| `fixture-verify::c11threads/ops::cnd_broadcast::hardened::cnd_broadcast_no_waiters` | c11threads/ops | cnd_broadcast | hardened | cnd_broadcast_no_waiters [hardened] | ISO C11 7.26.3.1 | PASS |
| `fixture-verify::c11threads/ops::cnd_broadcast::strict::cnd_broadcast_no_waiters` | c11threads/ops | cnd_broadcast | strict | cnd_broadcast_no_waiters [strict] | ISO C11 7.26.3.1 | PASS |
| `fixture-verify::c11threads/ops::cnd_destroy::hardened::cnd_destroy_initialized` | c11threads/ops | cnd_destroy | hardened | cnd_destroy_initialized [hardened] | ISO C11 7.26.3.3 | PASS |
| `fixture-verify::c11threads/ops::cnd_destroy::strict::cnd_destroy_initialized` | c11threads/ops | cnd_destroy | strict | cnd_destroy_initialized [strict] | ISO C11 7.26.3.3 | PASS |
| `fixture-verify::c11threads/ops::cnd_init::hardened::cnd_init_basic` | c11threads/ops | cnd_init | hardened | cnd_init_basic [hardened] | ISO C11 7.26.3.2 | PASS |
| `fixture-verify::c11threads/ops::cnd_init::strict::cnd_init_basic` | c11threads/ops | cnd_init | strict | cnd_init_basic [strict] | ISO C11 7.26.3.2 | PASS |
| `fixture-verify::c11threads/ops::cnd_signal::hardened::cnd_signal_no_waiters` | c11threads/ops | cnd_signal | hardened | cnd_signal_no_waiters [hardened] | ISO C11 7.26.3.5 | PASS |
| `fixture-verify::c11threads/ops::cnd_signal::strict::cnd_signal_no_waiters` | c11threads/ops | cnd_signal | strict | cnd_signal_no_waiters [strict] | ISO C11 7.26.3.5 | PASS |
| `fixture-verify::c11threads/ops::cnd_timedwait::hardened::cnd_timedwait_past_deadline` | c11threads/ops | cnd_timedwait | hardened | cnd_timedwait_past_deadline [hardened] | ISO C11 7.26.3.6 | PASS |
| `fixture-verify::c11threads/ops::cnd_timedwait::strict::cnd_timedwait_past_deadline` | c11threads/ops | cnd_timedwait | strict | cnd_timedwait_past_deadline [strict] | ISO C11 7.26.3.6 | PASS |
| `fixture-verify::c11threads/ops::mtx_destroy::hardened::mtx_destroy_initialized` | c11threads/ops | mtx_destroy | hardened | mtx_destroy_initialized [hardened] | ISO C11 7.26.4.1 | PASS |
| `fixture-verify::c11threads/ops::mtx_destroy::strict::mtx_destroy_initialized` | c11threads/ops | mtx_destroy | strict | mtx_destroy_initialized [strict] | ISO C11 7.26.4.1 | PASS |
| `fixture-verify::c11threads/ops::mtx_init::hardened::mtx_init_plain` | c11threads/ops | mtx_init | hardened | mtx_init_plain [hardened] | ISO C11 7.26.4.2 | PASS |
| `fixture-verify::c11threads/ops::mtx_init::strict::mtx_init_plain` | c11threads/ops | mtx_init | strict | mtx_init_plain [strict] | ISO C11 7.26.4.2 | PASS |
| `fixture-verify::c11threads/ops::mtx_lock::hardened::mtx_lock_plain` | c11threads/ops | mtx_lock | hardened | mtx_lock_plain [hardened] | ISO C11 7.26.4.3 | PASS |
| `fixture-verify::c11threads/ops::mtx_lock::strict::mtx_lock_plain` | c11threads/ops | mtx_lock | strict | mtx_lock_plain [strict] | ISO C11 7.26.4.3 | PASS |
| `fixture-verify::c11threads/ops::mtx_timedlock::hardened::mtx_timedlock_available` | c11threads/ops | mtx_timedlock | hardened | mtx_timedlock_available [hardened] | ISO C11 7.26.4.4 | PASS |
| `fixture-verify::c11threads/ops::mtx_timedlock::strict::mtx_timedlock_available` | c11threads/ops | mtx_timedlock | strict | mtx_timedlock_available [strict] | ISO C11 7.26.4.4 | PASS |
| `fixture-verify::c11threads/ops::mtx_trylock::hardened::mtx_trylock_plain` | c11threads/ops | mtx_trylock | hardened | mtx_trylock_plain [hardened] | ISO C11 7.26.4.5 | PASS |
| `fixture-verify::c11threads/ops::mtx_trylock::strict::mtx_trylock_plain` | c11threads/ops | mtx_trylock | strict | mtx_trylock_plain [strict] | ISO C11 7.26.4.5 | PASS |
| `fixture-verify::c11threads/ops::mtx_unlock::hardened::mtx_unlock_after_lock` | c11threads/ops | mtx_unlock | hardened | mtx_unlock_after_lock [hardened] | ISO C11 7.26.4.6 | PASS |
| `fixture-verify::c11threads/ops::mtx_unlock::strict::mtx_unlock_after_lock` | c11threads/ops | mtx_unlock | strict | mtx_unlock_after_lock [strict] | ISO C11 7.26.4.6 | PASS |
| `fixture-verify::c11threads/ops::thrd_create::hardened::thrd_create_join_result` | c11threads/ops | thrd_create | hardened | thrd_create_join_result [hardened] | ISO C11 7.26.5.1 | PASS |
| `fixture-verify::c11threads/ops::thrd_create::strict::thrd_create_join_result` | c11threads/ops | thrd_create | strict | thrd_create_join_result [strict] | ISO C11 7.26.5.1 | PASS |
| `fixture-verify::c11threads/ops::thrd_current::hardened::thrd_current_nonzero` | c11threads/ops | thrd_current | hardened | thrd_current_nonzero [hardened] | ISO C11 7.26.5.4 | PASS |
| `fixture-verify::c11threads/ops::thrd_current::strict::thrd_current_nonzero` | c11threads/ops | thrd_current | strict | thrd_current_nonzero [strict] | ISO C11 7.26.5.4 | PASS |
| `fixture-verify::c11threads/ops::thrd_detach::hardened::thrd_detach_joinless_thread` | c11threads/ops | thrd_detach | hardened | thrd_detach_joinless_thread [hardened] | ISO C11 7.26.5.2 | PASS |
| `fixture-verify::c11threads/ops::thrd_detach::strict::thrd_detach_joinless_thread` | c11threads/ops | thrd_detach | strict | thrd_detach_joinless_thread [strict] | ISO C11 7.26.5.2 | PASS |
| `fixture-verify::c11threads/ops::thrd_equal::hardened::thrd_equal_self` | c11threads/ops | thrd_equal | hardened | thrd_equal_self [hardened] | ISO C11 7.26.5.5 | PASS |
| `fixture-verify::c11threads/ops::thrd_equal::strict::thrd_equal_self` | c11threads/ops | thrd_equal | strict | thrd_equal_self [strict] | ISO C11 7.26.5.5 | PASS |
| `fixture-verify::c11threads/ops::thrd_join::hardened::thrd_join_collects_int_result` | c11threads/ops | thrd_join | hardened | thrd_join_collects_int_result [hardened] | ISO C11 7.26.5.6 | PASS |
| `fixture-verify::c11threads/ops::thrd_join::strict::thrd_join_collects_int_result` | c11threads/ops | thrd_join | strict | thrd_join_collects_int_result [strict] | ISO C11 7.26.5.6 | PASS |
| `fixture-verify::c11threads/ops::thrd_sleep::hardened::thrd_sleep_zero_duration` | c11threads/ops | thrd_sleep | hardened | thrd_sleep_zero_duration [hardened] | ISO C11 7.26.5.7 | PASS |
| `fixture-verify::c11threads/ops::thrd_sleep::strict::thrd_sleep_zero_duration` | c11threads/ops | thrd_sleep | strict | thrd_sleep_zero_duration [strict] | ISO C11 7.26.5.7 | PASS |
| `fixture-verify::c11threads/ops::thrd_yield::hardened::thrd_yield_returns` | c11threads/ops | thrd_yield | hardened | thrd_yield_returns [hardened] | ISO C11 7.26.5.8 | PASS |
| `fixture-verify::c11threads/ops::thrd_yield::strict::thrd_yield_returns` | c11threads/ops | thrd_yield | strict | thrd_yield_returns [strict] | ISO C11 7.26.5.8 | PASS |
| `fixture-verify::c11threads/ops::tss_create::hardened::tss_create_basic` | c11threads/ops | tss_create | hardened | tss_create_basic [hardened] | ISO C11 7.26.6.1 | PASS |
| `fixture-verify::c11threads/ops::tss_create::strict::tss_create_basic` | c11threads/ops | tss_create | strict | tss_create_basic [strict] | ISO C11 7.26.6.1 | PASS |
| `fixture-verify::c11threads/ops::tss_delete::hardened::tss_delete_created_key` | c11threads/ops | tss_delete | hardened | tss_delete_created_key [hardened] | ISO C11 7.26.6.2 | PASS |
| `fixture-verify::c11threads/ops::tss_delete::strict::tss_delete_created_key` | c11threads/ops | tss_delete | strict | tss_delete_created_key [strict] | ISO C11 7.26.6.2 | PASS |
| `fixture-verify::c11threads/ops::tss_get::hardened::tss_get_roundtrip` | c11threads/ops | tss_get | hardened | tss_get_roundtrip [hardened] | ISO C11 7.26.6.3 | PASS |
| `fixture-verify::c11threads/ops::tss_get::strict::tss_get_roundtrip` | c11threads/ops | tss_get | strict | tss_get_roundtrip [strict] | ISO C11 7.26.6.3 | PASS |
| `fixture-verify::c11threads/ops::tss_set::hardened::tss_set_roundtrip` | c11threads/ops | tss_set | hardened | tss_set_roundtrip [hardened] | ISO C11 7.26.6.4 | PASS |
| `fixture-verify::c11threads/ops::tss_set::strict::tss_set_roundtrip` | c11threads/ops | tss_set | strict | tss_set_roundtrip [strict] | ISO C11 7.26.6.4 | PASS |
| `fixture-verify::ctype::isalnum::hardened::isalnum_digit_5` | ctype | isalnum | hardened | isalnum_digit_5 [hardened] | POSIX.1-2017 isalnum | PASS |
| `fixture-verify::ctype::isalnum::hardened::isalnum_letter_M` | ctype | isalnum | hardened | isalnum_letter_M [hardened] | POSIX.1-2017 isalnum | PASS |
| `fixture-verify::ctype::isalnum::hardened::isalnum_underscore` | ctype | isalnum | hardened | isalnum_underscore [hardened] | POSIX.1-2017 isalnum | PASS |
| `fixture-verify::ctype::isalnum::strict::isalnum_digit_5` | ctype | isalnum | strict | isalnum_digit_5 [strict] | POSIX.1-2017 isalnum | PASS |
| `fixture-verify::ctype::isalnum::strict::isalnum_letter_M` | ctype | isalnum | strict | isalnum_letter_M [strict] | POSIX.1-2017 isalnum | PASS |
| `fixture-verify::ctype::isalnum::strict::isalnum_underscore` | ctype | isalnum | strict | isalnum_underscore [strict] | POSIX.1-2017 isalnum | PASS |
| `fixture-verify::ctype::isalpha::hardened::isalpha_digit_0` | ctype | isalpha | hardened | isalpha_digit_0 [hardened] | POSIX.1-2017 isalpha | PASS |
| `fixture-verify::ctype::isalpha::hardened::isalpha_lowercase_z` | ctype | isalpha | hardened | isalpha_lowercase_z [hardened] | POSIX.1-2017 isalpha | PASS |
| `fixture-verify::ctype::isalpha::hardened::isalpha_space` | ctype | isalpha | hardened | isalpha_space [hardened] | POSIX.1-2017 isalpha | PASS |
| `fixture-verify::ctype::isalpha::hardened::isalpha_uppercase_A` | ctype | isalpha | hardened | isalpha_uppercase_A [hardened] | POSIX.1-2017 isalpha | PASS |
| `fixture-verify::ctype::isalpha::strict::isalpha_digit_0` | ctype | isalpha | strict | isalpha_digit_0 [strict] | POSIX.1-2017 isalpha | PASS |
| `fixture-verify::ctype::isalpha::strict::isalpha_lowercase_z` | ctype | isalpha | strict | isalpha_lowercase_z [strict] | POSIX.1-2017 isalpha | PASS |
| `fixture-verify::ctype::isalpha::strict::isalpha_space` | ctype | isalpha | strict | isalpha_space [strict] | POSIX.1-2017 isalpha | PASS |
| `fixture-verify::ctype::isalpha::strict::isalpha_uppercase_A` | ctype | isalpha | strict | isalpha_uppercase_A [strict] | POSIX.1-2017 isalpha | PASS |
| `fixture-verify::ctype::isdigit::hardened::isdigit_0` | ctype | isdigit | hardened | isdigit_0 [hardened] | POSIX.1-2017 isdigit | PASS |
| `fixture-verify::ctype::isdigit::hardened::isdigit_9` | ctype | isdigit | hardened | isdigit_9 [hardened] | POSIX.1-2017 isdigit | PASS |
| `fixture-verify::ctype::isdigit::hardened::isdigit_A` | ctype | isdigit | hardened | isdigit_A [hardened] | POSIX.1-2017 isdigit | PASS |
| `fixture-verify::ctype::isdigit::strict::isdigit_0` | ctype | isdigit | strict | isdigit_0 [strict] | POSIX.1-2017 isdigit | PASS |
| `fixture-verify::ctype::isdigit::strict::isdigit_9` | ctype | isdigit | strict | isdigit_9 [strict] | POSIX.1-2017 isdigit | PASS |
| `fixture-verify::ctype::isdigit::strict::isdigit_A` | ctype | isdigit | strict | isdigit_A [strict] | POSIX.1-2017 isdigit | PASS |
| `fixture-verify::ctype::islower::hardened::islower_A` | ctype | islower | hardened | islower_A [hardened] | POSIX.1-2017 islower | PASS |
| `fixture-verify::ctype::islower::hardened::islower_a` | ctype | islower | hardened | islower_a [hardened] | POSIX.1-2017 islower | PASS |
| `fixture-verify::ctype::islower::strict::islower_A` | ctype | islower | strict | islower_A [strict] | POSIX.1-2017 islower | PASS |
| `fixture-verify::ctype::islower::strict::islower_a` | ctype | islower | strict | islower_a [strict] | POSIX.1-2017 islower | PASS |
| `fixture-verify::ctype::isprint::hardened::isprint_del` | ctype | isprint | hardened | isprint_del [hardened] | POSIX.1-2017 isprint | PASS |
| `fixture-verify::ctype::isprint::hardened::isprint_null` | ctype | isprint | hardened | isprint_null [hardened] | POSIX.1-2017 isprint | PASS |
| `fixture-verify::ctype::isprint::hardened::isprint_space` | ctype | isprint | hardened | isprint_space [hardened] | POSIX.1-2017 isprint | PASS |
| `fixture-verify::ctype::isprint::hardened::isprint_tilde` | ctype | isprint | hardened | isprint_tilde [hardened] | POSIX.1-2017 isprint | PASS |
| `fixture-verify::ctype::isprint::strict::isprint_del` | ctype | isprint | strict | isprint_del [strict] | POSIX.1-2017 isprint | PASS |
| `fixture-verify::ctype::isprint::strict::isprint_null` | ctype | isprint | strict | isprint_null [strict] | POSIX.1-2017 isprint | PASS |
| `fixture-verify::ctype::isprint::strict::isprint_space` | ctype | isprint | strict | isprint_space [strict] | POSIX.1-2017 isprint | PASS |
| `fixture-verify::ctype::isprint::strict::isprint_tilde` | ctype | isprint | strict | isprint_tilde [strict] | POSIX.1-2017 isprint | PASS |
| `fixture-verify::ctype::ispunct::hardened::ispunct_at` | ctype | ispunct | hardened | ispunct_at [hardened] | POSIX.1-2017 ispunct | PASS |
| `fixture-verify::ctype::ispunct::hardened::ispunct_exclamation` | ctype | ispunct | hardened | ispunct_exclamation [hardened] | POSIX.1-2017 ispunct | PASS |
| `fixture-verify::ctype::ispunct::hardened::ispunct_letter` | ctype | ispunct | hardened | ispunct_letter [hardened] | POSIX.1-2017 ispunct | PASS |
| `fixture-verify::ctype::ispunct::strict::ispunct_at` | ctype | ispunct | strict | ispunct_at [strict] | POSIX.1-2017 ispunct | PASS |
| `fixture-verify::ctype::ispunct::strict::ispunct_exclamation` | ctype | ispunct | strict | ispunct_exclamation [strict] | POSIX.1-2017 ispunct | PASS |
| `fixture-verify::ctype::ispunct::strict::ispunct_letter` | ctype | ispunct | strict | ispunct_letter [strict] | POSIX.1-2017 ispunct | PASS |
| `fixture-verify::ctype::isspace::hardened::isspace_letter` | ctype | isspace | hardened | isspace_letter [hardened] | POSIX.1-2017 isspace | PASS |
| `fixture-verify::ctype::isspace::hardened::isspace_newline` | ctype | isspace | hardened | isspace_newline [hardened] | POSIX.1-2017 isspace | PASS |
| `fixture-verify::ctype::isspace::hardened::isspace_space` | ctype | isspace | hardened | isspace_space [hardened] | POSIX.1-2017 isspace | PASS |
| `fixture-verify::ctype::isspace::hardened::isspace_tab` | ctype | isspace | hardened | isspace_tab [hardened] | POSIX.1-2017 isspace | PASS |
| `fixture-verify::ctype::isspace::strict::isspace_letter` | ctype | isspace | strict | isspace_letter [strict] | POSIX.1-2017 isspace | PASS |
| `fixture-verify::ctype::isspace::strict::isspace_newline` | ctype | isspace | strict | isspace_newline [strict] | POSIX.1-2017 isspace | PASS |
| `fixture-verify::ctype::isspace::strict::isspace_space` | ctype | isspace | strict | isspace_space [strict] | POSIX.1-2017 isspace | PASS |
| `fixture-verify::ctype::isspace::strict::isspace_tab` | ctype | isspace | strict | isspace_tab [strict] | POSIX.1-2017 isspace | PASS |
| `fixture-verify::ctype::isupper::hardened::isupper_A` | ctype | isupper | hardened | isupper_A [hardened] | POSIX.1-2017 isupper | PASS |
| `fixture-verify::ctype::isupper::hardened::isupper_a` | ctype | isupper | hardened | isupper_a [hardened] | POSIX.1-2017 isupper | PASS |
| `fixture-verify::ctype::isupper::strict::isupper_A` | ctype | isupper | strict | isupper_A [strict] | POSIX.1-2017 isupper | PASS |
| `fixture-verify::ctype::isupper::strict::isupper_a` | ctype | isupper | strict | isupper_a [strict] | POSIX.1-2017 isupper | PASS |
| `fixture-verify::ctype::isxdigit::hardened::isxdigit_9` | ctype | isxdigit | hardened | isxdigit_9 [hardened] | POSIX.1-2017 isxdigit | PASS |
| `fixture-verify::ctype::isxdigit::hardened::isxdigit_A` | ctype | isxdigit | hardened | isxdigit_A [hardened] | POSIX.1-2017 isxdigit | PASS |
| `fixture-verify::ctype::isxdigit::hardened::isxdigit_f` | ctype | isxdigit | hardened | isxdigit_f [hardened] | POSIX.1-2017 isxdigit | PASS |
| `fixture-verify::ctype::isxdigit::hardened::isxdigit_g` | ctype | isxdigit | hardened | isxdigit_g [hardened] | POSIX.1-2017 isxdigit | PASS |
| `fixture-verify::ctype::isxdigit::strict::isxdigit_9` | ctype | isxdigit | strict | isxdigit_9 [strict] | POSIX.1-2017 isxdigit | PASS |
| `fixture-verify::ctype::isxdigit::strict::isxdigit_A` | ctype | isxdigit | strict | isxdigit_A [strict] | POSIX.1-2017 isxdigit | PASS |
| `fixture-verify::ctype::isxdigit::strict::isxdigit_f` | ctype | isxdigit | strict | isxdigit_f [strict] | POSIX.1-2017 isxdigit | PASS |
| `fixture-verify::ctype::isxdigit::strict::isxdigit_g` | ctype | isxdigit | strict | isxdigit_g [strict] | POSIX.1-2017 isxdigit | PASS |
| `fixture-verify::ctype::tolower::hardened::tolower_A` | ctype | tolower | hardened | tolower_A [hardened] | POSIX.1-2017 tolower | PASS |
| `fixture-verify::ctype::tolower::hardened::tolower_Z` | ctype | tolower | hardened | tolower_Z [hardened] | POSIX.1-2017 tolower | PASS |
| `fixture-verify::ctype::tolower::hardened::tolower_already_lower` | ctype | tolower | hardened | tolower_already_lower [hardened] | POSIX.1-2017 tolower | PASS |
| `fixture-verify::ctype::tolower::hardened::tolower_digit` | ctype | tolower | hardened | tolower_digit [hardened] | POSIX.1-2017 tolower | PASS |
| `fixture-verify::ctype::tolower::strict::tolower_A` | ctype | tolower | strict | tolower_A [strict] | POSIX.1-2017 tolower | PASS |
| `fixture-verify::ctype::tolower::strict::tolower_Z` | ctype | tolower | strict | tolower_Z [strict] | POSIX.1-2017 tolower | PASS |
| `fixture-verify::ctype::tolower::strict::tolower_already_lower` | ctype | tolower | strict | tolower_already_lower [strict] | POSIX.1-2017 tolower | PASS |
| `fixture-verify::ctype::tolower::strict::tolower_digit` | ctype | tolower | strict | tolower_digit [strict] | POSIX.1-2017 tolower | PASS |
| `fixture-verify::ctype::toupper::hardened::toupper_a` | ctype | toupper | hardened | toupper_a [hardened] | POSIX.1-2017 toupper | PASS |
| `fixture-verify::ctype::toupper::hardened::toupper_already_upper` | ctype | toupper | hardened | toupper_already_upper [hardened] | POSIX.1-2017 toupper | PASS |
| `fixture-verify::ctype::toupper::hardened::toupper_digit` | ctype | toupper | hardened | toupper_digit [hardened] | POSIX.1-2017 toupper | PASS |
| `fixture-verify::ctype::toupper::hardened::toupper_z` | ctype | toupper | hardened | toupper_z [hardened] | POSIX.1-2017 toupper | PASS |
| `fixture-verify::ctype::toupper::strict::toupper_a` | ctype | toupper | strict | toupper_a [strict] | POSIX.1-2017 toupper | PASS |
| `fixture-verify::ctype::toupper::strict::toupper_already_upper` | ctype | toupper | strict | toupper_already_upper [strict] | POSIX.1-2017 toupper | PASS |
| `fixture-verify::ctype::toupper::strict::toupper_digit` | ctype | toupper | strict | toupper_digit [strict] | POSIX.1-2017 toupper | PASS |
| `fixture-verify::ctype::toupper::strict::toupper_z` | ctype | toupper | strict | toupper_z [strict] | POSIX.1-2017 toupper | PASS |
| `fixture-verify::dirent_ops::closedir::strict::closedir_valid_strict` | dirent_ops | closedir | strict | closedir_valid_strict | POSIX closedir | PASS |
| `fixture-verify::dirent_ops::dirfd::hardened::dirfd_valid_hardened` | dirent_ops | dirfd | hardened | dirfd_valid_hardened | POSIX dirfd | PASS |
| `fixture-verify::dirent_ops::dirfd::strict::dirfd_valid_strict` | dirent_ops | dirfd | strict | dirfd_valid_strict | POSIX dirfd | PASS |
| `fixture-verify::dirent_ops::opendir::hardened::opendir_nonexistent_hardened` | dirent_ops | opendir | hardened | opendir_nonexistent_hardened | POSIX opendir | PASS |
| `fixture-verify::dirent_ops::opendir::hardened::opendir_root_hardened` | dirent_ops | opendir | hardened | opendir_root_hardened | POSIX opendir | PASS |
| `fixture-verify::dirent_ops::opendir::strict::opendir_nonexistent_strict` | dirent_ops | opendir | strict | opendir_nonexistent_strict | POSIX opendir | PASS |
| `fixture-verify::dirent_ops::opendir::strict::opendir_root_strict` | dirent_ops | opendir | strict | opendir_root_strict | POSIX opendir | PASS |
| `fixture-verify::dirent_ops::readdir::strict::readdir_root_strict` | dirent_ops | readdir | strict | readdir_root_strict | POSIX readdir | PASS |
| `fixture-verify::dirent_ops::rewinddir::hardened::rewinddir_valid_hardened` | dirent_ops | rewinddir | hardened | rewinddir_valid_hardened | POSIX rewinddir | PASS |
| `fixture-verify::dirent_ops::rewinddir::strict::rewinddir_valid_strict` | dirent_ops | rewinddir | strict | rewinddir_valid_strict | POSIX rewinddir | PASS |
| `fixture-verify::dirent_ops::seekdir::strict::seekdir_zero_strict` | dirent_ops | seekdir | strict | seekdir_zero_strict | POSIX seekdir | PASS |
| `fixture-verify::dirent_ops::telldir::hardened::telldir_valid_hardened` | dirent_ops | telldir | hardened | telldir_valid_hardened | POSIX telldir | PASS |
| `fixture-verify::dirent_ops::telldir::strict::telldir_valid_strict` | dirent_ops | telldir | strict | telldir_valid_strict | POSIX telldir | PASS |
| `fixture-verify::dlfcn_ops::dlerror::strict::dlerror_after_success_strict` | dlfcn_ops | dlerror | strict | dlerror_after_success_strict | POSIX dlerror | PASS |
| `fixture-verify::dlfcn_ops::dlopen::hardened::dlopen_self_hardened` | dlfcn_ops | dlopen | hardened | dlopen_self_hardened | POSIX dlopen | PASS |
| `fixture-verify::dlfcn_ops::dlopen::strict::dlopen_nonexistent_strict` | dlfcn_ops | dlopen | strict | dlopen_nonexistent_strict | POSIX dlopen | PASS |
| `fixture-verify::dlfcn_ops::dlopen::strict::dlopen_self_strict` | dlfcn_ops | dlopen | strict | dlopen_self_strict | POSIX dlopen | PASS |
| `fixture-verify::dlfcn_ops::dlsym::hardened::dlsym_valid_hardened` | dlfcn_ops | dlsym | hardened | dlsym_valid_hardened | POSIX dlsym | PASS |
| `fixture-verify::dlfcn_ops::dlsym::strict::dlsym_nonexistent_strict` | dlfcn_ops | dlsym | strict | dlsym_nonexistent_strict | POSIX dlsym | PASS |
| `fixture-verify::dlfcn_ops::dlsym::strict::dlsym_valid_strict` | dlfcn_ops | dlsym | strict | dlsym_valid_strict | POSIX dlsym | PASS |
| `fixture-verify::elf/loader::Elf64Header::parse::strict::invalid_elf_magic` | elf/loader | Elf64Header::parse | strict | invalid_elf_magic | ELF64 Header | PASS |
| `fixture-verify::elf/loader::Elf64Header::parse::strict::valid_elf_magic` | elf/loader | Elf64Header::parse | strict | valid_elf_magic | ELF64 Header | PASS |
| `fixture-verify::elf/loader::ProgramFlags::to_mmap_prot::strict::program_flags_ro` | elf/loader | ProgramFlags::to_mmap_prot | strict | program_flags_ro | ELF Program Header | PASS |
| `fixture-verify::elf/loader::ProgramFlags::to_mmap_prot::strict::program_flags_rwx` | elf/loader | ProgramFlags::to_mmap_prot | strict | program_flags_rwx | ELF Program Header | PASS |
| `fixture-verify::elf/loader::SymbolBinding::from::strict::symbol_binding_global` | elf/loader | SymbolBinding::from | strict | symbol_binding_global | ELF Symbol Table | PASS |
| `fixture-verify::elf/loader::SymbolBinding::from::strict::symbol_binding_local` | elf/loader | SymbolBinding::from | strict | symbol_binding_local | ELF Symbol Table | PASS |
| `fixture-verify::elf/loader::SymbolBinding::from::strict::symbol_binding_weak` | elf/loader | SymbolBinding::from | strict | symbol_binding_weak | ELF Symbol Table | PASS |
| `fixture-verify::elf/loader::SymbolType::from::strict::symbol_type_func` | elf/loader | SymbolType::from | strict | symbol_type_func | ELF Symbol Table | PASS |
| `fixture-verify::elf/loader::SymbolType::from::strict::symbol_type_object` | elf/loader | SymbolType::from | strict | symbol_type_object | ELF Symbol Table | PASS |
| `fixture-verify::elf/loader::compute_relocation::strict::reloc_r_x86_64_64` | elf/loader | compute_relocation | strict | reloc_r_x86_64_64 | x86_64 Relocations | PASS |
| `fixture-verify::elf/loader::compute_relocation::strict::reloc_r_x86_64_glob_dat` | elf/loader | compute_relocation | strict | reloc_r_x86_64_glob_dat | x86_64 Relocations | PASS |
| `fixture-verify::elf/loader::compute_relocation::strict::reloc_r_x86_64_jump_slot` | elf/loader | compute_relocation | strict | reloc_r_x86_64_jump_slot | x86_64 Relocations | PASS |
| `fixture-verify::elf/loader::compute_relocation::strict::reloc_r_x86_64_none` | elf/loader | compute_relocation | strict | reloc_r_x86_64_none | x86_64 Relocations | PASS |
| `fixture-verify::elf/loader::compute_relocation::strict::reloc_r_x86_64_relative` | elf/loader | compute_relocation | strict | reloc_r_x86_64_relative | x86_64 Relocations | PASS |
| `fixture-verify::elf/loader::elf_hash::strict::elf_hash_empty` | elf/loader | elf_hash | strict | elf_hash_empty | ELF Hash | PASS |
| `fixture-verify::elf/loader::elf_hash::strict::elf_hash_malloc` | elf/loader | elf_hash | strict | elf_hash_malloc | ELF Hash | PASS |
| `fixture-verify::elf/loader::gnu_hash::strict::gnu_hash_malloc` | elf/loader | gnu_hash | strict | gnu_hash_malloc | GNU Hash | PASS |
| `fixture-verify::errno_ops::__errno_location::hardened::errno_location_nonnull_hardened` | errno_ops | __errno_location | hardened | errno_location_nonnull_hardened | glibc __errno_location | PASS |
| `fixture-verify::errno_ops::__errno_location::hardened::errno_set_read_roundtrip` | errno_ops | __errno_location | hardened | errno_set_read_roundtrip [hardened] | POSIX errno | PASS |
| `fixture-verify::errno_ops::__errno_location::hardened::errno_thread_local_isolation` | errno_ops | __errno_location | hardened | errno_thread_local_isolation [hardened] | POSIX errno thread-safety | PASS |
| `fixture-verify::errno_ops::__errno_location::strict::errno_initially_zero_strict` | errno_ops | __errno_location | strict | errno_initially_zero_strict | glibc __errno_location | PASS |
| `fixture-verify::errno_ops::__errno_location::strict::errno_location_nonnull_strict` | errno_ops | __errno_location | strict | errno_location_nonnull_strict | glibc __errno_location | PASS |
| `fixture-verify::errno_ops::__errno_location::strict::errno_set_read_roundtrip` | errno_ops | __errno_location | strict | errno_set_read_roundtrip [strict] | POSIX errno | PASS |
| `fixture-verify::errno_ops::__errno_location::strict::errno_thread_local_isolation` | errno_ops | __errno_location | strict | errno_thread_local_isolation [strict] | POSIX errno thread-safety | PASS |
| `fixture-verify::errno_ops::errno_constants::hardened::errno_macro_all_standard_values` | errno_ops | errno_constants | hardened | errno_macro_all_standard_values [hardened] | POSIX.1-2017 errno.h | PASS |
| `fixture-verify::errno_ops::errno_constants::strict::errno_macro_all_standard_values` | errno_ops | errno_constants | strict | errno_macro_all_standard_values [strict] | POSIX.1-2017 errno.h | PASS |
| `fixture-verify::errno_ops::errno_preservation::hardened::errno_preserved_across_successful_call` | errno_ops | errno_preservation | hardened | errno_preserved_across_successful_call [hardened] | POSIX errno semantics | PASS |
| `fixture-verify::errno_ops::errno_preservation::strict::errno_preserved_across_successful_call` | errno_ops | errno_preservation | strict | errno_preserved_across_successful_call [strict] | POSIX errno semantics | PASS |
| `fixture-verify::errno_ops::perror::hardened::perror_empty_prefix` | errno_ops | perror | hardened | perror_empty_prefix [hardened] | POSIX.1-2017 perror | PASS |
| `fixture-verify::errno_ops::perror::hardened::perror_null_prefix` | errno_ops | perror | hardened | perror_null_prefix [hardened] | POSIX.1-2017 perror | PASS |
| `fixture-verify::errno_ops::perror::hardened::perror_prefix` | errno_ops | perror | hardened | perror_prefix [hardened] | POSIX.1-2017 perror | PASS |
| `fixture-verify::errno_ops::perror::strict::perror_empty_prefix` | errno_ops | perror | strict | perror_empty_prefix [strict] | POSIX.1-2017 perror | PASS |
| `fixture-verify::errno_ops::perror::strict::perror_null_prefix` | errno_ops | perror | strict | perror_null_prefix [strict] | POSIX.1-2017 perror | PASS |
| `fixture-verify::errno_ops::perror::strict::perror_prefix` | errno_ops | perror | strict | perror_prefix [strict] | POSIX.1-2017 perror | PASS |
| `fixture-verify::errno_ops::strerror::hardened::strerror_eacces` | errno_ops | strerror | hardened | strerror_eacces [hardened] | POSIX.1-2017 strerror | PASS |
| `fixture-verify::errno_ops::strerror::hardened::strerror_eexist` | errno_ops | strerror | hardened | strerror_eexist [hardened] | POSIX.1-2017 strerror | PASS |
| `fixture-verify::errno_ops::strerror::hardened::strerror_einval` | errno_ops | strerror | hardened | strerror_einval [hardened] | POSIX.1-2017 strerror | PASS |
| `fixture-verify::errno_ops::strerror::hardened::strerror_enoent` | errno_ops | strerror | hardened | strerror_enoent [hardened] | POSIX.1-2017 strerror | PASS |
| `fixture-verify::errno_ops::strerror::hardened::strerror_enosys` | errno_ops | strerror | hardened | strerror_enosys [hardened] | POSIX.1-2017 strerror | PASS |
| `fixture-verify::errno_ops::strerror::hardened::strerror_etimedout` | errno_ops | strerror | hardened | strerror_etimedout [hardened] | POSIX.1-2017 strerror | PASS |
| `fixture-verify::errno_ops::strerror::hardened::strerror_negative` | errno_ops | strerror | hardened | strerror_negative [hardened] | POSIX.1-2017 strerror | PASS |
| `fixture-verify::errno_ops::strerror::hardened::strerror_unknown_positive` | errno_ops | strerror | hardened | strerror_unknown_positive [hardened] | POSIX.1-2017 strerror | PASS |
| `fixture-verify::errno_ops::strerror::hardened::strerror_zero` | errno_ops | strerror | hardened | strerror_zero [hardened] | POSIX.1-2017 strerror | PASS |
| `fixture-verify::errno_ops::strerror::strict::strerror_eacces` | errno_ops | strerror | strict | strerror_eacces [strict] | POSIX.1-2017 strerror | PASS |
| `fixture-verify::errno_ops::strerror::strict::strerror_eexist` | errno_ops | strerror | strict | strerror_eexist [strict] | POSIX.1-2017 strerror | PASS |
| `fixture-verify::errno_ops::strerror::strict::strerror_einval` | errno_ops | strerror | strict | strerror_einval [strict] | POSIX.1-2017 strerror | PASS |
| `fixture-verify::errno_ops::strerror::strict::strerror_enoent` | errno_ops | strerror | strict | strerror_enoent [strict] | POSIX.1-2017 strerror | PASS |
| `fixture-verify::errno_ops::strerror::strict::strerror_enosys` | errno_ops | strerror | strict | strerror_enosys [strict] | POSIX.1-2017 strerror | PASS |
| `fixture-verify::errno_ops::strerror::strict::strerror_etimedout` | errno_ops | strerror | strict | strerror_etimedout [strict] | POSIX.1-2017 strerror | PASS |
| `fixture-verify::errno_ops::strerror::strict::strerror_negative` | errno_ops | strerror | strict | strerror_negative [strict] | POSIX.1-2017 strerror | PASS |
| `fixture-verify::errno_ops::strerror::strict::strerror_unknown_positive` | errno_ops | strerror | strict | strerror_unknown_positive [strict] | POSIX.1-2017 strerror | PASS |
| `fixture-verify::errno_ops::strerror::strict::strerror_zero` | errno_ops | strerror | strict | strerror_zero [strict] | POSIX.1-2017 strerror | PASS |
| `fixture-verify::errno_ops::strerror_l::hardened::strerror_l_einval` | errno_ops | strerror_l | hardened | strerror_l_einval [hardened] | POSIX.1-2017 strerror_l | PASS |
| `fixture-verify::errno_ops::strerror_l::strict::strerror_l_einval` | errno_ops | strerror_l | strict | strerror_l_einval [strict] | POSIX.1-2017 strerror_l | PASS |
| `fixture-verify::errno_ops::strerror_r::hardened::strerror_r_buffer_too_small` | errno_ops | strerror_r | hardened | strerror_r_buffer_too_small [hardened] | POSIX.1-2017 strerror_r (XSI) | PASS |
| `fixture-verify::errno_ops::strerror_r::hardened::strerror_r_null_buffer` | errno_ops | strerror_r | hardened | strerror_r_null_buffer [hardened] | POSIX.1-2017 strerror_r (XSI) | PASS |
| `fixture-verify::errno_ops::strerror_r::hardened::strerror_r_success` | errno_ops | strerror_r | hardened | strerror_r_success [hardened] | POSIX.1-2017 strerror_r (XSI) | PASS |
| `fixture-verify::errno_ops::strerror_r::strict::strerror_r_buffer_too_small` | errno_ops | strerror_r | strict | strerror_r_buffer_too_small [strict] | POSIX.1-2017 strerror_r (XSI) | PASS |
| `fixture-verify::errno_ops::strerror_r::strict::strerror_r_null_buffer` | errno_ops | strerror_r | strict | strerror_r_null_buffer [strict] | POSIX.1-2017 strerror_r (XSI) | PASS |
| `fixture-verify::errno_ops::strerror_r::strict::strerror_r_success` | errno_ops | strerror_r | strict | strerror_r_success [strict] | POSIX.1-2017 strerror_r (XSI) | PASS |
| `fixture-verify::grp_ops::endgrent::hardened::endgrent_void_hardened` | grp_ops | endgrent | hardened | endgrent_void_hardened | POSIX endgrent | PASS |
| `fixture-verify::grp_ops::endgrent::strict::endgrent_void_strict` | grp_ops | endgrent | strict | endgrent_void_strict | POSIX endgrent | PASS |
| `fixture-verify::grp_ops::getgrgid::hardened::getgrgid_nonexistent_hardened` | grp_ops | getgrgid | hardened | getgrgid_nonexistent_hardened | POSIX getgrgid | PASS |
| `fixture-verify::grp_ops::getgrgid::hardened::getgrgid_zero_hardened` | grp_ops | getgrgid | hardened | getgrgid_zero_hardened | POSIX getgrgid | PASS |
| `fixture-verify::grp_ops::getgrgid::strict::getgrgid_nonexistent_strict` | grp_ops | getgrgid | strict | getgrgid_nonexistent_strict | POSIX getgrgid | PASS |
| `fixture-verify::grp_ops::getgrgid::strict::getgrgid_zero_strict` | grp_ops | getgrgid | strict | getgrgid_zero_strict | POSIX getgrgid | PASS |
| `fixture-verify::grp_ops::getgrnam::hardened::getgrnam_nonexistent_hardened` | grp_ops | getgrnam | hardened | getgrnam_nonexistent_hardened | POSIX getgrnam | PASS |
| `fixture-verify::grp_ops::getgrnam::hardened::getgrnam_root_hardened` | grp_ops | getgrnam | hardened | getgrnam_root_hardened | POSIX getgrnam | PASS |
| `fixture-verify::grp_ops::getgrnam::strict::getgrnam_nonexistent_strict` | grp_ops | getgrnam | strict | getgrnam_nonexistent_strict | POSIX getgrnam | PASS |
| `fixture-verify::grp_ops::getgrnam::strict::getgrnam_root_strict` | grp_ops | getgrnam | strict | getgrnam_root_strict | POSIX getgrnam | PASS |
| `fixture-verify::grp_ops::setgrent::hardened::setgrent_endgrent_hardened` | grp_ops | setgrent | hardened | setgrent_endgrent_hardened | POSIX setgrent/endgrent | PASS |
| `fixture-verify::grp_ops::setgrent::strict::setgrent_endgrent_strict` | grp_ops | setgrent | strict | setgrent_endgrent_strict | POSIX setgrent/endgrent | PASS |
| `fixture-verify::iconv/phase1::iconv::hardened::hardened_unsupported_encoding_denied` | iconv/phase1 | iconv | hardened | hardened_unsupported_encoding_denied | TSM hardened iconv unsupported encoding deny | PASS |
| `fixture-verify::iconv/phase1::iconv::hardened::hardened_utf16le_to_utf8` | iconv/phase1 | iconv | hardened | hardened_utf16le_to_utf8 | TSM hardened iconv | PASS |
| `fixture-verify::iconv/phase1::iconv::strict::strict_e2big_preserves_progress` | iconv/phase1 | iconv | strict | strict_e2big_preserves_progress | POSIX iconv | PASS |
| `fixture-verify::iconv/phase1::iconv::strict::strict_eilseq_invalid_utf8` | iconv/phase1 | iconv | strict | strict_eilseq_invalid_utf8 | POSIX iconv | PASS |
| `fixture-verify::iconv/phase1::iconv::strict::strict_einval_incomplete_utf8` | iconv/phase1 | iconv | strict | strict_einval_incomplete_utf8 | POSIX iconv | PASS |
| `fixture-verify::iconv/phase1::iconv::strict::strict_latin1_to_utf8_multibyte` | iconv/phase1 | iconv | strict | strict_latin1_to_utf8_multibyte | POSIX iconv | PASS |
| `fixture-verify::iconv/phase1::iconv::strict::strict_utf8_to_utf16le_basic` | iconv/phase1 | iconv | strict | strict_utf8_to_utf16le_basic | POSIX iconv | PASS |
| `fixture-verify::iconv/phase1::iconv::strict::strict_utf8_to_utf32_with_bom` | iconv/phase1 | iconv | strict | strict_utf8_to_utf32_with_bom | POSIX iconv | PASS |
| `fixture-verify::iconv/phase1::iconv_close::hardened::iconv_close_hardened_valid` | iconv/phase1 | iconv_close | hardened | iconv_close_hardened_valid | POSIX.1-2017 iconv_close hardened parity | PASS |
| `fixture-verify::iconv/phase1::iconv_close::strict::iconv_close_valid` | iconv/phase1 | iconv_close | strict | iconv_close_valid | POSIX.1-2017 iconv_close | PASS |
| `fixture-verify::iconv/phase1::iconv_open::hardened::iconv_open_hardened_utf8_to_utf16le` | iconv/phase1 | iconv_open | hardened | iconv_open_hardened_utf8_to_utf16le | POSIX.1-2017 iconv_open hardened parity | PASS |
| `fixture-verify::iconv/phase1::iconv_open::strict::iconv_open_unsupported` | iconv/phase1 | iconv_open | strict | iconv_open_unsupported | POSIX.1-2017 iconv_open | PASS |
| `fixture-verify::iconv/phase1::iconv_open::strict::iconv_open_utf8_to_utf16le` | iconv/phase1 | iconv_open | strict | iconv_open_utf8_to_utf16le | POSIX.1-2017 iconv_open | PASS |
| `fixture-verify::inet::htonl::hardened::htonl_loopback` | inet | htonl | hardened | htonl_loopback [hardened] | POSIX.1-2017 htonl | PASS |
| `fixture-verify::inet::htonl::hardened::htonl_one` | inet | htonl | hardened | htonl_one [hardened] | POSIX.1-2017 htonl | PASS |
| `fixture-verify::inet::htonl::strict::htonl_loopback` | inet | htonl | strict | htonl_loopback [strict] | POSIX.1-2017 htonl | PASS |
| `fixture-verify::inet::htonl::strict::htonl_one` | inet | htonl | strict | htonl_one [strict] | POSIX.1-2017 htonl | PASS |
| `fixture-verify::inet::htons::hardened::htons_443` | inet | htons | hardened | htons_443 [hardened] | POSIX.1-2017 htons | PASS |
| `fixture-verify::inet::htons::hardened::htons_80` | inet | htons | hardened | htons_80 [hardened] | POSIX.1-2017 htons | PASS |
| `fixture-verify::inet::htons::hardened::htons_zero` | inet | htons | hardened | htons_zero [hardened] | POSIX.1-2017 htons | PASS |
| `fixture-verify::inet::htons::strict::htons_443` | inet | htons | strict | htons_443 [strict] | POSIX.1-2017 htons | PASS |
| `fixture-verify::inet::htons::strict::htons_80` | inet | htons | strict | htons_80 [strict] | POSIX.1-2017 htons | PASS |
| `fixture-verify::inet::htons::strict::htons_zero` | inet | htons | strict | htons_zero [strict] | POSIX.1-2017 htons | PASS |
| `fixture-verify::inet::inet_addr::hardened::inet_addr_broadcast` | inet | inet_addr | hardened | inet_addr_broadcast [hardened] | POSIX.1-2017 inet_addr | PASS |
| `fixture-verify::inet::inet_addr::hardened::inet_addr_invalid` | inet | inet_addr | hardened | inet_addr_invalid [hardened] | POSIX.1-2017 inet_addr | PASS |
| `fixture-verify::inet::inet_addr::hardened::inet_addr_loopback` | inet | inet_addr | hardened | inet_addr_loopback [hardened] | POSIX.1-2017 inet_addr | PASS |
| `fixture-verify::inet::inet_addr::strict::inet_addr_broadcast` | inet | inet_addr | strict | inet_addr_broadcast [strict] | POSIX.1-2017 inet_addr | PASS |
| `fixture-verify::inet::inet_addr::strict::inet_addr_invalid` | inet | inet_addr | strict | inet_addr_invalid [strict] | POSIX.1-2017 inet_addr | PASS |
| `fixture-verify::inet::inet_addr::strict::inet_addr_loopback` | inet | inet_addr | strict | inet_addr_loopback [strict] | POSIX.1-2017 inet_addr | PASS |
| `fixture-verify::inet::inet_ntop::hardened::inet_ntop_v4_loopback` | inet | inet_ntop | hardened | inet_ntop_v4_loopback [hardened] | POSIX.1-2017 inet_ntop | PASS |
| `fixture-verify::inet::inet_ntop::hardened::inet_ntop_v4_zeros` | inet | inet_ntop | hardened | inet_ntop_v4_zeros [hardened] | POSIX.1-2017 inet_ntop | PASS |
| `fixture-verify::inet::inet_ntop::strict::inet_ntop_v4_loopback` | inet | inet_ntop | strict | inet_ntop_v4_loopback [strict] | POSIX.1-2017 inet_ntop | PASS |
| `fixture-verify::inet::inet_ntop::strict::inet_ntop_v4_zeros` | inet | inet_ntop | strict | inet_ntop_v4_zeros [strict] | POSIX.1-2017 inet_ntop | PASS |
| `fixture-verify::inet::inet_pton::hardened::inet_pton_v4_invalid` | inet | inet_pton | hardened | inet_pton_v4_invalid [hardened] | POSIX.1-2017 inet_pton | PASS |
| `fixture-verify::inet::inet_pton::hardened::inet_pton_v4_loopback` | inet | inet_pton | hardened | inet_pton_v4_loopback [hardened] | POSIX.1-2017 inet_pton | PASS |
| `fixture-verify::inet::inet_pton::hardened::inet_pton_v6_loopback` | inet | inet_pton | hardened | inet_pton_v6_loopback [hardened] | POSIX.1-2017 inet_pton | PASS |
| `fixture-verify::inet::inet_pton::strict::inet_pton_v4_invalid` | inet | inet_pton | strict | inet_pton_v4_invalid [strict] | POSIX.1-2017 inet_pton | PASS |
| `fixture-verify::inet::inet_pton::strict::inet_pton_v4_loopback` | inet | inet_pton | strict | inet_pton_v4_loopback [strict] | POSIX.1-2017 inet_pton | PASS |
| `fixture-verify::inet::inet_pton::strict::inet_pton_v6_loopback` | inet | inet_pton | strict | inet_pton_v6_loopback [strict] | POSIX.1-2017 inet_pton | PASS |
| `fixture-verify::inet::ntohl::hardened::ntohl_loopback_net` | inet | ntohl | hardened | ntohl_loopback_net [hardened] | POSIX.1-2017 ntohl | PASS |
| `fixture-verify::inet::ntohl::strict::ntohl_loopback_net` | inet | ntohl | strict | ntohl_loopback_net [strict] | POSIX.1-2017 ntohl | PASS |
| `fixture-verify::inet::ntohs::hardened::ntohs_80_net` | inet | ntohs | hardened | ntohs_80_net [hardened] | POSIX.1-2017 ntohs | PASS |
| `fixture-verify::inet::ntohs::strict::ntohs_80_net` | inet | ntohs | strict | ntohs_80_net [strict] | POSIX.1-2017 ntohs | PASS |
| `fixture-verify::io_internal::_IO_adjust_column::hardened::IO_adjust_column_newline_resets` | io_internal | _IO_adjust_column | hardened | IO_adjust_column_newline_resets [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_adjust_column::hardened::IO_adjust_column_null_line_returns_col` | io_internal | _IO_adjust_column | hardened | IO_adjust_column_null_line_returns_col [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_adjust_column::hardened::IO_adjust_column_tab_is_ordinary` | io_internal | _IO_adjust_column | hardened | IO_adjust_column_tab_is_ordinary [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_adjust_column::strict::IO_adjust_column_newline_resets` | io_internal | _IO_adjust_column | strict | IO_adjust_column_newline_resets [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_adjust_column::strict::IO_adjust_column_null_line_returns_col` | io_internal | _IO_adjust_column | strict | IO_adjust_column_null_line_returns_col [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_adjust_column::strict::IO_adjust_column_tab_is_ordinary` | io_internal | _IO_adjust_column | strict | IO_adjust_column_tab_is_ordinary [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_adjust_wcolumn::hardened::IO_adjust_wcolumn_newline_resets` | io_internal | _IO_adjust_wcolumn | hardened | IO_adjust_wcolumn_newline_resets [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_adjust_wcolumn::strict::IO_adjust_wcolumn_newline_resets` | io_internal | _IO_adjust_wcolumn | strict | IO_adjust_wcolumn_newline_resets [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_default_doallocate::hardened::IO_default_doallocate_returns_success` | io_internal | _IO_default_doallocate | hardened | IO_default_doallocate_returns_success [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_default_doallocate::strict::IO_default_doallocate_returns_success` | io_internal | _IO_default_doallocate | strict | IO_default_doallocate_returns_success [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_default_finish::hardened::IO_default_finish_is_noop` | io_internal | _IO_default_finish | hardened | IO_default_finish_is_noop [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_default_finish::strict::IO_default_finish_is_noop` | io_internal | _IO_default_finish | strict | IO_default_finish_is_noop [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_doallocbuf::hardened::IO_doallocbuf_is_noop` | io_internal | _IO_doallocbuf | hardened | IO_doallocbuf_is_noop [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_doallocbuf::strict::IO_doallocbuf_is_noop` | io_internal | _IO_doallocbuf | strict | IO_doallocbuf_is_noop [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_file_init::hardened::IO_file_init_is_noop` | io_internal | _IO_file_init | hardened | IO_file_init_is_noop [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_file_init::strict::IO_file_init_is_noop` | io_internal | _IO_file_init | strict | IO_file_init_is_noop [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_free_backup_area::hardened::IO_free_backup_area_is_noop` | io_internal | _IO_free_backup_area | hardened | IO_free_backup_area_is_noop [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_free_backup_area::strict::IO_free_backup_area_is_noop` | io_internal | _IO_free_backup_area | strict | IO_free_backup_area_is_noop [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_free_wbackup_area::hardened::IO_free_wbackup_area_is_noop` | io_internal | _IO_free_wbackup_area | hardened | IO_free_wbackup_area_is_noop [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_free_wbackup_area::strict::IO_free_wbackup_area_is_noop` | io_internal | _IO_free_wbackup_area | strict | IO_free_wbackup_area_is_noop [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_init::hardened::IO_init_is_noop` | io_internal | _IO_init | hardened | IO_init_is_noop [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_init::strict::IO_init_is_noop` | io_internal | _IO_init | strict | IO_init_is_noop [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_iter_begin::hardened::IO_iter_begin_equals_end_empty_list` | io_internal | _IO_iter_begin | hardened | IO_iter_begin_equals_end_empty_list [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_iter_begin::hardened::IO_iter_begin_returns_null` | io_internal | _IO_iter_begin | hardened | IO_iter_begin_returns_null [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_iter_begin::strict::IO_iter_begin_equals_end_empty_list` | io_internal | _IO_iter_begin | strict | IO_iter_begin_equals_end_empty_list [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_iter_begin::strict::IO_iter_begin_returns_null` | io_internal | _IO_iter_begin | strict | IO_iter_begin_returns_null [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_iter_end::hardened::IO_iter_end_returns_null` | io_internal | _IO_iter_end | hardened | IO_iter_end_returns_null [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_iter_end::strict::IO_iter_end_returns_null` | io_internal | _IO_iter_end | strict | IO_iter_end_returns_null [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_link_in::hardened::IO_link_in_is_noop` | io_internal | _IO_link_in | hardened | IO_link_in_is_noop [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_link_in::strict::IO_link_in_is_noop` | io_internal | _IO_link_in | strict | IO_link_in_is_noop [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_list_lock::hardened::IO_list_lock_is_noop` | io_internal | _IO_list_lock | hardened | IO_list_lock_is_noop [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_list_lock::strict::IO_list_lock_is_noop` | io_internal | _IO_list_lock | strict | IO_list_lock_is_noop [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_list_resetlock::hardened::IO_list_resetlock_is_noop` | io_internal | _IO_list_resetlock | hardened | IO_list_resetlock_is_noop [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_list_resetlock::strict::IO_list_resetlock_is_noop` | io_internal | _IO_list_resetlock | strict | IO_list_resetlock_is_noop [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_list_unlock::hardened::IO_list_unlock_is_noop` | io_internal | _IO_list_unlock | hardened | IO_list_unlock_is_noop [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_list_unlock::strict::IO_list_unlock_is_noop` | io_internal | _IO_list_unlock | strict | IO_list_unlock_is_noop [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_marker_delta::hardened::IO_marker_delta_returns_zero` | io_internal | _IO_marker_delta | hardened | IO_marker_delta_returns_zero [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_marker_delta::strict::IO_marker_delta_returns_zero` | io_internal | _IO_marker_delta | strict | IO_marker_delta_returns_zero [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_marker_difference::hardened::IO_marker_difference_returns_zero` | io_internal | _IO_marker_difference | hardened | IO_marker_difference_returns_zero [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_marker_difference::strict::IO_marker_difference_returns_zero` | io_internal | _IO_marker_difference | strict | IO_marker_difference_returns_zero [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_seekmark::hardened::IO_seekmark_returns_error` | io_internal | _IO_seekmark | hardened | IO_seekmark_returns_error [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_seekmark::strict::IO_seekmark_returns_error` | io_internal | _IO_seekmark | strict | IO_seekmark_returns_error [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_str_overflow::hardened::IO_str_overflow_returns_eof` | io_internal | _IO_str_overflow | hardened | IO_str_overflow_returns_eof [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_str_overflow::strict::IO_str_overflow_returns_eof` | io_internal | _IO_str_overflow | strict | IO_str_overflow_returns_eof [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_str_underflow::hardened::IO_str_underflow_returns_eof` | io_internal | _IO_str_underflow | hardened | IO_str_underflow_returns_eof [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_str_underflow::strict::IO_str_underflow_returns_eof` | io_internal | _IO_str_underflow | strict | IO_str_underflow_returns_eof [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_sungetc::hardened::IO_sungetc_returns_eof` | io_internal | _IO_sungetc | hardened | IO_sungetc_returns_eof [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_sungetc::strict::IO_sungetc_returns_eof` | io_internal | _IO_sungetc | strict | IO_sungetc_returns_eof [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_sungetwc::hardened::IO_sungetwc_returns_weof` | io_internal | _IO_sungetwc | hardened | IO_sungetwc_returns_weof [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_sungetwc::strict::IO_sungetwc_returns_weof` | io_internal | _IO_sungetwc | strict | IO_sungetwc_returns_weof [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_switch_to_wget_mode::hardened::IO_switch_to_wget_mode_delegates_to_fflush` | io_internal | _IO_switch_to_wget_mode | hardened | IO_switch_to_wget_mode_delegates_to_fflush [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_switch_to_wget_mode::strict::IO_switch_to_wget_mode_delegates_to_fflush` | io_internal | _IO_switch_to_wget_mode | strict | IO_switch_to_wget_mode_delegates_to_fflush [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_un_link::hardened::IO_un_link_is_noop` | io_internal | _IO_un_link | hardened | IO_un_link_is_noop [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_un_link::strict::IO_un_link_is_noop` | io_internal | _IO_un_link | strict | IO_un_link_is_noop [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_wdefault_doallocate::hardened::IO_wdefault_doallocate_returns_success` | io_internal | _IO_wdefault_doallocate | hardened | IO_wdefault_doallocate_returns_success [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_wdefault_doallocate::strict::IO_wdefault_doallocate_returns_success` | io_internal | _IO_wdefault_doallocate | strict | IO_wdefault_doallocate_returns_success [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_wdefault_uflow::hardened::IO_wdefault_uflow_returns_weof` | io_internal | _IO_wdefault_uflow | hardened | IO_wdefault_uflow_returns_weof [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_wdefault_uflow::strict::IO_wdefault_uflow_returns_weof` | io_internal | _IO_wdefault_uflow | strict | IO_wdefault_uflow_returns_weof [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_wfile_sync::hardened::IO_wfile_sync_delegates_to_fflush` | io_internal | _IO_wfile_sync | hardened | IO_wfile_sync_delegates_to_fflush [hardened] | glibc libio internal | PASS |
| `fixture-verify::io_internal::_IO_wfile_sync::strict::IO_wfile_sync_delegates_to_fflush` | io_internal | _IO_wfile_sync | strict | IO_wfile_sync_delegates_to_fflush [strict] | glibc libio internal | PASS |
| `fixture-verify::io_internal::dlinfo::hardened::dlinfo_returns_enosys` | io_internal | dlinfo | hardened | dlinfo_returns_enosys [hardened] | GNU extension dlinfo(3) | PASS |
| `fixture-verify::io_internal::dlinfo::strict::dlinfo_returns_enosys` | io_internal | dlinfo | strict | dlinfo_returns_enosys [strict] | GNU extension dlinfo(3) | PASS |
| `fixture-verify::loader_edges::dladdr::strict::dladdr_valid_address_strict` | loader_edges | dladdr | strict | dladdr_valid_address_strict | GNU dladdr(3) | PASS |
| `fixture-verify::loader_edges::dlclose::hardened::dlclose_double_close_hardened` | loader_edges | dlclose | hardened | dlclose_double_close_hardened | POSIX dlclose(3) | PASS |
| `fixture-verify::loader_edges::dlclose::strict::dlclose_double_close_strict` | loader_edges | dlclose | strict | dlclose_double_close_strict | POSIX dlclose(3) | PASS |
| `fixture-verify::loader_edges::dlinfo::strict::dlinfo_rtld_di_linkmap_strict` | loader_edges | dlinfo | strict | dlinfo_rtld_di_linkmap_strict | GNU dlinfo(3) | PASS |
| `fixture-verify::loader_edges::dlopen::hardened::dlopen_nonexistent_hardened` | loader_edges | dlopen | hardened | dlopen_nonexistent_hardened | POSIX dlopen(3) | PASS |
| `fixture-verify::loader_edges::dlopen::strict::dlopen_nonexistent_strict` | loader_edges | dlopen | strict | dlopen_nonexistent_strict | POSIX dlopen(3) | PASS |
| `fixture-verify::loader_edges::dlsym::strict::dlsym_undefined_strict` | loader_edges | dlsym | strict | dlsym_undefined_strict | POSIX dlsym(3) | PASS |
| `fixture-verify::locale_ops::duplocale::hardened::duplocale_handle_hardened` | locale_ops | duplocale | hardened | duplocale_handle_hardened | POSIX.1-2008 duplocale hardened parity | PASS |
| `fixture-verify::locale_ops::duplocale::strict::duplocale_handle_strict` | locale_ops | duplocale | strict | duplocale_handle_strict | POSIX.1-2008 duplocale | PASS |
| `fixture-verify::locale_ops::freelocale::hardened::freelocale_void_hardened` | locale_ops | freelocale | hardened | freelocale_void_hardened | POSIX.1-2008 freelocale hardened parity | PASS |
| `fixture-verify::locale_ops::freelocale::strict::freelocale_void_strict` | locale_ops | freelocale | strict | freelocale_void_strict | POSIX.1-2008 freelocale | PASS |
| `fixture-verify::locale_ops::localeconv::hardened::localeconv_nonnull_hardened` | locale_ops | localeconv | hardened | localeconv_nonnull_hardened | C11 7.11.2.1 localeconv | PASS |
| `fixture-verify::locale_ops::localeconv::strict::localeconv_nonnull_strict` | locale_ops | localeconv | strict | localeconv_nonnull_strict | C11 7.11.2.1 localeconv | PASS |
| `fixture-verify::locale_ops::newlocale::hardened::newlocale_unsupported_hardened` | locale_ops | newlocale | hardened | newlocale_unsupported_hardened | POSIX.1-2008 newlocale hardened fallback | PASS |
| `fixture-verify::locale_ops::newlocale::strict::newlocale_c_locale_strict` | locale_ops | newlocale | strict | newlocale_c_locale_strict | POSIX.1-2008 newlocale | PASS |
| `fixture-verify::locale_ops::nl_langinfo::hardened::nl_langinfo_unknown_hardened` | locale_ops | nl_langinfo | hardened | nl_langinfo_unknown_hardened | POSIX nl_langinfo (unsupported item hardened fallback) | PASS |
| `fixture-verify::locale_ops::nl_langinfo::strict::nl_langinfo_codeset_strict` | locale_ops | nl_langinfo | strict | nl_langinfo_codeset_strict | POSIX nl_langinfo (CODESET) | PASS |
| `fixture-verify::locale_ops::nl_langinfo::strict::nl_langinfo_radixchar_strict` | locale_ops | nl_langinfo | strict | nl_langinfo_radixchar_strict | POSIX nl_langinfo (RADIXCHAR) | PASS |
| `fixture-verify::locale_ops::nl_langinfo_l::hardened::nl_langinfo_l_unknown_hardened` | locale_ops | nl_langinfo_l | hardened | nl_langinfo_l_unknown_hardened | POSIX nl_langinfo_l (unsupported item hardened fallback) | PASS |
| `fixture-verify::locale_ops::nl_langinfo_l::strict::nl_langinfo_l_codeset_strict` | locale_ops | nl_langinfo_l | strict | nl_langinfo_l_codeset_strict | POSIX nl_langinfo_l (CODESET) | PASS |
| `fixture-verify::locale_ops::setlocale::hardened::setlocale_c_locale_hardened` | locale_ops | setlocale | hardened | setlocale_c_locale_hardened | C11 7.11.1.1 setlocale | PASS |
| `fixture-verify::locale_ops::setlocale::hardened::setlocale_unsupported_hardened` | locale_ops | setlocale | hardened | setlocale_unsupported_hardened | C11 7.11.1.1 setlocale | PASS |
| `fixture-verify::locale_ops::setlocale::strict::setlocale_c_locale_strict` | locale_ops | setlocale | strict | setlocale_c_locale_strict | C11 7.11.1.1 setlocale | PASS |
| `fixture-verify::locale_ops::setlocale::strict::setlocale_posix_strict` | locale_ops | setlocale | strict | setlocale_posix_strict | C11 7.11.1.1 setlocale | PASS |
| `fixture-verify::locale_ops::setlocale::strict::setlocale_query_strict` | locale_ops | setlocale | strict | setlocale_query_strict | C11 7.11.1.1 setlocale | PASS |
| `fixture-verify::locale_ops::uselocale::hardened::uselocale_query_hardened` | locale_ops | uselocale | hardened | uselocale_query_hardened | POSIX.1-2008 uselocale hardened parity | PASS |
| `fixture-verify::locale_ops::uselocale::strict::uselocale_query_strict` | locale_ops | uselocale | strict | uselocale_query_strict | POSIX.1-2008 uselocale | PASS |
| `fixture-verify::math::acos::hardened::acos_one` | math | acos | hardened | acos_one [hardened] | C11 7.12.4.1 acos | PASS |
| `fixture-verify::math::acos::hardened::acos_zero` | math | acos | hardened | acos_zero [hardened] | C11 7.12.4.1 acos | PASS |
| `fixture-verify::math::acos::strict::acos_one` | math | acos | strict | acos_one [strict] | C11 7.12.4.1 acos | PASS |
| `fixture-verify::math::acos::strict::acos_zero` | math | acos | strict | acos_zero [strict] | C11 7.12.4.1 acos | PASS |
| `fixture-verify::math::asin::hardened::asin_one` | math | asin | hardened | asin_one [hardened] | C11 7.12.4.2 asin | PASS |
| `fixture-verify::math::asin::hardened::asin_zero` | math | asin | hardened | asin_zero [hardened] | C11 7.12.4.2 asin | PASS |
| `fixture-verify::math::asin::strict::asin_one` | math | asin | strict | asin_one [strict] | C11 7.12.4.2 asin | PASS |
| `fixture-verify::math::asin::strict::asin_zero` | math | asin | strict | asin_zero [strict] | C11 7.12.4.2 asin | PASS |
| `fixture-verify::math::atan::hardened::atan_zero` | math | atan | hardened | atan_zero [hardened] | C11 7.12.4.3 atan | PASS |
| `fixture-verify::math::atan::strict::atan_zero` | math | atan | strict | atan_zero [strict] | C11 7.12.4.3 atan | PASS |
| `fixture-verify::math::atan2::hardened::atan2_one_one` | math | atan2 | hardened | atan2_one_one [hardened] | C11 7.12.4.4 atan2 | PASS |
| `fixture-verify::math::atan2::hardened::atan2_zero_one` | math | atan2 | hardened | atan2_zero_one [hardened] | C11 7.12.4.4 atan2 | PASS |
| `fixture-verify::math::atan2::strict::atan2_one_one` | math | atan2 | strict | atan2_one_one [strict] | C11 7.12.4.4 atan2 | PASS |
| `fixture-verify::math::atan2::strict::atan2_zero_one` | math | atan2 | strict | atan2_zero_one [strict] | C11 7.12.4.4 atan2 | PASS |
| `fixture-verify::math::ceil::hardened::ceil_negative_frac` | math | ceil | hardened | ceil_negative_frac [hardened] | C11 7.12.9.1 ceil | PASS |
| `fixture-verify::math::ceil::hardened::ceil_positive_frac` | math | ceil | hardened | ceil_positive_frac [hardened] | C11 7.12.9.1 ceil | PASS |
| `fixture-verify::math::ceil::strict::ceil_negative_frac` | math | ceil | strict | ceil_negative_frac [strict] | C11 7.12.9.1 ceil | PASS |
| `fixture-verify::math::ceil::strict::ceil_positive_frac` | math | ceil | strict | ceil_positive_frac [strict] | C11 7.12.9.1 ceil | PASS |
| `fixture-verify::math::cos::hardened::cos_pi` | math | cos | hardened | cos_pi [hardened] | C11 7.12.4.5 cos | PASS |
| `fixture-verify::math::cos::hardened::cos_zero` | math | cos | hardened | cos_zero [hardened] | C11 7.12.4.5 cos | PASS |
| `fixture-verify::math::cos::strict::cos_pi` | math | cos | strict | cos_pi [strict] | C11 7.12.4.5 cos | PASS |
| `fixture-verify::math::cos::strict::cos_zero` | math | cos | strict | cos_zero [strict] | C11 7.12.4.5 cos | PASS |
| `fixture-verify::math::erf::hardened::erf_zero` | math | erf | hardened | erf_zero [hardened] | C11 7.12.8.1 erf | PASS |
| `fixture-verify::math::erf::strict::erf_zero` | math | erf | strict | erf_zero [strict] | C11 7.12.8.1 erf | PASS |
| `fixture-verify::math::exp::hardened::exp_one` | math | exp | hardened | exp_one [hardened] | C11 7.12.6.1 exp | PASS |
| `fixture-verify::math::exp::hardened::exp_zero` | math | exp | hardened | exp_zero [hardened] | C11 7.12.6.1 exp | PASS |
| `fixture-verify::math::exp::strict::exp_one` | math | exp | strict | exp_one [strict] | C11 7.12.6.1 exp | PASS |
| `fixture-verify::math::exp::strict::exp_zero` | math | exp | strict | exp_zero [strict] | C11 7.12.6.1 exp | PASS |
| `fixture-verify::math::fabs::hardened::fabs_negative` | math | fabs | hardened | fabs_negative [hardened] | C11 7.12.7.2 fabs | PASS |
| `fixture-verify::math::fabs::hardened::fabs_positive` | math | fabs | hardened | fabs_positive [hardened] | C11 7.12.7.2 fabs | PASS |
| `fixture-verify::math::fabs::strict::fabs_negative` | math | fabs | strict | fabs_negative [strict] | C11 7.12.7.2 fabs | PASS |
| `fixture-verify::math::fabs::strict::fabs_positive` | math | fabs | strict | fabs_positive [strict] | C11 7.12.7.2 fabs | PASS |
| `fixture-verify::math::floor::hardened::floor_negative_frac` | math | floor | hardened | floor_negative_frac [hardened] | C11 7.12.9.2 floor | PASS |
| `fixture-verify::math::floor::hardened::floor_positive_frac` | math | floor | hardened | floor_positive_frac [hardened] | C11 7.12.9.2 floor | PASS |
| `fixture-verify::math::floor::strict::floor_negative_frac` | math | floor | strict | floor_negative_frac [strict] | C11 7.12.9.2 floor | PASS |
| `fixture-verify::math::floor::strict::floor_positive_frac` | math | floor | strict | floor_positive_frac [strict] | C11 7.12.9.2 floor | PASS |
| `fixture-verify::math::fmod::hardened::fmod_basic` | math | fmod | hardened | fmod_basic [hardened] | C11 7.12.10.1 fmod | PASS |
| `fixture-verify::math::fmod::strict::fmod_basic` | math | fmod | strict | fmod_basic [strict] | C11 7.12.10.1 fmod | PASS |
| `fixture-verify::math::lgamma::hardened::lgamma_one` | math | lgamma | hardened | lgamma_one [hardened] | C11 7.12.8.3 lgamma | PASS |
| `fixture-verify::math::lgamma::strict::lgamma_one` | math | lgamma | strict | lgamma_one [strict] | C11 7.12.8.3 lgamma | PASS |
| `fixture-verify::math::log::hardened::log_e` | math | log | hardened | log_e [hardened] | C11 7.12.6.7 log | PASS |
| `fixture-verify::math::log::hardened::log_one` | math | log | hardened | log_one [hardened] | C11 7.12.6.7 log | PASS |
| `fixture-verify::math::log::strict::log_e` | math | log | strict | log_e [strict] | C11 7.12.6.7 log | PASS |
| `fixture-verify::math::log::strict::log_one` | math | log | strict | log_one [strict] | C11 7.12.6.7 log | PASS |
| `fixture-verify::math::log10::hardened::log10_one` | math | log10 | hardened | log10_one [hardened] | C11 7.12.6.8 log10 | PASS |
| `fixture-verify::math::log10::hardened::log10_ten` | math | log10 | hardened | log10_ten [hardened] | C11 7.12.6.8 log10 | PASS |
| `fixture-verify::math::log10::strict::log10_one` | math | log10 | strict | log10_one [strict] | C11 7.12.6.8 log10 | PASS |
| `fixture-verify::math::log10::strict::log10_ten` | math | log10 | strict | log10_ten [strict] | C11 7.12.6.8 log10 | PASS |
| `fixture-verify::math::pow::hardened::pow_two_ten` | math | pow | hardened | pow_two_ten [hardened] | C11 7.12.7.4 pow | PASS |
| `fixture-verify::math::pow::hardened::pow_zero_exp` | math | pow | hardened | pow_zero_exp [hardened] | C11 7.12.7.4 pow | PASS |
| `fixture-verify::math::pow::strict::pow_two_ten` | math | pow | strict | pow_two_ten [strict] | C11 7.12.7.4 pow | PASS |
| `fixture-verify::math::pow::strict::pow_zero_exp` | math | pow | strict | pow_zero_exp [strict] | C11 7.12.7.4 pow | PASS |
| `fixture-verify::math::round::hardened::round_half_neg` | math | round | hardened | round_half_neg [hardened] | C11 7.12.9.6 round | PASS |
| `fixture-verify::math::round::hardened::round_half_up` | math | round | hardened | round_half_up [hardened] | C11 7.12.9.6 round | PASS |
| `fixture-verify::math::round::strict::round_half_neg` | math | round | strict | round_half_neg [strict] | C11 7.12.9.6 round | PASS |
| `fixture-verify::math::round::strict::round_half_up` | math | round | strict | round_half_up [strict] | C11 7.12.9.6 round | PASS |
| `fixture-verify::math::sin::hardened::sin_pi_half` | math | sin | hardened | sin_pi_half [hardened] | C11 7.12.4.6 sin | PASS |
| `fixture-verify::math::sin::hardened::sin_zero` | math | sin | hardened | sin_zero [hardened] | C11 7.12.4.6 sin | PASS |
| `fixture-verify::math::sin::strict::sin_pi_half` | math | sin | strict | sin_pi_half [strict] | C11 7.12.4.6 sin | PASS |
| `fixture-verify::math::sin::strict::sin_zero` | math | sin | strict | sin_zero [strict] | C11 7.12.4.6 sin | PASS |
| `fixture-verify::math::tan::hardened::tan_zero` | math | tan | hardened | tan_zero [hardened] | C11 7.12.4.7 tan | PASS |
| `fixture-verify::math::tan::strict::tan_zero` | math | tan | strict | tan_zero [strict] | C11 7.12.4.7 tan | PASS |
| `fixture-verify::math::tgamma::hardened::tgamma_five` | math | tgamma | hardened | tgamma_five [hardened] | C11 7.12.8.4 tgamma | PASS |
| `fixture-verify::math::tgamma::hardened::tgamma_one` | math | tgamma | hardened | tgamma_one [hardened] | C11 7.12.8.4 tgamma | PASS |
| `fixture-verify::math::tgamma::strict::tgamma_five` | math | tgamma | strict | tgamma_five [strict] | C11 7.12.8.4 tgamma | PASS |
| `fixture-verify::math::tgamma::strict::tgamma_one` | math | tgamma | strict | tgamma_one [strict] | C11 7.12.8.4 tgamma | PASS |
| `fixture-verify::membrane/mode-split::memcpy::hardened::hardened_memcpy_overflow_clamped` | membrane/mode-split | memcpy | hardened | hardened_memcpy_overflow_clamped | TSM hardened memcpy | PASS |
| `fixture-verify::membrane/mode-split::memcpy::strict::strict_memcpy_overflow_ub` | membrane/mode-split | memcpy | strict | strict_memcpy_overflow_ub | TSM strict memcpy | PASS |
| `fixture-verify::membrane/mode-split::strlen::hardened::hardened_strlen_unterminated_truncated` | membrane/mode-split | strlen | hardened | hardened_strlen_unterminated_truncated | TSM hardened strlen | PASS |
| `fixture-verify::membrane/mode-split::strlen::strict::strict_strlen_unterminated_ub` | membrane/mode-split | strlen | strict | strict_strlen_unterminated_ub | TSM strict strlen | PASS |
| `fixture-verify::memory_ops::memchr::strict::memchr_found_strict` | memory_ops | memchr | strict | memchr_found_strict | C11 7.24.5.1 memchr | PASS |
| `fixture-verify::memory_ops::memchr::strict::memchr_not_found_strict` | memory_ops | memchr | strict | memchr_not_found_strict | C11 7.24.5.1 memchr | PASS |
| `fixture-verify::memory_ops::memcmp::hardened::memcmp_greater_hardened` | memory_ops | memcmp | hardened | memcmp_greater_hardened | C11 7.24.4.1 memcmp | PASS |
| `fixture-verify::memory_ops::memcmp::strict::memcmp_equal_strict` | memory_ops | memcmp | strict | memcmp_equal_strict | C11 7.24.4.1 memcmp | PASS |
| `fixture-verify::memory_ops::memcmp::strict::memcmp_less_strict` | memory_ops | memcmp | strict | memcmp_less_strict | C11 7.24.4.1 memcmp | PASS |
| `fixture-verify::memory_ops::memcpy::hardened::memcpy_basic_hardened` | memory_ops | memcpy | hardened | memcpy_basic_hardened | C11 7.24.2.1 memcpy | PASS |
| `fixture-verify::memory_ops::memcpy::strict::memcpy_basic_strict` | memory_ops | memcpy | strict | memcpy_basic_strict | C11 7.24.2.1 memcpy | PASS |
| `fixture-verify::memory_ops::memcpy::strict::memcpy_zero_len_strict` | memory_ops | memcpy | strict | memcpy_zero_len_strict | C11 7.24.2.1 memcpy | PASS |
| `fixture-verify::memory_ops::memmove::strict::memmove_overlap_forward_strict` | memory_ops | memmove | strict | memmove_overlap_forward_strict | C11 7.24.2.2 memmove | PASS |
| `fixture-verify::memory_ops::memset::hardened::memset_zero_len_hardened` | memory_ops | memset | hardened | memset_zero_len_hardened | C11 7.24.6.1 memset | PASS |
| `fixture-verify::memory_ops::memset::strict::memset_basic_strict` | memory_ops | memset | strict | memset_basic_strict | C11 7.24.6.1 memset | PASS |
| `fixture-verify::mntent::getmntent_r::hardened::getmntent_r_basic_mount_line` | mntent | getmntent_r | hardened | getmntent_r_basic_mount_line [hardened] | glibc <mntent.h> getmntent_r parses six-field mount entries | PASS |
| `fixture-verify::mntent::getmntent_r::hardened::getmntent_r_defaults_missing_freq_passno` | mntent | getmntent_r | hardened | getmntent_r_defaults_missing_freq_passno [hardened] | glibc <mntent.h> getmntent_r defaults missing freq/passno to zero | PASS |
| `fixture-verify::mntent::getmntent_r::hardened::getmntent_r_skips_comment_line` | mntent | getmntent_r | hardened | getmntent_r_skips_comment_line [hardened] | glibc <mntent.h> getmntent_r skips comment-only records | PASS |
| `fixture-verify::mntent::getmntent_r::strict::getmntent_r_basic_mount_line` | mntent | getmntent_r | strict | getmntent_r_basic_mount_line [strict] | glibc <mntent.h> getmntent_r parses six-field mount entries | PASS |
| `fixture-verify::mntent::getmntent_r::strict::getmntent_r_defaults_missing_freq_passno` | mntent | getmntent_r | strict | getmntent_r_defaults_missing_freq_passno [strict] | glibc <mntent.h> getmntent_r defaults missing freq/passno to zero | PASS |
| `fixture-verify::mntent::getmntent_r::strict::getmntent_r_skips_comment_line` | mntent | getmntent_r | strict | getmntent_r_skips_comment_line [strict] | glibc <mntent.h> getmntent_r skips comment-only records | PASS |
| `fixture-verify::mntent::hasmntopt::hardened::hasmntopt_finds_key_value_token` | mntent | hasmntopt | hardened | hasmntopt_finds_key_value_token [hardened] | glibc <mntent.h> hasmntopt locates key=value option tokens | PASS |
| `fixture-verify::mntent::hasmntopt::hardened::hasmntopt_finds_whole_token` | mntent | hasmntopt | hardened | hasmntopt_finds_whole_token [hardened] | glibc <mntent.h> hasmntopt returns a pointer to a whole matching option token | PASS |
| `fixture-verify::mntent::hasmntopt::hardened::hasmntopt_rejects_substring` | mntent | hasmntopt | hardened | hasmntopt_rejects_substring [hardened] | glibc <mntent.h> hasmntopt requires comma-token boundaries | PASS |
| `fixture-verify::mntent::hasmntopt::strict::hasmntopt_finds_key_value_token` | mntent | hasmntopt | strict | hasmntopt_finds_key_value_token [strict] | glibc <mntent.h> hasmntopt locates key=value option tokens | PASS |
| `fixture-verify::mntent::hasmntopt::strict::hasmntopt_finds_whole_token` | mntent | hasmntopt | strict | hasmntopt_finds_whole_token [strict] | glibc <mntent.h> hasmntopt returns a pointer to a whole matching option token | PASS |
| `fixture-verify::mntent::hasmntopt::strict::hasmntopt_rejects_substring` | mntent | hasmntopt | strict | hasmntopt_rejects_substring [strict] | glibc <mntent.h> hasmntopt requires comma-token boundaries | PASS |
| `fixture-verify::poll_ops::poll::hardened::poll_oversized_nfds_hardened` | poll_ops | poll | hardened | poll_oversized_nfds_hardened | POSIX poll | PASS |
| `fixture-verify::poll_ops::poll::hardened::poll_stdin_readable_hardened` | poll_ops | poll | hardened | poll_stdin_readable_hardened | POSIX poll | PASS |
| `fixture-verify::poll_ops::poll::strict::poll_empty_fds_strict` | poll_ops | poll | strict | poll_empty_fds_strict | POSIX poll | PASS |
| `fixture-verify::poll_ops::poll::strict::poll_invalid_fd_strict` | poll_ops | poll | strict | poll_invalid_fd_strict | POSIX poll | PASS |
| `fixture-verify::poll_ops::poll::strict::poll_stdin_readable_strict` | poll_ops | poll | strict | poll_stdin_readable_strict | POSIX poll | PASS |
| `fixture-verify::poll_ops::select::strict::select_zero_timeout_strict` | poll_ops | select | strict | select_zero_timeout_strict | POSIX pselect / select | PASS |
| `fixture-verify::pressure_sensing::PressureSensor::observe::hardened::nominal_under_calm_hardened` | pressure_sensing | PressureSensor::observe | hardened | nominal_under_calm_hardened | bd-w2c3.7.1 §Hardened-Regime | PASS |
| `fixture-verify::pressure_sensing::PressureSensor::observe::hardened::recovery_re_escalation_hardened` | pressure_sensing | PressureSensor::observe | hardened | recovery_re_escalation_hardened | bd-w2c3.7.1 §Recovery-Protocol | PASS |
| `fixture-verify::pressure_sensing::PressureSensor::observe::strict::deterministic_replay_strict` | pressure_sensing | PressureSensor::observe | strict | deterministic_replay_strict | bd-w2c3.7.1 §Determinism | PASS |
| `fixture-verify::pressure_sensing::PressureSensor::observe::strict::escalate_to_overloaded_strict` | pressure_sensing | PressureSensor::observe | strict | escalate_to_overloaded_strict | bd-w2c3.7.1 §Regime-Transitions | PASS |
| `fixture-verify::pressure_sensing::PressureSensor::observe::strict::escalate_to_pressured_strict` | pressure_sensing | PressureSensor::observe | strict | escalate_to_pressured_strict | bd-w2c3.7.1 §Regime-Transitions | PASS |
| `fixture-verify::pressure_sensing::PressureSensor::observe::strict::hysteresis_prevents_flapping_strict` | pressure_sensing | PressureSensor::observe | strict | hysteresis_prevents_flapping_strict | bd-w2c3.7.1 §Hysteresis | PASS |
| `fixture-verify::pressure_sensing::PressureSensor::observe::strict::nominal_under_calm_strict` | pressure_sensing | PressureSensor::observe | strict | nominal_under_calm_strict | bd-w2c3.7.1 §Regime-Classifier | PASS |
| `fixture-verify::pressure_sensing::PressureSensor::observe::strict::recovery_hold_before_nominal_strict` | pressure_sensing | PressureSensor::observe | strict | recovery_hold_before_nominal_strict | bd-w2c3.7.1 §Recovery-Protocol | PASS |
| `fixture-verify::pressure_sensing::SystemRegime::degradation_active::hardened::degradation_active_in_overloaded_hardened` | pressure_sensing | SystemRegime::degradation_active | hardened | degradation_active_in_overloaded_hardened | bd-w2c3.7.1 §Degradation-Policy | PASS |
| `fixture-verify::printf_conformance::snprintf::strict::snprintf_exact_fit` | printf_conformance | snprintf | strict | snprintf_exact_fit | C11 7.21.6.5 exact fit | PASS |
| `fixture-verify::printf_conformance::snprintf::strict::snprintf_float_truncate` | printf_conformance | snprintf | strict | snprintf_float_truncate | C11 7.21.6.5 truncate float | PASS |
| `fixture-verify::printf_conformance::snprintf::strict::snprintf_just_null` | printf_conformance | snprintf | strict | snprintf_just_null | C11 7.21.6.5 size=1 | PASS |
| `fixture-verify::printf_conformance::snprintf::strict::snprintf_multi_conv_truncate` | printf_conformance | snprintf | strict | snprintf_multi_conv_truncate | C11 7.21.6.5 multi-conv truncate | PASS |
| `fixture-verify::printf_conformance::snprintf::strict::snprintf_null_buffer` | printf_conformance | snprintf | strict | snprintf_null_buffer | C11 7.21.6.5 NULL buffer | PASS |
| `fixture-verify::printf_conformance::snprintf::strict::snprintf_percent_truncate` | printf_conformance | snprintf | strict | snprintf_percent_truncate | C11 7.21.6.5 %% truncate | PASS |
| `fixture-verify::printf_conformance::snprintf::strict::snprintf_returns_would_write` | printf_conformance | snprintf | strict | snprintf_returns_would_write | C11 7.21.6.5 return value | PASS |
| `fixture-verify::printf_conformance::snprintf::strict::snprintf_truncates_mid_conversion` | printf_conformance | snprintf | strict | snprintf_truncates_mid_conversion | C11 7.21.6.5 mid-conversion truncate | PASS |
| `fixture-verify::printf_conformance::snprintf::strict::snprintf_zero_size` | printf_conformance | snprintf | strict | snprintf_zero_size | C11 7.21.6.5 size 0 | PASS |
| `fixture-verify::printf_conformance::sprintf::hardened::sprintf_n_count_mid` | printf_conformance | sprintf | hardened | sprintf_n_count_mid | C11 7.21.6.1 %n after chars | PASS |
| `fixture-verify::printf_conformance::sprintf::hardened::sprintf_n_count_zero` | printf_conformance | sprintf | hardened | sprintf_n_count_zero | C11 7.21.6.1 %n specifier at start | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_A_basic` | printf_conformance | sprintf | strict | sprintf_A_basic | C11 7.21.6.1 %A specifier | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_E_basic` | printf_conformance | sprintf | strict | sprintf_E_basic | C11 7.21.6.1 %E specifier | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_F_inf` | printf_conformance | sprintf | strict | sprintf_F_inf | C11 7.21.6.1 %F infinity | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_F_nan` | printf_conformance | sprintf | strict | sprintf_F_nan | C11 7.21.6.1 %F NaN | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_G_basic` | printf_conformance | sprintf | strict | sprintf_G_basic | C11 7.21.6.1 %G specifier | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_Le_basic` | printf_conformance | sprintf | strict | sprintf_Le_basic | C11 7.21.6.1 %Le long double | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_Lf_basic` | printf_conformance | sprintf | strict | sprintf_Lf_basic | C11 7.21.6.1 %Lf long double | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_X_alt_form` | printf_conformance | sprintf | strict | sprintf_X_alt_form | C11 7.21.6.1 %#X alternate form | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_X_basic` | printf_conformance | sprintf | strict | sprintf_X_basic | C11 7.21.6.1 %X specifier | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_a_basic` | printf_conformance | sprintf | strict | sprintf_a_basic | C11 7.21.6.1 %a specifier | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_a_negative` | printf_conformance | sprintf | strict | sprintf_a_negative | C11 7.21.6.1 %a negative | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_a_precision` | printf_conformance | sprintf | strict | sprintf_a_precision | C11 7.21.6.1 %.2a | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_c_basic` | printf_conformance | sprintf | strict | sprintf_c_basic | C11 7.21.6.1 %c specifier | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_c_left_width` | printf_conformance | sprintf | strict | sprintf_c_left_width | C11 7.21.6.1 %-c with width | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_c_nul` | printf_conformance | sprintf | strict | sprintf_c_nul | C11 7.21.6.1 %c NUL char | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_c_width` | printf_conformance | sprintf | strict | sprintf_c_width | C11 7.21.6.1 %c with width | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_consecutive_args` | printf_conformance | sprintf | strict | sprintf_consecutive_args | C11 7.21.6.1 many args | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_consecutive_percents` | printf_conformance | sprintf | strict | sprintf_consecutive_percents | C11 7.21.6.1 consecutive %% | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_d_asterisk_zero_width` | printf_conformance | sprintf | strict | sprintf_d_asterisk_zero_width | C11 7.21.6.1 * zero width | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_d_basic` | printf_conformance | sprintf | strict | sprintf_d_basic | C11 7.21.6.1 %d specifier | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_d_hash_ignored` | printf_conformance | sprintf | strict | sprintf_d_hash_ignored | C11 7.21.6.1 %#d # ignored | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_d_max_int` | printf_conformance | sprintf | strict | sprintf_d_max_int | C11 7.21.6.1 INT_MAX | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_d_min_int` | printf_conformance | sprintf | strict | sprintf_d_min_int | C11 7.21.6.1 INT_MIN | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_d_neg_zero_pad` | printf_conformance | sprintf | strict | sprintf_d_neg_zero_pad | C11 7.21.6.1 %0d negative | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_d_negative` | printf_conformance | sprintf | strict | sprintf_d_negative | C11 7.21.6.1 %d negative | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_d_precision_exceeds_value` | printf_conformance | sprintf | strict | sprintf_d_precision_exceeds_value | C11 7.21.6.1 precision >> value | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_d_sign_with_width` | printf_conformance | sprintf | strict | sprintf_d_sign_with_width | C11 7.21.6.1 %+d width interaction | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_d_sign_with_zero` | printf_conformance | sprintf | strict | sprintf_d_sign_with_zero | C11 7.21.6.1 %+0d | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_d_space_with_width` | printf_conformance | sprintf | strict | sprintf_d_space_with_width | C11 7.21.6.1 % d width | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_d_zero` | printf_conformance | sprintf | strict | sprintf_d_zero | C11 7.21.6.1 %d zero | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_d_zero_width` | printf_conformance | sprintf | strict | sprintf_d_zero_width | C11 7.21.6.1 %0d | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_e_basic` | printf_conformance | sprintf | strict | sprintf_e_basic | C11 7.21.6.1 %e specifier | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_e_neg_exp` | printf_conformance | sprintf | strict | sprintf_e_neg_exp | C11 7.21.6.1 %e negative exponent | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_e_neg_zero` | printf_conformance | sprintf | strict | sprintf_e_neg_zero | C11 7.21.6.1 %e -0.0 | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_e_plus_flag` | printf_conformance | sprintf | strict | sprintf_e_plus_flag | C11 7.21.6.1 %+e | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_e_precision` | printf_conformance | sprintf | strict | sprintf_e_precision | C11 7.21.6.1 %e precision | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_e_precision_one` | printf_conformance | sprintf | strict | sprintf_e_precision_one | C11 7.21.6.1 %.1e | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_e_round_half_even` | printf_conformance | sprintf | strict | sprintf_e_round_half_even | C11 7.21.6.1 %.0e banker's | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_e_round_half_even_3_5` | printf_conformance | sprintf | strict | sprintf_e_round_half_even_3_5 | C11 7.21.6.1 %.0e banker's 3.5 | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_e_width_precision` | printf_conformance | sprintf | strict | sprintf_e_width_precision | C11 7.21.6.1 %e width+precision | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_e_width_zero_pad` | printf_conformance | sprintf | strict | sprintf_e_width_zero_pad | C11 7.21.6.1 %0e width | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_e_zero` | printf_conformance | sprintf | strict | sprintf_e_zero | C11 7.21.6.1 %e zero | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_empty_format` | printf_conformance | sprintf | strict | sprintf_empty_format | C11 7.21.6.1 empty format | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_alt_precision_zero` | printf_conformance | sprintf | strict | sprintf_f_alt_precision_zero | C11 7.21.6.1 %#.0f alt form | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_basic` | printf_conformance | sprintf | strict | sprintf_f_basic | C11 7.21.6.1 %f specifier | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_denormal` | printf_conformance | sprintf | strict | sprintf_f_denormal | C11 7.21.6.1 %f denormal | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_inf` | printf_conformance | sprintf | strict | sprintf_f_inf | C11 7.21.6.1 %f infinity | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_integer_precision_large` | printf_conformance | sprintf | strict | sprintf_f_integer_precision_large | C11 7.21.6.1 %f very large | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_nan` | printf_conformance | sprintf | strict | sprintf_f_nan | C11 7.21.6.1 %f NaN | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_neg_inf` | printf_conformance | sprintf | strict | sprintf_f_neg_inf | C11 7.21.6.1 %f -infinity | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_negative` | printf_conformance | sprintf | strict | sprintf_f_negative | C11 7.21.6.1 %f negative | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_negative_zero` | printf_conformance | sprintf | strict | sprintf_f_negative_zero | C11 7.21.6.1 %f -0.0 | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_plus_inf` | printf_conformance | sprintf | strict | sprintf_f_plus_inf | C11 7.21.6.1 %+f infinity | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_plus_width` | printf_conformance | sprintf | strict | sprintf_f_plus_width | C11 7.21.6.1 %+f width | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_precision` | printf_conformance | sprintf | strict | sprintf_f_precision | C11 7.21.6.1 %f precision | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_precision_large` | printf_conformance | sprintf | strict | sprintf_f_precision_large | C11 7.21.6.1 %f high precision | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_precision_zero` | printf_conformance | sprintf | strict | sprintf_f_precision_zero | C11 7.21.6.1 %f precision 0 | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_round_half_even` | printf_conformance | sprintf | strict | sprintf_f_round_half_even | C11 7.21.6.1 %f banker's rounding | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_round_half_even_4_5` | printf_conformance | sprintf | strict | sprintf_f_round_half_even_4_5 | C11 7.21.6.1 %f banker's 4.5 | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_round_half_even_5_5` | printf_conformance | sprintf | strict | sprintf_f_round_half_even_5_5 | C11 7.21.6.1 %f banker's 5.5 | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_round_half_even_neg_2_5` | printf_conformance | sprintf | strict | sprintf_f_round_half_even_neg_2_5 | C11 7.21.6.1 %f banker's -2.5 | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_round_half_even_neg_3_5` | printf_conformance | sprintf | strict | sprintf_f_round_half_even_neg_3_5 | C11 7.21.6.1 %f banker's -3.5 | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_round_half_even_odd` | printf_conformance | sprintf | strict | sprintf_f_round_half_even_odd | C11 7.21.6.1 %f banker's rounding 3.5 | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_rounding_down` | printf_conformance | sprintf | strict | sprintf_f_rounding_down | C11 7.21.6.1 %f round down | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_rounding_up` | printf_conformance | sprintf | strict | sprintf_f_rounding_up | C11 7.21.6.1 %f round up | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_space_nan` | printf_conformance | sprintf | strict | sprintf_f_space_nan | C11 7.21.6.1 % f NaN | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_subnanosecond_precision` | printf_conformance | sprintf | strict | sprintf_f_subnanosecond_precision | C11 7.21.6.1 %f very small | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_very_large` | printf_conformance | sprintf | strict | sprintf_f_very_large | C11 7.21.6.1 %f large | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_very_small` | printf_conformance | sprintf | strict | sprintf_f_very_small | C11 7.21.6.1 %f small | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_width_left_justify` | printf_conformance | sprintf | strict | sprintf_f_width_left_justify | C11 7.21.6.1 %-f width | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_width_right_justify` | printf_conformance | sprintf | strict | sprintf_f_width_right_justify | C11 7.21.6.1 %f width | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_f_width_zero_pad` | printf_conformance | sprintf | strict | sprintf_f_width_zero_pad | C11 7.21.6.1 %0f width | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_g_alt_trailing` | printf_conformance | sprintf | strict | sprintf_g_alt_trailing | C11 7.21.6.1 %#g keeps trailing | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_g_basic` | printf_conformance | sprintf | strict | sprintf_g_basic | C11 7.21.6.1 %g specifier | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_g_large` | printf_conformance | sprintf | strict | sprintf_g_large | C11 7.21.6.1 %g large value | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_g_power_large` | printf_conformance | sprintf | strict | sprintf_g_power_large | C11 7.21.6.1 %g large | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_g_precision` | printf_conformance | sprintf | strict | sprintf_g_precision | C11 7.21.6.1 %.2g | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_g_precision_rounds` | printf_conformance | sprintf | strict | sprintf_g_precision_rounds | C11 7.21.6.1 %.2g | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_g_precision_zero` | printf_conformance | sprintf | strict | sprintf_g_precision_zero | C11 7.21.6.1 %.0g | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_g_small_fixed` | printf_conformance | sprintf | strict | sprintf_g_small_fixed | C11 7.21.6.1 %g basic | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_g_switch_to_e` | printf_conformance | sprintf | strict | sprintf_g_switch_to_e | C11 7.21.6.1 %g switches to e | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_g_trailing_zeros` | printf_conformance | sprintf | strict | sprintf_g_trailing_zeros | C11 7.21.6.1 %g no trailing zeros | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_g_zero` | printf_conformance | sprintf | strict | sprintf_g_zero | C11 7.21.6.1 %g zero | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_h_d` | printf_conformance | sprintf | strict | sprintf_h_d | C11 7.21.6.1 %hd length | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_h_overflow` | printf_conformance | sprintf | strict | sprintf_h_overflow | C11 7.21.6.1 %hd overflow | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_hh_d` | printf_conformance | sprintf | strict | sprintf_hh_d | C11 7.21.6.1 %hhd length | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_hh_overflow` | printf_conformance | sprintf | strict | sprintf_hh_overflow | C11 7.21.6.1 %hhd overflow | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_hhu_max` | printf_conformance | sprintf | strict | sprintf_hhu_max | C11 7.21.6.1 %hhu UCHAR_MAX | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_hhx_max` | printf_conformance | sprintf | strict | sprintf_hhx_max | C11 7.21.6.1 %hhx UCHAR_MAX | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_hu_max` | printf_conformance | sprintf | strict | sprintf_hu_max | C11 7.21.6.1 %hu USHRT_MAX | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_hx_max` | printf_conformance | sprintf | strict | sprintf_hx_max | C11 7.21.6.1 %hx USHRT_MAX | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_i_basic` | printf_conformance | sprintf | strict | sprintf_i_basic | C11 7.21.6.1 %i specifier | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_j_d` | printf_conformance | sprintf | strict | sprintf_j_d | C11 7.21.6.1 %jd intmax_t | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_l_d` | printf_conformance | sprintf | strict | sprintf_l_d | C11 7.21.6.1 %ld length | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_left_overrides_zero` | printf_conformance | sprintf | strict | sprintf_left_overrides_zero | C11 7.21.6.1 - overrides 0 | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_literal_percent` | printf_conformance | sprintf | strict | sprintf_literal_percent | C11 7.21.6.1 %% specifier | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_ll_d` | printf_conformance | sprintf | strict | sprintf_ll_d | C11 7.21.6.1 %lld length | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_lld_negative` | printf_conformance | sprintf | strict | sprintf_lld_negative | C11 7.21.6.1 %lld negative | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_llu_max` | printf_conformance | sprintf | strict | sprintf_llu_max | C11 7.21.6.1 ULLONG_MAX | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_llx_max` | printf_conformance | sprintf | strict | sprintf_llx_max | C11 7.21.6.1 %llx max | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_lo_max` | printf_conformance | sprintf | strict | sprintf_lo_max | C11 7.21.6.1 %lo ULONG_MAX | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_mixed_text` | printf_conformance | sprintf | strict | sprintf_mixed_text | C11 7.21.6.1 mixed text | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_mixed_types` | printf_conformance | sprintf | strict | sprintf_mixed_types | C11 7.21.6.1 mixed types | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_multiple_conversions` | printf_conformance | sprintf | strict | sprintf_multiple_conversions | C11 7.21.6.1 multiple | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_o_alt_form` | printf_conformance | sprintf | strict | sprintf_o_alt_form | C11 7.21.6.1 %#o alternate form | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_o_alt_precision` | printf_conformance | sprintf | strict | sprintf_o_alt_precision | C11 7.21.6.1 %#.5o | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_o_alt_zero` | printf_conformance | sprintf | strict | sprintf_o_alt_zero | C11 7.21.6.1 %#o zero | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_o_basic` | printf_conformance | sprintf | strict | sprintf_o_basic | C11 7.21.6.1 %o specifier | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_o_large_value` | printf_conformance | sprintf | strict | sprintf_o_large_value | C11 7.21.6.1 %o large | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_o_precision_zero` | printf_conformance | sprintf | strict | sprintf_o_precision_zero | C11 7.21.6.1 %.0o with zero | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_o_width_precision` | printf_conformance | sprintf | strict | sprintf_o_width_precision | C11 7.21.6.1 %o width+prec | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_o_zero` | printf_conformance | sprintf | strict | sprintf_o_zero | C11 7.21.6.1 %o zero | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_only_literal` | printf_conformance | sprintf | strict | sprintf_only_literal | C11 7.21.6.1 literal only | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_p_basic` | printf_conformance | sprintf | strict | sprintf_p_basic | C11 7.21.6.1 %p specifier | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_p_null` | printf_conformance | sprintf | strict | sprintf_p_null | C11 7.21.6.1 %p NULL | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_p_width` | printf_conformance | sprintf | strict | sprintf_p_width | C11 7.21.6.1 %p width | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_plus_flag_neg` | printf_conformance | sprintf | strict | sprintf_plus_flag_neg | C11 7.21.6.1 + flag negative | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_plus_flag_pos` | printf_conformance | sprintf | strict | sprintf_plus_flag_pos | C11 7.21.6.1 + flag positive | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_plus_overrides_space` | printf_conformance | sprintf | strict | sprintf_plus_overrides_space | C11 7.21.6.1 + overrides space | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_plus_space_interaction` | printf_conformance | sprintf | strict | sprintf_plus_space_interaction | C11 7.21.6.1 + overrides space | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_plus_zero` | printf_conformance | sprintf | strict | sprintf_plus_zero | C11 7.21.6.1 + with zero | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_positional_basic` | printf_conformance | sprintf | strict | sprintf_positional_basic | POSIX fprintf() positional args | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_positional_reorder` | printf_conformance | sprintf | strict | sprintf_positional_reorder | POSIX fprintf() positional reorder | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_positional_repeat` | printf_conformance | sprintf | strict | sprintf_positional_repeat | POSIX fprintf() positional repeat | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_positional_width` | printf_conformance | sprintf | strict | sprintf_positional_width | POSIX fprintf() positional width | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_precision_d` | printf_conformance | sprintf | strict | sprintf_precision_d | C11 7.21.6.1 precision with %d | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_precision_d_neg` | printf_conformance | sprintf | strict | sprintf_precision_d_neg | C11 7.21.6.1 precision negative | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_precision_d_zero` | printf_conformance | sprintf | strict | sprintf_precision_d_zero | C11 7.21.6.1 %.0d with zero value | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_precision_greater_width` | printf_conformance | sprintf | strict | sprintf_precision_greater_width | C11 7.21.6.1 precision > width | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_precision_larger_than_digits` | printf_conformance | sprintf | strict | sprintf_precision_larger_than_digits | C11 7.21.6.1 large precision | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_s_basic` | printf_conformance | sprintf | strict | sprintf_s_basic | C11 7.21.6.1 %s specifier | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_s_empty` | printf_conformance | sprintf | strict | sprintf_s_empty | C11 7.21.6.1 %s empty | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_s_null_precision` | printf_conformance | sprintf | strict | sprintf_s_null_precision | C11 7.21.6.1 %.0s empty | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_s_null_ptr` | printf_conformance | sprintf | strict | sprintf_s_null_ptr | C11 7.21.6.1 %s (null) | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_s_precision` | printf_conformance | sprintf | strict | sprintf_s_precision | C11 7.21.6.1 %s precision | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_s_precision_exceeds_len` | printf_conformance | sprintf | strict | sprintf_s_precision_exceeds_len | C11 7.21.6.1 %s precision > len | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_s_precision_zero` | printf_conformance | sprintf | strict | sprintf_s_precision_zero | C11 7.21.6.1 %s precision 0 | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_s_width` | printf_conformance | sprintf | strict | sprintf_s_width | C11 7.21.6.1 %s width | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_s_width_left` | printf_conformance | sprintf | strict | sprintf_s_width_left | C11 7.21.6.1 %-s left justify | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_s_width_precision` | printf_conformance | sprintf | strict | sprintf_s_width_precision | C11 7.21.6.1 %s width+precision | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_s_width_zero` | printf_conformance | sprintf | strict | sprintf_s_width_zero | C11 7.21.6.1 %0s ignored | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_space_flag_neg` | printf_conformance | sprintf | strict | sprintf_space_flag_neg | C11 7.21.6.1 space flag negative | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_space_flag_pos` | printf_conformance | sprintf | strict | sprintf_space_flag_pos | C11 7.21.6.1 space flag positive | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_star_both` | printf_conformance | sprintf | strict | sprintf_star_both | C11 7.21.6.1 *.* | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_star_neg_precision` | printf_conformance | sprintf | strict | sprintf_star_neg_precision | C11 7.21.6.1 .* negative precision | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_star_neg_width` | printf_conformance | sprintf | strict | sprintf_star_neg_width | C11 7.21.6.1 * negative width | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_star_precision` | printf_conformance | sprintf | strict | sprintf_star_precision | C11 7.21.6.1 .* precision | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_star_width` | printf_conformance | sprintf | strict | sprintf_star_width | C11 7.21.6.1 * width | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_string_precision_longer` | printf_conformance | sprintf | strict | sprintf_string_precision_longer | C11 7.21.6.1 %.s longer | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_string_width_precision` | printf_conformance | sprintf | strict | sprintf_string_width_precision | C11 7.21.6.1 %width.prec s | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_t_d` | printf_conformance | sprintf | strict | sprintf_t_d | C11 7.21.6.1 %td ptrdiff_t | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_u_basic` | printf_conformance | sprintf | strict | sprintf_u_basic | C11 7.21.6.1 %u specifier | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_u_max` | printf_conformance | sprintf | strict | sprintf_u_max | C11 7.21.6.1 UINT_MAX | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_u_zero` | printf_conformance | sprintf | strict | sprintf_u_zero | C11 7.21.6.1 %u zero | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_width_d` | printf_conformance | sprintf | strict | sprintf_width_d | C11 7.21.6.1 width with %d | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_width_d_left` | printf_conformance | sprintf | strict | sprintf_width_d_left | C11 7.21.6.1 %-d left justify | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_width_d_zero_neg` | printf_conformance | sprintf | strict | sprintf_width_d_zero_neg | C11 7.21.6.1 %0d negative | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_width_d_zero_pad` | printf_conformance | sprintf | strict | sprintf_width_d_zero_pad | C11 7.21.6.1 %0d zero pad | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_width_larger_than_output` | printf_conformance | sprintf | strict | sprintf_width_larger_than_output | C11 7.21.6.1 large width | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_width_precision_d` | printf_conformance | sprintf | strict | sprintf_width_precision_d | C11 7.21.6.1 width+precision | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_width_precision_neg_d` | printf_conformance | sprintf | strict | sprintf_width_precision_neg_d | C11 7.21.6.1 width+precision negative | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_x_alt_form` | printf_conformance | sprintf | strict | sprintf_x_alt_form | C11 7.21.6.1 %#x alternate form | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_x_alt_width_precision` | printf_conformance | sprintf | strict | sprintf_x_alt_width_precision | C11 7.21.6.1 %#x width+prec | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_x_alt_zero` | printf_conformance | sprintf | strict | sprintf_x_alt_zero | C11 7.21.6.1 %#x zero | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_x_basic` | printf_conformance | sprintf | strict | sprintf_x_basic | C11 7.21.6.1 %x specifier | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_x_large_value` | printf_conformance | sprintf | strict | sprintf_x_large_value | C11 7.21.6.1 %x large | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_x_precision_zero` | printf_conformance | sprintf | strict | sprintf_x_precision_zero | C11 7.21.6.1 %.0x with zero | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_x_uppercase_alt` | printf_conformance | sprintf | strict | sprintf_x_uppercase_alt | C11 7.21.6.1 %#08X | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_x_width_left_alt` | printf_conformance | sprintf | strict | sprintf_x_width_left_alt | C11 7.21.6.1 %-#8x | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_x_width_precision` | printf_conformance | sprintf | strict | sprintf_x_width_precision | C11 7.21.6.1 %x width+prec | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_x_zero` | printf_conformance | sprintf | strict | sprintf_x_zero | C11 7.21.6.1 %x zero | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_z_u` | printf_conformance | sprintf | strict | sprintf_z_u | C11 7.21.6.1 %zu length | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_zd_negative` | printf_conformance | sprintf | strict | sprintf_zd_negative | C11 7.21.6.1 %zd negative | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_zero_flag_ignored_with_precision` | printf_conformance | sprintf | strict | sprintf_zero_flag_ignored_with_precision | C11 7.21.6.1 0 flag ignored with precision | PASS |
| `fixture-verify::printf_conformance::sprintf::strict::sprintf_zu_basic` | printf_conformance | sprintf | strict | sprintf_zu_basic | C11 7.21.6.1 %zu size_t | PASS |
| `fixture-verify::process_ops::fork::hardened::fork_returns_child_or_zero_hardened` | process_ops | fork | hardened | fork_returns_child_or_zero_hardened | POSIX fork | PASS |
| `fixture-verify::process_ops::fork::strict::fork_returns_child_or_zero_strict` | process_ops | fork | strict | fork_returns_child_or_zero_strict | POSIX fork | PASS |
| `fixture-verify::process_ops::getpid::hardened::getpid_positive_hardened` | process_ops | getpid | hardened | getpid_positive_hardened | POSIX getpid | PASS |
| `fixture-verify::process_ops::getpid::strict::getpid_positive_strict` | process_ops | getpid | strict | getpid_positive_strict | POSIX getpid | PASS |
| `fixture-verify::process_ops::getppid::strict::getppid_positive_strict` | process_ops | getppid | strict | getppid_positive_strict | POSIX getppid | PASS |
| `fixture-verify::process_ops::waitpid::strict::waitpid_nohang_no_child_strict` | process_ops | waitpid | strict | waitpid_nohang_no_child_strict | POSIX waitpid | PASS |
| `fixture-verify::process_ops::waitpid::strict::waitpid_reaps_child_strict` | process_ops | waitpid | strict | waitpid_reaps_child_strict | POSIX waitpid | PASS |
| `fixture-verify::pthread/cond::pthread_cond_broadcast::hardened::broadcast_multiple_waiters` | pthread/cond | pthread_cond_broadcast | hardened | broadcast_multiple_waiters [hardened] | POSIX.1-2017 pthread_cond_broadcast | PASS |
| `fixture-verify::pthread/cond::pthread_cond_broadcast::hardened::broadcast_no_waiters` | pthread/cond | pthread_cond_broadcast | hardened | broadcast_no_waiters [hardened] | POSIX.1-2017 pthread_cond_broadcast | PASS |
| `fixture-verify::pthread/cond::pthread_cond_broadcast::hardened::broadcast_null_pointer` | pthread/cond | pthread_cond_broadcast | hardened | broadcast_null_pointer [hardened] | POSIX.1-2017 pthread_cond_broadcast | PASS |
| `fixture-verify::pthread/cond::pthread_cond_broadcast::strict::broadcast_multiple_waiters` | pthread/cond | pthread_cond_broadcast | strict | broadcast_multiple_waiters [strict] | POSIX.1-2017 pthread_cond_broadcast | PASS |
| `fixture-verify::pthread/cond::pthread_cond_broadcast::strict::broadcast_no_waiters` | pthread/cond | pthread_cond_broadcast | strict | broadcast_no_waiters [strict] | POSIX.1-2017 pthread_cond_broadcast | PASS |
| `fixture-verify::pthread/cond::pthread_cond_broadcast::strict::broadcast_null_pointer` | pthread/cond | pthread_cond_broadcast | strict | broadcast_null_pointer [strict] | POSIX.1-2017 pthread_cond_broadcast | PASS |
| `fixture-verify::pthread/cond::pthread_cond_destroy::hardened::destroy_idle` | pthread/cond | pthread_cond_destroy | hardened | destroy_idle [hardened] | POSIX.1-2017 pthread_cond_destroy | PASS |
| `fixture-verify::pthread/cond::pthread_cond_destroy::hardened::destroy_null_pointer` | pthread/cond | pthread_cond_destroy | hardened | destroy_null_pointer [hardened] | POSIX.1-2017 pthread_cond_destroy | PASS |
| `fixture-verify::pthread/cond::pthread_cond_destroy::hardened::destroy_with_waiters` | pthread/cond | pthread_cond_destroy | hardened | destroy_with_waiters [hardened] | POSIX.1-2017 pthread_cond_destroy | PASS |
| `fixture-verify::pthread/cond::pthread_cond_destroy::strict::destroy_idle` | pthread/cond | pthread_cond_destroy | strict | destroy_idle [strict] | POSIX.1-2017 pthread_cond_destroy | PASS |
| `fixture-verify::pthread/cond::pthread_cond_destroy::strict::destroy_null_pointer` | pthread/cond | pthread_cond_destroy | strict | destroy_null_pointer [strict] | POSIX.1-2017 pthread_cond_destroy | PASS |
| `fixture-verify::pthread/cond::pthread_cond_destroy::strict::destroy_with_waiters` | pthread/cond | pthread_cond_destroy | strict | destroy_with_waiters [strict] | POSIX.1-2017 pthread_cond_destroy | PASS |
| `fixture-verify::pthread/cond::pthread_cond_init::hardened::destroy_then_reinit` | pthread/cond | pthread_cond_init | hardened | destroy_then_reinit [hardened] | POSIX.1-2017 pthread_cond_init | PASS |
| `fixture-verify::pthread/cond::pthread_cond_init::hardened::init_default_attr` | pthread/cond | pthread_cond_init | hardened | init_default_attr [hardened] | POSIX.1-2017 pthread_cond_init | PASS |
| `fixture-verify::pthread/cond::pthread_cond_init::hardened::init_monotonic_clock` | pthread/cond | pthread_cond_init | hardened | init_monotonic_clock [hardened] | POSIX.1-2017 pthread_cond_init + pthread_condattr_setclock | PASS |
| `fixture-verify::pthread/cond::pthread_cond_init::hardened::init_null_pointer` | pthread/cond | pthread_cond_init | hardened | init_null_pointer [hardened] | POSIX.1-2017 pthread_cond_init | PASS |
| `fixture-verify::pthread/cond::pthread_cond_init::strict::destroy_then_reinit` | pthread/cond | pthread_cond_init | strict | destroy_then_reinit [strict] | POSIX.1-2017 pthread_cond_init | PASS |
| `fixture-verify::pthread/cond::pthread_cond_init::strict::init_default_attr` | pthread/cond | pthread_cond_init | strict | init_default_attr [strict] | POSIX.1-2017 pthread_cond_init | PASS |
| `fixture-verify::pthread/cond::pthread_cond_init::strict::init_monotonic_clock` | pthread/cond | pthread_cond_init | strict | init_monotonic_clock [strict] | POSIX.1-2017 pthread_cond_init + pthread_condattr_setclock | PASS |
| `fixture-verify::pthread/cond::pthread_cond_init::strict::init_null_pointer` | pthread/cond | pthread_cond_init | strict | init_null_pointer [strict] | POSIX.1-2017 pthread_cond_init | PASS |
| `fixture-verify::pthread/cond::pthread_cond_signal::hardened::signal_no_waiters` | pthread/cond | pthread_cond_signal | hardened | signal_no_waiters [hardened] | POSIX.1-2017 pthread_cond_signal | PASS |
| `fixture-verify::pthread/cond::pthread_cond_signal::hardened::signal_null_pointer` | pthread/cond | pthread_cond_signal | hardened | signal_null_pointer [hardened] | POSIX.1-2017 pthread_cond_signal | PASS |
| `fixture-verify::pthread/cond::pthread_cond_signal::hardened::signal_one_waiter` | pthread/cond | pthread_cond_signal | hardened | signal_one_waiter [hardened] | POSIX.1-2017 pthread_cond_signal | PASS |
| `fixture-verify::pthread/cond::pthread_cond_signal::strict::signal_no_waiters` | pthread/cond | pthread_cond_signal | strict | signal_no_waiters [strict] | POSIX.1-2017 pthread_cond_signal | PASS |
| `fixture-verify::pthread/cond::pthread_cond_signal::strict::signal_null_pointer` | pthread/cond | pthread_cond_signal | strict | signal_null_pointer [strict] | POSIX.1-2017 pthread_cond_signal | PASS |
| `fixture-verify::pthread/cond::pthread_cond_signal::strict::signal_one_waiter` | pthread/cond | pthread_cond_signal | strict | signal_one_waiter [strict] | POSIX.1-2017 pthread_cond_signal | PASS |
| `fixture-verify::pthread/cond::pthread_cond_timedwait::hardened::timedwait_before_deadline` | pthread/cond | pthread_cond_timedwait | hardened | timedwait_before_deadline [hardened] | POSIX.1-2017 pthread_cond_timedwait | PASS |
| `fixture-verify::pthread/cond::pthread_cond_timedwait::hardened::timedwait_expired_deadline` | pthread/cond | pthread_cond_timedwait | hardened | timedwait_expired_deadline [hardened] | POSIX.1-2017 pthread_cond_timedwait | PASS |
| `fixture-verify::pthread/cond::pthread_cond_timedwait::hardened::timedwait_invalid_nsec_billion` | pthread/cond | pthread_cond_timedwait | hardened | timedwait_invalid_nsec_billion [hardened] | POSIX.1-2017 pthread_cond_timedwait | PASS |
| `fixture-verify::pthread/cond::pthread_cond_timedwait::hardened::timedwait_invalid_nsec_negative` | pthread/cond | pthread_cond_timedwait | hardened | timedwait_invalid_nsec_negative [hardened] | POSIX.1-2017 pthread_cond_timedwait | PASS |
| `fixture-verify::pthread/cond::pthread_cond_timedwait::hardened::timedwait_monotonic_clock` | pthread/cond | pthread_cond_timedwait | hardened | timedwait_monotonic_clock [hardened] | POSIX.1-2017 pthread_cond_timedwait + pthread_condattr_setclock | PASS |
| `fixture-verify::pthread/cond::pthread_cond_timedwait::strict::timedwait_before_deadline` | pthread/cond | pthread_cond_timedwait | strict | timedwait_before_deadline [strict] | POSIX.1-2017 pthread_cond_timedwait | PASS |
| `fixture-verify::pthread/cond::pthread_cond_timedwait::strict::timedwait_expired_deadline` | pthread/cond | pthread_cond_timedwait | strict | timedwait_expired_deadline [strict] | POSIX.1-2017 pthread_cond_timedwait | PASS |
| `fixture-verify::pthread/cond::pthread_cond_timedwait::strict::timedwait_invalid_nsec_billion` | pthread/cond | pthread_cond_timedwait | strict | timedwait_invalid_nsec_billion [strict] | POSIX.1-2017 pthread_cond_timedwait | PASS |
| `fixture-verify::pthread/cond::pthread_cond_timedwait::strict::timedwait_invalid_nsec_negative` | pthread/cond | pthread_cond_timedwait | strict | timedwait_invalid_nsec_negative [strict] | POSIX.1-2017 pthread_cond_timedwait | PASS |
| `fixture-verify::pthread/cond::pthread_cond_timedwait::strict::timedwait_monotonic_clock` | pthread/cond | pthread_cond_timedwait | strict | timedwait_monotonic_clock [strict] | POSIX.1-2017 pthread_cond_timedwait + pthread_condattr_setclock | PASS |
| `fixture-verify::pthread/cond::pthread_cond_wait::hardened::spurious_wakeup_predicate_loop` | pthread/cond | pthread_cond_wait | hardened | spurious_wakeup_predicate_loop [hardened] | POSIX.1-2017 pthread_cond_wait (spurious wakeup) | PASS |
| `fixture-verify::pthread/cond::pthread_cond_wait::hardened::wait_basic` | pthread/cond | pthread_cond_wait | hardened | wait_basic [hardened] | POSIX.1-2017 pthread_cond_wait | PASS |
| `fixture-verify::pthread/cond::pthread_cond_wait::hardened::wait_mutex_mismatch` | pthread/cond | pthread_cond_wait | hardened | wait_mutex_mismatch [hardened] | POSIX.1-2017 pthread_cond_wait | PASS |
| `fixture-verify::pthread/cond::pthread_cond_wait::hardened::wait_null_condvar` | pthread/cond | pthread_cond_wait | hardened | wait_null_condvar [hardened] | POSIX.1-2017 pthread_cond_wait | PASS |
| `fixture-verify::pthread/cond::pthread_cond_wait::hardened::wait_null_mutex` | pthread/cond | pthread_cond_wait | hardened | wait_null_mutex [hardened] | POSIX.1-2017 pthread_cond_wait | PASS |
| `fixture-verify::pthread/cond::pthread_cond_wait::hardened::wait_reacquires_mutex` | pthread/cond | pthread_cond_wait | hardened | wait_reacquires_mutex [hardened] | POSIX.1-2017 pthread_cond_wait | PASS |
| `fixture-verify::pthread/cond::pthread_cond_wait::strict::spurious_wakeup_predicate_loop` | pthread/cond | pthread_cond_wait | strict | spurious_wakeup_predicate_loop [strict] | POSIX.1-2017 pthread_cond_wait (spurious wakeup) | PASS |
| `fixture-verify::pthread/cond::pthread_cond_wait::strict::wait_basic` | pthread/cond | pthread_cond_wait | strict | wait_basic [strict] | POSIX.1-2017 pthread_cond_wait | PASS |
| `fixture-verify::pthread/cond::pthread_cond_wait::strict::wait_mutex_mismatch` | pthread/cond | pthread_cond_wait | strict | wait_mutex_mismatch [strict] | POSIX.1-2017 pthread_cond_wait | PASS |
| `fixture-verify::pthread/cond::pthread_cond_wait::strict::wait_null_condvar` | pthread/cond | pthread_cond_wait | strict | wait_null_condvar [strict] | POSIX.1-2017 pthread_cond_wait | PASS |
| `fixture-verify::pthread/cond::pthread_cond_wait::strict::wait_null_mutex` | pthread/cond | pthread_cond_wait | strict | wait_null_mutex [strict] | POSIX.1-2017 pthread_cond_wait | PASS |
| `fixture-verify::pthread/cond::pthread_cond_wait::strict::wait_reacquires_mutex` | pthread/cond | pthread_cond_wait | strict | wait_reacquires_mutex [strict] | POSIX.1-2017 pthread_cond_wait | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_clockjoin_np::hardened::clockjoin_detached` | pthread/gnu_extensions | pthread_clockjoin_np | hardened | clockjoin_detached [hardened] | glibc pthread_clockjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_clockjoin_np::hardened::clockjoin_monotonic_success` | pthread/gnu_extensions | pthread_clockjoin_np | hardened | clockjoin_monotonic_success [hardened] | glibc pthread_clockjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_clockjoin_np::hardened::clockjoin_null_abstime_blocks` | pthread/gnu_extensions | pthread_clockjoin_np | hardened | clockjoin_null_abstime_blocks [hardened] | glibc pthread_clockjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_clockjoin_np::hardened::clockjoin_realtime_success` | pthread/gnu_extensions | pthread_clockjoin_np | hardened | clockjoin_realtime_success [hardened] | glibc pthread_clockjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_clockjoin_np::hardened::clockjoin_self` | pthread/gnu_extensions | pthread_clockjoin_np | hardened | clockjoin_self [hardened] | glibc pthread_clockjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_clockjoin_np::hardened::clockjoin_timeout` | pthread/gnu_extensions | pthread_clockjoin_np | hardened | clockjoin_timeout [hardened] | glibc pthread_clockjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_clockjoin_np::strict::clockjoin_detached` | pthread/gnu_extensions | pthread_clockjoin_np | strict | clockjoin_detached [strict] | glibc pthread_clockjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_clockjoin_np::strict::clockjoin_monotonic_success` | pthread/gnu_extensions | pthread_clockjoin_np | strict | clockjoin_monotonic_success [strict] | glibc pthread_clockjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_clockjoin_np::strict::clockjoin_null_abstime_blocks` | pthread/gnu_extensions | pthread_clockjoin_np | strict | clockjoin_null_abstime_blocks [strict] | glibc pthread_clockjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_clockjoin_np::strict::clockjoin_realtime_success` | pthread/gnu_extensions | pthread_clockjoin_np | strict | clockjoin_realtime_success [strict] | glibc pthread_clockjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_clockjoin_np::strict::clockjoin_self` | pthread/gnu_extensions | pthread_clockjoin_np | strict | clockjoin_self [strict] | glibc pthread_clockjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_clockjoin_np::strict::clockjoin_timeout` | pthread/gnu_extensions | pthread_clockjoin_np | strict | clockjoin_timeout [strict] | glibc pthread_clockjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_cond_clockwait::hardened::clockwait_invalid_clock` | pthread/gnu_extensions | pthread_cond_clockwait | hardened | clockwait_invalid_clock [hardened] | glibc pthread_cond_clockwait | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_cond_clockwait::hardened::clockwait_invalid_nsec` | pthread/gnu_extensions | pthread_cond_clockwait | hardened | clockwait_invalid_nsec [hardened] | glibc pthread_cond_clockwait | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_cond_clockwait::hardened::clockwait_monotonic` | pthread/gnu_extensions | pthread_cond_clockwait | hardened | clockwait_monotonic [hardened] | glibc pthread_cond_clockwait | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_cond_clockwait::hardened::clockwait_null_abstime` | pthread/gnu_extensions | pthread_cond_clockwait | hardened | clockwait_null_abstime [hardened] | glibc pthread_cond_clockwait | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_cond_clockwait::hardened::clockwait_null_condvar` | pthread/gnu_extensions | pthread_cond_clockwait | hardened | clockwait_null_condvar [hardened] | glibc pthread_cond_clockwait | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_cond_clockwait::hardened::clockwait_null_mutex` | pthread/gnu_extensions | pthread_cond_clockwait | hardened | clockwait_null_mutex [hardened] | glibc pthread_cond_clockwait | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_cond_clockwait::hardened::clockwait_realtime` | pthread/gnu_extensions | pthread_cond_clockwait | hardened | clockwait_realtime [hardened] | glibc pthread_cond_clockwait | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_cond_clockwait::hardened::clockwait_timeout` | pthread/gnu_extensions | pthread_cond_clockwait | hardened | clockwait_timeout [hardened] | glibc pthread_cond_clockwait | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_cond_clockwait::strict::clockwait_invalid_clock` | pthread/gnu_extensions | pthread_cond_clockwait | strict | clockwait_invalid_clock [strict] | glibc pthread_cond_clockwait | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_cond_clockwait::strict::clockwait_invalid_nsec` | pthread/gnu_extensions | pthread_cond_clockwait | strict | clockwait_invalid_nsec [strict] | glibc pthread_cond_clockwait | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_cond_clockwait::strict::clockwait_monotonic` | pthread/gnu_extensions | pthread_cond_clockwait | strict | clockwait_monotonic [strict] | glibc pthread_cond_clockwait | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_cond_clockwait::strict::clockwait_null_abstime` | pthread/gnu_extensions | pthread_cond_clockwait | strict | clockwait_null_abstime [strict] | glibc pthread_cond_clockwait | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_cond_clockwait::strict::clockwait_null_condvar` | pthread/gnu_extensions | pthread_cond_clockwait | strict | clockwait_null_condvar [strict] | glibc pthread_cond_clockwait | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_cond_clockwait::strict::clockwait_null_mutex` | pthread/gnu_extensions | pthread_cond_clockwait | strict | clockwait_null_mutex [strict] | glibc pthread_cond_clockwait | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_cond_clockwait::strict::clockwait_realtime` | pthread/gnu_extensions | pthread_cond_clockwait | strict | clockwait_realtime [strict] | glibc pthread_cond_clockwait | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_cond_clockwait::strict::clockwait_timeout` | pthread/gnu_extensions | pthread_cond_clockwait | strict | clockwait_timeout [strict] | glibc pthread_cond_clockwait | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_getattr_np::hardened::getattr_np_detach_state` | pthread/gnu_extensions | pthread_getattr_np | hardened | getattr_np_detach_state [hardened] | glibc pthread_getattr_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_getattr_np::hardened::getattr_np_null_attr` | pthread/gnu_extensions | pthread_getattr_np | hardened | getattr_np_null_attr [hardened] | glibc pthread_getattr_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_getattr_np::hardened::getattr_np_other_thread` | pthread/gnu_extensions | pthread_getattr_np | hardened | getattr_np_other_thread [hardened] | glibc pthread_getattr_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_getattr_np::hardened::getattr_np_self` | pthread/gnu_extensions | pthread_getattr_np | hardened | getattr_np_self [hardened] | glibc pthread_getattr_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_getattr_np::hardened::getattr_np_stack_info` | pthread/gnu_extensions | pthread_getattr_np | hardened | getattr_np_stack_info [hardened] | glibc pthread_getattr_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_getattr_np::strict::getattr_np_detach_state` | pthread/gnu_extensions | pthread_getattr_np | strict | getattr_np_detach_state [strict] | glibc pthread_getattr_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_getattr_np::strict::getattr_np_null_attr` | pthread/gnu_extensions | pthread_getattr_np | strict | getattr_np_null_attr [strict] | glibc pthread_getattr_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_getattr_np::strict::getattr_np_other_thread` | pthread/gnu_extensions | pthread_getattr_np | strict | getattr_np_other_thread [strict] | glibc pthread_getattr_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_getattr_np::strict::getattr_np_self` | pthread/gnu_extensions | pthread_getattr_np | strict | getattr_np_self [strict] | glibc pthread_getattr_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_getattr_np::strict::getattr_np_stack_info` | pthread/gnu_extensions | pthread_getattr_np | strict | getattr_np_stack_info [strict] | glibc pthread_getattr_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_timedjoin_np::hardened::timedjoin_before_exit` | pthread/gnu_extensions | pthread_timedjoin_np | hardened | timedjoin_before_exit [hardened] | glibc pthread_timedjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_timedjoin_np::hardened::timedjoin_detached_thread` | pthread/gnu_extensions | pthread_timedjoin_np | hardened | timedjoin_detached_thread [hardened] | glibc pthread_timedjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_timedjoin_np::hardened::timedjoin_invalid_nsec` | pthread/gnu_extensions | pthread_timedjoin_np | hardened | timedjoin_invalid_nsec [hardened] | glibc pthread_timedjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_timedjoin_np::hardened::timedjoin_invalid_thread` | pthread/gnu_extensions | pthread_timedjoin_np | hardened | timedjoin_invalid_thread [hardened] | glibc pthread_timedjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_timedjoin_np::hardened::timedjoin_null_abstime_blocks` | pthread/gnu_extensions | pthread_timedjoin_np | hardened | timedjoin_null_abstime_blocks [hardened] | glibc pthread_timedjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_timedjoin_np::hardened::timedjoin_self` | pthread/gnu_extensions | pthread_timedjoin_np | hardened | timedjoin_self [hardened] | glibc pthread_timedjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_timedjoin_np::hardened::timedjoin_timeout` | pthread/gnu_extensions | pthread_timedjoin_np | hardened | timedjoin_timeout [hardened] | glibc pthread_timedjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_timedjoin_np::strict::timedjoin_before_exit` | pthread/gnu_extensions | pthread_timedjoin_np | strict | timedjoin_before_exit [strict] | glibc pthread_timedjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_timedjoin_np::strict::timedjoin_detached_thread` | pthread/gnu_extensions | pthread_timedjoin_np | strict | timedjoin_detached_thread [strict] | glibc pthread_timedjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_timedjoin_np::strict::timedjoin_invalid_nsec` | pthread/gnu_extensions | pthread_timedjoin_np | strict | timedjoin_invalid_nsec [strict] | glibc pthread_timedjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_timedjoin_np::strict::timedjoin_invalid_thread` | pthread/gnu_extensions | pthread_timedjoin_np | strict | timedjoin_invalid_thread [strict] | glibc pthread_timedjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_timedjoin_np::strict::timedjoin_null_abstime_blocks` | pthread/gnu_extensions | pthread_timedjoin_np | strict | timedjoin_null_abstime_blocks [strict] | glibc pthread_timedjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_timedjoin_np::strict::timedjoin_self` | pthread/gnu_extensions | pthread_timedjoin_np | strict | timedjoin_self [strict] | glibc pthread_timedjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_timedjoin_np::strict::timedjoin_timeout` | pthread/gnu_extensions | pthread_timedjoin_np | strict | timedjoin_timeout [strict] | glibc pthread_timedjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_tryjoin_np::hardened::tryjoin_detached` | pthread/gnu_extensions | pthread_tryjoin_np | hardened | tryjoin_detached [hardened] | glibc pthread_tryjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_tryjoin_np::hardened::tryjoin_finished` | pthread/gnu_extensions | pthread_tryjoin_np | hardened | tryjoin_finished [hardened] | glibc pthread_tryjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_tryjoin_np::hardened::tryjoin_invalid_thread` | pthread/gnu_extensions | pthread_tryjoin_np | hardened | tryjoin_invalid_thread [hardened] | glibc pthread_tryjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_tryjoin_np::hardened::tryjoin_running` | pthread/gnu_extensions | pthread_tryjoin_np | hardened | tryjoin_running [hardened] | glibc pthread_tryjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_tryjoin_np::hardened::tryjoin_self` | pthread/gnu_extensions | pthread_tryjoin_np | hardened | tryjoin_self [hardened] | glibc pthread_tryjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_tryjoin_np::strict::tryjoin_detached` | pthread/gnu_extensions | pthread_tryjoin_np | strict | tryjoin_detached [strict] | glibc pthread_tryjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_tryjoin_np::strict::tryjoin_finished` | pthread/gnu_extensions | pthread_tryjoin_np | strict | tryjoin_finished [strict] | glibc pthread_tryjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_tryjoin_np::strict::tryjoin_invalid_thread` | pthread/gnu_extensions | pthread_tryjoin_np | strict | tryjoin_invalid_thread [strict] | glibc pthread_tryjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_tryjoin_np::strict::tryjoin_running` | pthread/gnu_extensions | pthread_tryjoin_np | strict | tryjoin_running [strict] | glibc pthread_tryjoin_np | PASS |
| `fixture-verify::pthread/gnu_extensions::pthread_tryjoin_np::strict::tryjoin_self` | pthread/gnu_extensions | pthread_tryjoin_np | strict | tryjoin_self [strict] | glibc pthread_tryjoin_np | PASS |
| `fixture-verify::pthread/mutex::__pthread_mutex_trylock::hardened::alias_mutex_trylock_unlocked` | pthread/mutex | __pthread_mutex_trylock | hardened | alias_mutex_trylock_unlocked [hardened] | POSIX.1-2017 pthread_mutex_trylock | PASS |
| `fixture-verify::pthread/mutex::__pthread_mutex_trylock::strict::alias_mutex_trylock_unlocked` | pthread/mutex | __pthread_mutex_trylock | strict | alias_mutex_trylock_unlocked [strict] | POSIX.1-2017 pthread_mutex_trylock | PASS |
| `fixture-verify::pthread/mutex::__pthread_mutex_unlock::hardened::alias_mutex_unlock` | pthread/mutex | __pthread_mutex_unlock | hardened | alias_mutex_unlock [hardened] | POSIX.1-2017 pthread_mutex_unlock | PASS |
| `fixture-verify::pthread/mutex::__pthread_mutex_unlock::strict::alias_mutex_unlock` | pthread/mutex | __pthread_mutex_unlock | strict | alias_mutex_unlock [strict] | POSIX.1-2017 pthread_mutex_unlock | PASS |
| `fixture-verify::pthread/mutex::pthread_mutex_destroy::hardened::mutex_destroy` | pthread/mutex | pthread_mutex_destroy | hardened | mutex_destroy [hardened] | POSIX.1-2017 pthread_mutex_destroy | PASS |
| `fixture-verify::pthread/mutex::pthread_mutex_destroy::strict::mutex_destroy` | pthread/mutex | pthread_mutex_destroy | strict | mutex_destroy [strict] | POSIX.1-2017 pthread_mutex_destroy | PASS |
| `fixture-verify::pthread/mutex::pthread_mutex_init::hardened::mutex_init_default` | pthread/mutex | pthread_mutex_init | hardened | mutex_init_default [hardened] | POSIX.1-2017 pthread_mutex_init | PASS |
| `fixture-verify::pthread/mutex::pthread_mutex_init::hardened::mutex_init_null_attr_default_type` | pthread/mutex | pthread_mutex_init | hardened | mutex_init_null_attr_default_type [hardened] | POSIX.1-2017 pthread_mutex_init | PASS |
| `fixture-verify::pthread/mutex::pthread_mutex_init::strict::mutex_init_default` | pthread/mutex | pthread_mutex_init | strict | mutex_init_default [strict] | POSIX.1-2017 pthread_mutex_init | PASS |
| `fixture-verify::pthread/mutex::pthread_mutex_init::strict::mutex_init_null_attr_default_type` | pthread/mutex | pthread_mutex_init | strict | mutex_init_null_attr_default_type [strict] | POSIX.1-2017 pthread_mutex_init | PASS |
| `fixture-verify::pthread/mutex::pthread_mutex_lock::hardened::mutex_lock_unlock` | pthread/mutex | pthread_mutex_lock | hardened | mutex_lock_unlock [hardened] | POSIX.1-2017 pthread_mutex_lock | PASS |
| `fixture-verify::pthread/mutex::pthread_mutex_lock::strict::mutex_contention_two_threads` | pthread/mutex | pthread_mutex_lock | strict | mutex_contention_two_threads | POSIX.1-2017 pthread_mutex_lock | PASS |
| `fixture-verify::pthread/mutex::pthread_mutex_lock::strict::mutex_lock_unlock` | pthread/mutex | pthread_mutex_lock | strict | mutex_lock_unlock [strict] | POSIX.1-2017 pthread_mutex_lock | PASS |
| `fixture-verify::pthread/mutex::pthread_mutex_trylock::hardened::mutex_trylock_locked_ebusy` | pthread/mutex | pthread_mutex_trylock | hardened | mutex_trylock_locked_ebusy [hardened] | POSIX.1-2017 pthread_mutex_trylock | PASS |
| `fixture-verify::pthread/mutex::pthread_mutex_trylock::hardened::mutex_trylock_unlocked` | pthread/mutex | pthread_mutex_trylock | hardened | mutex_trylock_unlocked [hardened] | POSIX.1-2017 pthread_mutex_trylock | PASS |
| `fixture-verify::pthread/mutex::pthread_mutex_trylock::strict::mutex_trylock_locked_ebusy` | pthread/mutex | pthread_mutex_trylock | strict | mutex_trylock_locked_ebusy [strict] | POSIX.1-2017 pthread_mutex_trylock | PASS |
| `fixture-verify::pthread/mutex::pthread_mutex_trylock::strict::mutex_trylock_unlocked` | pthread/mutex | pthread_mutex_trylock | strict | mutex_trylock_unlocked [strict] | POSIX.1-2017 pthread_mutex_trylock | PASS |
| `fixture-verify::pthread/mutex::pthread_mutex_unlock::hardened::mutex_unlock` | pthread/mutex | pthread_mutex_unlock | hardened | mutex_unlock [hardened] | POSIX.1-2017 pthread_mutex_unlock | PASS |
| `fixture-verify::pthread/mutex::pthread_mutex_unlock::strict::mutex_unlock` | pthread/mutex | pthread_mutex_unlock | strict | mutex_unlock [strict] | POSIX.1-2017 pthread_mutex_unlock | PASS |
| `fixture-verify::pthread/thread::pthread_create::strict::pthread_create_basic` | pthread/thread | pthread_create | strict | pthread_create_basic | POSIX.1-2017 pthread_create | PASS |
| `fixture-verify::pthread/thread::pthread_create::strict::pthread_create_multiple_concurrent` | pthread/thread | pthread_create | strict | pthread_create_multiple_concurrent | POSIX.1-2017 pthread_create | PASS |
| `fixture-verify::pthread/thread::pthread_detach::hardened::pthread_detach_null_einval` | pthread/thread | pthread_detach | hardened | pthread_detach_null_einval [hardened] | POSIX.1-2017 pthread_detach | PASS |
| `fixture-verify::pthread/thread::pthread_detach::strict::pthread_detach_finished_immediate_cleanup` | pthread/thread | pthread_detach | strict | pthread_detach_finished_immediate_cleanup | POSIX.1-2017 pthread_detach | PASS |
| `fixture-verify::pthread/thread::pthread_detach::strict::pthread_detach_null_einval` | pthread/thread | pthread_detach | strict | pthread_detach_null_einval [strict] | POSIX.1-2017 pthread_detach | PASS |
| `fixture-verify::pthread/thread::pthread_detach::strict::pthread_detach_running` | pthread/thread | pthread_detach | strict | pthread_detach_running | POSIX.1-2017 pthread_detach | PASS |
| `fixture-verify::pthread/thread::pthread_equal::hardened::pthread_equal_different_threads` | pthread/thread | pthread_equal | hardened | pthread_equal_different_threads [hardened] | POSIX.1-2017 pthread_equal | PASS |
| `fixture-verify::pthread/thread::pthread_equal::hardened::pthread_equal_same_thread` | pthread/thread | pthread_equal | hardened | pthread_equal_same_thread [hardened] | POSIX.1-2017 pthread_equal | PASS |
| `fixture-verify::pthread/thread::pthread_equal::strict::pthread_equal_different_threads` | pthread/thread | pthread_equal | strict | pthread_equal_different_threads [strict] | POSIX.1-2017 pthread_equal | PASS |
| `fixture-verify::pthread/thread::pthread_equal::strict::pthread_equal_same_thread` | pthread/thread | pthread_equal | strict | pthread_equal_same_thread [strict] | POSIX.1-2017 pthread_equal | PASS |
| `fixture-verify::pthread/thread::pthread_join::hardened::pthread_join_null_thread_einval` | pthread/thread | pthread_join | hardened | pthread_join_null_thread_einval [hardened] | POSIX.1-2017 pthread_join | PASS |
| `fixture-verify::pthread/thread::pthread_join::hardened::pthread_join_self_edeadlk` | pthread/thread | pthread_join | hardened | pthread_join_self_edeadlk [hardened] | POSIX.1-2017 pthread_join | PASS |
| `fixture-verify::pthread/thread::pthread_join::strict::pthread_join_null_thread_einval` | pthread/thread | pthread_join | strict | pthread_join_null_thread_einval [strict] | POSIX.1-2017 pthread_join | PASS |
| `fixture-verify::pthread/thread::pthread_join::strict::pthread_join_returns_retval` | pthread/thread | pthread_join | strict | pthread_join_returns_retval | POSIX.1-2017 pthread_join | PASS |
| `fixture-verify::pthread/thread::pthread_join::strict::pthread_join_self_edeadlk` | pthread/thread | pthread_join | strict | pthread_join_self_edeadlk [strict] | POSIX.1-2017 pthread_join | PASS |
| `fixture-verify::pthread/thread::pthread_self::hardened::pthread_self_returns_positive` | pthread/thread | pthread_self | hardened | pthread_self_returns_positive [hardened] | POSIX.1-2017 pthread_self | PASS |
| `fixture-verify::pthread/thread::pthread_self::strict::pthread_self_returns_positive` | pthread/thread | pthread_self | strict | pthread_self_returns_positive [strict] | POSIX.1-2017 pthread_self | PASS |
| `fixture-verify::pthread/tls_keys::pthread_getspecific::hardened::getspecific_default_zero` | pthread/tls_keys | pthread_getspecific | hardened | getspecific_default_zero [hardened] | POSIX.1-2017 pthread_getspecific | PASS |
| `fixture-verify::pthread/tls_keys::pthread_getspecific::hardened::getspecific_invalid_key` | pthread/tls_keys | pthread_getspecific | hardened | getspecific_invalid_key [hardened] | POSIX.1-2017 pthread_getspecific | PASS |
| `fixture-verify::pthread/tls_keys::pthread_getspecific::strict::getspecific_default_zero` | pthread/tls_keys | pthread_getspecific | strict | getspecific_default_zero [strict] | POSIX.1-2017 pthread_getspecific | PASS |
| `fixture-verify::pthread/tls_keys::pthread_getspecific::strict::getspecific_invalid_key` | pthread/tls_keys | pthread_getspecific | strict | getspecific_invalid_key [strict] | POSIX.1-2017 pthread_getspecific | PASS |
| `fixture-verify::pthread/tls_keys::pthread_key_create::hardened::key_create_exhaustion` | pthread/tls_keys | pthread_key_create | hardened | key_create_exhaustion [hardened] | POSIX.1-2017 pthread_key_create | PASS |
| `fixture-verify::pthread/tls_keys::pthread_key_create::hardened::key_create_success` | pthread/tls_keys | pthread_key_create | hardened | key_create_success [hardened] | POSIX.1-2017 pthread_key_create | PASS |
| `fixture-verify::pthread/tls_keys::pthread_key_create::hardened::key_create_with_destructor` | pthread/tls_keys | pthread_key_create | hardened | key_create_with_destructor [hardened] | POSIX.1-2017 pthread_key_create | PASS |
| `fixture-verify::pthread/tls_keys::pthread_key_create::strict::key_create_exhaustion` | pthread/tls_keys | pthread_key_create | strict | key_create_exhaustion [strict] | POSIX.1-2017 pthread_key_create | PASS |
| `fixture-verify::pthread/tls_keys::pthread_key_create::strict::key_create_success` | pthread/tls_keys | pthread_key_create | strict | key_create_success [strict] | POSIX.1-2017 pthread_key_create | PASS |
| `fixture-verify::pthread/tls_keys::pthread_key_create::strict::key_create_with_destructor` | pthread/tls_keys | pthread_key_create | strict | key_create_with_destructor [strict] | POSIX.1-2017 pthread_key_create | PASS |
| `fixture-verify::pthread/tls_keys::pthread_key_delete::hardened::key_delete_already_deleted` | pthread/tls_keys | pthread_key_delete | hardened | key_delete_already_deleted [hardened] | POSIX.1-2017 pthread_key_delete | PASS |
| `fixture-verify::pthread/tls_keys::pthread_key_delete::hardened::key_delete_does_not_call_destructors` | pthread/tls_keys | pthread_key_delete | hardened | key_delete_does_not_call_destructors [hardened] | POSIX.1-2017 pthread_key_delete | PASS |
| `fixture-verify::pthread/tls_keys::pthread_key_delete::hardened::key_delete_invalid_key` | pthread/tls_keys | pthread_key_delete | hardened | key_delete_invalid_key [hardened] | POSIX.1-2017 pthread_key_delete | PASS |
| `fixture-verify::pthread/tls_keys::pthread_key_delete::hardened::key_delete_valid` | pthread/tls_keys | pthread_key_delete | hardened | key_delete_valid [hardened] | POSIX.1-2017 pthread_key_delete | PASS |
| `fixture-verify::pthread/tls_keys::pthread_key_delete::strict::key_delete_already_deleted` | pthread/tls_keys | pthread_key_delete | strict | key_delete_already_deleted [strict] | POSIX.1-2017 pthread_key_delete | PASS |
| `fixture-verify::pthread/tls_keys::pthread_key_delete::strict::key_delete_does_not_call_destructors` | pthread/tls_keys | pthread_key_delete | strict | key_delete_does_not_call_destructors [strict] | POSIX.1-2017 pthread_key_delete | PASS |
| `fixture-verify::pthread/tls_keys::pthread_key_delete::strict::key_delete_invalid_key` | pthread/tls_keys | pthread_key_delete | strict | key_delete_invalid_key [strict] | POSIX.1-2017 pthread_key_delete | PASS |
| `fixture-verify::pthread/tls_keys::pthread_key_delete::strict::key_delete_valid` | pthread/tls_keys | pthread_key_delete | strict | key_delete_valid [strict] | POSIX.1-2017 pthread_key_delete | PASS |
| `fixture-verify::pthread/tls_keys::pthread_setspecific::hardened::setspecific_deleted_key` | pthread/tls_keys | pthread_setspecific | hardened | setspecific_deleted_key [hardened] | POSIX.1-2017 pthread_setspecific | PASS |
| `fixture-verify::pthread/tls_keys::pthread_setspecific::hardened::setspecific_out_of_bounds_key` | pthread/tls_keys | pthread_setspecific | hardened | setspecific_out_of_bounds_key [hardened] | POSIX.1-2017 pthread_setspecific | PASS |
| `fixture-verify::pthread/tls_keys::pthread_setspecific::hardened::setspecific_roundtrip` | pthread/tls_keys | pthread_setspecific | hardened | setspecific_roundtrip [hardened] | POSIX.1-2017 pthread_setspecific | PASS |
| `fixture-verify::pthread/tls_keys::pthread_setspecific::strict::setspecific_deleted_key` | pthread/tls_keys | pthread_setspecific | strict | setspecific_deleted_key [strict] | POSIX.1-2017 pthread_setspecific | PASS |
| `fixture-verify::pthread/tls_keys::pthread_setspecific::strict::setspecific_out_of_bounds_key` | pthread/tls_keys | pthread_setspecific | strict | setspecific_out_of_bounds_key [strict] | POSIX.1-2017 pthread_setspecific | PASS |
| `fixture-verify::pthread/tls_keys::pthread_setspecific::strict::setspecific_roundtrip` | pthread/tls_keys | pthread_setspecific | strict | setspecific_roundtrip [strict] | POSIX.1-2017 pthread_setspecific | PASS |
| `fixture-verify::pthread/tls_keys::teardown_thread_tls::hardened::destructor_bounded_iterations` | pthread/tls_keys | teardown_thread_tls | hardened | destructor_bounded_iterations [hardened] | POSIX.1-2017 pthread_key_create (destructor semantics) | PASS |
| `fixture-verify::pthread/tls_keys::teardown_thread_tls::hardened::destructor_fires_on_thread_exit` | pthread/tls_keys | teardown_thread_tls | hardened | destructor_fires_on_thread_exit [hardened] | POSIX.1-2017 pthread_key_create (destructor semantics) | PASS |
| `fixture-verify::pthread/tls_keys::teardown_thread_tls::hardened::destructor_iterates_on_reset` | pthread/tls_keys | teardown_thread_tls | hardened | destructor_iterates_on_reset [hardened] | POSIX.1-2017 pthread_key_create (destructor semantics) | PASS |
| `fixture-verify::pthread/tls_keys::teardown_thread_tls::hardened::destructor_not_called_for_null_value` | pthread/tls_keys | teardown_thread_tls | hardened | destructor_not_called_for_null_value [hardened] | POSIX.1-2017 pthread_key_create (destructor semantics) | PASS |
| `fixture-verify::pthread/tls_keys::teardown_thread_tls::strict::destructor_bounded_iterations` | pthread/tls_keys | teardown_thread_tls | strict | destructor_bounded_iterations [strict] | POSIX.1-2017 pthread_key_create (destructor semantics) | PASS |
| `fixture-verify::pthread/tls_keys::teardown_thread_tls::strict::destructor_fires_on_thread_exit` | pthread/tls_keys | teardown_thread_tls | strict | destructor_fires_on_thread_exit [strict] | POSIX.1-2017 pthread_key_create (destructor semantics) | PASS |
| `fixture-verify::pthread/tls_keys::teardown_thread_tls::strict::destructor_iterates_on_reset` | pthread/tls_keys | teardown_thread_tls | strict | destructor_iterates_on_reset [strict] | POSIX.1-2017 pthread_key_create (destructor semantics) | PASS |
| `fixture-verify::pthread/tls_keys::teardown_thread_tls::strict::destructor_not_called_for_null_value` | pthread/tls_keys | teardown_thread_tls | strict | destructor_not_called_for_null_value [strict] | POSIX.1-2017 pthread_key_create (destructor semantics) | PASS |
| `fixture-verify::pwd_ops::endpwent::hardened::endpwent_void_hardened` | pwd_ops | endpwent | hardened | endpwent_void_hardened | POSIX endpwent | PASS |
| `fixture-verify::pwd_ops::endpwent::strict::endpwent_void_strict` | pwd_ops | endpwent | strict | endpwent_void_strict | POSIX endpwent | PASS |
| `fixture-verify::pwd_ops::getpwnam::hardened::getpwnam_nonexistent_hardened` | pwd_ops | getpwnam | hardened | getpwnam_nonexistent_hardened | POSIX getpwnam | PASS |
| `fixture-verify::pwd_ops::getpwnam::hardened::getpwnam_root_hardened` | pwd_ops | getpwnam | hardened | getpwnam_root_hardened | POSIX getpwnam | PASS |
| `fixture-verify::pwd_ops::getpwnam::strict::getpwnam_nonexistent_strict` | pwd_ops | getpwnam | strict | getpwnam_nonexistent_strict | POSIX getpwnam | PASS |
| `fixture-verify::pwd_ops::getpwnam::strict::getpwnam_root_strict` | pwd_ops | getpwnam | strict | getpwnam_root_strict | POSIX getpwnam | PASS |
| `fixture-verify::pwd_ops::getpwuid::hardened::getpwuid_nonexistent_hardened` | pwd_ops | getpwuid | hardened | getpwuid_nonexistent_hardened | POSIX getpwuid | PASS |
| `fixture-verify::pwd_ops::getpwuid::hardened::getpwuid_zero_hardened` | pwd_ops | getpwuid | hardened | getpwuid_zero_hardened | POSIX getpwuid | PASS |
| `fixture-verify::pwd_ops::getpwuid::strict::getpwuid_nonexistent_strict` | pwd_ops | getpwuid | strict | getpwuid_nonexistent_strict | POSIX getpwuid | PASS |
| `fixture-verify::pwd_ops::getpwuid::strict::getpwuid_zero_strict` | pwd_ops | getpwuid | strict | getpwuid_zero_strict | POSIX getpwuid | PASS |
| `fixture-verify::pwd_ops::setpwent::hardened::setpwent_endpwent_hardened` | pwd_ops | setpwent | hardened | setpwent_endpwent_hardened | POSIX setpwent/endpwent | PASS |
| `fixture-verify::pwd_ops::setpwent::strict::setpwent_endpwent_strict` | pwd_ops | setpwent | strict | setpwent_endpwent_strict | POSIX setpwent/endpwent | PASS |
| `fixture-verify::regex_glob_ops::fnmatch::strict::fnmatch_no_match_strict` | regex_glob_ops | fnmatch | strict | fnmatch_no_match_strict | POSIX fnmatch(3) | PASS |
| `fixture-verify::regex_glob_ops::fnmatch::strict::fnmatch_wildcard_strict` | regex_glob_ops | fnmatch | strict | fnmatch_wildcard_strict | POSIX fnmatch(3) | PASS |
| `fixture-verify::regex_glob_ops::glob::hardened::glob_star_hardened` | regex_glob_ops | glob | hardened | glob_star_hardened | POSIX glob(3) | PASS |
| `fixture-verify::regex_glob_ops::glob::strict::glob_star_strict` | regex_glob_ops | glob | strict | glob_star_strict | POSIX glob(3) | PASS |
| `fixture-verify::regex_glob_ops::regcomp::hardened::regcomp_basic_hardened` | regex_glob_ops | regcomp | hardened | regcomp_basic_hardened | POSIX regcomp(3) | PASS |
| `fixture-verify::regex_glob_ops::regcomp::strict::regcomp_basic_strict` | regex_glob_ops | regcomp | strict | regcomp_basic_strict | POSIX regcomp(3) | PASS |
| `fixture-verify::regex_glob_ops::regexec::strict::regexec_match_strict` | regex_glob_ops | regexec | strict | regexec_match_strict | POSIX regexec(3) | PASS |
| `fixture-verify::regex_glob_ops::regexec::strict::regexec_nomatch_strict` | regex_glob_ops | regexec | strict | regexec_nomatch_strict | POSIX regexec(3) | PASS |
| `fixture-verify::regex_glob_ops::wordexp::hardened::wordexp_nocmd_single_quoted_literal_both` | regex_glob_ops | wordexp | hardened | wordexp_nocmd_single_quoted_literal_both [hardened] | POSIX wordexp(3) | PASS |
| `fixture-verify::regex_glob_ops::wordexp::hardened::wordexp_quoted_semicolon_both` | regex_glob_ops | wordexp | hardened | wordexp_quoted_semicolon_both [hardened] | POSIX wordexp(3) | PASS |
| `fixture-verify::regex_glob_ops::wordexp::hardened::wordexp_undef_double_quoted_variable_both` | regex_glob_ops | wordexp | hardened | wordexp_undef_double_quoted_variable_both [hardened] | POSIX wordexp(3) | PASS |
| `fixture-verify::regex_glob_ops::wordexp::strict::wordexp_nocmd_single_quoted_literal_both` | regex_glob_ops | wordexp | strict | wordexp_nocmd_single_quoted_literal_both [strict] | POSIX wordexp(3) | PASS |
| `fixture-verify::regex_glob_ops::wordexp::strict::wordexp_quoted_semicolon_both` | regex_glob_ops | wordexp | strict | wordexp_quoted_semicolon_both [strict] | POSIX wordexp(3) | PASS |
| `fixture-verify::regex_glob_ops::wordexp::strict::wordexp_undef_double_quoted_variable_both` | regex_glob_ops | wordexp | strict | wordexp_undef_double_quoted_variable_both [strict] | POSIX wordexp(3) | PASS |
| `fixture-verify::resolv/dns::DnsHeader::new_query::strict::dns_header_query` | resolv/dns | DnsHeader::new_query | strict | dns_header_query | RFC 1035 Section 4.1.1 | PASS |
| `fixture-verify::resolv/dns::ResolverConfig::default::strict::resolv_conf_default` | resolv/dns | ResolverConfig::default | strict | resolv_conf_default | resolver(5) | PASS |
| `fixture-verify::resolv/dns::ResolverConfig::parse::strict::resolv_conf_max_nameservers` | resolv/dns | ResolverConfig::parse | strict | resolv_conf_max_nameservers | resolver(5) | PASS |
| `fixture-verify::resolv/dns::ResolverConfig::parse::strict::resolv_conf_options_attempts` | resolv/dns | ResolverConfig::parse | strict | resolv_conf_options_attempts | resolver(5) | PASS |
| `fixture-verify::resolv/dns::ResolverConfig::parse::strict::resolv_conf_options_ndots` | resolv/dns | ResolverConfig::parse | strict | resolv_conf_options_ndots | resolver(5) | PASS |
| `fixture-verify::resolv/dns::ResolverConfig::parse::strict::resolv_conf_options_timeout` | resolv/dns | ResolverConfig::parse | strict | resolv_conf_options_timeout | resolver(5) | PASS |
| `fixture-verify::resolv/dns::ResolverConfig::parse::strict::resolv_conf_search_list` | resolv/dns | ResolverConfig::parse | strict | resolv_conf_search_list | resolver(5) | PASS |
| `fixture-verify::resolv/dns::ResolverConfig::parse::strict::resolv_conf_single_nameserver` | resolv/dns | ResolverConfig::parse | strict | resolv_conf_single_nameserver | resolver(5) | PASS |
| `fixture-verify::resolv/dns::encode_domain_name::strict::dns_encode_domain_name` | resolv/dns | encode_domain_name | strict | dns_encode_domain_name | RFC 1035 Section 3.1 | PASS |
| `fixture-verify::resolv/dns::encode_domain_name::strict::dns_encode_single_label` | resolv/dns | encode_domain_name | strict | dns_encode_single_label | RFC 1035 Section 3.1 | PASS |
| `fixture-verify::resolv/dns::freeaddrinfo::hardened::freeaddrinfo_numeric_ipv4_hardened` | resolv/dns | freeaddrinfo | hardened | freeaddrinfo_numeric_ipv4_hardened | POSIX freeaddrinfo | PASS |
| `fixture-verify::resolv/dns::freeaddrinfo::strict::freeaddrinfo_numeric_ipv4_strict` | resolv/dns | freeaddrinfo | strict | freeaddrinfo_numeric_ipv4_strict | POSIX freeaddrinfo | PASS |
| `fixture-verify::resolv/dns::getaddrinfo::hardened::getaddrinfo_hosts_file_subset_hardened` | resolv/dns | getaddrinfo | hardened | getaddrinfo_hosts_file_subset_hardened | /etc/hosts files backend subset | PASS |
| `fixture-verify::resolv/dns::getaddrinfo::strict::getaddrinfo_hosts_file_subset` | resolv/dns | getaddrinfo | strict | getaddrinfo_hosts_file_subset | /etc/hosts files backend subset | PASS |
| `fixture-verify::resolv/dns::getaddrinfo::strict::getaddrinfo_numeric_ipv4` | resolv/dns | getaddrinfo | strict | getaddrinfo_numeric_ipv4 | POSIX getaddrinfo | PASS |
| `fixture-verify::resolv/dns::getaddrinfo::strict::getaddrinfo_numeric_ipv6` | resolv/dns | getaddrinfo | strict | getaddrinfo_numeric_ipv6 | POSIX getaddrinfo | PASS |
| `fixture-verify::resolv/dns::getaddrinfo::strict::getaddrinfo_unknown_host` | resolv/dns | getaddrinfo | strict | getaddrinfo_unknown_host | POSIX getaddrinfo | PASS |
| `fixture-verify::resolv/dns::gethostbyname::hardened::gethostbyname_numeric_ipv4_hardened` | resolv/dns | gethostbyname | hardened | gethostbyname_numeric_ipv4_hardened | POSIX gethostbyname | PASS |
| `fixture-verify::resolv/dns::gethostbyname::strict::gethostbyname_numeric_ipv4` | resolv/dns | gethostbyname | strict | gethostbyname_numeric_ipv4 | POSIX gethostbyname | PASS |
| `fixture-verify::resolv/dns::lookup_hosts::hardened::hosts_lookup_basic_hardened` | resolv/dns | lookup_hosts | hardened | hosts_lookup_basic_hardened | /etc/hosts format | PASS |
| `fixture-verify::resolv/dns::lookup_hosts::hardened::hosts_lookup_case_insensitive_hardened` | resolv/dns | lookup_hosts | hardened | hosts_lookup_case_insensitive_hardened | /etc/hosts format | PASS |
| `fixture-verify::resolv/dns::lookup_hosts::hardened::hosts_lookup_inline_comments_and_aliases_hardened` | resolv/dns | lookup_hosts | hardened | hosts_lookup_inline_comments_and_aliases_hardened | /etc/hosts format | PASS |
| `fixture-verify::resolv/dns::lookup_hosts::strict::hosts_lookup_basic` | resolv/dns | lookup_hosts | strict | hosts_lookup_basic | /etc/hosts format | PASS |
| `fixture-verify::resolv/dns::lookup_hosts::strict::hosts_lookup_case_insensitive` | resolv/dns | lookup_hosts | strict | hosts_lookup_case_insensitive | /etc/hosts format | PASS |
| `fixture-verify::resolv/dns::lookup_hosts::strict::hosts_lookup_inline_comments_and_aliases` | resolv/dns | lookup_hosts | strict | hosts_lookup_inline_comments_and_aliases | /etc/hosts format | PASS |
| `fixture-verify::resource_ops::getrlimit::hardened::getrlimit_cpu_hardened` | resource_ops | getrlimit | hardened | getrlimit_cpu_hardened | POSIX getrlimit | PASS |
| `fixture-verify::resource_ops::getrlimit::hardened::getrlimit_invalid_hardened` | resource_ops | getrlimit | hardened | getrlimit_invalid_hardened | POSIX getrlimit | PASS |
| `fixture-verify::resource_ops::getrlimit::hardened::getrlimit_nofile_hardened` | resource_ops | getrlimit | hardened | getrlimit_nofile_hardened | POSIX getrlimit | PASS |
| `fixture-verify::resource_ops::getrlimit::strict::getrlimit_as_strict` | resource_ops | getrlimit | strict | getrlimit_as_strict | POSIX getrlimit | PASS |
| `fixture-verify::resource_ops::getrlimit::strict::getrlimit_core_strict` | resource_ops | getrlimit | strict | getrlimit_core_strict | POSIX getrlimit | PASS |
| `fixture-verify::resource_ops::getrlimit::strict::getrlimit_cpu_strict` | resource_ops | getrlimit | strict | getrlimit_cpu_strict | POSIX getrlimit | PASS |
| `fixture-verify::resource_ops::getrlimit::strict::getrlimit_data_strict` | resource_ops | getrlimit | strict | getrlimit_data_strict | POSIX getrlimit | PASS |
| `fixture-verify::resource_ops::getrlimit::strict::getrlimit_fsize_strict` | resource_ops | getrlimit | strict | getrlimit_fsize_strict | POSIX getrlimit | PASS |
| `fixture-verify::resource_ops::getrlimit::strict::getrlimit_invalid_strict` | resource_ops | getrlimit | strict | getrlimit_invalid_strict | POSIX getrlimit | PASS |
| `fixture-verify::resource_ops::getrlimit::strict::getrlimit_nofile_strict` | resource_ops | getrlimit | strict | getrlimit_nofile_strict | POSIX getrlimit | PASS |
| `fixture-verify::resource_ops::getrlimit::strict::getrlimit_stack_strict` | resource_ops | getrlimit | strict | getrlimit_stack_strict | POSIX getrlimit | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_A_hex_upper` | scanf_conformance | sscanf | strict | sscanf_A_hex_upper | C11 7.21.6.2 %A uppercase hex float | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_Lf_basic` | scanf_conformance | sscanf | strict | sscanf_Lf_basic | C11 7.21.6.2 %Lf long double | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_X_basic` | scanf_conformance | sscanf | strict | sscanf_X_basic | C11 7.21.6.2 %X specifier | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_a_basic` | scanf_conformance | sscanf | strict | sscanf_a_basic | C11 7.21.6.2 %a specifier | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_a_hex_basic` | scanf_conformance | sscanf | strict | sscanf_a_hex_basic | C11 7.21.6.2 %a hex float | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_a_hex_frac_only` | scanf_conformance | sscanf | strict | sscanf_a_hex_frac_only | C11 7.21.6.2 %a fraction only | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_a_hex_large` | scanf_conformance | sscanf | strict | sscanf_a_hex_large | C11 7.21.6.2 %a large hex float | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_a_hex_neg_exp` | scanf_conformance | sscanf | strict | sscanf_a_hex_neg_exp | C11 7.21.6.2 %a negative exponent | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_a_hex_negative` | scanf_conformance | sscanf | strict | sscanf_a_hex_negative | C11 7.21.6.2 %a negative hex float | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_a_hex_zero` | scanf_conformance | sscanf | strict | sscanf_a_hex_zero | C11 7.21.6.2 %a zero | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_c_basic` | scanf_conformance | sscanf | strict | sscanf_c_basic | C11 7.21.6.2 %c specifier | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_c_no_skip_ws` | scanf_conformance | sscanf | strict | sscanf_c_no_skip_ws | C11 7.21.6.2 %c no whitespace skip | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_c_width` | scanf_conformance | sscanf | strict | sscanf_c_width | C11 7.21.6.2 %c with width | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_complex_format` | scanf_conformance | sscanf | strict | sscanf_complex_format | C11 7.21.6.2 complex format | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_d_basic` | scanf_conformance | sscanf | strict | sscanf_d_basic | C11 7.21.6.2 %d specifier | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_d_leading_ws` | scanf_conformance | sscanf | strict | sscanf_d_leading_ws | C11 7.21.6.2 %d leading whitespace | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_d_negative` | scanf_conformance | sscanf | strict | sscanf_d_negative | C11 7.21.6.2 %d negative | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_d_overflow` | scanf_conformance | sscanf | strict | sscanf_d_overflow | C11 7.21.6.2 %d overflow | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_d_plus_sign` | scanf_conformance | sscanf | strict | sscanf_d_plus_sign | C11 7.21.6.2 %d plus sign | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_d_trailing_text` | scanf_conformance | sscanf | strict | sscanf_d_trailing_text | C11 7.21.6.2 %d stops at non-digit | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_d_underflow` | scanf_conformance | sscanf | strict | sscanf_d_underflow | C11 7.21.6.2 %d underflow | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_d_width` | scanf_conformance | sscanf | strict | sscanf_d_width | C11 7.21.6.2 %d with width | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_e_basic` | scanf_conformance | sscanf | strict | sscanf_e_basic | C11 7.21.6.2 %e specifier | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_eof_empty` | scanf_conformance | sscanf | strict | sscanf_eof_empty | C11 7.21.6.2 EOF on empty | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_eof_ws_only` | scanf_conformance | sscanf | strict | sscanf_eof_ws_only | C11 7.21.6.2 EOF whitespace only | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_f_E_exponent` | scanf_conformance | sscanf | strict | sscanf_f_E_exponent | C11 7.21.6.2 %f E exponent | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_f_basic` | scanf_conformance | sscanf | strict | sscanf_f_basic | C11 7.21.6.2 %f specifier | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_f_exponent` | scanf_conformance | sscanf | strict | sscanf_f_exponent | C11 7.21.6.2 %f exponent | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_f_hex` | scanf_conformance | sscanf | strict | sscanf_f_hex | C11 7.21.6.2 %f hex float | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_f_inf` | scanf_conformance | sscanf | strict | sscanf_f_inf | C11 7.21.6.2 %f infinity | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_f_infinity_full` | scanf_conformance | sscanf | strict | sscanf_f_infinity_full | C11 7.21.6.2 %f INFINITY | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_f_leading_dot` | scanf_conformance | sscanf | strict | sscanf_f_leading_dot | C11 7.21.6.2 %f leading dot | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_f_nan` | scanf_conformance | sscanf | strict | sscanf_f_nan | C11 7.21.6.2 %f NaN | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_f_neg_exponent` | scanf_conformance | sscanf | strict | sscanf_f_neg_exponent | C11 7.21.6.2 %f negative exponent | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_f_neg_inf` | scanf_conformance | sscanf | strict | sscanf_f_neg_inf | C11 7.21.6.2 %f -infinity | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_f_neg_zero` | scanf_conformance | sscanf | strict | sscanf_f_neg_zero | C11 7.21.6.2 %f negative zero | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_f_negative` | scanf_conformance | sscanf | strict | sscanf_f_negative | C11 7.21.6.2 %f negative | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_f_no_decimal` | scanf_conformance | sscanf | strict | sscanf_f_no_decimal | C11 7.21.6.2 %f no decimal | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_f_positive_exp` | scanf_conformance | sscanf | strict | sscanf_f_positive_exp | C11 7.21.6.2 %f +exponent | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_f_small` | scanf_conformance | sscanf | strict | sscanf_f_small | C11 7.21.6.2 %f small value | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_f_width` | scanf_conformance | sscanf | strict | sscanf_f_width | C11 7.21.6.2 %f with width | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_f_zero` | scanf_conformance | sscanf | strict | sscanf_f_zero | C11 7.21.6.2 %f zero | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_g_basic` | scanf_conformance | sscanf | strict | sscanf_g_basic | C11 7.21.6.2 %g specifier | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_h_d` | scanf_conformance | sscanf | strict | sscanf_h_d | C11 7.21.6.2 %hd length | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_hd_overflow` | scanf_conformance | sscanf | strict | sscanf_hd_overflow | C11 7.21.6.2 %hd overflow | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_hd_underflow` | scanf_conformance | sscanf | strict | sscanf_hd_underflow | C11 7.21.6.2 %hd underflow | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_hh_d` | scanf_conformance | sscanf | strict | sscanf_hh_d | C11 7.21.6.2 %hhd length | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_hhd_overflow` | scanf_conformance | sscanf | strict | sscanf_hhd_overflow | C11 7.21.6.2 %hhd overflow | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_hhd_underflow` | scanf_conformance | sscanf | strict | sscanf_hhd_underflow | C11 7.21.6.2 %hhd underflow | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_hu_overflow` | scanf_conformance | sscanf | strict | sscanf_hu_overflow | C11 7.21.6.2 %hu overflow wraps | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_i_HEX` | scanf_conformance | sscanf | strict | sscanf_i_HEX | C11 7.21.6.2 %i HEX | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_i_auto_decimal` | scanf_conformance | sscanf | strict | sscanf_i_auto_decimal | C11 7.21.6.2 %i auto decimal | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_i_auto_hex` | scanf_conformance | sscanf | strict | sscanf_i_auto_hex | C11 7.21.6.2 %i auto hex | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_i_auto_octal` | scanf_conformance | sscanf | strict | sscanf_i_auto_octal | C11 7.21.6.2 %i auto octal | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_i_decimal` | scanf_conformance | sscanf | strict | sscanf_i_decimal | C11 7.21.6.2 %i decimal | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_i_hex` | scanf_conformance | sscanf | strict | sscanf_i_hex | C11 7.21.6.2 %i hex | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_i_negative` | scanf_conformance | sscanf | strict | sscanf_i_negative | C11 7.21.6.2 %i negative | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_i_octal` | scanf_conformance | sscanf | strict | sscanf_i_octal | C11 7.21.6.2 %i octal | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_i_overflow` | scanf_conformance | sscanf | strict | sscanf_i_overflow | C11 7.21.6.2 %i overflow wraps | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_j_d` | scanf_conformance | sscanf | strict | sscanf_j_d | C11 7.21.6.2 %jd intmax_t | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_l_d` | scanf_conformance | sscanf | strict | sscanf_l_d | C11 7.21.6.2 %ld length | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_lf_basic` | scanf_conformance | sscanf | strict | sscanf_lf_basic | C11 7.21.6.2 %lf specifier | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_literal_match` | scanf_conformance | sscanf | strict | sscanf_literal_match | C11 7.21.6.2 literal chars | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_literal_mismatch` | scanf_conformance | sscanf | strict | sscanf_literal_mismatch | C11 7.21.6.2 literal mismatch | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_literal_percent` | scanf_conformance | sscanf | strict | sscanf_literal_percent | C11 7.21.6.2 %% literal | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_ll_d` | scanf_conformance | sscanf | strict | sscanf_ll_d | C11 7.21.6.2 %lld length | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_lld_no_wrap` | scanf_conformance | sscanf | strict | sscanf_lld_no_wrap | C11 7.21.6.2 %lld no wrap | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_llu_max` | scanf_conformance | sscanf | strict | sscanf_llu_max | C11 7.21.6.2 %llu ULLONG_MAX | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_llx_large` | scanf_conformance | sscanf | strict | sscanf_llx_large | C11 7.21.6.2 %llx large | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_multi_ws_format` | scanf_conformance | sscanf | strict | sscanf_multi_ws_format | C11 7.21.6.2 multiple format ws | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_multiple` | scanf_conformance | sscanf | strict | sscanf_multiple | C11 7.21.6.2 multiple conversions | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_n_after_ws` | scanf_conformance | sscanf | strict | sscanf_n_after_ws | C11 7.21.6.2 %n counts consumed | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_n_basic` | scanf_conformance | sscanf | strict | sscanf_n_basic | C11 7.21.6.2 %n specifier | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_no_match` | scanf_conformance | sscanf | strict | sscanf_no_match | C11 7.21.6.2 no conversion | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_o_basic` | scanf_conformance | sscanf | strict | sscanf_o_basic | C11 7.21.6.2 %o specifier | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_o_large` | scanf_conformance | sscanf | strict | sscanf_o_large | C11 7.21.6.2 %o large | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_o_leading_zero` | scanf_conformance | sscanf | strict | sscanf_o_leading_zero | C11 7.21.6.2 %o leading zero | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_p_basic` | scanf_conformance | sscanf | strict | sscanf_p_basic | C11 7.21.6.2 %p specifier | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_partial_conversion` | scanf_conformance | sscanf | strict | sscanf_partial_conversion | C11 7.21.6.2 partial match | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_s_basic` | scanf_conformance | sscanf | strict | sscanf_s_basic | C11 7.21.6.2 %s specifier | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_s_leading_ws` | scanf_conformance | sscanf | strict | sscanf_s_leading_ws | C11 7.21.6.2 %s skips whitespace | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_s_stops_ws` | scanf_conformance | sscanf | strict | sscanf_s_stops_ws | C11 7.21.6.2 %s stops at whitespace | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_s_width` | scanf_conformance | sscanf | strict | sscanf_s_width | C11 7.21.6.2 %s with width | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_scanset_alpha` | scanf_conformance | sscanf | strict | sscanf_scanset_alpha | C11 7.21.6.2 %[] alpha only | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_scanset_basic` | scanf_conformance | sscanf | strict | sscanf_scanset_basic | C11 7.21.6.2 %[] scanset | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_scanset_bracket` | scanf_conformance | sscanf | strict | sscanf_scanset_bracket | C11 7.21.6.2 %[] with ] | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_scanset_caret_first` | scanf_conformance | sscanf | strict | sscanf_scanset_caret_first | C11 7.21.6.2 %[^] at start | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_scanset_digits` | scanf_conformance | sscanf | strict | sscanf_scanset_digits | C11 7.21.6.2 %[] digits only | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_scanset_empty_match` | scanf_conformance | sscanf | strict | sscanf_scanset_empty_match | C11 7.21.6.2 %[] no match | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_scanset_hyphen_literal` | scanf_conformance | sscanf | strict | sscanf_scanset_hyphen_literal | C11 7.21.6.2 %[] hyphen at start | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_scanset_negated` | scanf_conformance | sscanf | strict | sscanf_scanset_negated | C11 7.21.6.2 %[^] negated | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_scanset_not_newline` | scanf_conformance | sscanf | strict | sscanf_scanset_not_newline | C11 7.21.6.2 %[^\n] | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_scanset_range` | scanf_conformance | sscanf | strict | sscanf_scanset_range | C11 7.21.6.2 %[] range | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_suppress_d` | scanf_conformance | sscanf | strict | sscanf_suppress_d | C11 7.21.6.2 * suppression | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_suppress_multiple` | scanf_conformance | sscanf | strict | sscanf_suppress_multiple | C11 7.21.6.2 multiple suppress | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_suppress_s` | scanf_conformance | sscanf | strict | sscanf_suppress_s | C11 7.21.6.2 * with %s | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_t_d` | scanf_conformance | sscanf | strict | sscanf_t_d | C11 7.21.6.2 %td ptrdiff_t | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_u_basic` | scanf_conformance | sscanf | strict | sscanf_u_basic | C11 7.21.6.2 %u specifier | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_u_max` | scanf_conformance | sscanf | strict | sscanf_u_max | C11 7.21.6.2 %u UINT_MAX | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_u_overflow` | scanf_conformance | sscanf | strict | sscanf_u_overflow | C11 7.21.6.2 %u overflow wraps | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_ws_in_format` | scanf_conformance | sscanf | strict | sscanf_ws_in_format | C11 7.21.6.2 format whitespace | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_x_basic` | scanf_conformance | sscanf | strict | sscanf_x_basic | C11 7.21.6.2 %x specifier | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_x_large` | scanf_conformance | sscanf | strict | sscanf_x_large | C11 7.21.6.2 %x large | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_x_prefix` | scanf_conformance | sscanf | strict | sscanf_x_prefix | C11 7.21.6.2 %x with 0x | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_x_width` | scanf_conformance | sscanf | strict | sscanf_x_width | C11 7.21.6.2 %x with width | PASS |
| `fixture-verify::scanf_conformance::sscanf::strict::sscanf_z_u` | scanf_conformance | sscanf | strict | sscanf_z_u | C11 7.21.6.2 %zu size_t | PASS |
| `fixture-verify::search/ops::hsearch::hardened::hcreate_hsearch_hdestroy_find_missing_key` | search/ops | hsearch | hardened | hcreate_hsearch_hdestroy_find_missing_key [hardened] | POSIX.1-2017 hsearch | PASS |
| `fixture-verify::search/ops::hsearch::hardened::hcreate_hsearch_hdestroy_replace_existing_data` | search/ops | hsearch | hardened | hcreate_hsearch_hdestroy_replace_existing_data [hardened] | POSIX.1-2017 hsearch | PASS |
| `fixture-verify::search/ops::hsearch::strict::hcreate_hsearch_hdestroy_find_missing_key` | search/ops | hsearch | strict | hcreate_hsearch_hdestroy_find_missing_key [strict] | POSIX.1-2017 hsearch | PASS |
| `fixture-verify::search/ops::hsearch::strict::hcreate_hsearch_hdestroy_replace_existing_data` | search/ops | hsearch | strict | hcreate_hsearch_hdestroy_replace_existing_data [strict] | POSIX.1-2017 hsearch | PASS |
| `fixture-verify::search/ops::hsearch_r::hardened::hcreate_r_hsearch_r_hdestroy_r_replace_existing_data` | search/ops | hsearch_r | hardened | hcreate_r_hsearch_r_hdestroy_r_replace_existing_data [hardened] | POSIX.1-2017 hsearch_r | PASS |
| `fixture-verify::search/ops::hsearch_r::strict::hcreate_r_hsearch_r_hdestroy_r_replace_existing_data` | search/ops | hsearch_r | strict | hcreate_r_hsearch_r_hdestroy_r_replace_existing_data [strict] | POSIX.1-2017 hsearch_r | PASS |
| `fixture-verify::search/ops::insque::hardened::insque_builds_chain` | search/ops | insque | hardened | insque_builds_chain [hardened] | XSI insque | PASS |
| `fixture-verify::search/ops::insque::strict::insque_builds_chain` | search/ops | insque | strict | insque_builds_chain [strict] | XSI insque | PASS |
| `fixture-verify::search/ops::lfind::hardened::lfind_existing_index` | search/ops | lfind | hardened | lfind_existing_index [hardened] | POSIX.1-2017 lfind | PASS |
| `fixture-verify::search/ops::lfind::strict::lfind_existing_index` | search/ops | lfind | strict | lfind_existing_index [strict] | POSIX.1-2017 lfind | PASS |
| `fixture-verify::search/ops::lsearch::hardened::lsearch_appends_missing` | search/ops | lsearch | hardened | lsearch_appends_missing [hardened] | POSIX.1-2017 lsearch | PASS |
| `fixture-verify::search/ops::lsearch::strict::lsearch_appends_missing` | search/ops | lsearch | strict | lsearch_appends_missing [strict] | POSIX.1-2017 lsearch | PASS |
| `fixture-verify::search/ops::remque::hardened::remque_middle_detaches_node` | search/ops | remque | hardened | remque_middle_detaches_node [hardened] | XSI remque | PASS |
| `fixture-verify::search/ops::remque::strict::remque_middle_detaches_node` | search/ops | remque | strict | remque_middle_detaches_node [strict] | XSI remque | PASS |
| `fixture-verify::search/ops::tdelete::hardened::tdelete_removes_leaf` | search/ops | tdelete | hardened | tdelete_removes_leaf [hardened] | POSIX.1-2017 tdelete | PASS |
| `fixture-verify::search/ops::tdelete::strict::tdelete_removes_leaf` | search/ops | tdelete | strict | tdelete_removes_leaf [strict] | POSIX.1-2017 tdelete | PASS |
| `fixture-verify::search/ops::tfind::hardened::tfind_existing_and_missing` | search/ops | tfind | hardened | tfind_existing_and_missing [hardened] | POSIX.1-2017 tfind | PASS |
| `fixture-verify::search/ops::tfind::strict::tfind_existing_and_missing` | search/ops | tfind | strict | tfind_existing_and_missing [strict] | POSIX.1-2017 tfind | PASS |
| `fixture-verify::search/ops::tsearch::hardened::tsearch_insert_and_find` | search/ops | tsearch | hardened | tsearch_insert_and_find [hardened] | POSIX.1-2017 tsearch | PASS |
| `fixture-verify::search/ops::tsearch::strict::tsearch_insert_and_find` | search/ops | tsearch | strict | tsearch_insert_and_find [strict] | POSIX.1-2017 tsearch | PASS |
| `fixture-verify::search/ops::twalk::hardened::twalk_visit_sequence` | search/ops | twalk | hardened | twalk_visit_sequence [hardened] | POSIX.1-2017 twalk | PASS |
| `fixture-verify::search/ops::twalk::strict::twalk_visit_sequence` | search/ops | twalk | strict | twalk_visit_sequence [strict] | POSIX.1-2017 twalk | PASS |
| `fixture-verify::session_ops::getlogin::hardened::getlogin_returns_user_hardened` | session_ops | getlogin | hardened | getlogin_returns_user_hardened | POSIX getlogin(3) | PASS |
| `fixture-verify::session_ops::getlogin::strict::getlogin_returns_user_strict` | session_ops | getlogin | strict | getlogin_returns_user_strict | POSIX getlogin(3) | PASS |
| `fixture-verify::session_ops::getlogin_r::strict::getlogin_r_returns_user_strict` | session_ops | getlogin_r | strict | getlogin_r_returns_user_strict | POSIX getlogin_r(3) | PASS |
| `fixture-verify::session_ops::getsid::strict::getsid_returns_sid_strict` | session_ops | getsid | strict | getsid_returns_sid_strict | POSIX getsid(2) | PASS |
| `fixture-verify::session_ops::setsid::hardened::setsid_creates_session_hardened` | session_ops | setsid | hardened | setsid_creates_session_hardened | POSIX setsid(2) | PASS |
| `fixture-verify::session_ops::setsid::strict::setsid_creates_session_strict` | session_ops | setsid | strict | setsid_creates_session_strict | POSIX setsid(2) | PASS |
| `fixture-verify::setjmp_nested_edges::setjmp_nested_edges::hardened::corrupted_jump_buffer_restore` | setjmp_nested_edges | setjmp_nested_edges | hardened | corrupted_jump_buffer_restore [hardened] | unsupported_deferred | PASS |
| `fixture-verify::setjmp_nested_edges::setjmp_nested_edges::hardened::cross_thread_longjmp` | setjmp_nested_edges | setjmp_nested_edges | hardened | cross_thread_longjmp [hardened] | unsupported_deferred | PASS |
| `fixture-verify::setjmp_nested_edges::setjmp_nested_edges::hardened::edge_zero_value_and_sigmask_roundtrip` | setjmp_nested_edges | setjmp_nested_edges | hardened | edge_zero_value_and_sigmask_roundtrip [hardened] | tests/integration/fixture_setjmp_edges.c | PASS |
| `fixture-verify::setjmp_nested_edges::setjmp_nested_edges::hardened::nested_two_level_longjmp` | setjmp_nested_edges | setjmp_nested_edges | hardened | nested_two_level_longjmp [hardened] | tests/integration/fixture_setjmp_nested.c | PASS |
| `fixture-verify::setjmp_nested_edges::setjmp_nested_edges::hardened::siglongjmp_without_sigsetjmp` | setjmp_nested_edges | setjmp_nested_edges | hardened | siglongjmp_without_sigsetjmp [hardened] | unsupported_deferred | PASS |
| `fixture-verify::setjmp_nested_edges::setjmp_nested_edges::strict::corrupted_jump_buffer_restore` | setjmp_nested_edges | setjmp_nested_edges | strict | corrupted_jump_buffer_restore [strict] | unsupported_deferred | PASS |
| `fixture-verify::setjmp_nested_edges::setjmp_nested_edges::strict::cross_thread_longjmp` | setjmp_nested_edges | setjmp_nested_edges | strict | cross_thread_longjmp [strict] | unsupported_deferred | PASS |
| `fixture-verify::setjmp_nested_edges::setjmp_nested_edges::strict::edge_zero_value_and_sigmask_roundtrip` | setjmp_nested_edges | setjmp_nested_edges | strict | edge_zero_value_and_sigmask_roundtrip [strict] | tests/integration/fixture_setjmp_edges.c | PASS |
| `fixture-verify::setjmp_nested_edges::setjmp_nested_edges::strict::nested_two_level_longjmp` | setjmp_nested_edges | setjmp_nested_edges | strict | nested_two_level_longjmp [strict] | tests/integration/fixture_setjmp_nested.c | PASS |
| `fixture-verify::setjmp_nested_edges::setjmp_nested_edges::strict::siglongjmp_without_sigsetjmp` | setjmp_nested_edges | setjmp_nested_edges | strict | siglongjmp_without_sigsetjmp [strict] | unsupported_deferred | PASS |
| `fixture-verify::setjmp_ops::_setjmp::strict::sigsetjmp_returns_zero_strict` | setjmp_ops | _setjmp | strict | sigsetjmp_returns_zero_strict | POSIX sigsetjmp | PASS |
| `fixture-verify::setjmp_ops::longjmp::hardened::longjmp_corrupted_buf_hardened` | setjmp_ops | longjmp | hardened | longjmp_corrupted_buf_hardened | FrankenLibC TSM repair | PASS |
| `fixture-verify::setjmp_ops::longjmp::hardened::longjmp_restores_hardened` | setjmp_ops | longjmp | hardened | longjmp_restores_hardened | C11 7.13.2.1 | PASS |
| `fixture-verify::setjmp_ops::longjmp::strict::longjmp_restores_strict` | setjmp_ops | longjmp | strict | longjmp_restores_strict | C11 7.13.2.1 | PASS |
| `fixture-verify::setjmp_ops::longjmp::strict::longjmp_zero_becomes_one_strict` | setjmp_ops | longjmp | strict | longjmp_zero_becomes_one_strict | C11 7.13.2.1 | PASS |
| `fixture-verify::setjmp_ops::setjmp::hardened::setjmp_returns_zero_hardened` | setjmp_ops | setjmp | hardened | setjmp_returns_zero_hardened | C11 7.13.1.1 | PASS |
| `fixture-verify::setjmp_ops::setjmp::strict::setjmp_returns_zero_strict` | setjmp_ops | setjmp | strict | setjmp_returns_zero_strict | C11 7.13.1.1 | PASS |
| `fixture-verify::signal_ops::gsignal::hardened::gsignal_above_max_both` | signal_ops | gsignal | hardened | gsignal_above_max_both [hardened] | System V gsignal | PASS |
| `fixture-verify::signal_ops::gsignal::hardened::gsignal_invalid_signal_both` | signal_ops | gsignal | hardened | gsignal_invalid_signal_both [hardened] | System V gsignal | PASS |
| `fixture-verify::signal_ops::gsignal::hardened::gsignal_negative_both` | signal_ops | gsignal | hardened | gsignal_negative_both [hardened] | System V gsignal | PASS |
| `fixture-verify::signal_ops::gsignal::hardened::gsignal_null_signal_both` | signal_ops | gsignal | hardened | gsignal_null_signal_both [hardened] | System V gsignal | PASS |
| `fixture-verify::signal_ops::gsignal::hardened::gsignal_sigkill_preinstall_both` | signal_ops | gsignal | hardened | gsignal_sigkill_preinstall_both [hardened] | System V gsignal | PASS |
| `fixture-verify::signal_ops::gsignal::hardened::gsignal_sigterm_delivery_both` | signal_ops | gsignal | hardened | gsignal_sigterm_delivery_both [hardened] | System V gsignal | PASS |
| `fixture-verify::signal_ops::gsignal::hardened::gsignal_sigusr1_delivery_both` | signal_ops | gsignal | hardened | gsignal_sigusr1_delivery_both [hardened] | System V gsignal | PASS |
| `fixture-verify::signal_ops::gsignal::hardened::gsignal_sigusr2_delivery_both` | signal_ops | gsignal | hardened | gsignal_sigusr2_delivery_both [hardened] | System V gsignal | PASS |
| `fixture-verify::signal_ops::gsignal::strict::gsignal_above_max_both` | signal_ops | gsignal | strict | gsignal_above_max_both [strict] | System V gsignal | PASS |
| `fixture-verify::signal_ops::gsignal::strict::gsignal_invalid_signal_both` | signal_ops | gsignal | strict | gsignal_invalid_signal_both [strict] | System V gsignal | PASS |
| `fixture-verify::signal_ops::gsignal::strict::gsignal_negative_both` | signal_ops | gsignal | strict | gsignal_negative_both [strict] | System V gsignal | PASS |
| `fixture-verify::signal_ops::gsignal::strict::gsignal_null_signal_both` | signal_ops | gsignal | strict | gsignal_null_signal_both [strict] | System V gsignal | PASS |
| `fixture-verify::signal_ops::gsignal::strict::gsignal_sigkill_preinstall_both` | signal_ops | gsignal | strict | gsignal_sigkill_preinstall_both [strict] | System V gsignal | PASS |
| `fixture-verify::signal_ops::gsignal::strict::gsignal_sigterm_delivery_both` | signal_ops | gsignal | strict | gsignal_sigterm_delivery_both [strict] | System V gsignal | PASS |
| `fixture-verify::signal_ops::gsignal::strict::gsignal_sigusr1_delivery_both` | signal_ops | gsignal | strict | gsignal_sigusr1_delivery_both [strict] | System V gsignal | PASS |
| `fixture-verify::signal_ops::gsignal::strict::gsignal_sigusr2_delivery_both` | signal_ops | gsignal | strict | gsignal_sigusr2_delivery_both [strict] | System V gsignal | PASS |
| `fixture-verify::signal_ops::kill::hardened::kill_invalid_signal_hardened` | signal_ops | kill | hardened | kill_invalid_signal_hardened | POSIX kill | PASS |
| `fixture-verify::signal_ops::kill::strict::kill_invalid_signal_strict` | signal_ops | kill | strict | kill_invalid_signal_strict | POSIX kill | PASS |
| `fixture-verify::signal_ops::kill::strict::kill_nonexistent_pid_zero_strict` | signal_ops | kill | strict | kill_nonexistent_pid_zero_strict | POSIX kill | PASS |
| `fixture-verify::signal_ops::kill::strict::kill_self_zero_strict` | signal_ops | kill | strict | kill_self_zero_strict | POSIX kill | PASS |
| `fixture-verify::signal_ops::raise::hardened::raise_zero_hardened` | signal_ops | raise | hardened | raise_zero_hardened | POSIX raise | PASS |
| `fixture-verify::signal_ops::raise::strict::raise_zero_strict` | signal_ops | raise | strict | raise_zero_strict | POSIX raise | PASS |
| `fixture-verify::signal_ops::sigaction::strict::sigaction_query_strict` | signal_ops | sigaction | strict | sigaction_query_strict | POSIX sigaction | PASS |
| `fixture-verify::signal_ops::sigaddset::hardened::sigaddset_sigusr1_hardened` | signal_ops | sigaddset | hardened | sigaddset_sigusr1_hardened | POSIX sigaddset | PASS |
| `fixture-verify::signal_ops::sigaddset::strict::sigaddset_invalid_strict` | signal_ops | sigaddset | strict | sigaddset_invalid_strict | POSIX sigaddset | PASS |
| `fixture-verify::signal_ops::sigaddset::strict::sigaddset_sigint_strict` | signal_ops | sigaddset | strict | sigaddset_sigint_strict | POSIX sigaddset | PASS |
| `fixture-verify::signal_ops::sigaddset::strict::sigaddset_sigterm_strict` | signal_ops | sigaddset | strict | sigaddset_sigterm_strict | POSIX sigaddset | PASS |
| `fixture-verify::signal_ops::sigdelset::strict::sigdelset_invalid_strict` | signal_ops | sigdelset | strict | sigdelset_invalid_strict | POSIX sigdelset | PASS |
| `fixture-verify::signal_ops::sigdelset::strict::sigdelset_sigint_strict` | signal_ops | sigdelset | strict | sigdelset_sigint_strict | POSIX sigdelset | PASS |
| `fixture-verify::signal_ops::sigemptyset::hardened::sigemptyset_basic_hardened` | signal_ops | sigemptyset | hardened | sigemptyset_basic_hardened | POSIX sigemptyset | PASS |
| `fixture-verify::signal_ops::sigemptyset::strict::sigemptyset_basic_strict` | signal_ops | sigemptyset | strict | sigemptyset_basic_strict | POSIX sigemptyset | PASS |
| `fixture-verify::signal_ops::sigfillset::hardened::sigfillset_basic_hardened` | signal_ops | sigfillset | hardened | sigfillset_basic_hardened | POSIX sigfillset | PASS |
| `fixture-verify::signal_ops::sigfillset::strict::sigfillset_basic_strict` | signal_ops | sigfillset | strict | sigfillset_basic_strict | POSIX sigfillset | PASS |
| `fixture-verify::signal_ops::sigismember::hardened::sigismember_full_hardened` | signal_ops | sigismember | hardened | sigismember_full_hardened | POSIX sigismember | PASS |
| `fixture-verify::signal_ops::sigismember::strict::sigismember_empty_set_strict` | signal_ops | sigismember | strict | sigismember_empty_set_strict | POSIX sigismember | PASS |
| `fixture-verify::signal_ops::sigismember::strict::sigismember_full_set_strict` | signal_ops | sigismember | strict | sigismember_full_set_strict | POSIX sigismember | PASS |
| `fixture-verify::signal_ops::sigismember::strict::sigismember_invalid_strict` | signal_ops | sigismember | strict | sigismember_invalid_strict | POSIX sigismember | PASS |
| `fixture-verify::signal_ops::signal::hardened::signal_install_above_max_both` | signal_ops | signal | hardened | signal_install_above_max_both [hardened] | POSIX signal | PASS |
| `fixture-verify::signal_ops::signal::hardened::signal_install_negative_both` | signal_ops | signal | hardened | signal_install_negative_both [hardened] | POSIX signal | PASS |
| `fixture-verify::signal_ops::signal::hardened::signal_install_sighup_both` | signal_ops | signal | hardened | signal_install_sighup_both [hardened] | POSIX signal | PASS |
| `fixture-verify::signal_ops::signal::hardened::signal_install_sigkill_both` | signal_ops | signal | hardened | signal_install_sigkill_both [hardened] | POSIX signal | PASS |
| `fixture-verify::signal_ops::signal::hardened::signal_install_sigrtmax_both` | signal_ops | signal | hardened | signal_install_sigrtmax_both [hardened] | POSIX signal | PASS |
| `fixture-verify::signal_ops::signal::hardened::signal_install_sigstop_both` | signal_ops | signal | hardened | signal_install_sigstop_both [hardened] | POSIX signal | PASS |
| `fixture-verify::signal_ops::signal::hardened::signal_install_sigterm_both` | signal_ops | signal | hardened | signal_install_sigterm_both [hardened] | POSIX signal | PASS |
| `fixture-verify::signal_ops::signal::hardened::signal_install_sigusr1_both` | signal_ops | signal | hardened | signal_install_sigusr1_both [hardened] | POSIX signal | PASS |
| `fixture-verify::signal_ops::signal::hardened::signal_install_sigusr2_both` | signal_ops | signal | hardened | signal_install_sigusr2_both [hardened] | POSIX signal | PASS |
| `fixture-verify::signal_ops::signal::hardened::signal_install_zero_both` | signal_ops | signal | hardened | signal_install_zero_both [hardened] | POSIX signal | PASS |
| `fixture-verify::signal_ops::signal::hardened::signal_invalid_signal_both` | signal_ops | signal | hardened | signal_invalid_signal_both [hardened] | POSIX signal | PASS |
| `fixture-verify::signal_ops::signal::strict::signal_install_above_max_both` | signal_ops | signal | strict | signal_install_above_max_both [strict] | POSIX signal | PASS |
| `fixture-verify::signal_ops::signal::strict::signal_install_negative_both` | signal_ops | signal | strict | signal_install_negative_both [strict] | POSIX signal | PASS |
| `fixture-verify::signal_ops::signal::strict::signal_install_sighup_both` | signal_ops | signal | strict | signal_install_sighup_both [strict] | POSIX signal | PASS |
| `fixture-verify::signal_ops::signal::strict::signal_install_sigkill_both` | signal_ops | signal | strict | signal_install_sigkill_both [strict] | POSIX signal | PASS |
| `fixture-verify::signal_ops::signal::strict::signal_install_sigrtmax_both` | signal_ops | signal | strict | signal_install_sigrtmax_both [strict] | POSIX signal | PASS |
| `fixture-verify::signal_ops::signal::strict::signal_install_sigstop_both` | signal_ops | signal | strict | signal_install_sigstop_both [strict] | POSIX signal | PASS |
| `fixture-verify::signal_ops::signal::strict::signal_install_sigterm_both` | signal_ops | signal | strict | signal_install_sigterm_both [strict] | POSIX signal | PASS |
| `fixture-verify::signal_ops::signal::strict::signal_install_sigusr1_both` | signal_ops | signal | strict | signal_install_sigusr1_both [strict] | POSIX signal | PASS |
| `fixture-verify::signal_ops::signal::strict::signal_install_sigusr2_both` | signal_ops | signal | strict | signal_install_sigusr2_both [strict] | POSIX signal | PASS |
| `fixture-verify::signal_ops::signal::strict::signal_install_zero_both` | signal_ops | signal | strict | signal_install_zero_both [strict] | POSIX signal | PASS |
| `fixture-verify::signal_ops::signal::strict::signal_invalid_signal_both` | signal_ops | signal | strict | signal_invalid_signal_both [strict] | POSIX signal | PASS |
| `fixture-verify::signal_ops::ssignal::hardened::ssignal_install_above_max_both` | signal_ops | ssignal | hardened | ssignal_install_above_max_both [hardened] | System V ssignal | PASS |
| `fixture-verify::signal_ops::ssignal::hardened::ssignal_install_negative_both` | signal_ops | ssignal | hardened | ssignal_install_negative_both [hardened] | System V ssignal | PASS |
| `fixture-verify::signal_ops::ssignal::hardened::ssignal_install_sigkill_both` | signal_ops | ssignal | hardened | ssignal_install_sigkill_both [hardened] | System V ssignal | PASS |
| `fixture-verify::signal_ops::ssignal::hardened::ssignal_install_sigrtmax_both` | signal_ops | ssignal | hardened | ssignal_install_sigrtmax_both [hardened] | System V ssignal | PASS |
| `fixture-verify::signal_ops::ssignal::hardened::ssignal_install_sigstop_both` | signal_ops | ssignal | hardened | ssignal_install_sigstop_both [hardened] | System V ssignal | PASS |
| `fixture-verify::signal_ops::ssignal::hardened::ssignal_install_sigterm_both` | signal_ops | ssignal | hardened | ssignal_install_sigterm_both [hardened] | System V ssignal | PASS |
| `fixture-verify::signal_ops::ssignal::hardened::ssignal_install_sigusr1_both` | signal_ops | ssignal | hardened | ssignal_install_sigusr1_both [hardened] | System V ssignal | PASS |
| `fixture-verify::signal_ops::ssignal::hardened::ssignal_install_zero_both` | signal_ops | ssignal | hardened | ssignal_install_zero_both [hardened] | System V ssignal | PASS |
| `fixture-verify::signal_ops::ssignal::hardened::ssignal_invalid_signal_both` | signal_ops | ssignal | hardened | ssignal_invalid_signal_both [hardened] | System V ssignal | PASS |
| `fixture-verify::signal_ops::ssignal::strict::ssignal_install_above_max_both` | signal_ops | ssignal | strict | ssignal_install_above_max_both [strict] | System V ssignal | PASS |
| `fixture-verify::signal_ops::ssignal::strict::ssignal_install_negative_both` | signal_ops | ssignal | strict | ssignal_install_negative_both [strict] | System V ssignal | PASS |
| `fixture-verify::signal_ops::ssignal::strict::ssignal_install_sigkill_both` | signal_ops | ssignal | strict | ssignal_install_sigkill_both [strict] | System V ssignal | PASS |
| `fixture-verify::signal_ops::ssignal::strict::ssignal_install_sigrtmax_both` | signal_ops | ssignal | strict | ssignal_install_sigrtmax_both [strict] | System V ssignal | PASS |
| `fixture-verify::signal_ops::ssignal::strict::ssignal_install_sigstop_both` | signal_ops | ssignal | strict | ssignal_install_sigstop_both [strict] | System V ssignal | PASS |
| `fixture-verify::signal_ops::ssignal::strict::ssignal_install_sigterm_both` | signal_ops | ssignal | strict | ssignal_install_sigterm_both [strict] | System V ssignal | PASS |
| `fixture-verify::signal_ops::ssignal::strict::ssignal_install_sigusr1_both` | signal_ops | ssignal | strict | ssignal_install_sigusr1_both [strict] | System V ssignal | PASS |
| `fixture-verify::signal_ops::ssignal::strict::ssignal_install_zero_both` | signal_ops | ssignal | strict | ssignal_install_zero_both [strict] | System V ssignal | PASS |
| `fixture-verify::signal_ops::ssignal::strict::ssignal_invalid_signal_both` | signal_ops | ssignal | strict | ssignal_invalid_signal_both [strict] | System V ssignal | PASS |
| `fixture-verify::socket_ops::bind::strict::bind_invalid_fd_strict` | socket_ops | bind | strict | bind_invalid_fd_strict | POSIX bind | PASS |
| `fixture-verify::socket_ops::getsockname::strict::getsockname_invalid_fd_strict` | socket_ops | getsockname | strict | getsockname_invalid_fd_strict | POSIX getsockname | PASS |
| `fixture-verify::socket_ops::getsockopt::hardened::getsockopt_so_type_stream` | socket_ops | getsockopt | hardened | getsockopt_so_type_stream [hardened] | POSIX getsockopt SO_TYPE | PASS |
| `fixture-verify::socket_ops::getsockopt::strict::getsockopt_so_type_stream` | socket_ops | getsockopt | strict | getsockopt_so_type_stream [strict] | POSIX getsockopt SO_TYPE | PASS |
| `fixture-verify::socket_ops::listen::strict::listen_invalid_fd_strict` | socket_ops | listen | strict | listen_invalid_fd_strict | POSIX listen | PASS |
| `fixture-verify::socket_ops::recv::hardened::recv_invalid_fd` | socket_ops | recv | hardened | recv_invalid_fd [hardened] | POSIX recv EBADF | PASS |
| `fixture-verify::socket_ops::recv::hardened::recv_socketpair_payload` | socket_ops | recv | hardened | recv_socketpair_payload [hardened] | POSIX recv | PASS |
| `fixture-verify::socket_ops::recv::strict::recv_invalid_fd` | socket_ops | recv | strict | recv_invalid_fd [strict] | POSIX recv EBADF | PASS |
| `fixture-verify::socket_ops::recv::strict::recv_socketpair_payload` | socket_ops | recv | strict | recv_socketpair_payload [strict] | POSIX recv | PASS |
| `fixture-verify::socket_ops::send::hardened::send_invalid_fd` | socket_ops | send | hardened | send_invalid_fd [hardened] | POSIX send EBADF | PASS |
| `fixture-verify::socket_ops::send::hardened::send_socketpair_payload` | socket_ops | send | hardened | send_socketpair_payload [hardened] | POSIX send | PASS |
| `fixture-verify::socket_ops::send::strict::send_invalid_fd` | socket_ops | send | strict | send_invalid_fd [strict] | POSIX send EBADF | PASS |
| `fixture-verify::socket_ops::send::strict::send_socketpair_payload` | socket_ops | send | strict | send_socketpair_payload [strict] | POSIX send | PASS |
| `fixture-verify::socket_ops::shutdown::strict::shutdown_invalid_fd_strict` | socket_ops | shutdown | strict | shutdown_invalid_fd_strict | POSIX shutdown | PASS |
| `fixture-verify::socket_ops::socket::hardened::socket_invalid_domain_hardened` | socket_ops | socket | hardened | socket_invalid_domain_hardened | POSIX socket | PASS |
| `fixture-verify::socket_ops::socket::hardened::socket_tcp_hardened` | socket_ops | socket | hardened | socket_tcp_hardened | POSIX socket | PASS |
| `fixture-verify::socket_ops::socket::strict::socket_invalid_domain_strict` | socket_ops | socket | strict | socket_invalid_domain_strict | POSIX socket | PASS |
| `fixture-verify::socket_ops::socket::strict::socket_tcp_strict` | socket_ops | socket | strict | socket_tcp_strict | POSIX socket | PASS |
| `fixture-verify::socket_ops::socket::strict::socket_udp_strict` | socket_ops | socket | strict | socket_udp_strict | POSIX socket | PASS |
| `fixture-verify::spawn_exec_ops::execve::strict::execve_eacces_strict` | spawn_exec_ops | execve | strict | execve_eacces_strict | POSIX execve(2) | PASS |
| `fixture-verify::spawn_exec_ops::execve::strict::execve_replaces_process_strict` | spawn_exec_ops | execve | strict | execve_replaces_process_strict | POSIX execve(2) | PASS |
| `fixture-verify::spawn_exec_ops::posix_spawn::hardened::posix_spawn_echo_hardened` | spawn_exec_ops | posix_spawn | hardened | posix_spawn_echo_hardened | POSIX posix_spawn(3) | PASS |
| `fixture-verify::spawn_exec_ops::posix_spawn::strict::posix_spawn_echo_strict` | spawn_exec_ops | posix_spawn | strict | posix_spawn_echo_strict | POSIX posix_spawn(3) | PASS |
| `fixture-verify::spawn_exec_ops::posix_spawn::strict::posix_spawn_nonexistent_strict` | spawn_exec_ops | posix_spawn | strict | posix_spawn_nonexistent_strict | POSIX posix_spawn(3) | PASS |
| `fixture-verify::spawn_exec_ops::system::hardened::system_returns_status_hardened` | spawn_exec_ops | system | hardened | system_returns_status_hardened | C11 7.22.4.8 | PASS |
| `fixture-verify::spawn_exec_ops::system::strict::system_returns_status_strict` | spawn_exec_ops | system | strict | system_returns_status_strict | C11 7.22.4.8 | PASS |
| `fixture-verify::startup_ops::__frankenlibc_startup_phase0::hardened::startup_phase0_rejects_unterminated_argv_hardened` | startup_ops | __frankenlibc_startup_phase0 | hardened | startup_phase0_rejects_unterminated_argv_hardened | FrankenLibC startup | PASS |
| `fixture-verify::startup_ops::__frankenlibc_startup_phase0::hardened::startup_phase0_rejects_unterminated_auxv_hardened` | startup_ops | __frankenlibc_startup_phase0 | hardened | startup_phase0_rejects_unterminated_auxv_hardened | FrankenLibC startup | PASS |
| `fixture-verify::startup_ops::__frankenlibc_startup_phase0::hardened::startup_phase0_rejects_unterminated_envp_hardened` | startup_ops | __frankenlibc_startup_phase0 | hardened | startup_phase0_rejects_unterminated_envp_hardened | FrankenLibC startup | PASS |
| `fixture-verify::startup_ops::__frankenlibc_startup_phase0::hardened::startup_phase0_returns_hardened` | startup_ops | __frankenlibc_startup_phase0 | hardened | startup_phase0_returns_hardened | FrankenLibC startup | PASS |
| `fixture-verify::startup_ops::__frankenlibc_startup_phase0::strict::startup_phase0_rejects_unterminated_argv_strict` | startup_ops | __frankenlibc_startup_phase0 | strict | startup_phase0_rejects_unterminated_argv_strict | FrankenLibC startup | PASS |
| `fixture-verify::startup_ops::__frankenlibc_startup_phase0::strict::startup_phase0_rejects_unterminated_auxv_strict` | startup_ops | __frankenlibc_startup_phase0 | strict | startup_phase0_rejects_unterminated_auxv_strict | FrankenLibC startup | PASS |
| `fixture-verify::startup_ops::__frankenlibc_startup_phase0::strict::startup_phase0_rejects_unterminated_envp_strict` | startup_ops | __frankenlibc_startup_phase0 | strict | startup_phase0_rejects_unterminated_envp_strict | FrankenLibC startup | PASS |
| `fixture-verify::startup_ops::__frankenlibc_startup_phase0::strict::startup_phase0_returns_strict` | startup_ops | __frankenlibc_startup_phase0 | strict | startup_phase0_returns_strict | FrankenLibC startup | PASS |
| `fixture-verify::startup_ops::__frankenlibc_startup_snapshot::hardened::startup_snapshot_secure_mode_secure_hardened` | startup_ops | __frankenlibc_startup_snapshot | hardened | startup_snapshot_secure_mode_secure_hardened | FrankenLibC startup | PASS |
| `fixture-verify::startup_ops::__frankenlibc_startup_snapshot::hardened::startup_snapshot_valid_hardened` | startup_ops | __frankenlibc_startup_snapshot | hardened | startup_snapshot_valid_hardened | FrankenLibC startup | PASS |
| `fixture-verify::startup_ops::__frankenlibc_startup_snapshot::strict::startup_snapshot_secure_mode_nonsecure_strict` | startup_ops | __frankenlibc_startup_snapshot | strict | startup_snapshot_secure_mode_nonsecure_strict | FrankenLibC startup | PASS |
| `fixture-verify::startup_ops::__frankenlibc_startup_snapshot::strict::startup_snapshot_valid_strict` | startup_ops | __frankenlibc_startup_snapshot | strict | startup_snapshot_valid_strict | FrankenLibC startup | PASS |
| `fixture-verify::startup_ops::__libc_start_main::strict::libc_start_main_entry_strict` | startup_ops | __libc_start_main | strict | libc_start_main_entry_strict | glibc __libc_start_main | PASS |
| `fixture-verify::startup_ops::__libc_start_main::strict::libc_start_main_phase0_disabled_fallback_host_strict` | startup_ops | __libc_start_main | strict | libc_start_main_phase0_disabled_fallback_host_strict | glibc __libc_start_main | PASS |
| `fixture-verify::startup_ops::__libc_start_main::strict::libc_start_main_phase0_missing_main_no_fallback_strict` | startup_ops | __libc_start_main | strict | libc_start_main_phase0_missing_main_no_fallback_strict | glibc __libc_start_main | PASS |
| `fixture-verify::startup_ops::__libc_start_main::strict::libc_start_main_phase0_unsafe_envp_fallback_host_strict` | startup_ops | __libc_start_main | strict | libc_start_main_phase0_unsafe_envp_fallback_host_strict | glibc __libc_start_main | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_ceil_uc::hardened::stdc_bit_ceil_uc_sparse` | stdbit/ops | stdc_bit_ceil_uc | hardened | stdc_bit_ceil_uc_sparse [hardened] | C23 7.18a.4.14 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_ceil_uc::hardened::stdc_bit_ceil_uc_zero` | stdbit/ops | stdc_bit_ceil_uc | hardened | stdc_bit_ceil_uc_zero [hardened] | C23 7.18a.4.14 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_ceil_uc::strict::stdc_bit_ceil_uc_sparse` | stdbit/ops | stdc_bit_ceil_uc | strict | stdc_bit_ceil_uc_sparse [strict] | C23 7.18a.4.14 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_ceil_uc::strict::stdc_bit_ceil_uc_zero` | stdbit/ops | stdc_bit_ceil_uc | strict | stdc_bit_ceil_uc_zero [strict] | C23 7.18a.4.14 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_ceil_ui::hardened::stdc_bit_ceil_ui_sparse` | stdbit/ops | stdc_bit_ceil_ui | hardened | stdc_bit_ceil_ui_sparse [hardened] | C23 7.18a.4.14 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_ceil_ui::hardened::stdc_bit_ceil_ui_zero` | stdbit/ops | stdc_bit_ceil_ui | hardened | stdc_bit_ceil_ui_zero [hardened] | C23 7.18a.4.14 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_ceil_ui::strict::stdc_bit_ceil_ui_sparse` | stdbit/ops | stdc_bit_ceil_ui | strict | stdc_bit_ceil_ui_sparse [strict] | C23 7.18a.4.14 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_ceil_ui::strict::stdc_bit_ceil_ui_zero` | stdbit/ops | stdc_bit_ceil_ui | strict | stdc_bit_ceil_ui_zero [strict] | C23 7.18a.4.14 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_ceil_ul::hardened::stdc_bit_ceil_ul_sparse` | stdbit/ops | stdc_bit_ceil_ul | hardened | stdc_bit_ceil_ul_sparse [hardened] | C23 7.18a.4.14 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_ceil_ul::hardened::stdc_bit_ceil_ul_zero` | stdbit/ops | stdc_bit_ceil_ul | hardened | stdc_bit_ceil_ul_zero [hardened] | C23 7.18a.4.14 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_ceil_ul::strict::stdc_bit_ceil_ul_sparse` | stdbit/ops | stdc_bit_ceil_ul | strict | stdc_bit_ceil_ul_sparse [strict] | C23 7.18a.4.14 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_ceil_ul::strict::stdc_bit_ceil_ul_zero` | stdbit/ops | stdc_bit_ceil_ul | strict | stdc_bit_ceil_ul_zero [strict] | C23 7.18a.4.14 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_ceil_ull::hardened::stdc_bit_ceil_ull_sparse` | stdbit/ops | stdc_bit_ceil_ull | hardened | stdc_bit_ceil_ull_sparse [hardened] | C23 7.18a.4.14 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_ceil_ull::hardened::stdc_bit_ceil_ull_zero` | stdbit/ops | stdc_bit_ceil_ull | hardened | stdc_bit_ceil_ull_zero [hardened] | C23 7.18a.4.14 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_ceil_ull::strict::stdc_bit_ceil_ull_sparse` | stdbit/ops | stdc_bit_ceil_ull | strict | stdc_bit_ceil_ull_sparse [strict] | C23 7.18a.4.14 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_ceil_ull::strict::stdc_bit_ceil_ull_zero` | stdbit/ops | stdc_bit_ceil_ull | strict | stdc_bit_ceil_ull_zero [strict] | C23 7.18a.4.14 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_ceil_us::hardened::stdc_bit_ceil_us_sparse` | stdbit/ops | stdc_bit_ceil_us | hardened | stdc_bit_ceil_us_sparse [hardened] | C23 7.18a.4.14 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_ceil_us::hardened::stdc_bit_ceil_us_zero` | stdbit/ops | stdc_bit_ceil_us | hardened | stdc_bit_ceil_us_zero [hardened] | C23 7.18a.4.14 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_ceil_us::strict::stdc_bit_ceil_us_sparse` | stdbit/ops | stdc_bit_ceil_us | strict | stdc_bit_ceil_us_sparse [strict] | C23 7.18a.4.14 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_ceil_us::strict::stdc_bit_ceil_us_zero` | stdbit/ops | stdc_bit_ceil_us | strict | stdc_bit_ceil_us_zero [strict] | C23 7.18a.4.14 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_floor_uc::hardened::stdc_bit_floor_uc_sparse` | stdbit/ops | stdc_bit_floor_uc | hardened | stdc_bit_floor_uc_sparse [hardened] | C23 7.18a.4.13 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_floor_uc::hardened::stdc_bit_floor_uc_zero` | stdbit/ops | stdc_bit_floor_uc | hardened | stdc_bit_floor_uc_zero [hardened] | C23 7.18a.4.13 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_floor_uc::strict::stdc_bit_floor_uc_sparse` | stdbit/ops | stdc_bit_floor_uc | strict | stdc_bit_floor_uc_sparse [strict] | C23 7.18a.4.13 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_floor_uc::strict::stdc_bit_floor_uc_zero` | stdbit/ops | stdc_bit_floor_uc | strict | stdc_bit_floor_uc_zero [strict] | C23 7.18a.4.13 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_floor_ui::hardened::stdc_bit_floor_ui_sparse` | stdbit/ops | stdc_bit_floor_ui | hardened | stdc_bit_floor_ui_sparse [hardened] | C23 7.18a.4.13 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_floor_ui::hardened::stdc_bit_floor_ui_zero` | stdbit/ops | stdc_bit_floor_ui | hardened | stdc_bit_floor_ui_zero [hardened] | C23 7.18a.4.13 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_floor_ui::strict::stdc_bit_floor_ui_sparse` | stdbit/ops | stdc_bit_floor_ui | strict | stdc_bit_floor_ui_sparse [strict] | C23 7.18a.4.13 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_floor_ui::strict::stdc_bit_floor_ui_zero` | stdbit/ops | stdc_bit_floor_ui | strict | stdc_bit_floor_ui_zero [strict] | C23 7.18a.4.13 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_floor_ul::hardened::stdc_bit_floor_ul_sparse` | stdbit/ops | stdc_bit_floor_ul | hardened | stdc_bit_floor_ul_sparse [hardened] | C23 7.18a.4.13 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_floor_ul::hardened::stdc_bit_floor_ul_zero` | stdbit/ops | stdc_bit_floor_ul | hardened | stdc_bit_floor_ul_zero [hardened] | C23 7.18a.4.13 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_floor_ul::strict::stdc_bit_floor_ul_sparse` | stdbit/ops | stdc_bit_floor_ul | strict | stdc_bit_floor_ul_sparse [strict] | C23 7.18a.4.13 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_floor_ul::strict::stdc_bit_floor_ul_zero` | stdbit/ops | stdc_bit_floor_ul | strict | stdc_bit_floor_ul_zero [strict] | C23 7.18a.4.13 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_floor_ull::hardened::stdc_bit_floor_ull_sparse` | stdbit/ops | stdc_bit_floor_ull | hardened | stdc_bit_floor_ull_sparse [hardened] | C23 7.18a.4.13 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_floor_ull::hardened::stdc_bit_floor_ull_zero` | stdbit/ops | stdc_bit_floor_ull | hardened | stdc_bit_floor_ull_zero [hardened] | C23 7.18a.4.13 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_floor_ull::strict::stdc_bit_floor_ull_sparse` | stdbit/ops | stdc_bit_floor_ull | strict | stdc_bit_floor_ull_sparse [strict] | C23 7.18a.4.13 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_floor_ull::strict::stdc_bit_floor_ull_zero` | stdbit/ops | stdc_bit_floor_ull | strict | stdc_bit_floor_ull_zero [strict] | C23 7.18a.4.13 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_floor_us::hardened::stdc_bit_floor_us_sparse` | stdbit/ops | stdc_bit_floor_us | hardened | stdc_bit_floor_us_sparse [hardened] | C23 7.18a.4.13 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_floor_us::hardened::stdc_bit_floor_us_zero` | stdbit/ops | stdc_bit_floor_us | hardened | stdc_bit_floor_us_zero [hardened] | C23 7.18a.4.13 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_floor_us::strict::stdc_bit_floor_us_sparse` | stdbit/ops | stdc_bit_floor_us | strict | stdc_bit_floor_us_sparse [strict] | C23 7.18a.4.13 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_floor_us::strict::stdc_bit_floor_us_zero` | stdbit/ops | stdc_bit_floor_us | strict | stdc_bit_floor_us_zero [strict] | C23 7.18a.4.13 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_width_uc::hardened::stdc_bit_width_uc_sparse` | stdbit/ops | stdc_bit_width_uc | hardened | stdc_bit_width_uc_sparse [hardened] | C23 7.18a.4.12 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_width_uc::hardened::stdc_bit_width_uc_zero` | stdbit/ops | stdc_bit_width_uc | hardened | stdc_bit_width_uc_zero [hardened] | C23 7.18a.4.12 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_width_uc::strict::stdc_bit_width_uc_sparse` | stdbit/ops | stdc_bit_width_uc | strict | stdc_bit_width_uc_sparse [strict] | C23 7.18a.4.12 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_width_uc::strict::stdc_bit_width_uc_zero` | stdbit/ops | stdc_bit_width_uc | strict | stdc_bit_width_uc_zero [strict] | C23 7.18a.4.12 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_width_ui::hardened::stdc_bit_width_ui_sparse` | stdbit/ops | stdc_bit_width_ui | hardened | stdc_bit_width_ui_sparse [hardened] | C23 7.18a.4.12 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_width_ui::hardened::stdc_bit_width_ui_zero` | stdbit/ops | stdc_bit_width_ui | hardened | stdc_bit_width_ui_zero [hardened] | C23 7.18a.4.12 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_width_ui::strict::stdc_bit_width_ui_sparse` | stdbit/ops | stdc_bit_width_ui | strict | stdc_bit_width_ui_sparse [strict] | C23 7.18a.4.12 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_width_ui::strict::stdc_bit_width_ui_zero` | stdbit/ops | stdc_bit_width_ui | strict | stdc_bit_width_ui_zero [strict] | C23 7.18a.4.12 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_width_ul::hardened::stdc_bit_width_ul_sparse` | stdbit/ops | stdc_bit_width_ul | hardened | stdc_bit_width_ul_sparse [hardened] | C23 7.18a.4.12 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_width_ul::hardened::stdc_bit_width_ul_zero` | stdbit/ops | stdc_bit_width_ul | hardened | stdc_bit_width_ul_zero [hardened] | C23 7.18a.4.12 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_width_ul::strict::stdc_bit_width_ul_sparse` | stdbit/ops | stdc_bit_width_ul | strict | stdc_bit_width_ul_sparse [strict] | C23 7.18a.4.12 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_width_ul::strict::stdc_bit_width_ul_zero` | stdbit/ops | stdc_bit_width_ul | strict | stdc_bit_width_ul_zero [strict] | C23 7.18a.4.12 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_width_ull::hardened::stdc_bit_width_ull_sparse` | stdbit/ops | stdc_bit_width_ull | hardened | stdc_bit_width_ull_sparse [hardened] | C23 7.18a.4.12 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_width_ull::hardened::stdc_bit_width_ull_zero` | stdbit/ops | stdc_bit_width_ull | hardened | stdc_bit_width_ull_zero [hardened] | C23 7.18a.4.12 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_width_ull::strict::stdc_bit_width_ull_sparse` | stdbit/ops | stdc_bit_width_ull | strict | stdc_bit_width_ull_sparse [strict] | C23 7.18a.4.12 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_width_ull::strict::stdc_bit_width_ull_zero` | stdbit/ops | stdc_bit_width_ull | strict | stdc_bit_width_ull_zero [strict] | C23 7.18a.4.12 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_width_us::hardened::stdc_bit_width_us_sparse` | stdbit/ops | stdc_bit_width_us | hardened | stdc_bit_width_us_sparse [hardened] | C23 7.18a.4.12 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_width_us::hardened::stdc_bit_width_us_zero` | stdbit/ops | stdc_bit_width_us | hardened | stdc_bit_width_us_zero [hardened] | C23 7.18a.4.12 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_width_us::strict::stdc_bit_width_us_sparse` | stdbit/ops | stdc_bit_width_us | strict | stdc_bit_width_us_sparse [strict] | C23 7.18a.4.12 | PASS |
| `fixture-verify::stdbit/ops::stdc_bit_width_us::strict::stdc_bit_width_us_zero` | stdbit/ops | stdc_bit_width_us | strict | stdc_bit_width_us_zero [strict] | C23 7.18a.4.12 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_ones_uc::hardened::stdc_count_ones_uc_sparse` | stdbit/ops | stdc_count_ones_uc | hardened | stdc_count_ones_uc_sparse [hardened] | C23 7.18a.4.9 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_ones_uc::hardened::stdc_count_ones_uc_zero` | stdbit/ops | stdc_count_ones_uc | hardened | stdc_count_ones_uc_zero [hardened] | C23 7.18a.4.9 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_ones_uc::strict::stdc_count_ones_uc_sparse` | stdbit/ops | stdc_count_ones_uc | strict | stdc_count_ones_uc_sparse [strict] | C23 7.18a.4.9 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_ones_uc::strict::stdc_count_ones_uc_zero` | stdbit/ops | stdc_count_ones_uc | strict | stdc_count_ones_uc_zero [strict] | C23 7.18a.4.9 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_ones_ui::hardened::stdc_count_ones_ui_sparse` | stdbit/ops | stdc_count_ones_ui | hardened | stdc_count_ones_ui_sparse [hardened] | C23 7.18a.4.9 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_ones_ui::hardened::stdc_count_ones_ui_zero` | stdbit/ops | stdc_count_ones_ui | hardened | stdc_count_ones_ui_zero [hardened] | C23 7.18a.4.9 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_ones_ui::strict::stdc_count_ones_ui_sparse` | stdbit/ops | stdc_count_ones_ui | strict | stdc_count_ones_ui_sparse [strict] | C23 7.18a.4.9 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_ones_ui::strict::stdc_count_ones_ui_zero` | stdbit/ops | stdc_count_ones_ui | strict | stdc_count_ones_ui_zero [strict] | C23 7.18a.4.9 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_ones_ul::hardened::stdc_count_ones_ul_sparse` | stdbit/ops | stdc_count_ones_ul | hardened | stdc_count_ones_ul_sparse [hardened] | C23 7.18a.4.9 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_ones_ul::hardened::stdc_count_ones_ul_zero` | stdbit/ops | stdc_count_ones_ul | hardened | stdc_count_ones_ul_zero [hardened] | C23 7.18a.4.9 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_ones_ul::strict::stdc_count_ones_ul_sparse` | stdbit/ops | stdc_count_ones_ul | strict | stdc_count_ones_ul_sparse [strict] | C23 7.18a.4.9 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_ones_ul::strict::stdc_count_ones_ul_zero` | stdbit/ops | stdc_count_ones_ul | strict | stdc_count_ones_ul_zero [strict] | C23 7.18a.4.9 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_ones_ull::hardened::stdc_count_ones_ull_sparse` | stdbit/ops | stdc_count_ones_ull | hardened | stdc_count_ones_ull_sparse [hardened] | C23 7.18a.4.9 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_ones_ull::hardened::stdc_count_ones_ull_zero` | stdbit/ops | stdc_count_ones_ull | hardened | stdc_count_ones_ull_zero [hardened] | C23 7.18a.4.9 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_ones_ull::strict::stdc_count_ones_ull_sparse` | stdbit/ops | stdc_count_ones_ull | strict | stdc_count_ones_ull_sparse [strict] | C23 7.18a.4.9 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_ones_ull::strict::stdc_count_ones_ull_zero` | stdbit/ops | stdc_count_ones_ull | strict | stdc_count_ones_ull_zero [strict] | C23 7.18a.4.9 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_ones_us::hardened::stdc_count_ones_us_sparse` | stdbit/ops | stdc_count_ones_us | hardened | stdc_count_ones_us_sparse [hardened] | C23 7.18a.4.9 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_ones_us::hardened::stdc_count_ones_us_zero` | stdbit/ops | stdc_count_ones_us | hardened | stdc_count_ones_us_zero [hardened] | C23 7.18a.4.9 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_ones_us::strict::stdc_count_ones_us_sparse` | stdbit/ops | stdc_count_ones_us | strict | stdc_count_ones_us_sparse [strict] | C23 7.18a.4.9 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_ones_us::strict::stdc_count_ones_us_zero` | stdbit/ops | stdc_count_ones_us | strict | stdc_count_ones_us_zero [strict] | C23 7.18a.4.9 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_zeros_uc::hardened::stdc_count_zeros_uc_sparse` | stdbit/ops | stdc_count_zeros_uc | hardened | stdc_count_zeros_uc_sparse [hardened] | C23 7.18a.4.10 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_zeros_uc::hardened::stdc_count_zeros_uc_zero` | stdbit/ops | stdc_count_zeros_uc | hardened | stdc_count_zeros_uc_zero [hardened] | C23 7.18a.4.10 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_zeros_uc::strict::stdc_count_zeros_uc_sparse` | stdbit/ops | stdc_count_zeros_uc | strict | stdc_count_zeros_uc_sparse [strict] | C23 7.18a.4.10 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_zeros_uc::strict::stdc_count_zeros_uc_zero` | stdbit/ops | stdc_count_zeros_uc | strict | stdc_count_zeros_uc_zero [strict] | C23 7.18a.4.10 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_zeros_ui::hardened::stdc_count_zeros_ui_sparse` | stdbit/ops | stdc_count_zeros_ui | hardened | stdc_count_zeros_ui_sparse [hardened] | C23 7.18a.4.10 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_zeros_ui::hardened::stdc_count_zeros_ui_zero` | stdbit/ops | stdc_count_zeros_ui | hardened | stdc_count_zeros_ui_zero [hardened] | C23 7.18a.4.10 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_zeros_ui::strict::stdc_count_zeros_ui_sparse` | stdbit/ops | stdc_count_zeros_ui | strict | stdc_count_zeros_ui_sparse [strict] | C23 7.18a.4.10 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_zeros_ui::strict::stdc_count_zeros_ui_zero` | stdbit/ops | stdc_count_zeros_ui | strict | stdc_count_zeros_ui_zero [strict] | C23 7.18a.4.10 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_zeros_ul::hardened::stdc_count_zeros_ul_sparse` | stdbit/ops | stdc_count_zeros_ul | hardened | stdc_count_zeros_ul_sparse [hardened] | C23 7.18a.4.10 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_zeros_ul::hardened::stdc_count_zeros_ul_zero` | stdbit/ops | stdc_count_zeros_ul | hardened | stdc_count_zeros_ul_zero [hardened] | C23 7.18a.4.10 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_zeros_ul::strict::stdc_count_zeros_ul_sparse` | stdbit/ops | stdc_count_zeros_ul | strict | stdc_count_zeros_ul_sparse [strict] | C23 7.18a.4.10 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_zeros_ul::strict::stdc_count_zeros_ul_zero` | stdbit/ops | stdc_count_zeros_ul | strict | stdc_count_zeros_ul_zero [strict] | C23 7.18a.4.10 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_zeros_ull::hardened::stdc_count_zeros_ull_sparse` | stdbit/ops | stdc_count_zeros_ull | hardened | stdc_count_zeros_ull_sparse [hardened] | C23 7.18a.4.10 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_zeros_ull::hardened::stdc_count_zeros_ull_zero` | stdbit/ops | stdc_count_zeros_ull | hardened | stdc_count_zeros_ull_zero [hardened] | C23 7.18a.4.10 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_zeros_ull::strict::stdc_count_zeros_ull_sparse` | stdbit/ops | stdc_count_zeros_ull | strict | stdc_count_zeros_ull_sparse [strict] | C23 7.18a.4.10 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_zeros_ull::strict::stdc_count_zeros_ull_zero` | stdbit/ops | stdc_count_zeros_ull | strict | stdc_count_zeros_ull_zero [strict] | C23 7.18a.4.10 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_zeros_us::hardened::stdc_count_zeros_us_sparse` | stdbit/ops | stdc_count_zeros_us | hardened | stdc_count_zeros_us_sparse [hardened] | C23 7.18a.4.10 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_zeros_us::hardened::stdc_count_zeros_us_zero` | stdbit/ops | stdc_count_zeros_us | hardened | stdc_count_zeros_us_zero [hardened] | C23 7.18a.4.10 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_zeros_us::strict::stdc_count_zeros_us_sparse` | stdbit/ops | stdc_count_zeros_us | strict | stdc_count_zeros_us_sparse [strict] | C23 7.18a.4.10 | PASS |
| `fixture-verify::stdbit/ops::stdc_count_zeros_us::strict::stdc_count_zeros_us_zero` | stdbit/ops | stdc_count_zeros_us | strict | stdc_count_zeros_us_zero [strict] | C23 7.18a.4.10 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_one_uc::hardened::stdc_first_leading_one_uc_sparse` | stdbit/ops | stdc_first_leading_one_uc | hardened | stdc_first_leading_one_uc_sparse [hardened] | C23 7.18a.4.6 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_one_uc::hardened::stdc_first_leading_one_uc_zero` | stdbit/ops | stdc_first_leading_one_uc | hardened | stdc_first_leading_one_uc_zero [hardened] | C23 7.18a.4.6 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_one_uc::strict::stdc_first_leading_one_uc_sparse` | stdbit/ops | stdc_first_leading_one_uc | strict | stdc_first_leading_one_uc_sparse [strict] | C23 7.18a.4.6 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_one_uc::strict::stdc_first_leading_one_uc_zero` | stdbit/ops | stdc_first_leading_one_uc | strict | stdc_first_leading_one_uc_zero [strict] | C23 7.18a.4.6 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_one_ui::hardened::stdc_first_leading_one_ui_sparse` | stdbit/ops | stdc_first_leading_one_ui | hardened | stdc_first_leading_one_ui_sparse [hardened] | C23 7.18a.4.6 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_one_ui::hardened::stdc_first_leading_one_ui_zero` | stdbit/ops | stdc_first_leading_one_ui | hardened | stdc_first_leading_one_ui_zero [hardened] | C23 7.18a.4.6 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_one_ui::strict::stdc_first_leading_one_ui_sparse` | stdbit/ops | stdc_first_leading_one_ui | strict | stdc_first_leading_one_ui_sparse [strict] | C23 7.18a.4.6 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_one_ui::strict::stdc_first_leading_one_ui_zero` | stdbit/ops | stdc_first_leading_one_ui | strict | stdc_first_leading_one_ui_zero [strict] | C23 7.18a.4.6 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_one_ul::hardened::stdc_first_leading_one_ul_sparse` | stdbit/ops | stdc_first_leading_one_ul | hardened | stdc_first_leading_one_ul_sparse [hardened] | C23 7.18a.4.6 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_one_ul::hardened::stdc_first_leading_one_ul_zero` | stdbit/ops | stdc_first_leading_one_ul | hardened | stdc_first_leading_one_ul_zero [hardened] | C23 7.18a.4.6 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_one_ul::strict::stdc_first_leading_one_ul_sparse` | stdbit/ops | stdc_first_leading_one_ul | strict | stdc_first_leading_one_ul_sparse [strict] | C23 7.18a.4.6 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_one_ul::strict::stdc_first_leading_one_ul_zero` | stdbit/ops | stdc_first_leading_one_ul | strict | stdc_first_leading_one_ul_zero [strict] | C23 7.18a.4.6 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_one_ull::hardened::stdc_first_leading_one_ull_sparse` | stdbit/ops | stdc_first_leading_one_ull | hardened | stdc_first_leading_one_ull_sparse [hardened] | C23 7.18a.4.6 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_one_ull::hardened::stdc_first_leading_one_ull_zero` | stdbit/ops | stdc_first_leading_one_ull | hardened | stdc_first_leading_one_ull_zero [hardened] | C23 7.18a.4.6 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_one_ull::strict::stdc_first_leading_one_ull_sparse` | stdbit/ops | stdc_first_leading_one_ull | strict | stdc_first_leading_one_ull_sparse [strict] | C23 7.18a.4.6 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_one_ull::strict::stdc_first_leading_one_ull_zero` | stdbit/ops | stdc_first_leading_one_ull | strict | stdc_first_leading_one_ull_zero [strict] | C23 7.18a.4.6 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_one_us::hardened::stdc_first_leading_one_us_sparse` | stdbit/ops | stdc_first_leading_one_us | hardened | stdc_first_leading_one_us_sparse [hardened] | C23 7.18a.4.6 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_one_us::hardened::stdc_first_leading_one_us_zero` | stdbit/ops | stdc_first_leading_one_us | hardened | stdc_first_leading_one_us_zero [hardened] | C23 7.18a.4.6 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_one_us::strict::stdc_first_leading_one_us_sparse` | stdbit/ops | stdc_first_leading_one_us | strict | stdc_first_leading_one_us_sparse [strict] | C23 7.18a.4.6 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_one_us::strict::stdc_first_leading_one_us_zero` | stdbit/ops | stdc_first_leading_one_us | strict | stdc_first_leading_one_us_zero [strict] | C23 7.18a.4.6 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_zero_uc::hardened::stdc_first_leading_zero_uc_top_nibble` | stdbit/ops | stdc_first_leading_zero_uc | hardened | stdc_first_leading_zero_uc_top_nibble [hardened] | C23 7.18a.4.5 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_zero_uc::hardened::stdc_first_leading_zero_uc_zero` | stdbit/ops | stdc_first_leading_zero_uc | hardened | stdc_first_leading_zero_uc_zero [hardened] | C23 7.18a.4.5 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_zero_uc::strict::stdc_first_leading_zero_uc_top_nibble` | stdbit/ops | stdc_first_leading_zero_uc | strict | stdc_first_leading_zero_uc_top_nibble [strict] | C23 7.18a.4.5 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_zero_uc::strict::stdc_first_leading_zero_uc_zero` | stdbit/ops | stdc_first_leading_zero_uc | strict | stdc_first_leading_zero_uc_zero [strict] | C23 7.18a.4.5 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_zero_ui::hardened::stdc_first_leading_zero_ui_top_nibble` | stdbit/ops | stdc_first_leading_zero_ui | hardened | stdc_first_leading_zero_ui_top_nibble [hardened] | C23 7.18a.4.5 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_zero_ui::hardened::stdc_first_leading_zero_ui_zero` | stdbit/ops | stdc_first_leading_zero_ui | hardened | stdc_first_leading_zero_ui_zero [hardened] | C23 7.18a.4.5 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_zero_ui::strict::stdc_first_leading_zero_ui_top_nibble` | stdbit/ops | stdc_first_leading_zero_ui | strict | stdc_first_leading_zero_ui_top_nibble [strict] | C23 7.18a.4.5 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_zero_ui::strict::stdc_first_leading_zero_ui_zero` | stdbit/ops | stdc_first_leading_zero_ui | strict | stdc_first_leading_zero_ui_zero [strict] | C23 7.18a.4.5 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_zero_ul::hardened::stdc_first_leading_zero_ul_top_nibble` | stdbit/ops | stdc_first_leading_zero_ul | hardened | stdc_first_leading_zero_ul_top_nibble [hardened] | C23 7.18a.4.5 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_zero_ul::hardened::stdc_first_leading_zero_ul_zero` | stdbit/ops | stdc_first_leading_zero_ul | hardened | stdc_first_leading_zero_ul_zero [hardened] | C23 7.18a.4.5 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_zero_ul::strict::stdc_first_leading_zero_ul_top_nibble` | stdbit/ops | stdc_first_leading_zero_ul | strict | stdc_first_leading_zero_ul_top_nibble [strict] | C23 7.18a.4.5 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_zero_ul::strict::stdc_first_leading_zero_ul_zero` | stdbit/ops | stdc_first_leading_zero_ul | strict | stdc_first_leading_zero_ul_zero [strict] | C23 7.18a.4.5 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_zero_ull::hardened::stdc_first_leading_zero_ull_top_nibble` | stdbit/ops | stdc_first_leading_zero_ull | hardened | stdc_first_leading_zero_ull_top_nibble [hardened] | C23 7.18a.4.5 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_zero_ull::hardened::stdc_first_leading_zero_ull_zero` | stdbit/ops | stdc_first_leading_zero_ull | hardened | stdc_first_leading_zero_ull_zero [hardened] | C23 7.18a.4.5 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_zero_ull::strict::stdc_first_leading_zero_ull_top_nibble` | stdbit/ops | stdc_first_leading_zero_ull | strict | stdc_first_leading_zero_ull_top_nibble [strict] | C23 7.18a.4.5 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_zero_ull::strict::stdc_first_leading_zero_ull_zero` | stdbit/ops | stdc_first_leading_zero_ull | strict | stdc_first_leading_zero_ull_zero [strict] | C23 7.18a.4.5 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_zero_us::hardened::stdc_first_leading_zero_us_top_nibble` | stdbit/ops | stdc_first_leading_zero_us | hardened | stdc_first_leading_zero_us_top_nibble [hardened] | C23 7.18a.4.5 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_zero_us::hardened::stdc_first_leading_zero_us_zero` | stdbit/ops | stdc_first_leading_zero_us | hardened | stdc_first_leading_zero_us_zero [hardened] | C23 7.18a.4.5 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_zero_us::strict::stdc_first_leading_zero_us_top_nibble` | stdbit/ops | stdc_first_leading_zero_us | strict | stdc_first_leading_zero_us_top_nibble [strict] | C23 7.18a.4.5 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_leading_zero_us::strict::stdc_first_leading_zero_us_zero` | stdbit/ops | stdc_first_leading_zero_us | strict | stdc_first_leading_zero_us_zero [strict] | C23 7.18a.4.5 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_one_uc::hardened::stdc_first_trailing_one_uc_shifted` | stdbit/ops | stdc_first_trailing_one_uc | hardened | stdc_first_trailing_one_uc_shifted [hardened] | C23 7.18a.4.8 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_one_uc::hardened::stdc_first_trailing_one_uc_zero` | stdbit/ops | stdc_first_trailing_one_uc | hardened | stdc_first_trailing_one_uc_zero [hardened] | C23 7.18a.4.8 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_one_uc::strict::stdc_first_trailing_one_uc_shifted` | stdbit/ops | stdc_first_trailing_one_uc | strict | stdc_first_trailing_one_uc_shifted [strict] | C23 7.18a.4.8 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_one_uc::strict::stdc_first_trailing_one_uc_zero` | stdbit/ops | stdc_first_trailing_one_uc | strict | stdc_first_trailing_one_uc_zero [strict] | C23 7.18a.4.8 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_one_ui::hardened::stdc_first_trailing_one_ui_shifted` | stdbit/ops | stdc_first_trailing_one_ui | hardened | stdc_first_trailing_one_ui_shifted [hardened] | C23 7.18a.4.8 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_one_ui::hardened::stdc_first_trailing_one_ui_zero` | stdbit/ops | stdc_first_trailing_one_ui | hardened | stdc_first_trailing_one_ui_zero [hardened] | C23 7.18a.4.8 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_one_ui::strict::stdc_first_trailing_one_ui_shifted` | stdbit/ops | stdc_first_trailing_one_ui | strict | stdc_first_trailing_one_ui_shifted [strict] | C23 7.18a.4.8 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_one_ui::strict::stdc_first_trailing_one_ui_zero` | stdbit/ops | stdc_first_trailing_one_ui | strict | stdc_first_trailing_one_ui_zero [strict] | C23 7.18a.4.8 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_one_ul::hardened::stdc_first_trailing_one_ul_shifted` | stdbit/ops | stdc_first_trailing_one_ul | hardened | stdc_first_trailing_one_ul_shifted [hardened] | C23 7.18a.4.8 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_one_ul::hardened::stdc_first_trailing_one_ul_zero` | stdbit/ops | stdc_first_trailing_one_ul | hardened | stdc_first_trailing_one_ul_zero [hardened] | C23 7.18a.4.8 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_one_ul::strict::stdc_first_trailing_one_ul_shifted` | stdbit/ops | stdc_first_trailing_one_ul | strict | stdc_first_trailing_one_ul_shifted [strict] | C23 7.18a.4.8 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_one_ul::strict::stdc_first_trailing_one_ul_zero` | stdbit/ops | stdc_first_trailing_one_ul | strict | stdc_first_trailing_one_ul_zero [strict] | C23 7.18a.4.8 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_one_ull::hardened::stdc_first_trailing_one_ull_shifted` | stdbit/ops | stdc_first_trailing_one_ull | hardened | stdc_first_trailing_one_ull_shifted [hardened] | C23 7.18a.4.8 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_one_ull::hardened::stdc_first_trailing_one_ull_zero` | stdbit/ops | stdc_first_trailing_one_ull | hardened | stdc_first_trailing_one_ull_zero [hardened] | C23 7.18a.4.8 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_one_ull::strict::stdc_first_trailing_one_ull_shifted` | stdbit/ops | stdc_first_trailing_one_ull | strict | stdc_first_trailing_one_ull_shifted [strict] | C23 7.18a.4.8 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_one_ull::strict::stdc_first_trailing_one_ull_zero` | stdbit/ops | stdc_first_trailing_one_ull | strict | stdc_first_trailing_one_ull_zero [strict] | C23 7.18a.4.8 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_one_us::hardened::stdc_first_trailing_one_us_shifted` | stdbit/ops | stdc_first_trailing_one_us | hardened | stdc_first_trailing_one_us_shifted [hardened] | C23 7.18a.4.8 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_one_us::hardened::stdc_first_trailing_one_us_zero` | stdbit/ops | stdc_first_trailing_one_us | hardened | stdc_first_trailing_one_us_zero [hardened] | C23 7.18a.4.8 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_one_us::strict::stdc_first_trailing_one_us_shifted` | stdbit/ops | stdc_first_trailing_one_us | strict | stdc_first_trailing_one_us_shifted [strict] | C23 7.18a.4.8 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_one_us::strict::stdc_first_trailing_one_us_zero` | stdbit/ops | stdc_first_trailing_one_us | strict | stdc_first_trailing_one_us_zero [strict] | C23 7.18a.4.8 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_zero_uc::hardened::stdc_first_trailing_zero_uc_low_nibble` | stdbit/ops | stdc_first_trailing_zero_uc | hardened | stdc_first_trailing_zero_uc_low_nibble [hardened] | C23 7.18a.4.7 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_zero_uc::hardened::stdc_first_trailing_zero_uc_zero` | stdbit/ops | stdc_first_trailing_zero_uc | hardened | stdc_first_trailing_zero_uc_zero [hardened] | C23 7.18a.4.7 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_zero_uc::strict::stdc_first_trailing_zero_uc_low_nibble` | stdbit/ops | stdc_first_trailing_zero_uc | strict | stdc_first_trailing_zero_uc_low_nibble [strict] | C23 7.18a.4.7 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_zero_uc::strict::stdc_first_trailing_zero_uc_zero` | stdbit/ops | stdc_first_trailing_zero_uc | strict | stdc_first_trailing_zero_uc_zero [strict] | C23 7.18a.4.7 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_zero_ui::hardened::stdc_first_trailing_zero_ui_low_nibble` | stdbit/ops | stdc_first_trailing_zero_ui | hardened | stdc_first_trailing_zero_ui_low_nibble [hardened] | C23 7.18a.4.7 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_zero_ui::hardened::stdc_first_trailing_zero_ui_zero` | stdbit/ops | stdc_first_trailing_zero_ui | hardened | stdc_first_trailing_zero_ui_zero [hardened] | C23 7.18a.4.7 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_zero_ui::strict::stdc_first_trailing_zero_ui_low_nibble` | stdbit/ops | stdc_first_trailing_zero_ui | strict | stdc_first_trailing_zero_ui_low_nibble [strict] | C23 7.18a.4.7 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_zero_ui::strict::stdc_first_trailing_zero_ui_zero` | stdbit/ops | stdc_first_trailing_zero_ui | strict | stdc_first_trailing_zero_ui_zero [strict] | C23 7.18a.4.7 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_zero_ul::hardened::stdc_first_trailing_zero_ul_low_nibble` | stdbit/ops | stdc_first_trailing_zero_ul | hardened | stdc_first_trailing_zero_ul_low_nibble [hardened] | C23 7.18a.4.7 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_zero_ul::hardened::stdc_first_trailing_zero_ul_zero` | stdbit/ops | stdc_first_trailing_zero_ul | hardened | stdc_first_trailing_zero_ul_zero [hardened] | C23 7.18a.4.7 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_zero_ul::strict::stdc_first_trailing_zero_ul_low_nibble` | stdbit/ops | stdc_first_trailing_zero_ul | strict | stdc_first_trailing_zero_ul_low_nibble [strict] | C23 7.18a.4.7 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_zero_ul::strict::stdc_first_trailing_zero_ul_zero` | stdbit/ops | stdc_first_trailing_zero_ul | strict | stdc_first_trailing_zero_ul_zero [strict] | C23 7.18a.4.7 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_zero_ull::hardened::stdc_first_trailing_zero_ull_low_nibble` | stdbit/ops | stdc_first_trailing_zero_ull | hardened | stdc_first_trailing_zero_ull_low_nibble [hardened] | C23 7.18a.4.7 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_zero_ull::hardened::stdc_first_trailing_zero_ull_zero` | stdbit/ops | stdc_first_trailing_zero_ull | hardened | stdc_first_trailing_zero_ull_zero [hardened] | C23 7.18a.4.7 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_zero_ull::strict::stdc_first_trailing_zero_ull_low_nibble` | stdbit/ops | stdc_first_trailing_zero_ull | strict | stdc_first_trailing_zero_ull_low_nibble [strict] | C23 7.18a.4.7 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_zero_ull::strict::stdc_first_trailing_zero_ull_zero` | stdbit/ops | stdc_first_trailing_zero_ull | strict | stdc_first_trailing_zero_ull_zero [strict] | C23 7.18a.4.7 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_zero_us::hardened::stdc_first_trailing_zero_us_low_nibble` | stdbit/ops | stdc_first_trailing_zero_us | hardened | stdc_first_trailing_zero_us_low_nibble [hardened] | C23 7.18a.4.7 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_zero_us::hardened::stdc_first_trailing_zero_us_zero` | stdbit/ops | stdc_first_trailing_zero_us | hardened | stdc_first_trailing_zero_us_zero [hardened] | C23 7.18a.4.7 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_zero_us::strict::stdc_first_trailing_zero_us_low_nibble` | stdbit/ops | stdc_first_trailing_zero_us | strict | stdc_first_trailing_zero_us_low_nibble [strict] | C23 7.18a.4.7 | PASS |
| `fixture-verify::stdbit/ops::stdc_first_trailing_zero_us::strict::stdc_first_trailing_zero_us_zero` | stdbit/ops | stdc_first_trailing_zero_us | strict | stdc_first_trailing_zero_us_zero [strict] | C23 7.18a.4.7 | PASS |
| `fixture-verify::stdbit/ops::stdc_has_single_bit_uc::hardened::stdc_has_single_bit_uc_power` | stdbit/ops | stdc_has_single_bit_uc | hardened | stdc_has_single_bit_uc_power [hardened] | C23 7.18a.4.11 | PASS |
| `fixture-verify::stdbit/ops::stdc_has_single_bit_uc::hardened::stdc_has_single_bit_uc_zero` | stdbit/ops | stdc_has_single_bit_uc | hardened | stdc_has_single_bit_uc_zero [hardened] | C23 7.18a.4.11 | PASS |
| `fixture-verify::stdbit/ops::stdc_has_single_bit_uc::strict::stdc_has_single_bit_uc_power` | stdbit/ops | stdc_has_single_bit_uc | strict | stdc_has_single_bit_uc_power [strict] | C23 7.18a.4.11 | PASS |
| `fixture-verify::stdbit/ops::stdc_has_single_bit_uc::strict::stdc_has_single_bit_uc_zero` | stdbit/ops | stdc_has_single_bit_uc | strict | stdc_has_single_bit_uc_zero [strict] | C23 7.18a.4.11 | PASS |
| `fixture-verify::stdbit/ops::stdc_has_single_bit_ui::hardened::stdc_has_single_bit_ui_power` | stdbit/ops | stdc_has_single_bit_ui | hardened | stdc_has_single_bit_ui_power [hardened] | C23 7.18a.4.11 | PASS |
| `fixture-verify::stdbit/ops::stdc_has_single_bit_ui::hardened::stdc_has_single_bit_ui_zero` | stdbit/ops | stdc_has_single_bit_ui | hardened | stdc_has_single_bit_ui_zero [hardened] | C23 7.18a.4.11 | PASS |
| `fixture-verify::stdbit/ops::stdc_has_single_bit_ui::strict::stdc_has_single_bit_ui_power` | stdbit/ops | stdc_has_single_bit_ui | strict | stdc_has_single_bit_ui_power [strict] | C23 7.18a.4.11 | PASS |
| `fixture-verify::stdbit/ops::stdc_has_single_bit_ui::strict::stdc_has_single_bit_ui_zero` | stdbit/ops | stdc_has_single_bit_ui | strict | stdc_has_single_bit_ui_zero [strict] | C23 7.18a.4.11 | PASS |
| `fixture-verify::stdbit/ops::stdc_has_single_bit_ul::hardened::stdc_has_single_bit_ul_power` | stdbit/ops | stdc_has_single_bit_ul | hardened | stdc_has_single_bit_ul_power [hardened] | C23 7.18a.4.11 | PASS |
| `fixture-verify::stdbit/ops::stdc_has_single_bit_ul::hardened::stdc_has_single_bit_ul_zero` | stdbit/ops | stdc_has_single_bit_ul | hardened | stdc_has_single_bit_ul_zero [hardened] | C23 7.18a.4.11 | PASS |
| `fixture-verify::stdbit/ops::stdc_has_single_bit_ul::strict::stdc_has_single_bit_ul_power` | stdbit/ops | stdc_has_single_bit_ul | strict | stdc_has_single_bit_ul_power [strict] | C23 7.18a.4.11 | PASS |
| `fixture-verify::stdbit/ops::stdc_has_single_bit_ul::strict::stdc_has_single_bit_ul_zero` | stdbit/ops | stdc_has_single_bit_ul | strict | stdc_has_single_bit_ul_zero [strict] | C23 7.18a.4.11 | PASS |
| `fixture-verify::stdbit/ops::stdc_has_single_bit_ull::hardened::stdc_has_single_bit_ull_power` | stdbit/ops | stdc_has_single_bit_ull | hardened | stdc_has_single_bit_ull_power [hardened] | C23 7.18a.4.11 | PASS |
| `fixture-verify::stdbit/ops::stdc_has_single_bit_ull::hardened::stdc_has_single_bit_ull_zero` | stdbit/ops | stdc_has_single_bit_ull | hardened | stdc_has_single_bit_ull_zero [hardened] | C23 7.18a.4.11 | PASS |
| `fixture-verify::stdbit/ops::stdc_has_single_bit_ull::strict::stdc_has_single_bit_ull_power` | stdbit/ops | stdc_has_single_bit_ull | strict | stdc_has_single_bit_ull_power [strict] | C23 7.18a.4.11 | PASS |
| `fixture-verify::stdbit/ops::stdc_has_single_bit_ull::strict::stdc_has_single_bit_ull_zero` | stdbit/ops | stdc_has_single_bit_ull | strict | stdc_has_single_bit_ull_zero [strict] | C23 7.18a.4.11 | PASS |
| `fixture-verify::stdbit/ops::stdc_has_single_bit_us::hardened::stdc_has_single_bit_us_power` | stdbit/ops | stdc_has_single_bit_us | hardened | stdc_has_single_bit_us_power [hardened] | C23 7.18a.4.11 | PASS |
| `fixture-verify::stdbit/ops::stdc_has_single_bit_us::hardened::stdc_has_single_bit_us_zero` | stdbit/ops | stdc_has_single_bit_us | hardened | stdc_has_single_bit_us_zero [hardened] | C23 7.18a.4.11 | PASS |
| `fixture-verify::stdbit/ops::stdc_has_single_bit_us::strict::stdc_has_single_bit_us_power` | stdbit/ops | stdc_has_single_bit_us | strict | stdc_has_single_bit_us_power [strict] | C23 7.18a.4.11 | PASS |
| `fixture-verify::stdbit/ops::stdc_has_single_bit_us::strict::stdc_has_single_bit_us_zero` | stdbit/ops | stdc_has_single_bit_us | strict | stdc_has_single_bit_us_zero [strict] | C23 7.18a.4.11 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_ones_uc::hardened::stdc_leading_ones_uc_top_nibble` | stdbit/ops | stdc_leading_ones_uc | hardened | stdc_leading_ones_uc_top_nibble [hardened] | C23 7.18a.4.2 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_ones_uc::hardened::stdc_leading_ones_uc_zero` | stdbit/ops | stdc_leading_ones_uc | hardened | stdc_leading_ones_uc_zero [hardened] | C23 7.18a.4.2 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_ones_uc::strict::stdc_leading_ones_uc_top_nibble` | stdbit/ops | stdc_leading_ones_uc | strict | stdc_leading_ones_uc_top_nibble [strict] | C23 7.18a.4.2 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_ones_uc::strict::stdc_leading_ones_uc_zero` | stdbit/ops | stdc_leading_ones_uc | strict | stdc_leading_ones_uc_zero [strict] | C23 7.18a.4.2 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_ones_ui::hardened::stdc_leading_ones_ui_top_nibble` | stdbit/ops | stdc_leading_ones_ui | hardened | stdc_leading_ones_ui_top_nibble [hardened] | C23 7.18a.4.2 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_ones_ui::hardened::stdc_leading_ones_ui_zero` | stdbit/ops | stdc_leading_ones_ui | hardened | stdc_leading_ones_ui_zero [hardened] | C23 7.18a.4.2 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_ones_ui::strict::stdc_leading_ones_ui_top_nibble` | stdbit/ops | stdc_leading_ones_ui | strict | stdc_leading_ones_ui_top_nibble [strict] | C23 7.18a.4.2 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_ones_ui::strict::stdc_leading_ones_ui_zero` | stdbit/ops | stdc_leading_ones_ui | strict | stdc_leading_ones_ui_zero [strict] | C23 7.18a.4.2 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_ones_ul::hardened::stdc_leading_ones_ul_top_nibble` | stdbit/ops | stdc_leading_ones_ul | hardened | stdc_leading_ones_ul_top_nibble [hardened] | C23 7.18a.4.2 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_ones_ul::hardened::stdc_leading_ones_ul_zero` | stdbit/ops | stdc_leading_ones_ul | hardened | stdc_leading_ones_ul_zero [hardened] | C23 7.18a.4.2 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_ones_ul::strict::stdc_leading_ones_ul_top_nibble` | stdbit/ops | stdc_leading_ones_ul | strict | stdc_leading_ones_ul_top_nibble [strict] | C23 7.18a.4.2 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_ones_ul::strict::stdc_leading_ones_ul_zero` | stdbit/ops | stdc_leading_ones_ul | strict | stdc_leading_ones_ul_zero [strict] | C23 7.18a.4.2 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_ones_ull::hardened::stdc_leading_ones_ull_top_nibble` | stdbit/ops | stdc_leading_ones_ull | hardened | stdc_leading_ones_ull_top_nibble [hardened] | C23 7.18a.4.2 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_ones_ull::hardened::stdc_leading_ones_ull_zero` | stdbit/ops | stdc_leading_ones_ull | hardened | stdc_leading_ones_ull_zero [hardened] | C23 7.18a.4.2 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_ones_ull::strict::stdc_leading_ones_ull_top_nibble` | stdbit/ops | stdc_leading_ones_ull | strict | stdc_leading_ones_ull_top_nibble [strict] | C23 7.18a.4.2 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_ones_ull::strict::stdc_leading_ones_ull_zero` | stdbit/ops | stdc_leading_ones_ull | strict | stdc_leading_ones_ull_zero [strict] | C23 7.18a.4.2 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_ones_us::hardened::stdc_leading_ones_us_top_nibble` | stdbit/ops | stdc_leading_ones_us | hardened | stdc_leading_ones_us_top_nibble [hardened] | C23 7.18a.4.2 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_ones_us::hardened::stdc_leading_ones_us_zero` | stdbit/ops | stdc_leading_ones_us | hardened | stdc_leading_ones_us_zero [hardened] | C23 7.18a.4.2 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_ones_us::strict::stdc_leading_ones_us_top_nibble` | stdbit/ops | stdc_leading_ones_us | strict | stdc_leading_ones_us_top_nibble [strict] | C23 7.18a.4.2 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_ones_us::strict::stdc_leading_ones_us_zero` | stdbit/ops | stdc_leading_ones_us | strict | stdc_leading_ones_us_zero [strict] | C23 7.18a.4.2 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_zeros_uc::hardened::stdc_leading_zeros_uc_sparse` | stdbit/ops | stdc_leading_zeros_uc | hardened | stdc_leading_zeros_uc_sparse [hardened] | C23 7.18a.4.1 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_zeros_uc::hardened::stdc_leading_zeros_uc_zero` | stdbit/ops | stdc_leading_zeros_uc | hardened | stdc_leading_zeros_uc_zero [hardened] | C23 7.18a.4.1 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_zeros_uc::strict::stdc_leading_zeros_uc_sparse` | stdbit/ops | stdc_leading_zeros_uc | strict | stdc_leading_zeros_uc_sparse [strict] | C23 7.18a.4.1 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_zeros_uc::strict::stdc_leading_zeros_uc_zero` | stdbit/ops | stdc_leading_zeros_uc | strict | stdc_leading_zeros_uc_zero [strict] | C23 7.18a.4.1 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_zeros_ui::hardened::stdc_leading_zeros_ui_sparse` | stdbit/ops | stdc_leading_zeros_ui | hardened | stdc_leading_zeros_ui_sparse [hardened] | C23 7.18a.4.1 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_zeros_ui::hardened::stdc_leading_zeros_ui_zero` | stdbit/ops | stdc_leading_zeros_ui | hardened | stdc_leading_zeros_ui_zero [hardened] | C23 7.18a.4.1 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_zeros_ui::strict::stdc_leading_zeros_ui_sparse` | stdbit/ops | stdc_leading_zeros_ui | strict | stdc_leading_zeros_ui_sparse [strict] | C23 7.18a.4.1 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_zeros_ui::strict::stdc_leading_zeros_ui_zero` | stdbit/ops | stdc_leading_zeros_ui | strict | stdc_leading_zeros_ui_zero [strict] | C23 7.18a.4.1 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_zeros_ul::hardened::stdc_leading_zeros_ul_sparse` | stdbit/ops | stdc_leading_zeros_ul | hardened | stdc_leading_zeros_ul_sparse [hardened] | C23 7.18a.4.1 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_zeros_ul::hardened::stdc_leading_zeros_ul_zero` | stdbit/ops | stdc_leading_zeros_ul | hardened | stdc_leading_zeros_ul_zero [hardened] | C23 7.18a.4.1 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_zeros_ul::strict::stdc_leading_zeros_ul_sparse` | stdbit/ops | stdc_leading_zeros_ul | strict | stdc_leading_zeros_ul_sparse [strict] | C23 7.18a.4.1 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_zeros_ul::strict::stdc_leading_zeros_ul_zero` | stdbit/ops | stdc_leading_zeros_ul | strict | stdc_leading_zeros_ul_zero [strict] | C23 7.18a.4.1 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_zeros_ull::hardened::stdc_leading_zeros_ull_sparse` | stdbit/ops | stdc_leading_zeros_ull | hardened | stdc_leading_zeros_ull_sparse [hardened] | C23 7.18a.4.1 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_zeros_ull::hardened::stdc_leading_zeros_ull_zero` | stdbit/ops | stdc_leading_zeros_ull | hardened | stdc_leading_zeros_ull_zero [hardened] | C23 7.18a.4.1 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_zeros_ull::strict::stdc_leading_zeros_ull_sparse` | stdbit/ops | stdc_leading_zeros_ull | strict | stdc_leading_zeros_ull_sparse [strict] | C23 7.18a.4.1 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_zeros_ull::strict::stdc_leading_zeros_ull_zero` | stdbit/ops | stdc_leading_zeros_ull | strict | stdc_leading_zeros_ull_zero [strict] | C23 7.18a.4.1 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_zeros_us::hardened::stdc_leading_zeros_us_sparse` | stdbit/ops | stdc_leading_zeros_us | hardened | stdc_leading_zeros_us_sparse [hardened] | C23 7.18a.4.1 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_zeros_us::hardened::stdc_leading_zeros_us_zero` | stdbit/ops | stdc_leading_zeros_us | hardened | stdc_leading_zeros_us_zero [hardened] | C23 7.18a.4.1 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_zeros_us::strict::stdc_leading_zeros_us_sparse` | stdbit/ops | stdc_leading_zeros_us | strict | stdc_leading_zeros_us_sparse [strict] | C23 7.18a.4.1 | PASS |
| `fixture-verify::stdbit/ops::stdc_leading_zeros_us::strict::stdc_leading_zeros_us_zero` | stdbit/ops | stdc_leading_zeros_us | strict | stdc_leading_zeros_us_zero [strict] | C23 7.18a.4.1 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_ones_uc::hardened::stdc_trailing_ones_uc_low_nibble` | stdbit/ops | stdc_trailing_ones_uc | hardened | stdc_trailing_ones_uc_low_nibble [hardened] | C23 7.18a.4.4 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_ones_uc::hardened::stdc_trailing_ones_uc_zero` | stdbit/ops | stdc_trailing_ones_uc | hardened | stdc_trailing_ones_uc_zero [hardened] | C23 7.18a.4.4 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_ones_uc::strict::stdc_trailing_ones_uc_low_nibble` | stdbit/ops | stdc_trailing_ones_uc | strict | stdc_trailing_ones_uc_low_nibble [strict] | C23 7.18a.4.4 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_ones_uc::strict::stdc_trailing_ones_uc_zero` | stdbit/ops | stdc_trailing_ones_uc | strict | stdc_trailing_ones_uc_zero [strict] | C23 7.18a.4.4 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_ones_ui::hardened::stdc_trailing_ones_ui_low_nibble` | stdbit/ops | stdc_trailing_ones_ui | hardened | stdc_trailing_ones_ui_low_nibble [hardened] | C23 7.18a.4.4 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_ones_ui::hardened::stdc_trailing_ones_ui_zero` | stdbit/ops | stdc_trailing_ones_ui | hardened | stdc_trailing_ones_ui_zero [hardened] | C23 7.18a.4.4 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_ones_ui::strict::stdc_trailing_ones_ui_low_nibble` | stdbit/ops | stdc_trailing_ones_ui | strict | stdc_trailing_ones_ui_low_nibble [strict] | C23 7.18a.4.4 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_ones_ui::strict::stdc_trailing_ones_ui_zero` | stdbit/ops | stdc_trailing_ones_ui | strict | stdc_trailing_ones_ui_zero [strict] | C23 7.18a.4.4 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_ones_ul::hardened::stdc_trailing_ones_ul_low_nibble` | stdbit/ops | stdc_trailing_ones_ul | hardened | stdc_trailing_ones_ul_low_nibble [hardened] | C23 7.18a.4.4 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_ones_ul::hardened::stdc_trailing_ones_ul_zero` | stdbit/ops | stdc_trailing_ones_ul | hardened | stdc_trailing_ones_ul_zero [hardened] | C23 7.18a.4.4 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_ones_ul::strict::stdc_trailing_ones_ul_low_nibble` | stdbit/ops | stdc_trailing_ones_ul | strict | stdc_trailing_ones_ul_low_nibble [strict] | C23 7.18a.4.4 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_ones_ul::strict::stdc_trailing_ones_ul_zero` | stdbit/ops | stdc_trailing_ones_ul | strict | stdc_trailing_ones_ul_zero [strict] | C23 7.18a.4.4 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_ones_ull::hardened::stdc_trailing_ones_ull_low_nibble` | stdbit/ops | stdc_trailing_ones_ull | hardened | stdc_trailing_ones_ull_low_nibble [hardened] | C23 7.18a.4.4 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_ones_ull::hardened::stdc_trailing_ones_ull_zero` | stdbit/ops | stdc_trailing_ones_ull | hardened | stdc_trailing_ones_ull_zero [hardened] | C23 7.18a.4.4 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_ones_ull::strict::stdc_trailing_ones_ull_low_nibble` | stdbit/ops | stdc_trailing_ones_ull | strict | stdc_trailing_ones_ull_low_nibble [strict] | C23 7.18a.4.4 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_ones_ull::strict::stdc_trailing_ones_ull_zero` | stdbit/ops | stdc_trailing_ones_ull | strict | stdc_trailing_ones_ull_zero [strict] | C23 7.18a.4.4 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_ones_us::hardened::stdc_trailing_ones_us_low_nibble` | stdbit/ops | stdc_trailing_ones_us | hardened | stdc_trailing_ones_us_low_nibble [hardened] | C23 7.18a.4.4 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_ones_us::hardened::stdc_trailing_ones_us_zero` | stdbit/ops | stdc_trailing_ones_us | hardened | stdc_trailing_ones_us_zero [hardened] | C23 7.18a.4.4 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_ones_us::strict::stdc_trailing_ones_us_low_nibble` | stdbit/ops | stdc_trailing_ones_us | strict | stdc_trailing_ones_us_low_nibble [strict] | C23 7.18a.4.4 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_ones_us::strict::stdc_trailing_ones_us_zero` | stdbit/ops | stdc_trailing_ones_us | strict | stdc_trailing_ones_us_zero [strict] | C23 7.18a.4.4 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_zeros_uc::hardened::stdc_trailing_zeros_uc_shifted` | stdbit/ops | stdc_trailing_zeros_uc | hardened | stdc_trailing_zeros_uc_shifted [hardened] | C23 7.18a.4.3 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_zeros_uc::hardened::stdc_trailing_zeros_uc_zero` | stdbit/ops | stdc_trailing_zeros_uc | hardened | stdc_trailing_zeros_uc_zero [hardened] | C23 7.18a.4.3 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_zeros_uc::strict::stdc_trailing_zeros_uc_shifted` | stdbit/ops | stdc_trailing_zeros_uc | strict | stdc_trailing_zeros_uc_shifted [strict] | C23 7.18a.4.3 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_zeros_uc::strict::stdc_trailing_zeros_uc_zero` | stdbit/ops | stdc_trailing_zeros_uc | strict | stdc_trailing_zeros_uc_zero [strict] | C23 7.18a.4.3 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_zeros_ui::hardened::stdc_trailing_zeros_ui_shifted` | stdbit/ops | stdc_trailing_zeros_ui | hardened | stdc_trailing_zeros_ui_shifted [hardened] | C23 7.18a.4.3 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_zeros_ui::hardened::stdc_trailing_zeros_ui_zero` | stdbit/ops | stdc_trailing_zeros_ui | hardened | stdc_trailing_zeros_ui_zero [hardened] | C23 7.18a.4.3 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_zeros_ui::strict::stdc_trailing_zeros_ui_shifted` | stdbit/ops | stdc_trailing_zeros_ui | strict | stdc_trailing_zeros_ui_shifted [strict] | C23 7.18a.4.3 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_zeros_ui::strict::stdc_trailing_zeros_ui_zero` | stdbit/ops | stdc_trailing_zeros_ui | strict | stdc_trailing_zeros_ui_zero [strict] | C23 7.18a.4.3 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_zeros_ul::hardened::stdc_trailing_zeros_ul_shifted` | stdbit/ops | stdc_trailing_zeros_ul | hardened | stdc_trailing_zeros_ul_shifted [hardened] | C23 7.18a.4.3 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_zeros_ul::hardened::stdc_trailing_zeros_ul_zero` | stdbit/ops | stdc_trailing_zeros_ul | hardened | stdc_trailing_zeros_ul_zero [hardened] | C23 7.18a.4.3 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_zeros_ul::strict::stdc_trailing_zeros_ul_shifted` | stdbit/ops | stdc_trailing_zeros_ul | strict | stdc_trailing_zeros_ul_shifted [strict] | C23 7.18a.4.3 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_zeros_ul::strict::stdc_trailing_zeros_ul_zero` | stdbit/ops | stdc_trailing_zeros_ul | strict | stdc_trailing_zeros_ul_zero [strict] | C23 7.18a.4.3 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_zeros_ull::hardened::stdc_trailing_zeros_ull_shifted` | stdbit/ops | stdc_trailing_zeros_ull | hardened | stdc_trailing_zeros_ull_shifted [hardened] | C23 7.18a.4.3 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_zeros_ull::hardened::stdc_trailing_zeros_ull_zero` | stdbit/ops | stdc_trailing_zeros_ull | hardened | stdc_trailing_zeros_ull_zero [hardened] | C23 7.18a.4.3 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_zeros_ull::strict::stdc_trailing_zeros_ull_shifted` | stdbit/ops | stdc_trailing_zeros_ull | strict | stdc_trailing_zeros_ull_shifted [strict] | C23 7.18a.4.3 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_zeros_ull::strict::stdc_trailing_zeros_ull_zero` | stdbit/ops | stdc_trailing_zeros_ull | strict | stdc_trailing_zeros_ull_zero [strict] | C23 7.18a.4.3 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_zeros_us::hardened::stdc_trailing_zeros_us_shifted` | stdbit/ops | stdc_trailing_zeros_us | hardened | stdc_trailing_zeros_us_shifted [hardened] | C23 7.18a.4.3 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_zeros_us::hardened::stdc_trailing_zeros_us_zero` | stdbit/ops | stdc_trailing_zeros_us | hardened | stdc_trailing_zeros_us_zero [hardened] | C23 7.18a.4.3 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_zeros_us::strict::stdc_trailing_zeros_us_shifted` | stdbit/ops | stdc_trailing_zeros_us | strict | stdc_trailing_zeros_us_shifted [strict] | C23 7.18a.4.3 | PASS |
| `fixture-verify::stdbit/ops::stdc_trailing_zeros_us::strict::stdc_trailing_zeros_us_zero` | stdbit/ops | stdc_trailing_zeros_us | strict | stdc_trailing_zeros_us_zero [strict] | C23 7.18a.4.3 | PASS |
| `fixture-verify::stdio_file_ops::asprintf::hardened::asprintf_literal_hardened` | stdio_file_ops | asprintf | hardened | asprintf_literal_hardened | GNU asprintf | PASS |
| `fixture-verify::stdio_file_ops::asprintf::strict::asprintf_literal_strict` | stdio_file_ops | asprintf | strict | asprintf_literal_strict | GNU asprintf | PASS |
| `fixture-verify::stdio_file_ops::dprintf::hardened::dprintf_literal_hardened` | stdio_file_ops | dprintf | hardened | dprintf_literal_hardened | POSIX dprintf | PASS |
| `fixture-verify::stdio_file_ops::dprintf::strict::dprintf_literal_strict` | stdio_file_ops | dprintf | strict | dprintf_literal_strict | POSIX dprintf | PASS |
| `fixture-verify::stdio_file_ops::fclose::strict::fclose_valid_strict` | stdio_file_ops | fclose | strict | fclose_valid_strict | C11 7.21.5.1 fclose | PASS |
| `fixture-verify::stdio_file_ops::feof::strict::feof_devnull_read_after_eof_strict` | stdio_file_ops | feof | strict | feof_devnull_read_after_eof_strict | C11 7.21.10.2 feof | PASS |
| `fixture-verify::stdio_file_ops::feof::strict::feof_devnull_read_no_read_strict` | stdio_file_ops | feof | strict | feof_devnull_read_no_read_strict | C11 7.21.10.2 feof | PASS |
| `fixture-verify::stdio_file_ops::ferror::hardened::ferror_devzero_hardened` | stdio_file_ops | ferror | hardened | ferror_devzero_hardened | C11 7.21.10.3 ferror | PASS |
| `fixture-verify::stdio_file_ops::ferror::strict::ferror_devnull_no_error_strict` | stdio_file_ops | ferror | strict | ferror_devnull_no_error_strict | C11 7.21.10.3 ferror | PASS |
| `fixture-verify::stdio_file_ops::fflush::hardened::fflush_devnull_hardened` | stdio_file_ops | fflush | hardened | fflush_devnull_hardened | C11 7.21.5.2 fflush | PASS |
| `fixture-verify::stdio_file_ops::fflush::strict::fflush_devnull_strict` | stdio_file_ops | fflush | strict | fflush_devnull_strict | C11 7.21.5.2 fflush | PASS |
| `fixture-verify::stdio_file_ops::fgetc::hardened::fgetc_devzero_hardened` | stdio_file_ops | fgetc | hardened | fgetc_devzero_hardened | C11 7.21.7.1 fgetc | PASS |
| `fixture-verify::stdio_file_ops::fgetc::strict::fgetc_devnull_read_strict` | stdio_file_ops | fgetc | strict | fgetc_devnull_read_strict | C11 7.21.7.1 fgetc | PASS |
| `fixture-verify::stdio_file_ops::fgetc::strict::fgetc_devzero_strict` | stdio_file_ops | fgetc | strict | fgetc_devzero_strict | C11 7.21.7.1 fgetc | PASS |
| `fixture-verify::stdio_file_ops::fgets::hardened::fgets_devnull_eof_hardened` | stdio_file_ops | fgets | hardened | fgets_devnull_eof_hardened | C11 7.21.7.2 fgets | PASS |
| `fixture-verify::stdio_file_ops::fgets::strict::fgets_devnull_eof_strict` | stdio_file_ops | fgets | strict | fgets_devnull_eof_strict | C11 7.21.7.2 fgets | PASS |
| `fixture-verify::stdio_file_ops::fileno::hardened::fileno_devnull_hardened` | stdio_file_ops | fileno | hardened | fileno_devnull_hardened | POSIX.1-2017 fileno | PASS |
| `fixture-verify::stdio_file_ops::fileno::strict::fileno_devnull_strict` | stdio_file_ops | fileno | strict | fileno_devnull_strict | POSIX.1-2017 fileno | PASS |
| `fixture-verify::stdio_file_ops::fileno::strict::fileno_devzero_strict` | stdio_file_ops | fileno | strict | fileno_devzero_strict | POSIX.1-2017 fileno | PASS |
| `fixture-verify::stdio_file_ops::fopen::hardened::fopen_valid_mode_hardened` | stdio_file_ops | fopen | hardened | fopen_valid_mode_hardened | C11 7.21.5.3 fopen | PASS |
| `fixture-verify::stdio_file_ops::fopen::strict::fopen_invalid_path_strict` | stdio_file_ops | fopen | strict | fopen_invalid_path_strict | C11 7.21.5.3 fopen | PASS |
| `fixture-verify::stdio_file_ops::fopen::strict::fopen_valid_mode_strict` | stdio_file_ops | fopen | strict | fopen_valid_mode_strict | C11 7.21.5.3 fopen | PASS |
| `fixture-verify::stdio_file_ops::fprintf::strict::fprintf_devnull_strict` | stdio_file_ops | fprintf | strict | fprintf_devnull_strict | C11 7.21.6.1 fprintf | PASS |
| `fixture-verify::stdio_file_ops::fputc::hardened::fputc_devnull_hardened` | stdio_file_ops | fputc | hardened | fputc_devnull_hardened | C11 7.21.7.3 fputc | PASS |
| `fixture-verify::stdio_file_ops::fputc::strict::fputc_devnull_strict` | stdio_file_ops | fputc | strict | fputc_devnull_strict | C11 7.21.7.3 fputc | PASS |
| `fixture-verify::stdio_file_ops::fputc::strict::fputc_devnull_zero_strict` | stdio_file_ops | fputc | strict | fputc_devnull_zero_strict | C11 7.21.7.3 fputc | PASS |
| `fixture-verify::stdio_file_ops::fputs::hardened::fputs_devnull_hardened` | stdio_file_ops | fputs | hardened | fputs_devnull_hardened | C11 7.21.7.4 fputs | PASS |
| `fixture-verify::stdio_file_ops::fputs::strict::fputs_devnull_strict` | stdio_file_ops | fputs | strict | fputs_devnull_strict | C11 7.21.7.4 fputs | PASS |
| `fixture-verify::stdio_file_ops::fread::hardened::fread_devzero_hardened` | stdio_file_ops | fread | hardened | fread_devzero_hardened | C11 7.21.8.1 fread | PASS |
| `fixture-verify::stdio_file_ops::fread::strict::fread_devzero_strict` | stdio_file_ops | fread | strict | fread_devzero_strict | C11 7.21.8.1 fread | PASS |
| `fixture-verify::stdio_file_ops::fseek::strict::fseek_devnull_rw_strict` | stdio_file_ops | fseek | strict | fseek_devnull_rw_strict | C11 7.21.9.2 fseek | PASS |
| `fixture-verify::stdio_file_ops::ftell::strict::ftell_after_seek_strict` | stdio_file_ops | ftell | strict | ftell_after_seek_strict | C11 7.21.9.4 ftell | PASS |
| `fixture-verify::stdio_file_ops::fwrite::strict::fwrite_devnull_strict` | stdio_file_ops | fwrite | strict | fwrite_devnull_strict | C11 7.21.8.2 fwrite | PASS |
| `fixture-verify::stdio_file_ops::printf::hardened::printf_literal_hardened` | stdio_file_ops | printf | hardened | printf_literal_hardened | C11 7.21.6.3 printf | PASS |
| `fixture-verify::stdio_file_ops::printf::strict::printf_literal_strict` | stdio_file_ops | printf | strict | printf_literal_strict | C11 7.21.6.3 printf | PASS |
| `fixture-verify::stdio_file_ops::setbuf::hardened::setbuf_devnull_null_hardened` | stdio_file_ops | setbuf | hardened | setbuf_devnull_null_hardened | C11 7.21.5.5 setbuf | PASS |
| `fixture-verify::stdio_file_ops::setbuf::strict::setbuf_devnull_null_strict` | stdio_file_ops | setbuf | strict | setbuf_devnull_null_strict | C11 7.21.5.5 setbuf | PASS |
| `fixture-verify::stdio_file_ops::setvbuf::hardened::setvbuf_devnull_unbuffered_hardened` | stdio_file_ops | setvbuf | hardened | setvbuf_devnull_unbuffered_hardened | C11 7.21.5.6 setvbuf | PASS |
| `fixture-verify::stdio_file_ops::setvbuf::strict::setvbuf_devnull_unbuffered_strict` | stdio_file_ops | setvbuf | strict | setvbuf_devnull_unbuffered_strict | C11 7.21.5.6 setvbuf | PASS |
| `fixture-verify::stdio_file_ops::snprintf::hardened::snprintf_basic_hardened` | stdio_file_ops | snprintf | hardened | snprintf_basic_hardened | C11 7.21.6.5 snprintf | PASS |
| `fixture-verify::stdio_file_ops::snprintf::strict::snprintf_basic_strict` | stdio_file_ops | snprintf | strict | snprintf_basic_strict | C11 7.21.6.5 snprintf | PASS |
| `fixture-verify::stdio_file_ops::snprintf::strict::snprintf_truncation_strict` | stdio_file_ops | snprintf | strict | snprintf_truncation_strict | C11 7.21.6.5 snprintf | PASS |
| `fixture-verify::stdio_file_ops::ungetc::hardened::ungetc_devnull_read_hardened` | stdio_file_ops | ungetc | hardened | ungetc_devnull_read_hardened | C11 7.21.7.10 ungetc | PASS |
| `fixture-verify::stdio_file_ops::ungetc::strict::ungetc_devnull_read_strict` | stdio_file_ops | ungetc | strict | ungetc_devnull_read_strict | C11 7.21.7.10 ungetc | PASS |
| `fixture-verify::stdio_file_ops::vasprintf::hardened::vasprintf_literal_hardened` | stdio_file_ops | vasprintf | hardened | vasprintf_literal_hardened | GNU vasprintf | PASS |
| `fixture-verify::stdio_file_ops::vasprintf::strict::vasprintf_literal_strict` | stdio_file_ops | vasprintf | strict | vasprintf_literal_strict | GNU vasprintf | PASS |
| `fixture-verify::stdio_file_ops::vdprintf::hardened::vdprintf_literal_hardened` | stdio_file_ops | vdprintf | hardened | vdprintf_literal_hardened | POSIX vdprintf | PASS |
| `fixture-verify::stdio_file_ops::vdprintf::strict::vdprintf_literal_strict` | stdio_file_ops | vdprintf | strict | vdprintf_literal_strict | POSIX vdprintf | PASS |
| `fixture-verify::stdio_file_ops::vsnprintf::hardened::vsnprintf_literal_hardened` | stdio_file_ops | vsnprintf | hardened | vsnprintf_literal_hardened | C11 7.21.6.12 vsnprintf | PASS |
| `fixture-verify::stdio_file_ops::vsnprintf::strict::vsnprintf_literal_strict` | stdio_file_ops | vsnprintf | strict | vsnprintf_literal_strict | C11 7.21.6.12 vsnprintf | PASS |
| `fixture-verify::stdio_file_ops::vsprintf::hardened::vsprintf_literal_hardened` | stdio_file_ops | vsprintf | hardened | vsprintf_literal_hardened | C11 7.21.6.9 vsprintf | PASS |
| `fixture-verify::stdio_file_ops::vsprintf::strict::vsprintf_literal_strict` | stdio_file_ops | vsprintf | strict | vsprintf_literal_strict | C11 7.21.6.9 vsprintf | PASS |
| `fixture-verify::stdlib/conversion::atoi::strict::atoi_basic` | stdlib/conversion | atoi | strict | atoi_basic | POSIX atoi | PASS |
| `fixture-verify::stdlib/conversion::atoi::strict::atoi_negative` | stdlib/conversion | atoi | strict | atoi_negative | POSIX atoi | PASS |
| `fixture-verify::stdlib/conversion::atoi::strict::atoi_whitespace` | stdlib/conversion | atoi | strict | atoi_whitespace | POSIX atoi | PASS |
| `fixture-verify::stdlib/conversion::strtol::strict::strtol_auto` | stdlib/conversion | strtol | strict | strtol_auto | POSIX strtol | PASS |
| `fixture-verify::stdlib/conversion::strtol::strict::strtol_decimal` | stdlib/conversion | strtol | strict | strtol_decimal | POSIX strtol | PASS |
| `fixture-verify::stdlib/conversion::strtol::strict::strtol_hex` | stdlib/conversion | strtol | strict | strtol_hex | POSIX strtol | PASS |
| `fixture-verify::stdlib/conversion::strtol::strict::strtol_overflow_max` | stdlib/conversion | strtol | strict | strtol_overflow_max | POSIX strtol | PASS |
| `fixture-verify::stdlib/numeric::atoi::strict::atoi_basic` | stdlib/numeric | atoi | strict | atoi_basic | POSIX atoi | PASS |
| `fixture-verify::stdlib/numeric::atoi::strict::atoi_negative` | stdlib/numeric | atoi | strict | atoi_negative | POSIX atoi | PASS |
| `fixture-verify::stdlib/numeric::atoi::strict::atoi_whitespace` | stdlib/numeric | atoi | strict | atoi_whitespace | POSIX atoi | PASS |
| `fixture-verify::stdlib/numeric::atol::strict::atol_basic` | stdlib/numeric | atol | strict | atol_basic | POSIX atol | PASS |
| `fixture-verify::stdlib/numeric::atol::strict::atol_large` | stdlib/numeric | atol | strict | atol_large | POSIX atol | PASS |
| `fixture-verify::stdlib/numeric::atol::strict::atol_negative` | stdlib/numeric | atol | strict | atol_negative | POSIX atol | PASS |
| `fixture-verify::stdlib/numeric::getbsize::hardened::getbsize_bare_1024_preserves_byte_header` | stdlib/numeric | getbsize | hardened | getbsize_bare_1024_preserves_byte_header [hardened] | BSD libutil getbsize bare byte count | PASS |
| `fixture-verify::stdlib/numeric::getbsize::hardened::getbsize_default_unset` | stdlib/numeric | getbsize | hardened | getbsize_default_unset [hardened] | BSD libutil getbsize default BLOCKSIZE | PASS |
| `fixture-verify::stdlib/numeric::getbsize::hardened::getbsize_empty_env_falls_back_to_default` | stdlib/numeric | getbsize | hardened | getbsize_empty_env_falls_back_to_default [hardened] | BSD libutil getbsize empty BLOCKSIZE fallback | PASS |
| `fixture-verify::stdlib/numeric::getbsize::hardened::getbsize_garbage_falls_back_to_default` | stdlib/numeric | getbsize | hardened | getbsize_garbage_falls_back_to_default [hardened] | BSD libutil getbsize invalid BLOCKSIZE fallback | PASS |
| `fixture-verify::stdlib/numeric::getbsize::hardened::getbsize_huge_g_value_clamps_to_ceiling` | stdlib/numeric | getbsize | hardened | getbsize_huge_g_value_clamps_to_ceiling [hardened] | BSD libutil getbsize upper clamp | PASS |
| `fixture-verify::stdlib/numeric::getbsize::hardened::getbsize_implicit_one_unit_suffix` | stdlib/numeric | getbsize | hardened | getbsize_implicit_one_unit_suffix [hardened] | BSD libutil getbsize implicit one-unit suffix | PASS |
| `fixture-verify::stdlib/numeric::getbsize::hardened::getbsize_lowercase_k_suffix_normalizes_header` | stdlib/numeric | getbsize | hardened | getbsize_lowercase_k_suffix_normalizes_header [hardened] | BSD libutil getbsize lowercase suffix normalization | PASS |
| `fixture-verify::stdlib/numeric::getbsize::hardened::getbsize_negative_value_clamps_to_floor` | stdlib/numeric | getbsize | hardened | getbsize_negative_value_clamps_to_floor [hardened] | BSD libutil getbsize signed lower clamp | PASS |
| `fixture-verify::stdlib/numeric::getbsize::hardened::getbsize_negative_zero_unit_suffix` | stdlib/numeric | getbsize | hardened | getbsize_negative_zero_unit_suffix [hardened] | BSD libutil getbsize signed zero suffix | PASS |
| `fixture-verify::stdlib/numeric::getbsize::hardened::getbsize_one_k_preserves_suffix_header` | stdlib/numeric | getbsize | hardened | getbsize_one_k_preserves_suffix_header [hardened] | BSD libutil getbsize suffix spelling | PASS |
| `fixture-verify::stdlib/numeric::getbsize::hardened::getbsize_plus_prefixed_mega_suffix` | stdlib/numeric | getbsize | hardened | getbsize_plus_prefixed_mega_suffix [hardened] | BSD libutil getbsize signed decimal prefix | PASS |
| `fixture-verify::stdlib/numeric::getbsize::hardened::getbsize_tiny_value_clamps_to_floor` | stdlib/numeric | getbsize | hardened | getbsize_tiny_value_clamps_to_floor [hardened] | BSD libutil getbsize lower clamp | PASS |
| `fixture-verify::stdlib/numeric::getbsize::strict::getbsize_bare_1024_preserves_byte_header` | stdlib/numeric | getbsize | strict | getbsize_bare_1024_preserves_byte_header [strict] | BSD libutil getbsize bare byte count | PASS |
| `fixture-verify::stdlib/numeric::getbsize::strict::getbsize_default_unset` | stdlib/numeric | getbsize | strict | getbsize_default_unset [strict] | BSD libutil getbsize default BLOCKSIZE | PASS |
| `fixture-verify::stdlib/numeric::getbsize::strict::getbsize_empty_env_falls_back_to_default` | stdlib/numeric | getbsize | strict | getbsize_empty_env_falls_back_to_default [strict] | BSD libutil getbsize empty BLOCKSIZE fallback | PASS |
| `fixture-verify::stdlib/numeric::getbsize::strict::getbsize_garbage_falls_back_to_default` | stdlib/numeric | getbsize | strict | getbsize_garbage_falls_back_to_default [strict] | BSD libutil getbsize invalid BLOCKSIZE fallback | PASS |
| `fixture-verify::stdlib/numeric::getbsize::strict::getbsize_huge_g_value_clamps_to_ceiling` | stdlib/numeric | getbsize | strict | getbsize_huge_g_value_clamps_to_ceiling [strict] | BSD libutil getbsize upper clamp | PASS |
| `fixture-verify::stdlib/numeric::getbsize::strict::getbsize_implicit_one_unit_suffix` | stdlib/numeric | getbsize | strict | getbsize_implicit_one_unit_suffix [strict] | BSD libutil getbsize implicit one-unit suffix | PASS |
| `fixture-verify::stdlib/numeric::getbsize::strict::getbsize_lowercase_k_suffix_normalizes_header` | stdlib/numeric | getbsize | strict | getbsize_lowercase_k_suffix_normalizes_header [strict] | BSD libutil getbsize lowercase suffix normalization | PASS |
| `fixture-verify::stdlib/numeric::getbsize::strict::getbsize_negative_value_clamps_to_floor` | stdlib/numeric | getbsize | strict | getbsize_negative_value_clamps_to_floor [strict] | BSD libutil getbsize signed lower clamp | PASS |
| `fixture-verify::stdlib/numeric::getbsize::strict::getbsize_negative_zero_unit_suffix` | stdlib/numeric | getbsize | strict | getbsize_negative_zero_unit_suffix [strict] | BSD libutil getbsize signed zero suffix | PASS |
| `fixture-verify::stdlib/numeric::getbsize::strict::getbsize_one_k_preserves_suffix_header` | stdlib/numeric | getbsize | strict | getbsize_one_k_preserves_suffix_header [strict] | BSD libutil getbsize suffix spelling | PASS |
| `fixture-verify::stdlib/numeric::getbsize::strict::getbsize_plus_prefixed_mega_suffix` | stdlib/numeric | getbsize | strict | getbsize_plus_prefixed_mega_suffix [strict] | BSD libutil getbsize signed decimal prefix | PASS |
| `fixture-verify::stdlib/numeric::getbsize::strict::getbsize_tiny_value_clamps_to_floor` | stdlib/numeric | getbsize | strict | getbsize_tiny_value_clamps_to_floor [strict] | BSD libutil getbsize lower clamp | PASS |
| `fixture-verify::stdlib/numeric::strtol::strict::strtol_base10` | stdlib/numeric | strtol | strict | strtol_base10 | POSIX strtol | PASS |
| `fixture-verify::stdlib/numeric::strtol::strict::strtol_hex_auto` | stdlib/numeric | strtol | strict | strtol_hex_auto | POSIX strtol | PASS |
| `fixture-verify::stdlib/numeric::strtoul::strict::strtoul_basic` | stdlib/numeric | strtoul | strict | strtoul_basic | POSIX strtoul | PASS |
| `fixture-verify::stdlib/numeric::strtoul::strict::strtoul_negative_wrap` | stdlib/numeric | strtoul | strict | strtoul_negative_wrap | POSIX strtoul | PASS |
| `fixture-verify::stdlib/sort::bsearch::hardened::bsearch_found_hardened` | stdlib/sort | bsearch | hardened | bsearch_found_hardened | ISO C bsearch | PASS |
| `fixture-verify::stdlib/sort::bsearch::strict::bsearch_empty_strict` | stdlib/sort | bsearch | strict | bsearch_empty_strict | ISO C bsearch | PASS |
| `fixture-verify::stdlib/sort::bsearch::strict::bsearch_first_element_strict` | stdlib/sort | bsearch | strict | bsearch_first_element_strict | ISO C bsearch | PASS |
| `fixture-verify::stdlib/sort::bsearch::strict::bsearch_found` | stdlib/sort | bsearch | strict | bsearch_found | ISO C bsearch | PASS |
| `fixture-verify::stdlib/sort::bsearch::strict::bsearch_last_element_strict` | stdlib/sort | bsearch | strict | bsearch_last_element_strict | ISO C bsearch | PASS |
| `fixture-verify::stdlib/sort::bsearch::strict::bsearch_not_found` | stdlib/sort | bsearch | strict | bsearch_not_found | ISO C bsearch | PASS |
| `fixture-verify::stdlib/sort::qsort::hardened::qsort_int_hardened` | stdlib/sort | qsort | hardened | qsort_int_hardened | ISO C qsort | PASS |
| `fixture-verify::stdlib/sort::qsort::strict::qsort_duplicates_strict` | stdlib/sort | qsort | strict | qsort_duplicates_strict | ISO C qsort | PASS |
| `fixture-verify::stdlib/sort::qsort::strict::qsort_empty_strict` | stdlib/sort | qsort | strict | qsort_empty_strict | ISO C qsort | PASS |
| `fixture-verify::stdlib/sort::qsort::strict::qsort_int` | stdlib/sort | qsort | strict | qsort_int | ISO C qsort | PASS |
| `fixture-verify::stdlib/sort::qsort::strict::qsort_reversed_strict` | stdlib/sort | qsort | strict | qsort_reversed_strict | ISO C qsort | PASS |
| `fixture-verify::stdlib/sort::qsort::strict::qsort_single_strict` | stdlib/sort | qsort | strict | qsort_single_strict | ISO C qsort | PASS |
| `fixture-verify::string/memcpy::memcpy::hardened::copy_full_8_hardened` | string/memcpy | memcpy | hardened | copy_full_8_hardened | POSIX.1-2017 memcpy | PASS |
| `fixture-verify::string/memcpy::memcpy::hardened::copy_single_byte_hardened` | string/memcpy | memcpy | hardened | copy_single_byte_hardened | POSIX.1-2017 memcpy | PASS |
| `fixture-verify::string/memcpy::memcpy::hardened::copy_zero_hardened` | string/memcpy | memcpy | hardened | copy_zero_hardened | POSIX.1-2017 memcpy | PASS |
| `fixture-verify::string/memcpy::memcpy::strict::copy_full_8` | string/memcpy | memcpy | strict | copy_full_8 | POSIX.1-2017 memcpy | PASS |
| `fixture-verify::string/memcpy::memcpy::strict::copy_high_bytes_strict` | string/memcpy | memcpy | strict | copy_high_bytes_strict | POSIX.1-2017 memcpy | PASS |
| `fixture-verify::string/memcpy::memcpy::strict::copy_larger_16_strict` | string/memcpy | memcpy | strict | copy_larger_16_strict | POSIX.1-2017 memcpy | PASS |
| `fixture-verify::string/memcpy::memcpy::strict::copy_partial_4` | string/memcpy | memcpy | strict | copy_partial_4 | POSIX.1-2017 memcpy | PASS |
| `fixture-verify::string/memcpy::memcpy::strict::copy_single_byte` | string/memcpy | memcpy | strict | copy_single_byte | POSIX.1-2017 memcpy | PASS |
| `fixture-verify::string/memcpy::memcpy::strict::copy_zero` | string/memcpy | memcpy | strict | copy_zero | POSIX.1-2017 memcpy | PASS |
| `fixture-verify::string/memory::memchr::strict::memchr_found` | string/memory | memchr | strict | memchr_found | POSIX memchr | PASS |
| `fixture-verify::string/memory::memcmp::strict::memcmp_equal` | string/memory | memcmp | strict | memcmp_equal | POSIX memcmp | PASS |
| `fixture-verify::string/memory::memcmp::strict::memcmp_less` | string/memory | memcmp | strict | memcmp_less | POSIX memcmp | PASS |
| `fixture-verify::string/memory::memrchr::strict::memrchr_found` | string/memory | memrchr | strict | memrchr_found | GNU memrchr | PASS |
| `fixture-verify::string/memory::memset::strict::memset_basic` | string/memory | memset | strict | memset_basic | POSIX memset | PASS |
| `fixture-verify::string/memory::strcat::strict::strcat_basic` | string/memory | strcat | strict | strcat_basic | POSIX strcat | PASS |
| `fixture-verify::string/memory::strchr::strict::strchr_found` | string/memory | strchr | strict | strchr_found | POSIX strchr | PASS |
| `fixture-verify::string/memory::strcmp::strict::strcmp_equal` | string/memory | strcmp | strict | strcmp_equal | POSIX strcmp | PASS |
| `fixture-verify::string/memory::strcmp::strict::strcmp_less` | string/memory | strcmp | strict | strcmp_less | POSIX strcmp | PASS |
| `fixture-verify::string/memory::strcpy::strict::strcpy_basic` | string/memory | strcpy | strict | strcpy_basic | POSIX strcpy | PASS |
| `fixture-verify::string/memory::strncat::strict::strncat_basic` | string/memory | strncat | strict | strncat_basic | POSIX strncat | PASS |
| `fixture-verify::string/memory::strncpy::strict::strncpy_basic` | string/memory | strncpy | strict | strncpy_basic | POSIX strncpy | PASS |
| `fixture-verify::string/memory::strrchr::strict::strrchr_found` | string/memory | strrchr | strict | strrchr_found | POSIX strrchr | PASS |
| `fixture-verify::string/memory::strstr::strict::strstr_found` | string/memory | strstr | strict | strstr_found | POSIX strstr | PASS |
| `fixture-verify::string/narrow::__memcmpeq::hardened::both___memcmpeq_zero_length_equal` | string/narrow | __memcmpeq | hardened | both___memcmpeq_zero_length_equal [hardened] | glibc internal __memcmpeq | PASS |
| `fixture-verify::string/narrow::__memcmpeq::strict::both___memcmpeq_zero_length_equal` | string/narrow | __memcmpeq | strict | both___memcmpeq_zero_length_equal [strict] | glibc internal __memcmpeq | PASS |
| `fixture-verify::string/narrow::__mempcpy::hardened::both___mempcpy_binary_boundary_return_offset` | string/narrow | __mempcpy | hardened | both___mempcpy_binary_boundary_return_offset [hardened] | glibc internal __mempcpy | PASS |
| `fixture-verify::string/narrow::__mempcpy::hardened::hardened___mempcpy_dst_bound_clamps_requested_len` | string/narrow | __mempcpy | hardened | hardened___mempcpy_dst_bound_clamps_requested_len | TSM hardened __mempcpy destination bounds | PASS |
| `fixture-verify::string/narrow::__mempcpy::strict::both___mempcpy_binary_boundary_return_offset` | string/narrow | __mempcpy | strict | both___mempcpy_binary_boundary_return_offset [strict] | glibc internal __mempcpy | PASS |
| `fixture-verify::string/narrow::__rawmemchr::hardened::both___rawmemchr_zero_byte_at_boundary` | string/narrow | __rawmemchr | hardened | both___rawmemchr_zero_byte_at_boundary [hardened] | glibc internal __rawmemchr | PASS |
| `fixture-verify::string/narrow::__rawmemchr::strict::both___rawmemchr_zero_byte_at_boundary` | string/narrow | __rawmemchr | strict | both___rawmemchr_zero_byte_at_boundary [strict] | glibc internal __rawmemchr | PASS |
| `fixture-verify::string/narrow::__stpcpy::hardened::both___stpcpy_empty_string_return_offset` | string/narrow | __stpcpy | hardened | both___stpcpy_empty_string_return_offset [hardened] | glibc internal __stpcpy | PASS |
| `fixture-verify::string/narrow::__stpcpy::strict::both___stpcpy_empty_string_return_offset` | string/narrow | __stpcpy | strict | both___stpcpy_empty_string_return_offset [strict] | glibc internal __stpcpy | PASS |
| `fixture-verify::string/narrow::__stpcpy_small::hardened::both___stpcpy_small_ascii_return_offset` | string/narrow | __stpcpy_small | hardened | both___stpcpy_small_ascii_return_offset [hardened] | glibc internal __stpcpy_small | PASS |
| `fixture-verify::string/narrow::__stpcpy_small::strict::both___stpcpy_small_ascii_return_offset` | string/narrow | __stpcpy_small | strict | both___stpcpy_small_ascii_return_offset [strict] | glibc internal __stpcpy_small | PASS |
| `fixture-verify::string/narrow::__stpncpy::hardened::both___stpncpy_pads_to_boundary` | string/narrow | __stpncpy | hardened | both___stpncpy_pads_to_boundary [hardened] | glibc internal __stpncpy | PASS |
| `fixture-verify::string/narrow::__stpncpy::strict::both___stpncpy_pads_to_boundary` | string/narrow | __stpncpy | strict | both___stpncpy_pads_to_boundary [strict] | glibc internal __stpncpy | PASS |
| `fixture-verify::string/narrow::__strcasecmp::hardened::both___strcasecmp_ascii_casefold_equal` | string/narrow | __strcasecmp | hardened | both___strcasecmp_ascii_casefold_equal [hardened] | glibc internal __strcasecmp | PASS |
| `fixture-verify::string/narrow::__strcasecmp::strict::both___strcasecmp_ascii_casefold_equal` | string/narrow | __strcasecmp | strict | both___strcasecmp_ascii_casefold_equal [strict] | glibc internal __strcasecmp | PASS |
| `fixture-verify::string/narrow::__strcasecmp_l::hardened::both___strcasecmp_l_ascii_casefold_equal` | string/narrow | __strcasecmp_l | hardened | both___strcasecmp_l_ascii_casefold_equal [hardened] | glibc internal __strcasecmp_l | PASS |
| `fixture-verify::string/narrow::__strcasecmp_l::strict::both___strcasecmp_l_ascii_casefold_equal` | string/narrow | __strcasecmp_l | strict | both___strcasecmp_l_ascii_casefold_equal [strict] | glibc internal __strcasecmp_l | PASS |
| `fixture-verify::string/narrow::__strcasestr::hardened::both___strcasestr_case_insensitive_found` | string/narrow | __strcasestr | hardened | both___strcasestr_case_insensitive_found [hardened] | glibc internal __strcasestr | PASS |
| `fixture-verify::string/narrow::__strcasestr::strict::both___strcasestr_case_insensitive_found` | string/narrow | __strcasestr | strict | both___strcasestr_case_insensitive_found [strict] | glibc internal __strcasestr | PASS |
| `fixture-verify::string/narrow::__strcoll_l::hardened::both___strcoll_l_c_locale_order` | string/narrow | __strcoll_l | hardened | both___strcoll_l_c_locale_order [hardened] | glibc internal __strcoll_l | PASS |
| `fixture-verify::string/narrow::__strcoll_l::strict::both___strcoll_l_c_locale_order` | string/narrow | __strcoll_l | strict | both___strcoll_l_c_locale_order [strict] | glibc internal __strcoll_l | PASS |
| `fixture-verify::string/narrow::__strcpy_small::hardened::both___strcpy_small_ascii_return_dst` | string/narrow | __strcpy_small | hardened | both___strcpy_small_ascii_return_dst [hardened] | glibc internal __strcpy_small | PASS |
| `fixture-verify::string/narrow::__strcpy_small::strict::both___strcpy_small_ascii_return_dst` | string/narrow | __strcpy_small | strict | both___strcpy_small_ascii_return_dst [strict] | glibc internal __strcpy_small | PASS |
| `fixture-verify::string/narrow::__strcspn_c1::hardened::both___strcspn_c1_reject_found` | string/narrow | __strcspn_c1 | hardened | both___strcspn_c1_reject_found [hardened] | glibc internal __strcspn_c1 | PASS |
| `fixture-verify::string/narrow::__strcspn_c1::strict::both___strcspn_c1_reject_found` | string/narrow | __strcspn_c1 | strict | both___strcspn_c1_reject_found [strict] | glibc internal __strcspn_c1 | PASS |
| `fixture-verify::string/narrow::memchr::strict::strict_memchr_found` | string/narrow | memchr | strict | strict_memchr_found | POSIX memchr | PASS |
| `fixture-verify::string/narrow::memcmp::strict::strict_memcmp_equal` | string/narrow | memcmp | strict | strict_memcmp_equal | POSIX memcmp | PASS |
| `fixture-verify::string/narrow::memcmp::strict::strict_memcmp_less` | string/narrow | memcmp | strict | strict_memcmp_less | POSIX memcmp | PASS |
| `fixture-verify::string/narrow::memmove::strict::strict_memmove_basic` | string/narrow | memmove | strict | strict_memmove_basic | POSIX memmove | PASS |
| `fixture-verify::string/narrow::memrchr::strict::strict_memrchr_found` | string/narrow | memrchr | strict | strict_memrchr_found | GNU memrchr | PASS |
| `fixture-verify::string/narrow::memset::strict::strict_memset_basic` | string/narrow | memset | strict | strict_memset_basic | POSIX memset | PASS |
| `fixture-verify::string/narrow::strcat::hardened::hardened_strcat_overflow` | string/narrow | strcat | hardened | hardened_strcat_overflow | TSM hardened strcat | PASS |
| `fixture-verify::string/narrow::strcat::strict::strict_strcat_basic` | string/narrow | strcat | strict | strict_strcat_basic | POSIX strcat | PASS |
| `fixture-verify::string/narrow::strchr::strict::strict_strchr_found` | string/narrow | strchr | strict | strict_strchr_found | POSIX strchr | PASS |
| `fixture-verify::string/narrow::strcmp::strict::strict_strcmp_equal` | string/narrow | strcmp | strict | strict_strcmp_equal | POSIX strcmp | PASS |
| `fixture-verify::string/narrow::strcpy::hardened::hardened_strcpy_overflow` | string/narrow | strcpy | hardened | hardened_strcpy_overflow | TSM hardened strcpy | PASS |
| `fixture-verify::string/narrow::strcpy::strict::strict_strcpy_basic` | string/narrow | strcpy | strict | strict_strcpy_basic | POSIX strcpy | PASS |
| `fixture-verify::string/narrow::strlcat::hardened::hardened_strlcat_dst_bound_clamps_requested_size` | string/narrow | strlcat | hardened | hardened_strlcat_dst_bound_clamps_requested_size | TSM hardened strlcat destination bounds | PASS |
| `fixture-verify::string/narrow::strlcat::strict::strict_strlcat_truncates_with_nul` | string/narrow | strlcat | strict | strict_strlcat_truncates_with_nul | BSD strlcat | PASS |
| `fixture-verify::string/narrow::strlcpy::hardened::hardened_strlcpy_dst_bound_clamps_requested_size` | string/narrow | strlcpy | hardened | hardened_strlcpy_dst_bound_clamps_requested_size | TSM hardened strlcpy destination bounds | PASS |
| `fixture-verify::string/narrow::strlcpy::strict::strict_strlcpy_truncates_with_nul` | string/narrow | strlcpy | strict | strict_strlcpy_truncates_with_nul | BSD strlcpy | PASS |
| `fixture-verify::string/narrow::strncpy::strict::strict_strncpy_basic` | string/narrow | strncpy | strict | strict_strncpy_basic | POSIX strncpy | PASS |
| `fixture-verify::string/narrow::strrchr::strict::strict_strrchr_found` | string/narrow | strrchr | strict | strict_strrchr_found | POSIX strrchr | PASS |
| `fixture-verify::string/narrow::strstr::strict::strict_strstr_found` | string/narrow | strstr | strict | strict_strstr_found | POSIX strstr | PASS |
| `fixture-verify::string/strlen::strlen::hardened::empty_string_hardened` | string/strlen | strlen | hardened | empty_string_hardened | POSIX.1-2017 strlen | PASS |
| `fixture-verify::string/strlen::strlen::hardened::hello_hardened` | string/strlen | strlen | hardened | hello_hardened | POSIX.1-2017 strlen | PASS |
| `fixture-verify::string/strlen::strlen::hardened::high_bytes_hardened` | string/strlen | strlen | hardened | high_bytes_hardened | POSIX.1-2017 strlen | PASS |
| `fixture-verify::string/strlen::strlen::strict::embedded_high_byte_strict` | string/strlen | strlen | strict | embedded_high_byte_strict | POSIX.1-2017 strlen | PASS |
| `fixture-verify::string/strlen::strlen::strict::empty_string` | string/strlen | strlen | strict | empty_string | POSIX.1-2017 strlen | PASS |
| `fixture-verify::string/strlen::strlen::strict::hello` | string/strlen | strlen | strict | hello | POSIX.1-2017 strlen | PASS |
| `fixture-verify::string/strlen::strlen::strict::high_bytes_strict` | string/strlen | strlen | strict | high_bytes_strict | POSIX.1-2017 strlen | PASS |
| `fixture-verify::string/strlen::strlen::strict::longer_string_strict` | string/strlen | strlen | strict | longer_string_strict | POSIX.1-2017 strlen | PASS |
| `fixture-verify::string/strlen::strlen::strict::single_char` | string/strlen | strlen | strict | single_char | POSIX.1-2017 strlen | PASS |
| `fixture-verify::string/strtok::strtok::strict::strtok_all_delims` | string/strtok | strtok | strict | strtok_all_delims | POSIX.1-2017 strtok | PASS |
| `fixture-verify::string/strtok::strtok::strict::strtok_basic_first` | string/strtok | strtok | strict | strtok_basic_first | POSIX.1-2017 strtok | PASS |
| `fixture-verify::string/strtok::strtok::strict::strtok_comma_delim` | string/strtok | strtok | strict | strtok_comma_delim | POSIX.1-2017 strtok | PASS |
| `fixture-verify::string/strtok::strtok::strict::strtok_leading_delims` | string/strtok | strtok | strict | strtok_leading_delims | POSIX.1-2017 strtok | PASS |
| `fixture-verify::string/strtok::strtok::strict::strtok_no_delim_found` | string/strtok | strtok | strict | strtok_no_delim_found | POSIX.1-2017 strtok | PASS |
| `fixture-verify::string/strtok::strtok_r::strict::strtok_r_basic_first` | string/strtok | strtok_r | strict | strtok_r_basic_first | POSIX.1-2017 strtok_r | PASS |
| `fixture-verify::string/strtok::strtok_r::strict::strtok_r_comma_delim` | string/strtok | strtok_r | strict | strtok_r_comma_delim | POSIX.1-2017 strtok_r | PASS |
| `fixture-verify::string/strtok::strtok_r::strict::strtok_r_empty` | string/strtok | strtok_r | strict | strtok_r_empty | POSIX.1-2017 strtok_r | PASS |
| `fixture-verify::string/wide::wcscat::hardened::wcscat_basic` | string/wide | wcscat | hardened | wcscat_basic [hardened] | C11 7.29.4.3.1 wcscat | PASS |
| `fixture-verify::string/wide::wcscat::hardened::wcscat_empty_dst` | string/wide | wcscat | hardened | wcscat_empty_dst [hardened] | C11 7.29.4.3.1 wcscat | PASS |
| `fixture-verify::string/wide::wcscat::hardened::wcscat_empty_src` | string/wide | wcscat | hardened | wcscat_empty_src [hardened] | C11 7.29.4.3.1 wcscat | PASS |
| `fixture-verify::string/wide::wcscat::strict::strict_wcscat_basic` | string/wide | wcscat | strict | strict_wcscat_basic | ISO C wcscat | PASS |
| `fixture-verify::string/wide::wcscat::strict::wcscat_basic` | string/wide | wcscat | strict | wcscat_basic [strict] | C11 7.29.4.3.1 wcscat | PASS |
| `fixture-verify::string/wide::wcscat::strict::wcscat_empty_dst` | string/wide | wcscat | strict | wcscat_empty_dst [strict] | C11 7.29.4.3.1 wcscat | PASS |
| `fixture-verify::string/wide::wcscat::strict::wcscat_empty_src` | string/wide | wcscat | strict | wcscat_empty_src [strict] | C11 7.29.4.3.1 wcscat | PASS |
| `fixture-verify::string/wide::wcschr::hardened::wcschr_found` | string/wide | wcschr | hardened | wcschr_found [hardened] | C11 7.29.4.5.1 wcschr | PASS |
| `fixture-verify::string/wide::wcschr::hardened::wcschr_not_found` | string/wide | wcschr | hardened | wcschr_not_found [hardened] | C11 7.29.4.5.1 wcschr | PASS |
| `fixture-verify::string/wide::wcschr::hardened::wcschr_null_char` | string/wide | wcschr | hardened | wcschr_null_char [hardened] | C11 7.29.4.5.1 wcschr | PASS |
| `fixture-verify::string/wide::wcschr::strict::strict_wcschr_found` | string/wide | wcschr | strict | strict_wcschr_found | ISO C wcschr | PASS |
| `fixture-verify::string/wide::wcschr::strict::strict_wcschr_not_found` | string/wide | wcschr | strict | strict_wcschr_not_found | ISO C wcschr | PASS |
| `fixture-verify::string/wide::wcschr::strict::wcschr_found` | string/wide | wcschr | strict | wcschr_found [strict] | C11 7.29.4.5.1 wcschr | PASS |
| `fixture-verify::string/wide::wcschr::strict::wcschr_not_found` | string/wide | wcschr | strict | wcschr_not_found [strict] | C11 7.29.4.5.1 wcschr | PASS |
| `fixture-verify::string/wide::wcschr::strict::wcschr_null_char` | string/wide | wcschr | strict | wcschr_null_char [strict] | C11 7.29.4.5.1 wcschr | PASS |
| `fixture-verify::string/wide::wcscmp::hardened::wcscmp_equal` | string/wide | wcscmp | hardened | wcscmp_equal [hardened] | C11 7.29.4.4.1 wcscmp | PASS |
| `fixture-verify::string/wide::wcscmp::hardened::wcscmp_greater` | string/wide | wcscmp | hardened | wcscmp_greater [hardened] | C11 7.29.4.4.1 wcscmp | PASS |
| `fixture-verify::string/wide::wcscmp::hardened::wcscmp_less` | string/wide | wcscmp | hardened | wcscmp_less [hardened] | C11 7.29.4.4.1 wcscmp | PASS |
| `fixture-verify::string/wide::wcscmp::hardened::wcscmp_prefix` | string/wide | wcscmp | hardened | wcscmp_prefix [hardened] | C11 7.29.4.4.1 wcscmp | PASS |
| `fixture-verify::string/wide::wcscmp::strict::strict_wcscmp_equal` | string/wide | wcscmp | strict | strict_wcscmp_equal | ISO C wcscmp | PASS |
| `fixture-verify::string/wide::wcscmp::strict::strict_wcscmp_less` | string/wide | wcscmp | strict | strict_wcscmp_less | ISO C wcscmp | PASS |
| `fixture-verify::string/wide::wcscmp::strict::wcscmp_equal` | string/wide | wcscmp | strict | wcscmp_equal [strict] | C11 7.29.4.4.1 wcscmp | PASS |
| `fixture-verify::string/wide::wcscmp::strict::wcscmp_greater` | string/wide | wcscmp | strict | wcscmp_greater [strict] | C11 7.29.4.4.1 wcscmp | PASS |
| `fixture-verify::string/wide::wcscmp::strict::wcscmp_less` | string/wide | wcscmp | strict | wcscmp_less [strict] | C11 7.29.4.4.1 wcscmp | PASS |
| `fixture-verify::string/wide::wcscmp::strict::wcscmp_prefix` | string/wide | wcscmp | strict | wcscmp_prefix [strict] | C11 7.29.4.4.1 wcscmp | PASS |
| `fixture-verify::string/wide::wcscpy::hardened::hardened_wcscpy_overflow` | string/wide | wcscpy | hardened | hardened_wcscpy_overflow | TSM hardened wcscpy | PASS |
| `fixture-verify::string/wide::wcscpy::hardened::wcscpy_basic` | string/wide | wcscpy | hardened | wcscpy_basic [hardened] | C11 7.29.4.2.1 wcscpy | PASS |
| `fixture-verify::string/wide::wcscpy::hardened::wcscpy_empty` | string/wide | wcscpy | hardened | wcscpy_empty [hardened] | C11 7.29.4.2.1 wcscpy | PASS |
| `fixture-verify::string/wide::wcscpy::strict::strict_wcscpy_basic` | string/wide | wcscpy | strict | strict_wcscpy_basic | ISO C wcscpy | PASS |
| `fixture-verify::string/wide::wcscpy::strict::wcscpy_basic` | string/wide | wcscpy | strict | wcscpy_basic [strict] | C11 7.29.4.2.1 wcscpy | PASS |
| `fixture-verify::string/wide::wcscpy::strict::wcscpy_empty` | string/wide | wcscpy | strict | wcscpy_empty [strict] | C11 7.29.4.2.1 wcscpy | PASS |
| `fixture-verify::string/wide::wcscspn::hardened::wcscspn_found` | string/wide | wcscspn | hardened | wcscspn_found [hardened] | C11 7.29.4.5.2 wcscspn | PASS |
| `fixture-verify::string/wide::wcscspn::hardened::wcscspn_none` | string/wide | wcscspn | hardened | wcscspn_none [hardened] | C11 7.29.4.5.2 wcscspn | PASS |
| `fixture-verify::string/wide::wcscspn::strict::wcscspn_found` | string/wide | wcscspn | strict | wcscspn_found [strict] | C11 7.29.4.5.2 wcscspn | PASS |
| `fixture-verify::string/wide::wcscspn::strict::wcscspn_none` | string/wide | wcscspn | strict | wcscspn_none [strict] | C11 7.29.4.5.2 wcscspn | PASS |
| `fixture-verify::string/wide::wcslen::hardened::wcslen_basic` | string/wide | wcslen | hardened | wcslen_basic [hardened] | C11 7.29.4.6.1 wcslen | PASS |
| `fixture-verify::string/wide::wcslen::hardened::wcslen_empty` | string/wide | wcslen | hardened | wcslen_empty [hardened] | C11 7.29.4.6.1 wcslen | PASS |
| `fixture-verify::string/wide::wcslen::hardened::wcslen_unicode` | string/wide | wcslen | hardened | wcslen_unicode [hardened] | C11 7.29.4.6.1 wcslen | PASS |
| `fixture-verify::string/wide::wcslen::strict::strict_wcslen_basic` | string/wide | wcslen | strict | strict_wcslen_basic | ISO C wcslen | PASS |
| `fixture-verify::string/wide::wcslen::strict::strict_wcslen_empty` | string/wide | wcslen | strict | strict_wcslen_empty | ISO C wcslen | PASS |
| `fixture-verify::string/wide::wcslen::strict::wcslen_basic` | string/wide | wcslen | strict | wcslen_basic [strict] | C11 7.29.4.6.1 wcslen | PASS |
| `fixture-verify::string/wide::wcslen::strict::wcslen_empty` | string/wide | wcslen | strict | wcslen_empty [strict] | C11 7.29.4.6.1 wcslen | PASS |
| `fixture-verify::string/wide::wcslen::strict::wcslen_unicode` | string/wide | wcslen | strict | wcslen_unicode [strict] | C11 7.29.4.6.1 wcslen | PASS |
| `fixture-verify::string/wide::wcsncat::hardened::wcsncat_basic` | string/wide | wcsncat | hardened | wcsncat_basic [hardened] | C11 7.29.4.3.2 wcsncat | PASS |
| `fixture-verify::string/wide::wcsncat::hardened::wcsncat_zero_n` | string/wide | wcsncat | hardened | wcsncat_zero_n [hardened] | C11 7.29.4.3.2 wcsncat | PASS |
| `fixture-verify::string/wide::wcsncat::strict::wcsncat_basic` | string/wide | wcsncat | strict | wcsncat_basic [strict] | C11 7.29.4.3.2 wcsncat | PASS |
| `fixture-verify::string/wide::wcsncat::strict::wcsncat_zero_n` | string/wide | wcsncat | strict | wcsncat_zero_n [strict] | C11 7.29.4.3.2 wcsncat | PASS |
| `fixture-verify::string/wide::wcsncmp::hardened::wcsncmp_diff_at_n` | string/wide | wcsncmp | hardened | wcsncmp_diff_at_n [hardened] | C11 7.29.4.4.2 wcsncmp | PASS |
| `fixture-verify::string/wide::wcsncmp::hardened::wcsncmp_equal_n` | string/wide | wcsncmp | hardened | wcsncmp_equal_n [hardened] | C11 7.29.4.4.2 wcsncmp | PASS |
| `fixture-verify::string/wide::wcsncmp::hardened::wcsncmp_zero_n` | string/wide | wcsncmp | hardened | wcsncmp_zero_n [hardened] | C11 7.29.4.4.2 wcsncmp | PASS |
| `fixture-verify::string/wide::wcsncmp::strict::strict_wcsncmp_equal` | string/wide | wcsncmp | strict | strict_wcsncmp_equal | ISO C wcsncmp | PASS |
| `fixture-verify::string/wide::wcsncmp::strict::strict_wcsncmp_less` | string/wide | wcsncmp | strict | strict_wcsncmp_less | ISO C wcsncmp | PASS |
| `fixture-verify::string/wide::wcsncmp::strict::wcsncmp_diff_at_n` | string/wide | wcsncmp | strict | wcsncmp_diff_at_n [strict] | C11 7.29.4.4.2 wcsncmp | PASS |
| `fixture-verify::string/wide::wcsncmp::strict::wcsncmp_equal_n` | string/wide | wcsncmp | strict | wcsncmp_equal_n [strict] | C11 7.29.4.4.2 wcsncmp | PASS |
| `fixture-verify::string/wide::wcsncmp::strict::wcsncmp_zero_n` | string/wide | wcsncmp | strict | wcsncmp_zero_n [strict] | C11 7.29.4.4.2 wcsncmp | PASS |
| `fixture-verify::string/wide::wcsncpy::hardened::wcsncpy_basic` | string/wide | wcsncpy | hardened | wcsncpy_basic [hardened] | C11 7.29.4.2.2 wcsncpy | PASS |
| `fixture-verify::string/wide::wcsncpy::hardened::wcsncpy_pad` | string/wide | wcsncpy | hardened | wcsncpy_pad [hardened] | C11 7.29.4.2.2 wcsncpy | PASS |
| `fixture-verify::string/wide::wcsncpy::hardened::wcsncpy_truncate` | string/wide | wcsncpy | hardened | wcsncpy_truncate [hardened] | C11 7.29.4.2.2 wcsncpy | PASS |
| `fixture-verify::string/wide::wcsncpy::strict::strict_wcsncpy_basic` | string/wide | wcsncpy | strict | strict_wcsncpy_basic | ISO C wcsncpy | PASS |
| `fixture-verify::string/wide::wcsncpy::strict::strict_wcsncpy_pad` | string/wide | wcsncpy | strict | strict_wcsncpy_pad | ISO C wcsncpy | PASS |
| `fixture-verify::string/wide::wcsncpy::strict::wcsncpy_basic` | string/wide | wcsncpy | strict | wcsncpy_basic [strict] | C11 7.29.4.2.2 wcsncpy | PASS |
| `fixture-verify::string/wide::wcsncpy::strict::wcsncpy_pad` | string/wide | wcsncpy | strict | wcsncpy_pad [strict] | C11 7.29.4.2.2 wcsncpy | PASS |
| `fixture-verify::string/wide::wcsncpy::strict::wcsncpy_truncate` | string/wide | wcsncpy | strict | wcsncpy_truncate [strict] | C11 7.29.4.2.2 wcsncpy | PASS |
| `fixture-verify::string/wide::wcspbrk::hardened::wcspbrk_found` | string/wide | wcspbrk | hardened | wcspbrk_found [hardened] | C11 7.29.4.5.3 wcspbrk | PASS |
| `fixture-verify::string/wide::wcspbrk::hardened::wcspbrk_not_found` | string/wide | wcspbrk | hardened | wcspbrk_not_found [hardened] | C11 7.29.4.5.3 wcspbrk | PASS |
| `fixture-verify::string/wide::wcspbrk::strict::wcspbrk_found` | string/wide | wcspbrk | strict | wcspbrk_found [strict] | C11 7.29.4.5.3 wcspbrk | PASS |
| `fixture-verify::string/wide::wcspbrk::strict::wcspbrk_not_found` | string/wide | wcspbrk | strict | wcspbrk_not_found [strict] | C11 7.29.4.5.3 wcspbrk | PASS |
| `fixture-verify::string/wide::wcsrchr::hardened::wcsrchr_found` | string/wide | wcsrchr | hardened | wcsrchr_found [hardened] | C11 7.29.4.5.4 wcsrchr | PASS |
| `fixture-verify::string/wide::wcsrchr::hardened::wcsrchr_not_found` | string/wide | wcsrchr | hardened | wcsrchr_not_found [hardened] | C11 7.29.4.5.4 wcsrchr | PASS |
| `fixture-verify::string/wide::wcsrchr::strict::strict_wcsrchr_found` | string/wide | wcsrchr | strict | strict_wcsrchr_found | ISO C wcsrchr | PASS |
| `fixture-verify::string/wide::wcsrchr::strict::strict_wcsrchr_not_found` | string/wide | wcsrchr | strict | strict_wcsrchr_not_found | ISO C wcsrchr | PASS |
| `fixture-verify::string/wide::wcsrchr::strict::wcsrchr_found` | string/wide | wcsrchr | strict | wcsrchr_found [strict] | C11 7.29.4.5.4 wcsrchr | PASS |
| `fixture-verify::string/wide::wcsrchr::strict::wcsrchr_not_found` | string/wide | wcsrchr | strict | wcsrchr_not_found [strict] | C11 7.29.4.5.4 wcsrchr | PASS |
| `fixture-verify::string/wide::wcsspn::hardened::wcsspn_all_match` | string/wide | wcsspn | hardened | wcsspn_all_match [hardened] | C11 7.29.4.5.5 wcsspn | PASS |
| `fixture-verify::string/wide::wcsspn::hardened::wcsspn_none` | string/wide | wcsspn | hardened | wcsspn_none [hardened] | C11 7.29.4.5.5 wcsspn | PASS |
| `fixture-verify::string/wide::wcsspn::hardened::wcsspn_partial` | string/wide | wcsspn | hardened | wcsspn_partial [hardened] | C11 7.29.4.5.5 wcsspn | PASS |
| `fixture-verify::string/wide::wcsspn::strict::wcsspn_all_match` | string/wide | wcsspn | strict | wcsspn_all_match [strict] | C11 7.29.4.5.5 wcsspn | PASS |
| `fixture-verify::string/wide::wcsspn::strict::wcsspn_none` | string/wide | wcsspn | strict | wcsspn_none [strict] | C11 7.29.4.5.5 wcsspn | PASS |
| `fixture-verify::string/wide::wcsspn::strict::wcsspn_partial` | string/wide | wcsspn | strict | wcsspn_partial [strict] | C11 7.29.4.5.5 wcsspn | PASS |
| `fixture-verify::string/wide::wcsstr::hardened::wcsstr_empty_needle` | string/wide | wcsstr | hardened | wcsstr_empty_needle [hardened] | C11 7.29.4.5.7 wcsstr | PASS |
| `fixture-verify::string/wide::wcsstr::hardened::wcsstr_found` | string/wide | wcsstr | hardened | wcsstr_found [hardened] | C11 7.29.4.5.7 wcsstr | PASS |
| `fixture-verify::string/wide::wcsstr::hardened::wcsstr_not_found` | string/wide | wcsstr | hardened | wcsstr_not_found [hardened] | C11 7.29.4.5.7 wcsstr | PASS |
| `fixture-verify::string/wide::wcsstr::strict::strict_wcsstr_found` | string/wide | wcsstr | strict | strict_wcsstr_found | ISO C wcsstr | PASS |
| `fixture-verify::string/wide::wcsstr::strict::wcsstr_empty_needle` | string/wide | wcsstr | strict | wcsstr_empty_needle [strict] | C11 7.29.4.5.7 wcsstr | PASS |
| `fixture-verify::string/wide::wcsstr::strict::wcsstr_found` | string/wide | wcsstr | strict | wcsstr_found [strict] | C11 7.29.4.5.7 wcsstr | PASS |
| `fixture-verify::string/wide::wcsstr::strict::wcsstr_not_found` | string/wide | wcsstr | strict | wcsstr_not_found [strict] | C11 7.29.4.5.7 wcsstr | PASS |
| `fixture-verify::string/wide::wmemchr::hardened::wmemchr_found` | string/wide | wmemchr | hardened | wmemchr_found [hardened] | C11 7.29.4.5.8 wmemchr | PASS |
| `fixture-verify::string/wide::wmemchr::hardened::wmemchr_limited` | string/wide | wmemchr | hardened | wmemchr_limited [hardened] | C11 7.29.4.5.8 wmemchr | PASS |
| `fixture-verify::string/wide::wmemchr::hardened::wmemchr_not_found` | string/wide | wmemchr | hardened | wmemchr_not_found [hardened] | C11 7.29.4.5.8 wmemchr | PASS |
| `fixture-verify::string/wide::wmemchr::strict::wmemchr_found` | string/wide | wmemchr | strict | wmemchr_found [strict] | C11 7.29.4.5.8 wmemchr | PASS |
| `fixture-verify::string/wide::wmemchr::strict::wmemchr_limited` | string/wide | wmemchr | strict | wmemchr_limited [strict] | C11 7.29.4.5.8 wmemchr | PASS |
| `fixture-verify::string/wide::wmemchr::strict::wmemchr_not_found` | string/wide | wmemchr | strict | wmemchr_not_found [strict] | C11 7.29.4.5.8 wmemchr | PASS |
| `fixture-verify::string/wide::wmemcmp::hardened::wmemcmp_equal` | string/wide | wmemcmp | hardened | wmemcmp_equal [hardened] | C11 7.29.4.4.3 wmemcmp | PASS |
| `fixture-verify::string/wide::wmemcmp::hardened::wmemcmp_greater` | string/wide | wmemcmp | hardened | wmemcmp_greater [hardened] | C11 7.29.4.4.3 wmemcmp | PASS |
| `fixture-verify::string/wide::wmemcmp::hardened::wmemcmp_less` | string/wide | wmemcmp | hardened | wmemcmp_less [hardened] | C11 7.29.4.4.3 wmemcmp | PASS |
| `fixture-verify::string/wide::wmemcmp::hardened::wmemcmp_zero_n` | string/wide | wmemcmp | hardened | wmemcmp_zero_n [hardened] | C11 7.29.4.4.3 wmemcmp | PASS |
| `fixture-verify::string/wide::wmemcmp::strict::wmemcmp_equal` | string/wide | wmemcmp | strict | wmemcmp_equal [strict] | C11 7.29.4.4.3 wmemcmp | PASS |
| `fixture-verify::string/wide::wmemcmp::strict::wmemcmp_greater` | string/wide | wmemcmp | strict | wmemcmp_greater [strict] | C11 7.29.4.4.3 wmemcmp | PASS |
| `fixture-verify::string/wide::wmemcmp::strict::wmemcmp_less` | string/wide | wmemcmp | strict | wmemcmp_less [strict] | C11 7.29.4.4.3 wmemcmp | PASS |
| `fixture-verify::string/wide::wmemcmp::strict::wmemcmp_zero_n` | string/wide | wmemcmp | strict | wmemcmp_zero_n [strict] | C11 7.29.4.4.3 wmemcmp | PASS |
| `fixture-verify::string/wide::wmemcpy::hardened::wmemcpy_basic` | string/wide | wmemcpy | hardened | wmemcpy_basic [hardened] | C11 7.29.4.2.3 wmemcpy | PASS |
| `fixture-verify::string/wide::wmemcpy::hardened::wmemcpy_partial` | string/wide | wmemcpy | hardened | wmemcpy_partial [hardened] | C11 7.29.4.2.3 wmemcpy | PASS |
| `fixture-verify::string/wide::wmemcpy::hardened::wmemcpy_zero` | string/wide | wmemcpy | hardened | wmemcpy_zero [hardened] | C11 7.29.4.2.3 wmemcpy | PASS |
| `fixture-verify::string/wide::wmemcpy::strict::wmemcpy_basic` | string/wide | wmemcpy | strict | wmemcpy_basic [strict] | C11 7.29.4.2.3 wmemcpy | PASS |
| `fixture-verify::string/wide::wmemcpy::strict::wmemcpy_partial` | string/wide | wmemcpy | strict | wmemcpy_partial [strict] | C11 7.29.4.2.3 wmemcpy | PASS |
| `fixture-verify::string/wide::wmemcpy::strict::wmemcpy_zero` | string/wide | wmemcpy | strict | wmemcpy_zero [strict] | C11 7.29.4.2.3 wmemcpy | PASS |
| `fixture-verify::string/wide::wmemmove::hardened::wmemmove_basic` | string/wide | wmemmove | hardened | wmemmove_basic [hardened] | C11 7.29.4.2.4 wmemmove | PASS |
| `fixture-verify::string/wide::wmemmove::strict::wmemmove_basic` | string/wide | wmemmove | strict | wmemmove_basic [strict] | C11 7.29.4.2.4 wmemmove | PASS |
| `fixture-verify::string/wide::wmemset::hardened::wmemset_basic` | string/wide | wmemset | hardened | wmemset_basic [hardened] | C11 7.29.4.6.2 wmemset | PASS |
| `fixture-verify::string/wide::wmemset::hardened::wmemset_zero` | string/wide | wmemset | hardened | wmemset_zero [hardened] | C11 7.29.4.6.2 wmemset | PASS |
| `fixture-verify::string/wide::wmemset::strict::wmemset_basic` | string/wide | wmemset | strict | wmemset_basic [strict] | C11 7.29.4.6.2 wmemset | PASS |
| `fixture-verify::string/wide::wmemset::strict::wmemset_zero` | string/wide | wmemset | strict | wmemset_zero [strict] | C11 7.29.4.6.2 wmemset | PASS |
| `fixture-verify::string/wide_memory::wmemchr::strict::wmemchr_found` | string/wide_memory | wmemchr | strict | wmemchr_found | ISO C wmemchr | PASS |
| `fixture-verify::string/wide_memory::wmemcmp::strict::wmemcmp_equal` | string/wide_memory | wmemcmp | strict | wmemcmp_equal | ISO C wmemcmp | PASS |
| `fixture-verify::string/wide_memory::wmemcmp::strict::wmemcmp_less` | string/wide_memory | wmemcmp | strict | wmemcmp_less | ISO C wmemcmp | PASS |
| `fixture-verify::string/wide_memory::wmemcpy::strict::wmemcpy_basic` | string/wide_memory | wmemcpy | strict | wmemcpy_basic | ISO C wmemcpy | PASS |
| `fixture-verify::string/wide_memory::wmemmove::strict::wmemmove_basic` | string/wide_memory | wmemmove | strict | wmemmove_basic | ISO C wmemmove | PASS |
| `fixture-verify::string/wide_memory::wmemset::strict::wmemset_basic` | string/wide_memory | wmemset | strict | wmemset_basic | ISO C wmemset | PASS |
| `fixture-verify::sysv_ipc_ops::msgget::strict::msgget_create_strict` | sysv_ipc_ops | msgget | strict | msgget_create_strict | POSIX msgget(2) | PASS |
| `fixture-verify::sysv_ipc_ops::semctl::strict::semctl_setval_strict` | sysv_ipc_ops | semctl | strict | semctl_setval_strict | POSIX semctl(2) | PASS |
| `fixture-verify::sysv_ipc_ops::semget::hardened::semget_create_hardened` | sysv_ipc_ops | semget | hardened | semget_create_hardened | POSIX semget(2) | PASS |
| `fixture-verify::sysv_ipc_ops::semget::strict::semget_create_strict` | sysv_ipc_ops | semget | strict | semget_create_strict | POSIX semget(2) | PASS |
| `fixture-verify::sysv_ipc_ops::semop::strict::semop_wait_strict` | sysv_ipc_ops | semop | strict | semop_wait_strict | POSIX semop(2) | PASS |
| `fixture-verify::sysv_ipc_ops::shmat::strict::shmat_attach_strict` | sysv_ipc_ops | shmat | strict | shmat_attach_strict | POSIX shmat(2) | PASS |
| `fixture-verify::sysv_ipc_ops::shmdt::strict::shmdt_detach_strict` | sysv_ipc_ops | shmdt | strict | shmdt_detach_strict | POSIX shmdt(2) | PASS |
| `fixture-verify::sysv_ipc_ops::shmget::hardened::shmget_create_hardened` | sysv_ipc_ops | shmget | hardened | shmget_create_hardened | POSIX shmget(2) | PASS |
| `fixture-verify::sysv_ipc_ops::shmget::strict::shmget_create_strict` | sysv_ipc_ops | shmget | strict | shmget_create_strict | POSIX shmget(2) | PASS |
| `fixture-verify::termios_ops::cfgetispeed::strict::cfgetispeed_b9600_strict` | termios_ops | cfgetispeed | strict | cfgetispeed_b9600_strict | POSIX cfgetispeed | PASS |
| `fixture-verify::termios_ops::cfgetospeed::strict::cfgetospeed_b9600_strict` | termios_ops | cfgetospeed | strict | cfgetospeed_b9600_strict | POSIX cfgetospeed | PASS |
| `fixture-verify::termios_ops::cfsetispeed::strict::cfsetispeed_b115200_strict` | termios_ops | cfsetispeed | strict | cfsetispeed_b115200_strict | POSIX cfsetispeed | PASS |
| `fixture-verify::termios_ops::cfsetospeed::strict::cfsetospeed_b115200_strict` | termios_ops | cfsetospeed | strict | cfsetospeed_b115200_strict | POSIX cfsetospeed | PASS |
| `fixture-verify::termios_ops::tcgetattr::hardened::tcgetattr_invalid_fd_hardened` | termios_ops | tcgetattr | hardened | tcgetattr_invalid_fd_hardened | POSIX tcgetattr | PASS |
| `fixture-verify::termios_ops::tcgetattr::hardened::tcgetattr_stdin_hardened` | termios_ops | tcgetattr | hardened | tcgetattr_stdin_hardened | POSIX tcgetattr | PASS |
| `fixture-verify::termios_ops::tcgetattr::strict::tcgetattr_invalid_fd_strict` | termios_ops | tcgetattr | strict | tcgetattr_invalid_fd_strict | POSIX tcgetattr | PASS |
| `fixture-verify::termios_ops::tcgetattr::strict::tcgetattr_stdin_strict` | termios_ops | tcgetattr | strict | tcgetattr_stdin_strict | POSIX tcgetattr | PASS |
| `fixture-verify::time_ops::clock::strict::clock_returns_positive_strict` | time_ops | clock | strict | clock_returns_positive_strict | C11 7.27.2.1 clock | PASS |
| `fixture-verify::time_ops::clock_gettime::hardened::clock_gettime_realtime_hardened` | time_ops | clock_gettime | hardened | clock_gettime_realtime_hardened | POSIX clock_gettime | PASS |
| `fixture-verify::time_ops::clock_gettime::strict::clock_gettime_invalid_strict` | time_ops | clock_gettime | strict | clock_gettime_invalid_strict | POSIX clock_gettime | PASS |
| `fixture-verify::time_ops::clock_gettime::strict::clock_gettime_monotonic_strict` | time_ops | clock_gettime | strict | clock_gettime_monotonic_strict | POSIX clock_gettime | PASS |
| `fixture-verify::time_ops::clock_gettime::strict::clock_gettime_realtime_strict` | time_ops | clock_gettime | strict | clock_gettime_realtime_strict | POSIX clock_gettime | PASS |
| `fixture-verify::time_ops::localtime_r::strict::localtime_r_epoch_strict` | time_ops | localtime_r | strict | localtime_r_epoch_strict | POSIX localtime_r | PASS |
| `fixture-verify::time_ops::time::hardened::time_returns_positive_hardened` | time_ops | time | hardened | time_returns_positive_hardened | POSIX time | PASS |
| `fixture-verify::time_ops::time::strict::time_returns_positive_strict` | time_ops | time | strict | time_returns_positive_strict | POSIX time | PASS |
| `fixture-verify::unistd::access::hardened::access_nonexistent_enoent` | unistd | access | hardened | access_nonexistent_enoent [hardened] | POSIX.1-2017 access | PASS |
| `fixture-verify::unistd::access::hardened::access_root_exists` | unistd | access | hardened | access_root_exists [hardened] | POSIX.1-2017 access | PASS |
| `fixture-verify::unistd::access::strict::access_nonexistent_enoent` | unistd | access | strict | access_nonexistent_enoent [strict] | POSIX.1-2017 access | PASS |
| `fixture-verify::unistd::access::strict::access_root_exists` | unistd | access | strict | access_root_exists [strict] | POSIX.1-2017 access | PASS |
| `fixture-verify::unistd::close::hardened::close_invalid_fd_ebadf` | unistd | close | hardened | close_invalid_fd_ebadf [hardened] | POSIX.1-2017 close | PASS |
| `fixture-verify::unistd::close::hardened::close_valid_fd` | unistd | close | hardened | close_valid_fd [hardened] | POSIX.1-2017 close | PASS |
| `fixture-verify::unistd::close::strict::close_invalid_fd_ebadf` | unistd | close | strict | close_invalid_fd_ebadf [strict] | POSIX.1-2017 close | PASS |
| `fixture-verify::unistd::close::strict::close_valid_fd` | unistd | close | strict | close_valid_fd [strict] | POSIX.1-2017 close | PASS |
| `fixture-verify::unistd::getcwd::hardened::getcwd_nonempty` | unistd | getcwd | hardened | getcwd_nonempty [hardened] | POSIX.1-2017 getcwd | PASS |
| `fixture-verify::unistd::getcwd::strict::getcwd_nonempty` | unistd | getcwd | strict | getcwd_nonempty [strict] | POSIX.1-2017 getcwd | PASS |
| `fixture-verify::unistd::getegid::hardened::getegid_nonneg` | unistd | getegid | hardened | getegid_nonneg [hardened] | POSIX.1-2017 getegid | PASS |
| `fixture-verify::unistd::getegid::strict::getegid_nonneg` | unistd | getegid | strict | getegid_nonneg [strict] | POSIX.1-2017 getegid | PASS |
| `fixture-verify::unistd::geteuid::hardened::geteuid_nonneg` | unistd | geteuid | hardened | geteuid_nonneg [hardened] | POSIX.1-2017 geteuid | PASS |
| `fixture-verify::unistd::geteuid::strict::geteuid_nonneg` | unistd | geteuid | strict | geteuid_nonneg [strict] | POSIX.1-2017 geteuid | PASS |
| `fixture-verify::unistd::getgid::hardened::getgid_nonneg` | unistd | getgid | hardened | getgid_nonneg [hardened] | POSIX.1-2017 getgid | PASS |
| `fixture-verify::unistd::getgid::strict::getgid_nonneg` | unistd | getgid | strict | getgid_nonneg [strict] | POSIX.1-2017 getgid | PASS |
| `fixture-verify::unistd::getpid::hardened::getpid_positive` | unistd | getpid | hardened | getpid_positive [hardened] | POSIX.1-2017 getpid | PASS |
| `fixture-verify::unistd::getpid::strict::getpid_positive` | unistd | getpid | strict | getpid_positive [strict] | POSIX.1-2017 getpid | PASS |
| `fixture-verify::unistd::getppid::hardened::getppid_positive` | unistd | getppid | hardened | getppid_positive [hardened] | POSIX.1-2017 getppid | PASS |
| `fixture-verify::unistd::getppid::strict::getppid_positive` | unistd | getppid | strict | getppid_positive [strict] | POSIX.1-2017 getppid | PASS |
| `fixture-verify::unistd::getuid::hardened::getuid_nonneg` | unistd | getuid | hardened | getuid_nonneg [hardened] | POSIX.1-2017 getuid | PASS |
| `fixture-verify::unistd::getuid::strict::getuid_nonneg` | unistd | getuid | strict | getuid_nonneg [strict] | POSIX.1-2017 getuid | PASS |
| `fixture-verify::unistd::isatty::hardened::isatty_invalid_fd` | unistd | isatty | hardened | isatty_invalid_fd [hardened] | POSIX.1-2017 isatty | PASS |
| `fixture-verify::unistd::isatty::hardened::isatty_stdin` | unistd | isatty | hardened | isatty_stdin [hardened] | POSIX.1-2017 isatty | PASS |
| `fixture-verify::unistd::isatty::strict::isatty_invalid_fd` | unistd | isatty | strict | isatty_invalid_fd [strict] | POSIX.1-2017 isatty | PASS |
| `fixture-verify::unistd::isatty::strict::isatty_stdin` | unistd | isatty | strict | isatty_stdin [strict] | POSIX.1-2017 isatty | PASS |
| `fixture-verify::unistd::lseek::hardened::lseek_set` | unistd | lseek | hardened | lseek_set [hardened] | POSIX.1-2017 lseek | PASS |
| `fixture-verify::unistd::lseek::strict::lseek_set` | unistd | lseek | strict | lseek_set [strict] | POSIX.1-2017 lseek | PASS |
| `fixture-verify::unistd::pipe::hardened::pipe_creates_two_fds` | unistd | pipe | hardened | pipe_creates_two_fds [hardened] | POSIX.1-2017 pipe | PASS |
| `fixture-verify::unistd::pipe::strict::pipe_creates_two_fds` | unistd | pipe | strict | pipe_creates_two_fds [strict] | POSIX.1-2017 pipe | PASS |
| `fixture-verify::unistd::read::strict::read_from_pipe` | unistd | read | strict | read_from_pipe | POSIX.1-2017 read | PASS |
| `fixture-verify::unistd::write::strict::read_write_pipe` | unistd | write | strict | read_write_pipe | POSIX.1-2017 write | PASS |
| `fixture-verify::virtual_memory_ops::madvise::strict::madvise_normal_strict` | virtual_memory_ops | madvise | strict | madvise_normal_strict | POSIX posix_madvise / Linux madvise | PASS |
| `fixture-verify::virtual_memory_ops::mmap::hardened::mmap_anon_rw_hardened` | virtual_memory_ops | mmap | hardened | mmap_anon_rw_hardened | POSIX mmap | PASS |
| `fixture-verify::virtual_memory_ops::mmap::hardened::mmap_invalid_prot_hardened` | virtual_memory_ops | mmap | hardened | mmap_invalid_prot_hardened | POSIX mmap | PASS |
| `fixture-verify::virtual_memory_ops::mmap::hardened::mmap_missing_visibility_hardened` | virtual_memory_ops | mmap | hardened | mmap_missing_visibility_hardened | POSIX mmap | PASS |
| `fixture-verify::virtual_memory_ops::mmap::strict::mmap_anon_rw_strict` | virtual_memory_ops | mmap | strict | mmap_anon_rw_strict | POSIX mmap | PASS |
| `fixture-verify::virtual_memory_ops::mmap::strict::mmap_zero_length_strict` | virtual_memory_ops | mmap | strict | mmap_zero_length_strict | POSIX mmap | PASS |
| `fixture-verify::virtual_memory_ops::mprotect::strict::mprotect_read_only_strict` | virtual_memory_ops | mprotect | strict | mprotect_read_only_strict | POSIX mprotect | PASS |
| `fixture-verify::virtual_memory_ops::munmap::strict::munmap_valid_strict` | virtual_memory_ops | munmap | strict | munmap_valid_strict | POSIX munmap | PASS |
