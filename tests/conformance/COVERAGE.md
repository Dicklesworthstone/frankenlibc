# Conformance Test Coverage

This document tracks fixture test coverage for FrankenLibC conformance testing.
Generated: 2026-04-18

## Summary

| Metric | Count |
|--------|-------|
| Total fixture files | 55 |
| Fixtures with unit tests | 46 |
| Fixtures pending coverage | 9 |
| Unit test pass rate | 100% |

## Fixture Coverage Matrix

### Covered (46 fixtures with passing unit tests)

| Fixture | Test Name | Status |
|---------|-----------|--------|
| allocator | allocator_fixture_cases_match | PASS |
| backtrace_ops | backtrace_ops_fixture_cases_match | PASS |
| ctype_ops | ctype_ops_fixture_cases_match | PASS |
| dirent_ops | dirent_ops_fixture_cases_match | PASS |
| dlfcn_ops | dlfcn_ops_fixture_cases_match | PASS |
| elf_loader | elf_loader_fixture_cases_match | PASS |
| errno_ops | errno_ops_fixture_cases_match | PASS |
| grp_ops | grp_ops_fixture_cases_match | PASS |
| iconv_phase1 | iconv_phase1_fixture_cases_match | PASS |
| inet_ops | inet_ops_fixture_cases_match | PASS |
| io_internal_ops | io_internal_ops_fixture_cases_match | PASS |
| locale_ops | locale_ops_fixture_cases_match | PASS |
| math_ops | math_ops_fixture_cases_match | PASS |
| membrane_mode_split | membrane_mode_split_fixture_cases_match | PASS |
| memcpy_strict | memcpy_strict_fixture_cases_match | PASS |
| memory_ops | memory_ops_fixture_cases_match | PASS |
| poll_ops | poll_ops_fixture_cases_match | PASS |
| pressure_sensing | pressure_sensing_fixture_cases_match | PASS |
| process_ops | process_ops_fixture_cases_match | PASS |
| pthread_cond | pthread_cond_fixture_cases_match | PASS |
| pthread_gnu_extensions | pthread_gnu_extensions_fixture_cases_match | PASS |
| pthread_mutex | pthread_mutex_fixture_cases_match | PASS |
| pthread_tls_keys | pthread_tls_keys_fixture_cases_match | PASS |
| pwd_ops | pwd_ops_fixture_cases_match | PASS |
| regex_glob_ops | regex_glob_ops_fixture_cases_match | PASS |
| resource_ops | resource_ops_fixture_cases_match | PASS |
| search_ops | search_ops_fixture_cases_match | PASS |
| session_ops | session_ops_fixture_cases_match | PASS |
| setjmp_ops | setjmp_ops_fixture_cases_match | PASS |
| signal_ops | signal_ops_fixture_cases_match | PASS |
| socket_ops | socket_ops_fixture_cases_match | PASS |
| startup_ops | startup_ops_fixture_cases_match | PASS |
| stdio_file_ops | stdio_file_ops_fixture_cases_match | PASS |
| stdlib_conversion | stdlib_conversion_fixture_cases_match | PASS |
| stdlib_numeric | stdlib_numeric_fixture_cases_match | PASS |
| stdlib_sort | stdlib_sort_fixture_cases_match | PASS |
| string_memory_full | string_memory_full_fixture_cases_match | PASS |
| string_ops | string_ops_fixture_cases_match | PASS |
| string_strtok | string_strtok_fixture_cases_match | PASS |
| strlen_strict | strlen_strict_fixture_cases_match | PASS |
| time_ops | time_ops_fixture_cases_match | PASS |
| unistd_ops | unistd_ops_fixture_cases_match | PASS |
| virtual_memory_ops | virtual_memory_ops_fixture_cases_match | PASS |
| wide_memory | wide_memory_fixture_cases_match | PASS |
| wide_string | wide_string_fixture_cases_match | PASS |
| wide_string_ops | wide_string_ops_fixture_cases_match | PASS |

### Pending Coverage (9 fixtures)

| Fixture | Blocker | Notes |
|---------|---------|-------|
| loader_edges | Ready | dlopen/dlsym/dlclose edge cases - executors exist |
| printf_conformance | Complex schema | Uses expected_output_pattern/expected_output_bytes variants |
| pthread_thread | STUB executor | Thread lifecycle operations stubbed |
| resolver | Network dependent | DNS resolution requires network |
| scanf_conformance | STUB executor | sscanf executor returns "STUB" |
| setjmp_nested_edges | Integration format | Uses program_scenarios (requires C binary execution) |
| spawn_exec_ops | Ready | posix_spawn/execve/system - executors exist |
| sysv_ipc_ops | Ready | semget/shmget/msgget - executors exist |
| termios_ops | Environment dependent | Terminal I/O varies by environment |

### Ready for Implementation

These fixtures have working executors and can be added when lib.rs is available:

1. **sysv_ipc_ops** - Tests semget, semop, semctl, shmget, shmat, shmdt, msgget
2. **loader_edges** - Tests dlopen, dlsym, dlclose, dladdr, dlinfo edge cases  
3. **spawn_exec_ops** - Tests posix_spawn, system, execve, execvp operations

## Test Commands

```bash
# Run all fixture unit tests
cargo test --package frankenlibc_conformance fixture_cases_match

# Run specific fixture test
cargo test --package frankenlibc_conformance <fixture>_fixture_cases_match

# Run harness conformance tests
cargo test -p frankenlibc-harness --test <fixture>_conformance_test
```

## Coverage Gaps Analysis

### High Priority (working executors, blocked by file reservation)

- sysv_ipc_ops (9 cases)
- loader_edges (7 cases)
- spawn_exec_ops (already added in latest session)

### Medium Priority (needs executor work)

- printf_conformance - needs pattern matching in test harness
- scanf_conformance - needs sscanf executor implementation

### Low Priority (structural blockers)

- setjmp_nested_edges - requires integration test framework
- resolver - requires network mocking or real DNS
- termios_ops - requires terminal emulation
- pthread_thread - requires thread lifecycle implementation

## Pending Changes

The following fixture tests have been validated (49 tests pass) but are blocked
by file reservation on `crates/frankenlibc_conformance/src/lib.rs`:

- spawn_exec_ops_fixture_cases_match_execute_fixture_case
- sysv_ipc_ops_fixture_cases_match_execute_fixture_case  
- loader_edges_fixture_cases_match_execute_fixture_case

These will be committed when the reservation is released.

## Related Documents

- [DISCREPANCIES.md](DISCREPANCIES.md) - Known conformance divergences
- [fixtures/](fixtures/) - JSON fixture files
