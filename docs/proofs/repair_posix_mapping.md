# Hardened Repair/POSIX Mapping (bd-34s.1)

This table records the deterministic mapping from hardened invalid-input class to repair/deny action and POSIX-facing fixture outcome.

| Invalid Input Class | Family/Symbol | Decision | Healing Action | Policy ID | Expected Output (fixture) | Expected errno |
|---|---|---|---|---|---|---|
| `memcpy_overflow` | `StringMemory/memcpy` | Repair | `ClampSize` | `tsm.repair.stringmemory.memcpy_overflow.v1` | `[1, 2]` | `0` |
| `unterminated_scan` | `StringMemory/strlen` | Repair | `ClampSize` | `tsm.repair.stringmemory.unterminated_scan.v1` | `3` | `0` |
| `string_copy_overflow` | `StringMemory/strcpy` | Repair | `TruncateWithNull` | `tsm.repair.stringmemory.string_copy_overflow.v1` | `[65, 0]` | `0` |
| `string_concat_overflow` | `StringMemory/strcat` | Repair | `TruncateWithNull` | `tsm.repair.stringmemory.string_concat_overflow.v1` | `[65, 66, 0]` | `0` |
| `wide_copy_overflow` | `WideChar/wcscpy` | Repair | `TruncateWithNull` | `tsm.repair.widechar.wide_copy_overflow.v1` | `[65, 0]` | `0` |
| `iconv_unsupported_encoding` | `Iconv/iconv_open` | Deny | `None` | `tsm.deny.iconv.iconv_unsupported_encoding.v1` | `open_err errno=22` | `22` |
| `poll_oversized_nfds` | `Poll/poll` | Repair | `ClampSize` | `tsm.repair.poll.poll_oversized_nfds.v1` | `POLL_CLAMPED` | `0` |
| `locale_unsupported_fallback` | `Locale/setlocale` | Repair | `ReturnSafeDefault` | `tsm.repair.locale.locale_unsupported_fallback.v1` | `C` | `0` |
| `mmap_invalid_protection` | `VirtualMemory/mmap` | Repair | `UpgradeToSafeVariant` | `tsm.repair.virtual_memory.mmap_invalid_protection.v1` | `MAPPED_REPAIRED` | `0` |
| `mmap_missing_visibility` | `VirtualMemory/mmap` | Repair | `UpgradeToSafeVariant` | `tsm.repair.virtual_memory.mmap_missing_visibility.v1` | `MAPPED_REPAIRED` | `0` |
| `startup_unterminated_auxv` | `Startup/__frankenlibc_startup_phase0` | Deny | `None` | `tsm.deny.startup.startup_unterminated_auxv.v1` | `DENY_INVALID_STARTUP_CONTEXT` | `7` |
| `socket_invalid_domain` | `Socket/socket` | Deny | `None` | `tsm.deny.socket.socket_invalid_domain.v1` | `-1` | `97` |
| `invalid_signal_number` | `Signal/kill` | Deny | `None` | `tsm.deny.signal.invalid_signal_number.v1` | `-1` | `22` |
| `invalid_resource_query` | `Resource/getrlimit` | Deny | `None` | `tsm.deny.resource.invalid_resource_query.v1` | `-1` | `22` |
| `invalid_terminal_fd` | `Termios/tcgetattr` | Deny | `None` | `tsm.deny.termios.invalid_terminal_fd.v1` | `-1` | `9` |

## Sources
- Matrix artifact: `tests/conformance/hardened_repair_deny_matrix.v1.json`
- Fixture references: `tests/conformance/fixtures/*.json` entries linked in matrix `fixture_case_refs`
- Gate enforcement: `scripts/check_hardened_repair_deny_matrix.sh`
- Coverage report artifact: `target/conformance/hardened_repair_deny_matrix.report.json`
- Structured gate log: `target/conformance/hardened_repair_deny_matrix.log.jsonl`
