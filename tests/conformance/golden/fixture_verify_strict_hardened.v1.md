# frankenlibc Conformance Report

- Mode: strict+hardened
- Timestamp: 1970-01-01T00:00:00Z
- Total: 91
- Passed: 91
- Failed: 0

| Trace | Family | Symbol | Mode | Case | Spec | Status |
|-------|--------|--------|------|------|------|--------|
| `fixture-verify::allocator::calloc::strict::calloc_basic` | allocator | calloc | strict | calloc_basic | POSIX calloc | PASS |
| `fixture-verify::allocator::free::strict::free_null` | allocator | free | strict | free_null | POSIX free | PASS |
| `fixture-verify::allocator::malloc::strict::malloc_basic` | allocator | malloc | strict | malloc_basic | POSIX malloc | PASS |
| `fixture-verify::allocator::malloc::strict::malloc_zero` | allocator | malloc | strict | malloc_zero | POSIX malloc | PASS |
| `fixture-verify::allocator::realloc::strict::realloc_null_is_malloc` | allocator | realloc | strict | realloc_null_is_malloc | POSIX realloc | PASS |
| `fixture-verify::iconv/phase1::iconv::hardened::hardened_utf16le_to_utf8` | iconv/phase1 | iconv | hardened | hardened_utf16le_to_utf8 | TSM hardened iconv | PASS |
| `fixture-verify::iconv/phase1::iconv::strict::strict_e2big_preserves_progress` | iconv/phase1 | iconv | strict | strict_e2big_preserves_progress | POSIX iconv | PASS |
| `fixture-verify::iconv/phase1::iconv::strict::strict_eilseq_invalid_utf8` | iconv/phase1 | iconv | strict | strict_eilseq_invalid_utf8 | POSIX iconv | PASS |
| `fixture-verify::iconv/phase1::iconv::strict::strict_einval_incomplete_utf8` | iconv/phase1 | iconv | strict | strict_einval_incomplete_utf8 | POSIX iconv | PASS |
| `fixture-verify::iconv/phase1::iconv::strict::strict_latin1_to_utf8_multibyte` | iconv/phase1 | iconv | strict | strict_latin1_to_utf8_multibyte | POSIX iconv | PASS |
| `fixture-verify::iconv/phase1::iconv::strict::strict_unsupported_encoding` | iconv/phase1 | iconv | strict | strict_unsupported_encoding | POSIX iconv | PASS |
| `fixture-verify::iconv/phase1::iconv::strict::strict_utf8_to_utf16le_basic` | iconv/phase1 | iconv | strict | strict_utf8_to_utf16le_basic | POSIX iconv | PASS |
| `fixture-verify::membrane/mode-split::memcpy::hardened::hardened_memcpy_overflow_clamped` | membrane/mode-split | memcpy | hardened | hardened_memcpy_overflow_clamped | TSM hardened memcpy | PASS |
| `fixture-verify::membrane/mode-split::memcpy::strict::strict_memcpy_overflow_ub` | membrane/mode-split | memcpy | strict | strict_memcpy_overflow_ub | TSM strict memcpy | PASS |
| `fixture-verify::membrane/mode-split::strlen::hardened::hardened_strlen_unterminated_truncated` | membrane/mode-split | strlen | hardened | hardened_strlen_unterminated_truncated | TSM hardened strlen | PASS |
| `fixture-verify::membrane/mode-split::strlen::strict::strict_strlen_unterminated_ub` | membrane/mode-split | strlen | strict | strict_strlen_unterminated_ub | TSM strict strlen | PASS |
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
| `fixture-verify::stdlib/numeric::strtol::strict::strtol_base10` | stdlib/numeric | strtol | strict | strtol_base10 | POSIX strtol | PASS |
| `fixture-verify::stdlib/numeric::strtol::strict::strtol_hex_auto` | stdlib/numeric | strtol | strict | strtol_hex_auto | POSIX strtol | PASS |
| `fixture-verify::stdlib/numeric::strtoul::strict::strtoul_basic` | stdlib/numeric | strtoul | strict | strtoul_basic | POSIX strtoul | PASS |
| `fixture-verify::stdlib/numeric::strtoul::strict::strtoul_negative_wrap` | stdlib/numeric | strtoul | strict | strtoul_negative_wrap | POSIX strtoul | PASS |
| `fixture-verify::stdlib/sort::bsearch::strict::bsearch_found` | stdlib/sort | bsearch | strict | bsearch_found | ISO C bsearch | PASS |
| `fixture-verify::stdlib/sort::bsearch::strict::bsearch_not_found` | stdlib/sort | bsearch | strict | bsearch_not_found | ISO C bsearch | PASS |
| `fixture-verify::stdlib/sort::qsort::strict::qsort_int` | stdlib/sort | qsort | strict | qsort_int | ISO C qsort | PASS |
| `fixture-verify::string/memcpy::memcpy::strict::copy_full_8` | string/memcpy | memcpy | strict | copy_full_8 | POSIX.1-2017 memcpy | PASS |
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
| `fixture-verify::string/narrow::strncpy::strict::strict_strncpy_basic` | string/narrow | strncpy | strict | strict_strncpy_basic | POSIX strncpy | PASS |
| `fixture-verify::string/narrow::strrchr::strict::strict_strrchr_found` | string/narrow | strrchr | strict | strict_strrchr_found | POSIX strrchr | PASS |
| `fixture-verify::string/narrow::strstr::strict::strict_strstr_found` | string/narrow | strstr | strict | strict_strstr_found | POSIX strstr | PASS |
| `fixture-verify::string/strlen::strlen::strict::empty_string` | string/strlen | strlen | strict | empty_string | POSIX.1-2017 strlen | PASS |
| `fixture-verify::string/strlen::strlen::strict::hello` | string/strlen | strlen | strict | hello | POSIX.1-2017 strlen | PASS |
| `fixture-verify::string/strlen::strlen::strict::single_char` | string/strlen | strlen | strict | single_char | POSIX.1-2017 strlen | PASS |
| `fixture-verify::string/wide::wcscat::strict::strict_wcscat_basic` | string/wide | wcscat | strict | strict_wcscat_basic | ISO C wcscat | PASS |
| `fixture-verify::string/wide::wcschr::strict::strict_wcschr_found` | string/wide | wcschr | strict | strict_wcschr_found | ISO C wcschr | PASS |
| `fixture-verify::string/wide::wcschr::strict::strict_wcschr_not_found` | string/wide | wcschr | strict | strict_wcschr_not_found | ISO C wcschr | PASS |
| `fixture-verify::string/wide::wcscmp::strict::strict_wcscmp_equal` | string/wide | wcscmp | strict | strict_wcscmp_equal | ISO C wcscmp | PASS |
| `fixture-verify::string/wide::wcscmp::strict::strict_wcscmp_less` | string/wide | wcscmp | strict | strict_wcscmp_less | ISO C wcscmp | PASS |
| `fixture-verify::string/wide::wcscmp::strict::wcscmp_equal` | string/wide | wcscmp | strict | wcscmp_equal | ISO C wcscmp | PASS |
| `fixture-verify::string/wide::wcscmp::strict::wcscmp_less` | string/wide | wcscmp | strict | wcscmp_less | ISO C wcscmp | PASS |
| `fixture-verify::string/wide::wcscpy::hardened::hardened_wcscpy_overflow` | string/wide | wcscpy | hardened | hardened_wcscpy_overflow | TSM hardened wcscpy | PASS |
| `fixture-verify::string/wide::wcscpy::strict::strict_wcscpy_basic` | string/wide | wcscpy | strict | strict_wcscpy_basic | ISO C wcscpy | PASS |
| `fixture-verify::string/wide::wcscpy::strict::wcscpy_basic` | string/wide | wcscpy | strict | wcscpy_basic | ISO C wcscpy | PASS |
| `fixture-verify::string/wide::wcslen::strict::strict_wcslen_basic` | string/wide | wcslen | strict | strict_wcslen_basic | ISO C wcslen | PASS |
| `fixture-verify::string/wide::wcslen::strict::strict_wcslen_empty` | string/wide | wcslen | strict | strict_wcslen_empty | ISO C wcslen | PASS |
| `fixture-verify::string/wide::wcslen::strict::wcslen_basic` | string/wide | wcslen | strict | wcslen_basic | ISO C wcslen | PASS |
| `fixture-verify::string/wide::wcsncpy::strict::strict_wcsncpy_basic` | string/wide | wcsncpy | strict | strict_wcsncpy_basic | ISO C wcsncpy | PASS |
| `fixture-verify::string/wide::wcsncpy::strict::strict_wcsncpy_pad` | string/wide | wcsncpy | strict | strict_wcsncpy_pad | ISO C wcsncpy | PASS |
| `fixture-verify::string/wide::wcsstr::strict::strict_wcsstr_found` | string/wide | wcsstr | strict | strict_wcsstr_found | ISO C wcsstr | PASS |
| `fixture-verify::string/wide_memory::wmemchr::strict::wmemchr_found` | string/wide_memory | wmemchr | strict | wmemchr_found | ISO C wmemchr | PASS |
| `fixture-verify::string/wide_memory::wmemcmp::strict::wmemcmp_equal` | string/wide_memory | wmemcmp | strict | wmemcmp_equal | ISO C wmemcmp | PASS |
| `fixture-verify::string/wide_memory::wmemcmp::strict::wmemcmp_less` | string/wide_memory | wmemcmp | strict | wmemcmp_less | ISO C wmemcmp | PASS |
| `fixture-verify::string/wide_memory::wmemcpy::strict::wmemcpy_basic` | string/wide_memory | wmemcpy | strict | wmemcpy_basic | ISO C wmemcpy | PASS |
| `fixture-verify::string/wide_memory::wmemmove::strict::wmemmove_basic` | string/wide_memory | wmemmove | strict | wmemmove_basic | ISO C wmemmove | PASS |
| `fixture-verify::string/wide_memory::wmemset::strict::wmemset_basic` | string/wide_memory | wmemset | strict | wmemset_basic | ISO C wmemset | PASS |
