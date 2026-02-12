# glibc_rust Conformance Report

- Mode: strict+hardened
- Timestamp: 1970-01-01T00:00:00Z
- Total: 91
- Passed: 91
- Failed: 0

| Case | Spec | Status |
|------|------|--------|
| atoi_basic | POSIX atoi | PASS |
| atoi_basic | POSIX atoi | PASS |
| atoi_negative | POSIX atoi | PASS |
| atoi_negative | POSIX atoi | PASS |
| atoi_whitespace | POSIX atoi | PASS |
| atoi_whitespace | POSIX atoi | PASS |
| bsearch_found | ISO C bsearch | PASS |
| bsearch_not_found | ISO C bsearch | PASS |
| calloc_basic | POSIX calloc | PASS |
| copy_full_8 | POSIX.1-2017 memcpy | PASS |
| copy_partial_4 | POSIX.1-2017 memcpy | PASS |
| copy_single_byte | POSIX.1-2017 memcpy | PASS |
| copy_zero | POSIX.1-2017 memcpy | PASS |
| empty_string | POSIX.1-2017 strlen | PASS |
| free_null | POSIX free | PASS |
| hardened_memcpy_overflow_clamped | TSM hardened memcpy | PASS |
| hardened_strcat_overflow | TSM hardened strcat | PASS |
| hardened_strcpy_overflow | TSM hardened strcpy | PASS |
| hardened_strlen_unterminated_truncated | TSM hardened strlen | PASS |
| hardened_utf16le_to_utf8 | TSM hardened iconv | PASS |
| hardened_wcscpy_overflow | TSM hardened wcscpy | PASS |
| hello | POSIX.1-2017 strlen | PASS |
| malloc_basic | POSIX malloc | PASS |
| malloc_zero | POSIX malloc | PASS |
| memchr_found | POSIX memchr | PASS |
| memcmp_equal | POSIX memcmp | PASS |
| memcmp_less | POSIX memcmp | PASS |
| memrchr_found | GNU memrchr | PASS |
| memset_basic | POSIX memset | PASS |
| qsort_int | ISO C qsort | PASS |
| realloc_null_is_malloc | POSIX realloc | PASS |
| single_char | POSIX.1-2017 strlen | PASS |
| strcat_basic | POSIX strcat | PASS |
| strchr_found | POSIX strchr | PASS |
| strcmp_equal | POSIX strcmp | PASS |
| strcmp_less | POSIX strcmp | PASS |
| strcpy_basic | POSIX strcpy | PASS |
| strict_e2big_preserves_progress | POSIX iconv | PASS |
| strict_eilseq_invalid_utf8 | POSIX iconv | PASS |
| strict_einval_incomplete_utf8 | POSIX iconv | PASS |
| strict_latin1_to_utf8_multibyte | POSIX iconv | PASS |
| strict_memchr_found | POSIX memchr | PASS |
| strict_memcmp_equal | POSIX memcmp | PASS |
| strict_memcmp_less | POSIX memcmp | PASS |
| strict_memcpy_overflow_ub | TSM strict memcpy | PASS |
| strict_memmove_basic | POSIX memmove | PASS |
| strict_memrchr_found | GNU memrchr | PASS |
| strict_memset_basic | POSIX memset | PASS |
| strict_strcat_basic | POSIX strcat | PASS |
| strict_strchr_found | POSIX strchr | PASS |
| strict_strcmp_equal | POSIX strcmp | PASS |
| strict_strcpy_basic | POSIX strcpy | PASS |
| strict_strlen_unterminated_ub | TSM strict strlen | PASS |
| strict_strncpy_basic | POSIX strncpy | PASS |
| strict_strrchr_found | POSIX strrchr | PASS |
| strict_strstr_found | POSIX strstr | PASS |
| strict_unsupported_encoding | POSIX iconv | PASS |
| strict_utf8_to_utf16le_basic | POSIX iconv | PASS |
| strict_wcscat_basic | ISO C wcscat | PASS |
| strict_wcschr_found | ISO C wcschr | PASS |
| strict_wcschr_not_found | ISO C wcschr | PASS |
| strict_wcscmp_equal | ISO C wcscmp | PASS |
| strict_wcscmp_less | ISO C wcscmp | PASS |
| strict_wcscpy_basic | ISO C wcscpy | PASS |
| strict_wcslen_basic | ISO C wcslen | PASS |
| strict_wcslen_empty | ISO C wcslen | PASS |
| strict_wcsncpy_basic | ISO C wcsncpy | PASS |
| strict_wcsncpy_pad | ISO C wcsncpy | PASS |
| strict_wcsstr_found | ISO C wcsstr | PASS |
| strncat_basic | POSIX strncat | PASS |
| strncpy_basic | POSIX strncpy | PASS |
| strrchr_found | POSIX strrchr | PASS |
| strstr_found | POSIX strstr | PASS |
| strtol_auto | POSIX strtol | PASS |
| strtol_base10 | POSIX strtol | PASS |
| strtol_decimal | POSIX strtol | PASS |
| strtol_hex | POSIX strtol | PASS |
| strtol_hex_auto | POSIX strtol | PASS |
| strtol_overflow_max | POSIX strtol | PASS |
| strtoul_basic | POSIX strtoul | PASS |
| strtoul_negative_wrap | POSIX strtoul | PASS |
| wcscmp_equal | ISO C wcscmp | PASS |
| wcscmp_less | ISO C wcscmp | PASS |
| wcscpy_basic | ISO C wcscpy | PASS |
| wcslen_basic | ISO C wcslen | PASS |
| wmemchr_found | ISO C wmemchr | PASS |
| wmemcmp_equal | ISO C wmemcmp | PASS |
| wmemcmp_less | ISO C wmemcmp | PASS |
| wmemcpy_basic | ISO C wmemcpy | PASS |
| wmemmove_basic | ISO C wmemmove | PASS |
| wmemset_basic | ISO C wmemset | PASS |
