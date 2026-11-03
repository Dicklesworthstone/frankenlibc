#!/usr/bin/env python3
"""Print hashes of the integrated, checked-in legacy resolver sources.

The historical filename remains, but source assembly is retired. CI builds
these files directly. This command never edits sources or publishes blobs.
"""
import argparse
import hashlib
from pathlib import Path

def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    root = Path(__file__).resolve().parent.parent
    for relative in (
        'crates/frankenlibc-abi/src/resolv_state.rs',
        'crates/frankenlibc-abi/src/resolv_state/global.rs',
        'crates/frankenlibc-abi/src/glibc_internal_abi.rs',
        'crates/frankenlibc-abi/src/unistd_abi.rs',
    ):
        print(hashlib.sha256((root / relative).read_bytes()).hexdigest(), relative)

if __name__ == '__main__':
    main()
