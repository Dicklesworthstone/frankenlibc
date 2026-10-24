#!/usr/bin/env python3
"""Validate and stage the bounded native-segment permission change.

Candidate preparation is pinned to an immutable original blob. Export creates
unreferenced Git objects only; publication/rebase is a separate reviewed write.
After integration the workflow only runs the committed source and mutation gate.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import urllib.request

SOURCE = Path('crates/frankenlibc-abi/src/malloc_abi.rs')
HELPER = Path('crates/frankenlibc-abi/src/segment_mapping.rs')
ORIGINAL = '989cc87b8d26856e9c725c65117100160cdf9d63'
UTIL = Path('crates/frankenlibc-membrane/src/util.rs')
UTIL_ORIGINAL = '9afef4bcbdb7552c28ef5a61e76945ab05a99721'
OUT = Path('artifacts/segment-mapping')


def blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def replace_once(text, old, new):
    assert text.count(old) == 1, f'expected unique patch anchor: {old[:90]!r}'
    return text.replace(old, new, 1)


def prepare():
    original = SOURCE.read_bytes()
    assert blob(original) == ORIGINAL, 'allocator changed: review before rebasing candidate'
    s = original.decode()
    s = replace_once(s, 'use frankenlibc_core::syscall as raw_syscall;\n',
                    'use frankenlibc_core::syscall as raw_syscall;\n\n'
                    '#[path = "segment_mapping.rs"]\nmod segment_mapping;\n')
    s = replace_once(s, 'struct SegmentDescriptor {\n    meta_base: AtomicUsize,',
                    'struct SegmentDescriptor {\n'
                    '    // Only chunk refills consult this permission bitmap.\n'
                    '    writable: segment_mapping::WritablePages,\n'
                    '    meta_base: AtomicUsize,')
    s = replace_once(s, '            meta_base: AtomicUsize::new(0),',
                    '            writable: segment_mapping::WritablePages::new(),\n'
                    '            meta_base: AtomicUsize::new(0),')
    s = replace_once(s,
                    '                        SEGMENT_RESERVE_SIZE,\n'
                    '                        libc::PROT_READ | libc::PROT_WRITE,',
                    '                        SEGMENT_RESERVE_SIZE,\n'
                    '                        libc::PROT_NONE,')
    s = replace_once(s,
                    '                // arena; untouched pages remain demand-zero and uncommitted.',
                    '                // arena. Reserve it inaccessible: MAP_NORESERVE alone does\n'
                    '                // not stop writable mappings from counting against RLIMIT_DATA.\n'
                    '                // Sidecars become readable before ownership publication, and\n'
                    '                // payload granules become writable before chunk publication.')
    anchor = '    let meta_base = arena_base + SEGMENT_ARENA_SIZE + raw_index * SEGMENT_SIDECAR_STRIDE;\n'
    s = replace_once(s, anchor, anchor +
                    '    // Every slot lookup in an owned segment may read its metadata, even\n'
                    '    // when that slot has never been allocated. Enable the complete sidecar\n'
                    '    // before publishing ownership, but leave unused payload inaccessible.\n'
                    '    let meta_writable = meta_bytes.checked_next_multiple_of(segment_mapping::GRANULE)?;\n'
                    '    // SAFETY: this uniquely claimed, unpublished sidecar lies wholly inside\n'
                    '    // our immortal reservation. No libc trampoline or allocator is entered.\n'
                    '    if unsafe {\n'
                    '        raw_syscall::sys_mprotect(\n'
                    '            meta_base as *mut c_void,\n'
                    '            meta_writable,\n'
                    '            libc::PROT_READ | libc::PROT_WRITE,\n'
                    '        )\n'
                    '    }.is_err() {\n'
                    '        return None;\n'
                    '    }\n')
    anchor = ('        let end = start\n'
              '            .saturating_add(SEGMENT_BUMP_CHUNK)\n'
              '            .min(header.slot_count);\n')
    s = replace_once(s, anchor, anchor +
                    '        let base = segment_base(segment_index)?;\n'
                    '        let first_byte = SEGMENT_HEADER_BYTES + start as usize * header.class_size as usize;\n'
                    '        let end_byte = SEGMENT_HEADER_BYTES + end as usize * header.class_size as usize;\n'
                    '        // Upgrade before claiming: failure leaves the cursor untouched, so\n'
                    '        // resource pressure cannot consume chunks or expose inaccessible slots.\n'
                    '        // SAFETY: the descriptor uniquely identifies this immortal segment;\n'
                    '        // permissions only increase, including across concurrent refills/fork.\n'
                    '        if !unsafe { descriptor.writable.enable(base, SEGMENT_SIZE, first_byte, end_byte) } {\n'
                    '            return None;\n'
                    '        }\n')
    assert s.count('mod segment_mapping;') == 1
    assert s.count('#[test]') == original.decode().count('#[test]'), 'existing tests changed'
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'original-malloc.rs').write_bytes(original)
    SOURCE.write_text(s)
    # The ABI already calls these shared no-self-interposition helpers. Their
    # crate-private visibility currently prevents any ABI build from linking.
    util = UTIL.read_bytes()
    assert blob(util) == UTIL_ORIGINAL, 'shared math helpers changed: review first'
    (OUT / 'original-util.rs').write_bytes(util)
    visible = util.decode()
    for name in ['trunc_f64', 'floor_f64', 'ceil_f64', 'round_f64']:
        visible = replace_once(visible, f'pub(crate) fn {name}(', f'pub fn {name}(')
    UTIL.write_text(visible)
    (OUT / 'candidate.patch').write_bytes(subprocess.check_output(['git', 'diff', '--', str(SOURCE), str(UTIL)]))
    print('Candidate allocator blob:', blob(SOURCE.read_bytes()), flush=True)
    for line in Path('.beads/issues.jsonl').open():
        row = json.loads(line)
        if row.get('id') == 'bd-4n397c':
            print('Target bead:', json.dumps(row), flush=True)


def export():
    objects = []
    for path in [SOURCE, HELPER, UTIL]:
        data = path.read_bytes()
        request = urllib.request.Request(
            f'https://api.github.com/repos/{os.environ["GITHUB_REPOSITORY"]}/git/blobs',
            data=json.dumps({'content': data.decode(), 'encoding': 'utf-8'}).encode(),
            headers={'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
                     'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json'},
            method='POST')
        with urllib.request.urlopen(request, timeout=60) as response:
            result = json.load(response)
        assert result['sha'] == blob(data), 'GitHub object differs from tested source'
        objects.append({'path': str(path), 'sha': result['sha'], 'sha256': hashlib.sha256(data).hexdigest()})
    manifest = {'source_commit': os.environ['GITHUB_SHA'], 'objects': objects}
    (OUT / 'candidate-objects.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))


def mutation():
    original = SOURCE.read_bytes()
    test = 'segment_mapping_actual_segment_reservation_stays_inaccessible_until_refill'
    command = ['cargo', 'test', '-p', 'frankenlibc-abi', '--test', 'malloc_abi_test', test,
               '--', '--exact', '--nocapture', '--test-threads=1']
    mutant = replace_once(original.decode(),
                          '                        SEGMENT_RESERVE_SIZE,\n                        libc::PROT_NONE,',
                          '                        SEGMENT_RESERVE_SIZE,\n                        libc::PROT_READ | libc::PROT_WRITE,')
    try:
        SOURCE.write_text(mutant)
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
        (OUT / 'eager-mutation.log').write_bytes(result.stdout)
        print(result.stdout.decode(errors='replace'))
        assert result.returncode != 0, 'eager writable reservation escaped the regression'
        assert b'0 passed; 1 failed;' in result.stdout, 'mutation must compile and execute'
        assert b'unused payload must remain PROT_NONE' in result.stdout
    finally:
        SOURCE.write_bytes(original)
    subprocess.run(command, check=True, timeout=600)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['prepare', 'export', 'mutation'])
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    {'prepare': prepare, 'export': export, 'mutation': mutation}[args.action]()
