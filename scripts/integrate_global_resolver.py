#!/usr/bin/env python3
"""Apply reviewed, hash-pinned global resolver edits without losing concurrent work.

Default is a dry-run unified diff. --apply writes these three source files;
--publish-blobs additionally publishes immutable blobs ONLY, never commits or
refs. Used temporarily to carry small edits into oversized connector files.
"""
import argparse
import base64
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.request

BASELINES = {
    'crates/frankenlibc-abi/src/resolv_state.rs': 'bb6028bde4a85be29b3b919a9e4c43ba5b3a9eed',
    'crates/frankenlibc-abi/src/glibc_internal_abi.rs': 'e7cc1a5f33d9d49b83451ce4313c24b16340571c',
    'crates/frankenlibc-abi/src/unistd_abi.rs': 'ab6ecb393672197a8aa7d1f0f8dae25c0056ee90',
}
def digest(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()

def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('expected one source match: ' + old[:100])
    return text.replace(old, new, 1)

def body_span(text, name):
    # Skip string/char literals and comments while balancing this function.
    match = list(re.finditer(r'\b(?:pub\s+)?unsafe\s+(?:extern\s+"C"\s+)?fn\s+' + re.escape(name) + r'\s*\(', text))
    if len(match) != 1:
        raise ValueError('ambiguous function: ' + name)
    start = text.index('{', match[0].end())
    # The targeted old functions contain ordinary Rust strings, no raw strings.
    token = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])\'|[{}]')
    depth = 0
    for item in token.finditer(text, start):
        if item.group() == '{':
            depth += 1
        elif item.group() == '}':
            depth -= 1
            if depth == 0:
                return match[0].start(), start, item.end()
    raise ValueError('unclosed function: ' + name)

def arguments(text, name, expected):
    start, brace, _ = body_span(text, name)
    signature = text[start:brace]
    params = signature[signature.index('(') + 1:signature.rindex(')')]
    result = re.findall(r'(?:^|,)\s*([A-Za-z_]\w*)\s*:', params)
    if len(result) != expected:
        raise ValueError('unexpected ABI signature: ' + name)
    return result

def replace_body(text, name, target):
    _, start, end = body_span(text, name)
    return text[:start + 1] + '\n    // SAFETY: the shared native boundary validates this thread\'s state and caller buffers.\n    unsafe { ' + target + ' }\n' + text[end - 1:]

def changes(originals):
    state_path, abi_path, unistd_path = BASELINES
    state = originals[state_path].decode()
    state = once(state, 'use std::collections::BTreeMap;', 'pub mod global;\n\nuse std::collections::BTreeMap;')
    state = once(state, 'fn initial_config() -> (ResolverConfig, c_ulong) {',
        'fn initial_config() -> (ResolverConfig, c_ulong, [bool; 2]) {')
    old = '''    let edns0 = content.split(|&byte| byte == b'\\n').any(|line| {
        let mut words = line.split(u8::is_ascii_whitespace).filter(|word| !word.is_empty());
        words.next() == Some(b"options".as_slice())
            && words.any(|word| word.starts_with(b"edns0"))
    });'''
    new = '''    let mut edns0 = false;
    let mut explicit_timing = [false; 2];
    for line in content.split(|&byte| byte == b'\\n') {
        let mut words = line.split(u8::is_ascii_whitespace).filter(|word| !word.is_empty());
        if words.next() != Some(b"options".as_slice()) { continue; }
        for word in words {
            edns0 |= word.starts_with(b"edns0");
            for (index, prefix) in [b"timeout:".as_slice(), b"attempts:".as_slice()].into_iter().enumerate() {
                if let Some(value) = word.strip_prefix(prefix) {
                    // Match ResolverConfig's checked decimal parser exactly:
                    // invalid/overflowing options do not override old timing.
                    let valid = !value.is_empty() && value.iter().try_fold(0u32, |number, &byte| {
                        if byte.is_ascii_digit() {
                            number.checked_mul(10)?.checked_add(u32::from(byte - b'0'))
                        } else { None }
                    }).is_some();
                    explicit_timing[index] |= valid;
                }
            }
        }
    }'''
    state = once(state, old, new)
    state = once(state, '(config, if edns0 { RES_USE_EDNS0 } else { 0 })',
        '(config, if edns0 { RES_USE_EDNS0 } else { 0 }, explicit_timing)')
    state = once(state, 'pub unsafe fn init(pointer: *mut c_void) -> c_int {', '''pub unsafe fn init(pointer: *mut c_void) -> c_int {
    // SAFETY: the caller supplies the same state required by init_impl.
    unsafe { init_impl(pointer, false) }
}

// res_init preserves nonzero legacy timing and already initialized options;
// res_ninit deliberately starts from fresh defaults. Both parse ONE snapshot.
unsafe fn init_impl(pointer: *mut c_void, legacy_global: bool) -> c_int {''')
    state = once(state, 'let (config, extended_options) = initial_config();',
        'let (config, extended_options, explicit_timing) = initial_config();')
    state = once(state, 'let id = if state.id == 0 {', 'let id = if legacy_global || state.id == 0 {')
    state = once(state, '    next.retrans = config.timeout as c_int;\n    next.retry = config.attempts as c_int;', '''    next.retrans = if legacy_global && state.retrans != 0 && !explicit_timing[0] {
        state.retrans
    } else { config.timeout as c_int };
    next.retry = if legacy_global && state.retry != 0 && !explicit_timing[1] {
        state.retry
    } else { config.attempts as c_int };''')
    state = once(state, 'next.options = RES_INIT | RES_DEFAULT | extended_options;', '''next.options = RES_INIT | extended_options | if legacy_global && state.options & RES_INIT != 0 {
        state.options
    } else { RES_DEFAULT };''')
    abi = originals[abi_path].decode()
    for name, count, destination in [
        ('__res_mkquery', 10, 'mkquery'),
        ('__res_querydomain', 6, 'querydomain'),
        ('__res_send', 4, 'send'),
    ]:
        params = arguments(abi, name, count)
        target = 'crate::resolv_state::global::' + destination + '(' + ', '.join(params) + ')'
        abi = replace_body(abi, name, target)
    abi = once(abi, '// Only QUERY (op=0) is supported; all other opcodes return -1.',
        '// Uses the calling thread\'s state; QUERY and NOTIFY follow the native builder.')
    begin = abi.index('// __res_state: return a pointer to the per-thread resolver state.')
    end = abi.index('#[repr(C, align(8))]', begin)
    abi = abi[:begin] + '''// __res_state: stable, initially zeroed public state for the calling thread.
// Legacy APIs initialize it on first use; direct callers may configure it and
// pass it to res_n*. Keep alignment and address stable in both TLS backends.
''' + abi[end:]
    abi = once(abi, 'struct ResStateBuf([u8; 640]);', '''struct ResStateBuf([u8; 640]);

impl Drop for ResStateBuf {
    fn drop(&mut self) {
        // SAFETY: this thread's aligned state is still live. close releases
        // only native-owned configuration, never caller overrides or sockets.
        unsafe { crate::resolv_state::close(self.0.as_mut_ptr().cast()) };
    }
}''')
    start, brace, end = body_span(abi, '__res_state')
    abi = abi[:brace + 1] + '\n    res_state_ptr()\n' + abi[end - 1:]
    unistd = originals[unistd_path].decode()
    for name, count, destination in [('res_init', 0, 'init'), ('res_query', 5, 'query'), ('res_search', 5, 'search')]:
        params = arguments(unistd, name, count)
        if count:
            params[3] += '.cast()'
        target = 'crate::resolv_state::global::' + destination + '(' + ', '.join(params) + ')'
        unistd = replace_body(unistd, name, target)
    # Remove the now-unreachable duplicate receiver, not any source file.
    start, _, end = body_span(unistd, 'dns_query_raw')
    unistd = unistd[:start] + '// Raw DNS exchange is shared by global and reentrant APIs in resolv_state.\n' + unistd[end:]
    # All six replacements are complete bodies; cached config remains for
    # existing host/address lookup callers, not these legacy query operations.
    return {state_path: state.encode(), abi_path: abi.encode(), unistd_path: unistd.encode()}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--publish-blobs', action='store_true')
    args = parser.parse_args()
    if args.publish_blobs and not args.apply:
        parser.error('--publish-blobs requires --apply')
    originals = {path: Path(path).read_bytes() for path in BASELINES}
    if all(b'crate::resolv_state::global::' in originals[path] for path in list(BASELINES)[1:]):
        print('Global entry points already integrated; no source overlays applied.')
        return
    current = originals
    originals = {}
    for path, sha in BASELINES.items():
        if digest(current[path]) == sha:
            data = current[path]
        else:
            # Preserve unrelated concurrent work. Recover the immutable review
            # baseline, then let git apply reject overlapping source edits.
            try:
                data = subprocess.check_output(['git', 'cat-file', 'blob', sha], stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                request = urllib.request.Request(
                    'https://api.github.com/repos/' + os.environ['GITHUB_REPOSITORY'] + '/git/blobs/' + sha,
                    headers={'Authorization': 'Bearer ' + os.environ['GH_TOKEN'], 'Accept': 'application/vnd.github+json'})
                with urllib.request.urlopen(request, timeout=60) as response:
                    blob = json.load(response)
                if blob.get('encoding') != 'base64':
                    raise ValueError('unexpected blob encoding: ' + path)
                data = base64.b64decode(blob['content'])
        if digest(data) != sha:
            raise ValueError('immutable baseline hash mismatch: ' + path)
        originals[path] = data
    updated = changes(originals)
    artifact = Path('artifacts/global-resolver')
    artifact.mkdir(parents=True, exist_ok=True)
    diff = ''.join(''.join(difflib.unified_diff(originals[path].decode().splitlines(True),
        data.decode().splitlines(True), fromfile='a/' + path, tofile='b/' + path))
        for path, data in updated.items())
    (artifact / 'integration.diff').write_text(diff)
    # Complete old function bodies and changed initialization lines form the
    # checked hunks. No 3-way conflict resolution, whitespace ignoring, staging,
    # checkout/reset, or unreviewed whole-file replacement is performed.
    subprocess.run(['git', 'apply', '--check', '-'], input=diff.encode(), check=True)
    if args.apply:
        subprocess.run(['git', 'apply', '-'], input=diff.encode(), check=True)
        updated = {path: Path(path).read_bytes() for path in BASELINES}
        actual = ''.join(''.join(difflib.unified_diff(current[path].decode().splitlines(True),
            data.decode().splitlines(True), fromfile='a/' + path, tofile='b/' + path))
            for path, data in updated.items())
        (artifact / 'applied-integration.diff').write_text(actual)
    hashes = {}
    for path, data in updated.items():
        hashes[path] = digest(data)
        if args.publish_blobs:
            request = urllib.request.Request(
                'https://api.github.com/repos/' + os.environ['GITHUB_REPOSITORY'] + '/git/blobs',
                data=json.dumps({'content': data.decode(), 'encoding': 'utf-8'}).encode(),
                headers={'Authorization': 'Bearer ' + os.environ['GH_TOKEN'], 'Accept': 'application/vnd.github+json'},
                method='POST')
            with urllib.request.urlopen(request, timeout=60) as response:
                if json.load(response)['sha'] != hashes[path]:
                    raise ValueError('published blob hash mismatch: ' + path)
        print('GLOBAL_SOURCE_BLOB', hashes[path], path, flush=True)
    (artifact / 'source-blobs.json').write_text(json.dumps(hashes, indent=2) + '\n')
    if not args.apply:
        print(diff)

if __name__ == '__main__':
    main()
