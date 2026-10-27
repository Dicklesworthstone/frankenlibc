#!/usr/bin/env python3
"""Compare deployed AUTH_DES clients and RFC 868 with live versioned GNU libc.

An independent peer decrypts the actual authentication bytes with GNU DES,
checks timestamps/windows, returns server proofs, and rejects a nickname once
to force a real client refresh/retry. Local keyserver hooks isolate key storage;
the existing NSS test module supplies the classic constructor's public key.
RFC 868 peers exclusively bind loopback port 37; no system configuration or
existing service is changed. Each provider/mode runs in a separate process.
"""
import argparse
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import time


LIBC = C.CDLL('libc.so.6', use_errno=True)
LIBC.dlvsym.argtypes = [C.c_void_p, C.c_char_p, C.c_char_p]
LIBC.dlvsym.restype = C.c_void_p
NAME = b'unix.authdes@franken.invalid'
KEY = b'12345678'
SEALED = b'SEALED!!'
NICK = b'\x11\x82\xf3\x44'
PUBLIC = b'0123456789abcdef' * 3 + b'\0'


class NetObject(C.Structure):
    _fields_ = [('length', C.c_uint), ('bytes', C.c_void_p)]


class CryptArgument(C.Structure):
    _fields_ = [('name', C.c_char_p), ('public', NetObject), ('key', C.c_ubyte * 8)]


class CryptResult(C.Structure):
    _fields_ = [('status', C.c_int), ('key', C.c_ubyte * 8)]


class Opaque(C.Structure):
    _fields_ = [('flavor', C.c_int), ('base', C.c_void_p), ('length', C.c_uint)]


class Auth(C.Structure):
    _fields_ = [('credential', Opaque), ('verifier', Opaque), ('key', C.c_ubyte * 8),
                ('ops', C.POINTER(C.c_void_p)), ('private', C.c_void_p)]


class Xdr(C.Structure):
    _fields_ = [('op', C.c_int), ('ops', C.c_void_p), ('public', C.c_void_p),
                ('private', C.c_void_p), ('base', C.c_void_p), ('handy', C.c_uint)]


class Timeval(C.Structure):
    _fields_ = [('seconds', C.c_long), ('micros', C.c_long)]


class RpcTimeval(C.Structure):
    _fields_ = [('seconds', C.c_uint32), ('micros', C.c_uint32)]


class Address(C.Structure):
    _fields_ = [('family', C.c_ushort), ('port', C.c_ushort),
                ('address', C.c_ubyte * 4), ('zero', C.c_ubyte * 8)]


class Client(C.Structure):
    _fields_ = [('auth', C.c_void_p), ('ops', C.POINTER(C.c_void_p)), ('private', C.c_void_p)]


def gnu(name):
    pointer = LIBC.dlvsym(LIBC._handle, name.encode(), b'GLIBC_2.2.5')
    if not pointer:
        raise RuntimeError(f'missing GNU oracle {name}@GLIBC_2.2.5')
    return pointer


def provider(pointer, library, expected_base=None):
    class Info(C.Structure):
        _fields_ = [('file', C.c_char_p), ('base', C.c_void_p), ('symbol', C.c_char_p), ('address', C.c_void_p)]
    info = Info()
    LIBC.dladdr.argtypes = [C.c_void_p, C.POINTER(Info)]
    if not LIBC.dladdr(pointer, C.byref(info)) or not info.file:
        raise RuntimeError('WRONG AUTH_DES PROVIDER')
    if (expected_base is not None and info.base != expected_base) or (
            expected_base is None and not os.path.samefile(library, info.file)):
        raise RuntimeError('WRONG AUTH_DES PROVIDER')
    return info.base


def word(number):
    return struct.pack('!I', number & 0xffffffff)


def unpack_auth(data, offset=0):
    flavor, size = struct.unpack_from('!2I', data, offset)
    assert size <= 400 and offset + 8 + size <= len(data)
    return flavor, data[offset + 8:offset + 8 + size], offset + 8 + (size + 3) // 4 * 4


def worker(args):
    candidate = args.provider == 'candidate'
    library = C.CDLL(str(args.library), mode=os.RTLD_LOCAL | os.RTLD_NOW) if candidate else LIBC
    candidate_base = None

    def symbol(name):
        nonlocal candidate_base
        pointer = C.cast(getattr(library, name), C.c_void_p).value if candidate else gnu(name)
        if candidate and args.force_host:
            pointer = gnu(name)
        if candidate:
            candidate_base = provider(pointer, args.library, candidate_base)
        return pointer

    def function(name, result, *types):
        return C.CFUNCTYPE(result, *types)(symbol(name))

    create_pk = function('authdes_pk_create', C.c_void_p, C.c_void_p, C.c_void_p, C.c_uint, C.c_void_p, C.c_void_p)
    create = function('authdes_create', C.c_void_p, C.c_void_p, C.c_uint, C.c_void_p, C.c_void_p)
    xdrmem = function('xdrmem_create', None, C.c_void_p, C.c_void_p, C.c_uint, C.c_int)
    rtime = function('rtime', C.c_int, C.c_void_p, C.c_void_p, C.c_void_p)
    codec = function('xdr_authdes_cred', C.c_int, C.c_void_p, C.c_void_p)
    errno_slot = function('__errno_location', C.POINTER(C.c_int))
    rows = []

    def check(name, condition, detail=None):
        if not condition:
            raise AssertionError((name, detail))
        rows.append(name)

    # Independent reference crypto remains GNU even while testing the candidate.
    ecb = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_uint, C.c_uint)(gnu('ecb_crypt'))
    cbc = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_uint, C.c_uint, C.c_void_p)(gnu('cbc_crypt'))

    def crypt(data, decrypt=False, chained=False):
        output = C.create_string_buffer(data, len(data))
        key = C.create_string_buffer(KEY, 8)
        mode = 2 | int(decrypt)
        rc = cbc(key, output, len(data), mode, C.create_string_buffer(8)) if chained else ecb(key, output, len(data), mode)
        assert rc == 0
        return output.raw

    result = CryptResult(0, (C.c_ubyte * 8).from_buffer_copy(SEALED))
    failure_result = CryptResult(2, (C.c_ubyte * 8)())
    generated = C.create_string_buffer(KEY, 8)
    calls = []
    expected_public = [PUBLIC]
    hook_errors = []
    refuse_refresh = [False]

    @C.CFUNCTYPE(C.c_void_p, C.c_uint, C.c_void_p)
    def encrypt(uid, argument):
        try:
            value = C.cast(argument, C.POINTER(CryptArgument)).contents
            assert uid == os.geteuid() and value.name == NAME
            assert C.string_at(value.public.bytes, value.public.length) == expected_public[0]
            assert bytes(value.key) == KEY
            calls.append('encrypt')
            if refuse_refresh[0]:
                return C.addressof(failure_result)
            return C.addressof(result)
        except BaseException as failure:
            hook_errors.append(repr(failure))
            return C.addressof(failure_result)

    @C.CFUNCTYPE(C.c_void_p, C.c_uint, C.c_void_p)
    def generate(uid, argument):
        if uid != os.geteuid() or argument:
            hook_errors.append('bad generator arguments')
            return None
        calls.append('generate')
        return C.addressof(generated)

    def hook_slots(name):
        # A dlopen-local libc keeps its exported object, but ELF GLOB_DAT may
        # bind internal references to GNU's earlier versioned compatibility
        # object. Set both public slots in this isolated worker. AUTH operation
        # pointers below must still name the candidate, proving native execution.
        pointers = {symbol(name)}
        if candidate:
            pointers.add(gnu(name))
        return [C.c_void_p.from_address(pointer) for pointer in pointers]

    encrypt_slots = hook_slots('__key_encryptsession_pk_LOCAL')
    generate_slots = hook_slots('__key_gendes_LOCAL')
    for slot in encrypt_slots:
        slot.value = C.cast(encrypt, C.c_void_p).value
    for slot in generate_slots:
        slot.value = C.cast(generate, C.c_void_p).value

    def op(auth, index, result_type, *types):
        pointer = C.cast(auth, C.POINTER(Auth)).contents.ops[index]
        if candidate:
            provider(pointer, args.library, candidate_base)
        return C.CFUNCTYPE(result_type, C.c_void_p, *types)(pointer)

    def marshalled(auth, capacity=512):
        stream = Xdr()
        data = C.create_string_buffer(capacity)
        xdrmem(C.byref(stream), data, capacity, 0)
        ok = op(auth, 1, C.c_int, C.c_void_p)(auth, C.byref(stream))
        length = stream.private - C.addressof(data)
        return ok, data.raw[:length]

    def verify_wire(data, full, name, offset_seconds=0):
        flavor, cred, offset = unpack_auth(data)
        vflavor, verf, end = unpack_auth(data, offset)
        assert end == len(data) and flavor == 3 and vflavor == 3 and len(verf) == 12
        kind = struct.unpack_from('!I', cred)[0]
        assert kind == (0 if full else 1)
        if full:
            size = struct.unpack_from('!I', cred, 4)[0]
            padded = (size + 3) // 4 * 4
            assert cred[8:8 + size] == name and not any(cred[8 + size:8 + padded])
            assert cred[8 + padded:16 + padded] == SEALED
            plain = crypt(verf[:8] + cred[16 + padded:20 + padded] + verf[8:], True, True)
            assert struct.unpack('!2I', plain[8:]) == (300, 299)
            stamp = plain[:8]
        else:
            assert cred[4:] == NICK
            stamp = crypt(verf[:8], True)
        seconds, micros = struct.unpack('!2I', stamp)
        assert abs(seconds - int(time.time()) - offset_seconds) <= 5 and micros < 1_000_000
        return stamp

    getname = function('getnetname', C.c_int, C.c_void_p)
    own_name = C.create_string_buffer(256)
    check('netname', getname(own_name) == 1)
    server = C.create_string_buffer(NAME)
    public = C.create_string_buffer(PUBLIC, len(PUBLIC))
    object_ = NetObject(len(PUBLIC), C.addressof(public))
    key = C.create_string_buffer(KEY, 8)
    auth = create_pk(server, C.byref(object_), 300, None, key)
    check('supplied-key-constructor', bool(auth) and calls == ['encrypt'],
          {'auth': auth, 'calls': calls, 'hook_errors': hook_errors, 'errno': errno_slot()[0]})
    check('public-auth-layout', C.cast(auth, C.POINTER(Auth)).contents.credential.flavor == 3 and
          bytes(C.cast(auth, C.POINTER(Auth)).contents.key) == KEY)
    check('marshal-small-buffer', marshalled(auth, 7)[0] == 0)
    ok, wire = marshalled(auth)
    check('marshal-fullname', ok == 1)
    stamp = verify_wire(wire, True, own_name.value)
    check('fullname-cbc-proof', True)
    sec, usec = struct.unpack('!2I', stamp)
    proof = crypt(word(sec - 1) + word(usec)) + NICK
    proof_bytes = C.create_string_buffer(proof, 12)
    verifier = Opaque(3, C.addressof(proof_bytes), 11)
    validate = op(auth, 2, C.c_int, C.c_void_p)
    check('reject-short-proof', validate(auth, C.byref(verifier)) == 0)
    verifier.length = 12
    proof_bytes[0] = bytes([proof[0] ^ 1])
    check('reject-corrupt-proof', validate(auth, C.byref(verifier)) == 0)
    proof_bytes.raw = proof
    verifier.flavor = 0
    check('accept-proven-server', validate(auth, C.byref(verifier)) == 1)
    ok, wire = marshalled(auth)
    check('marshal-nickname', ok == 1)
    verify_wire(wire, False, own_name.value)
    check('nickname-ecb-proof', True)
    refuse_refresh[0] = True
    check('reject-failed-refresh', op(auth, 3, C.c_int)(auth) == 0)
    refuse_refresh[0] = False
    ok, wire = marshalled(auth)
    check('failed-refresh-retains-nickname', ok == 1)
    verify_wire(wire, False, own_name.value)
    # Refresh must use owned copies, after caller strings/public bytes change.
    server.value = b'changed'
    public.raw = b'X' * len(PUBLIC)
    key.raw = b'XXXXXXXX'
    check('refresh-owned-inputs', op(auth, 3, C.c_int)(auth) == 1 and calls == ['encrypt'] * 3)
    ok, wire = marshalled(auth)
    check('refresh-fullname', ok == 1)
    verify_wire(wire, True, own_name.value)
    op(auth, 4, None)(auth)
    check('destroy-supplied', not hook_errors)

    server.value = NAME
    public.raw = PUBLIC
    calls.clear()
    for slot in generate_slots:
        slot.value = None
    mapper = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mapper.bind(('127.0.0.1', 111))
    mapper.settimeout(4)
    generator = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    generator.bind(('127.0.0.1', 0))
    generator.settimeout(4)
    generation_errors, generation_packets = [], []

    def generate_peer():
        try:
            for endpoint, expected, payload in [
                (mapper, (0, 2, 100000, 2, 3), word(generator.getsockname()[1])),
                (generator, (0, 2, 100029, 1, 4), KEY),
            ]:
                request, remote = endpoint.recvfrom(4096)
                header = struct.unpack_from('!6I', request)
                assert header[1:] == expected
                first, cred, offset = unpack_auth(request, 24)
                second, verf, offset = unpack_auth(request, offset)
                assert (first, cred, second, verf) == (0, b'', 0, b'')
                assert request[offset:] == (word(100029) + word(1) + word(17) + word(0) if endpoint is mapper else b'')
                generation_packets.append(expected[2])
                endpoint.sendto(word(header[0]) + word(1) + word(0) + word(0) + word(0) + word(0) + payload, remote)
        except BaseException as failure:
            generation_errors.append(repr(failure))

    generation = threading.Thread(target=generate_peer, daemon=True)
    generation.start()
    auth = create_pk(server, C.byref(object_), 300, None, None)
    generation.join(5)
    mapper.close()
    generator.close()
    check('generated-key-constructor', bool(auth) and calls == ['encrypt'])
    check('generated-key-wire', not generation.is_alive() and not generation_errors and generation_packets == [100000, 100029])
    ok, wire = marshalled(auth)
    check('generated-key-marshal', ok == 1)
    verify_wire(wire, True, own_name.value)

    # Execute actual UDP CLIENT calls with AUTH_DES, including one server
    # rejection that requires a refresh and a newly marshalled fullname.
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('127.0.0.1', 0))
    udp.settimeout(4)
    errors, packets = [], []

    def peer():
        try:
            for index in range(4):
                request, remote = udp.recvfrom(4096)
                xid, direction, rpcvers, prog, vers, proc = struct.unpack_from('!6I', request)
                assert (direction, rpcvers, prog, vers, proc) == (0, 2, 0x31234567, 1, 7)
                _, _, end = unpack_auth(request, 24)
                _, _, end = unpack_auth(request, end)
                assert request[end:] == word(9)
                packets.append(index)
                if index == 2:
                    # MSG_DENIED / AUTH_ERROR / AUTH_REJECTEDCRED.
                    udp.sendto(word(xid) + word(1) + word(1) + word(1) + word(2), remote)
                    continue
                timestamp_bytes = verify_wire(request[24:end], index in (0, 3), own_name.value)
                seconds, micros = struct.unpack('!2I', timestamp_bytes)
                response_proof = crypt(word(seconds - 1) + word(micros)) + NICK
                response = word(xid) + word(1) + word(0) + word(3) + word(12) + response_proof + word(0) + word(42)
                udp.sendto(response, remote)
        except BaseException as failure:
            errors.append(repr(failure))

    thread = threading.Thread(target=peer, daemon=True)
    thread.start()
    clntudp = function('clntudp_create', C.c_void_p, C.c_void_p, C.c_ulong, C.c_ulong, Timeval, C.c_void_p)
    address = Address(socket.AF_INET, socket.htons(udp.getsockname()[1]), (C.c_ubyte * 4)(127, 0, 0, 1), (C.c_ubyte * 8)())
    descriptor = C.c_int(-1)
    client = clntudp(C.byref(address), 0x31234567, 1, Timeval(0, 100000), C.byref(descriptor))
    check('udp-client-created', bool(client))
    handle = C.cast(client, C.POINTER(Client)).contents
    handle.auth = auth
    call = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_ulong, C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p, Timeval)(handle.ops[0])
    xdr_int = symbol('xdr_int')
    for index in range(3):
        argument, answer = C.c_int(9), C.c_int(-1)
        rc = call(client, 7, xdr_int, C.byref(argument), xdr_int, C.byref(answer), Timeval(2, 0))
        check(f'authenticated-rpc-{index}', rc == 0 and answer.value == 42)
    thread.join(5)
    check('wire-refresh-retry', not thread.is_alive() and not errors and packets == list(range(4)))
    C.CFUNCTYPE(None, C.c_void_p)(handle.ops[4])(client)
    udp.close()
    op(auth, 4, None)(auth)
    check('destroy-generated', not hook_errors)

    # A genuine GNU NSS public module gives both classic constructors the same
    # key. Only this worker enters a private root containing its nsswitch file;
    # the real system's configuration is never changed. Native NSS reads that
    # file; GNU's earlier cached configuration is explicitly selected as well.
    module = C.CDLL(str(args.module), mode=os.RTLD_LOCAL | os.RTLD_NOW)
    if not candidate:
        configure = getattr(library, '__nss_configure_lookup')
        configure.argtypes = [C.c_char_p, C.c_char_p]
        configure.restype = C.c_int
        assert configure(b'publickey', b'rpcid_first') == 0
    os.chroot(args.root)
    os.chdir('/')
    expected_public[0] = b'a' * 48 + b'\0'
    key.raw = KEY
    auth = create(server, 300, None, key)
    check('classic-nss-constructor', bool(auth))
    ok, wire = marshalled(auth)
    check('classic-fullname-marshal', ok == 1)
    verify_wire(wire, True, own_name.value)
    op(auth, 4, None)(auth)
    check('classic-nss-hook', not hook_errors)
    del module

    # Constructor and refresh both synchronize against the supplied TIME host.
    # A changed caller address must not redirect a later refresh of this AUTH.
    expected_public[0] = PUBLIC
    clock_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clock_server.bind(('127.0.0.1', 37))
    clock_server.settimeout(4)
    clock_packets, clock_errors = [], []

    def clock_peer():
        try:
            for offset in (120, 240):
                query, remote = clock_server.recvfrom(32)
                assert len(query) == 4
                clock_packets.append(offset)
                clock_server.sendto(word(int(time.time()) + offset + 2208988800), remote)
        except BaseException as failure:
            clock_errors.append(repr(failure))

    clock_thread = threading.Thread(target=clock_peer, daemon=True)
    clock_thread.start()
    clock_address = Address(socket.AF_INET, 0, (C.c_ubyte * 4)(127, 0, 0, 1), (C.c_ubyte * 8)())
    auth = create_pk(server, C.byref(object_), 300, C.byref(clock_address), key)
    check('clock-sync-constructor', bool(auth))
    ok, wire = marshalled(auth)
    check('clock-sync-fullname', ok == 1)
    verify_wire(wire, True, own_name.value, 120)
    clock_address.address[0] = 192
    check('clock-sync-owned-refresh', op(auth, 3, C.c_int)(auth) == 1)
    ok, wire = marshalled(auth)
    check('clock-sync-refreshed-proof', ok == 1)
    verify_wire(wire, True, own_name.value, 240)
    clock_thread.join(5)
    clock_server.close()
    check('clock-sync-two-queries', not clock_thread.is_alive() and not clock_errors and clock_packets == [120, 240])
    op(auth, 4, None)(auth)

    # The wire union is not a C union: nickname lives at byte32 in GNU's
    # 40-byte credential record. Both encode and decode must respect that slot.
    cred = C.create_string_buffer(b'\xa5' * 40, 40)
    C.c_int.from_buffer(cred).value = 1
    C.memmove(C.addressof(cred) + 32, NICK, 4)
    encoded = C.create_string_buffer(16)
    stream = Xdr()
    xdrmem(C.byref(stream), encoded, 16, 0)
    check('xdr-nickname-encode', codec(C.byref(stream), cred) == 1 and encoded.raw[:8] == word(1) + NICK)
    decoded = C.create_string_buffer(b'\xa5' * 40, 40)
    xdrmem(C.byref(stream), encoded, 8, 1)
    check('xdr-nickname-decode', codec(C.byref(stream), decoded) == 1 and decoded.raw[32:36] == NICK and decoded.raw[8:32] == b'\xa5' * 24)
    xdrmem(C.byref(stream), None, 0, 2)
    check('xdr-nickname-free', codec(C.byref(stream), decoded) == 1)

    def time_case(label, tcp, reply):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
        if tcp:
            # Rebind only our previous TIME_WAIT sockets. No SO_REUSEPORT is
            # enabled, so an existing listening TIME service still blocks us.
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', 37))
        listener.settimeout(3)
        if tcp:
            listener.listen(1)
        observations, failures = [], []

        def server_time():
            try:
                if tcp:
                    connection, _ = listener.accept()
                    with connection:
                        connection.sendall(reply)
                else:
                    query, remote = listener.recvfrom(32)
                    observations.append(len(query))
                    if reply is not None:
                        listener.sendto(reply, remote)
            except BaseException as failure:
                failures.append(repr(failure))

        thread = threading.Thread(target=server_time, daemon=True)
        thread.start()
        address = Address(0, socket.htons(999), (C.c_ubyte * 4)(127, 0, 0, 1), (C.c_ubyte * 8)())
        output = C.create_string_buffer(b'\xa5' * 16, 16)
        timeout = RpcTimeval(0, 100000)
        errno_slot()[0] = 0
        rc = rtime(C.byref(address), C.byref(output, 4), None if tcp else C.byref(timeout))
        actual_error = errno_slot()[0]
        thread.join(4)
        listener.close()
        check(label + '-peer', not thread.is_alive() and not failures and (tcp or observations == [4]))
        check(label + '-address', address.family == socket.AF_INET and address.port == socket.htons(37))
        check(label + '-canaries', output.raw[:4] == b'\xa5' * 4 and output.raw[12:] == b'\xa5' * 4)
        if reply is not None and len(reply) == 4:
            check(label + '-result', rc == 0 and struct.unpack('=2I', output.raw[4:12]) == (1234567890, 0))
        else:
            wanted = 110 if reply is None else 5
            check(label + '-result', rc == -1 and actual_error == wanted and output.raw == b'\xa5' * 16)

    time_case('time-udp', False, word(1234567890 + 2208988800))
    time_case('time-tcp', True, word(1234567890 + 2208988800))
    time_case('time-udp-short', False, b'ab')
    time_case('time-tcp-short', True, b'ab')
    time_case('time-timeout', False, None)
    check('hook-completion', not hook_errors)
    print(json.dumps({'provider': args.provider, 'mode': os.environ.get('FRANKENLIBC_MODE'), 'rows': rows}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', nargs='?', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--host-only', action='store_true')
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--provider', choices=('host', 'candidate'))
    parser.add_argument('--module', type=Path)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--force-host', action='store_true')
    args = parser.parse_args()
    if args.worker:
        try:
            worker(args)
        except RuntimeError as failure:
            if 'WRONG AUTH_DES PROVIDER' in str(failure):
                print(str(failure), file=sys.stderr)
                return 90
            raise
        return 0
    if not args.output or (not args.host_only and not args.library):
        parser.error('require --output and a candidate library, or --host-only')
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    repository = Path(__file__).resolve().parent.parent
    module = out / 'libnss_rpcid_first.so.2'
    subprocess.run(['gcc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                    '-Wl,-soname,libnss_rpcid_first.so.2', str(repository / 'tests/integration/fixture_rpc_identity_module.c'),
                    '-o', str(module)], check=True)
    clean = {key: value for key, value in os.environ.items() if key != 'LD_PRELOAD' and not key.startswith(('FRANKENLIBC_', 'RPC_IDENTITY_'))}
    library = args.library.resolve() if args.library else None
    report = {'library_sha256': hashlib.sha256(library.read_bytes()).hexdigest() if library else None,
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'host_checks': 0, 'candidate_checks': 0, 'provider_negatives': 0, 'runs': []}
    scenarios = [('host', 'host', None, False)]
    if not args.host_only:
        scenarios += [('strict', 'candidate', 'strict', False), ('hardened', 'candidate', 'hardened', False),
                      ('provider-negative', 'candidate', 'strict', True)]
    for label, provider_name, mode, negative in scenarios:
        command = [sys.executable, str(Path(__file__).resolve())]
        if library:
            command.append(str(library))
        command += ['--worker', '--provider', provider_name, '--module', str(module)]
        root = out / f'root-{label}'
        (root / 'etc').mkdir(parents=True)
        (root / 'etc/nsswitch.conf').write_text('publickey: rpcid_first\n')
        command += ['--root', str(root)]
        if negative:
            command.append('--force-host')
        environment = dict(clean)
        if mode:
            environment.update(FRANKENLIBC_MODE=mode, FRANKENLIBC_THREAD_NATIVE='0')
        run = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=35)
        (out / f'{label}.stdout').write_text(run.stdout)
        (out / f'{label}.stderr').write_text(run.stderr)
        if negative:
            assert run.returncode == 90 and 'WRONG AUTH_DES PROVIDER' in run.stderr, (label, run.returncode, run.stderr)
            report['provider_negatives'] += 1
            continue
        if run.returncode:
            raise RuntimeError(f'{label} failed {run.returncode}: {run.stderr}')
        record = json.loads(run.stdout)
        assert len(record['rows']) == 57, (label, len(record['rows']))
        if provider_name == 'candidate':
            assert record['rows'] == report['runs'][0]['rows'], (label, 'different executed checks')
        report['host_checks' if provider_name == 'host' else 'candidate_checks'] += len(record['rows'])
        report['runs'].append(record)
    assert report['host_checks'] == 57
    if not args.host_only:
        assert report['candidate_checks'] == 114 and report['provider_negatives'] == 1
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ('host_checks', 'candidate_checks', 'provider_negatives')}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
