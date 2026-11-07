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
import select
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


def server_worker(args):
    """No-socket GNU/server oracle, including the real memory RPC dispatch."""
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

    authenticate = function('_authenticate', C.c_int, C.c_void_p, C.c_void_p)
    getuser = function('authdes_getucred', C.c_int, C.c_void_p, C.c_void_p,
                       C.c_void_p, C.c_void_p, C.c_void_p)
    # Pin transitive public entry points as well as the two operations under test.
    for name in ('getpublickey', 'netname2user', 'key_decryptsession_pk'):
        symbol(name)
    create_service = function('svcraw_create', C.c_void_p)
    register = function('svc_register', C.c_int, C.c_void_p, C.c_ulong,
                        C.c_ulong, C.c_void_p, C.c_int)
    unregister = function('svc_unregister', None, C.c_ulong, C.c_ulong)
    reply = function('svc_sendreply', C.c_int, C.c_void_p, C.c_void_p, C.c_void_p)
    create_client = function('clntraw_create', C.c_void_p, C.c_ulong, C.c_ulong)
    create_unix_service = function('svcunixfd_create', C.c_void_p, C.c_int, C.c_uint, C.c_uint)
    create_unix_client = function('clntunix_create', C.c_void_p, C.c_void_p,
                                 C.c_ulong, C.c_ulong, C.c_void_p, C.c_uint, C.c_uint)
    dispatch_ready = function('svc_getreq_common', None, C.c_int)
    create_auth = function('authdes_pk_create', C.c_void_p, C.c_void_p,
                          C.c_void_p, C.c_uint, C.c_void_p, C.c_void_p)
    null_auth = function('authnone_create', C.c_void_p)
    getname = function('getnetname', C.c_int, C.c_void_p)
    xdr_uint = symbol('xdr_u_int')

    class Transport(C.Structure):
        _fields_ = [('socket', C.c_int), ('port', C.c_ushort),
                    ('ops', C.POINTER(C.c_void_p)), ('addrlen', C.c_int),
                    ('address', Address), ('verifier', Opaque),
                    ('private1', C.c_void_p), ('private2', C.c_void_p),
                    ('padding', C.c_ubyte * 256)]

    class Request(C.Structure):
        _fields_ = [('program', C.c_ulong), ('version', C.c_ulong),
                    ('procedure', C.c_ulong), ('credential', Opaque),
                    ('cooked', C.c_void_p), ('transport', C.c_void_p)]

    class Message(C.Structure):
        _fields_ = [('xid', C.c_ulong), ('direction', C.c_int),
                    ('rpcversion', C.c_ulong), ('program', C.c_ulong),
                    ('version', C.c_ulong), ('procedure', C.c_ulong),
                    ('credential', Opaque), ('verifier', Opaque)]

    class Fullname(C.Structure):
        _fields_ = [('name', C.c_char_p), ('key', C.c_ubyte * 8), ('window', C.c_uint)]

    class DesCredential(C.Structure):
        _fields_ = [('kind', C.c_int), ('fullname', Fullname), ('nickname', C.c_uint)]

    class IdOutput(C.Structure):
        _fields_ = [('before', C.c_uint), ('value', C.c_uint), ('after', C.c_uint)]

    class CountOutput(C.Structure):
        _fields_ = [('before', C.c_ushort), ('value', C.c_short), ('after', C.c_ushort)]

    assert (C.sizeof(Transport), C.sizeof(Request), C.sizeof(Message),
            C.sizeof(DesCredential)) == (336, 64, 96, 40)
    module = C.CDLL(str(args.module), mode=os.RTLD_LOCAL | os.RTLD_NOW)
    mode = module.rpc_auth_des_mode
    mode.argtypes, mode.restype = [C.c_uint], None
    calls = module.rpc_auth_des_calls
    calls.argtypes, calls.restype = [C.c_uint], C.c_uint
    lookup_callback = module.rpc_auth_des_callback
    lookup_callback.argtypes, lookup_callback.restype = [C.c_void_p], None
    if not candidate:
        configure = LIBC.__nss_configure_lookup
        configure.argtypes, configure.restype = [C.c_char_p, C.c_char_p], C.c_int
        assert configure(b'publickey', b'rpcdes') == 0

    # Independent crypto is GNU even for candidate authentication. No candidate
    # encoder constructs these messages or judges its own server proof.
    ecb = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_uint, C.c_uint)(gnu('ecb_crypt'))
    cbc = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_uint, C.c_uint, C.c_void_p)(gnu('cbc_crypt'))

    def crypt(data, decrypt=False, chained=False):
        output, key = C.create_string_buffer(data, len(data)), C.create_string_buffer(KEY, 8)
        rc = cbc(key, output, len(data), 2 | int(decrypt), C.create_string_buffer(8)) if chained else ecb(key, output, len(data), 2 | int(decrypt))
        assert rc == 0
        return output.raw

    key_result = CryptResult(0, (C.c_ubyte * 8).from_buffer_copy(KEY))
    sealed_result = CryptResult(0, (C.c_ubyte * 8).from_buffer_copy(SEALED))
    failure_result = CryptResult(2, (C.c_ubyte * 8)())
    hook_errors, hook_calls = [], []
    refuse_key = [False]
    key_reentry = [None]

    @C.CFUNCTYPE(C.c_void_p, C.c_uint, C.c_void_p)
    def decrypt(uid, argument):
        try:
            value = C.cast(argument, C.POINTER(CryptArgument)).contents
            assert uid == os.geteuid() and bytes(value.key) == SEALED
            assert C.string_at(value.public.bytes, value.public.length) == b'a' * 48 + b'\0'
            hook_calls.append(('decrypt', value.name.decode()))
            if key_reentry[0] is not None:
                callback, key_reentry[0] = key_reentry[0], None
                callback()
            return C.addressof(failure_result if refuse_key[0] else key_result)
        except BaseException as failure:
            hook_errors.append(repr(failure))
            return C.addressof(failure_result)

    @C.CFUNCTYPE(C.c_void_p, C.c_uint, C.c_void_p)
    def encrypt(uid, argument):
        try:
            value = C.cast(argument, C.POINTER(CryptArgument)).contents
            assert uid == os.geteuid() and bytes(value.key) == KEY
            assert C.string_at(value.public.bytes, value.public.length) == b'a' * 48 + b'\0'
            hook_calls.append(('encrypt', value.name.decode()))
            return C.addressof(sealed_result)
        except BaseException as failure:
            hook_errors.append(repr(failure))
            return C.addressof(failure_result)

    hooks = []
    for name, callback in (('__key_decryptsession_pk_LOCAL', decrypt),
                           ('__key_encryptsession_pk_LOCAL', encrypt)):
        pointers = {symbol(name)}
        if candidate:
            pointers.add(gnu(name))
        for pointer in pointers:
            slot = C.c_void_p.from_address(pointer)
            slot.value = C.cast(callback, C.c_void_p).value
            hooks.append(slot)

    if candidate:
        # Only this disposable child sees the private NSS file. GNU uses its
        # process-local configure operation, so its oracle needs no privilege.
        os.chroot(args.root)
        os.chdir('/')

    rows, extensions, held = [], [], []

    def check(label, condition, detail=None, extension=False):
        if not condition:
            raise AssertionError((label, detail, hook_errors))
        (extensions if extension else rows).append(label)

    def fullname(name, seconds, micros=123456, window=300, window_verifier=None):
        check_word = (window - 1) & 0xffffffff if window_verifier is None else window_verifier
        blocks = crypt(struct.pack('!4I', seconds, micros, window, check_word), chained=True)
        credential = word(0) + word(len(name)) + name + bytes((-len(name)) % 4) + SEALED + blocks[8:12]
        return credential, blocks[:8] + blocks[12:]

    def nickname(slot, seconds, micros=123456):
        return word(1) + struct.pack('=I', slot), crypt(struct.pack('!2I', seconds, micros)) + b'IGNR'

    class Call:
        def __init__(self, pair):
            credential, verifier = pair
            # GNU's legacy inline decoder can read past a declared short body;
            # padding keeps even the independent malformed oracle memory-safe.
            self.credential = C.create_string_buffer(credential, 400)
            self.verifier = C.create_string_buffer(verifier, 400)
            self.output = C.create_string_buffer(400)
            self.cooked = C.create_string_buffer(b'\xa5' * 432, 432)
            self.cooked_address = C.addressof(self.cooked) + 16
            self.transport = Transport()
            self.transport.verifier.base = C.addressof(self.output)
            self.request = Request(0x31234567, 1, 1, Opaque(), self.cooked_address,
                                   C.addressof(self.transport))
            self.message = Message(1, 0, 2, 0x31234567, 1, 1,
                                   Opaque(3, C.addressof(self.credential), len(credential)),
                                   Opaque(3, C.addressof(self.verifier), len(verifier)))

    def run(label, pair, status, stamp=None, name=None, extension=False):
        call = Call(pair)
        rc = authenticate(C.byref(call.request), C.byref(call.message))
        assert call.cooked.raw[:16] == b'\xa5' * 16 and call.cooked.raw[-16:] == b'\xa5' * 16
        assert rc == status, (label, rc, status)
        if rc == 0:
            credential = C.cast(call.cooked_address, C.POINTER(DesCredential)).contents
            proof = C.string_at(call.transport.verifier.base, call.transport.verifier.length)
            assert call.transport.verifier.flavor == 3 and len(proof) == 12
            assert crypt(proof[:8], True) == struct.pack('!2I', (stamp[0] - 1) & 0xffffffff, stamp[1])
            assert struct.unpack('=I', proof[8:])[0] == credential.nickname
            assert credential.kind == 0 and credential.fullname.name == name
            assert bytes(credential.fullname.key) == KEY and credential.fullname.window == 300
            call.nickname = credential.nickname
            held.append(call)
        check(label, not hook_errors, extension=extension)
        return call

    def mapped(label, cooked, expected, tail=False, extension=False):
        sentinel = 0xa5a5a5a5
        uid, gid = IdOutput(sentinel, sentinel, sentinel), IdOutput(sentinel, sentinel, sentinel)
        count = CountOutput(0xa5a5, -1234, 0xa5a5)
        groups = (C.c_uint * 65538)(*([sentinel] * 65538))
        rc = getuser(cooked, C.byref(uid, IdOutput.value.offset), C.byref(gid, IdOutput.value.offset),
                     C.byref(count, CountOutput.value.offset), C.byref(groups, C.sizeof(C.c_uint)))
        assert uid.before == uid.after == gid.before == gid.after == sentinel
        assert count.before == count.after == 0xa5a5 and groups[0] == groups[-1] == sentinel
        if expected is None:
            assert rc == 0 and uid.value == gid.value == sentinel and count.value == -1234
            assert all(value == sentinel for value in groups)
        else:
            expected_uid, expected_gid, expected_groups = expected
            assert rc == 1 and (uid.value, gid.value, count.value) == (
                expected_uid, expected_gid, len(expected_groups))
            assert list(groups[1:1 + count.value]) == expected_groups
            if tail:
                assert groups[1 + count.value] == sentinel, 'wrote an unreported group'
        check(label, not hook_errors, extension=extension)

    stamp = int(time.time())
    user = b'unix.1001@franken.invalid'
    first = run('server-fullname', fullname(user, stamp), 0, (stamp, 123456), user)
    run('server-fullname-retransmit', fullname(user, stamp), 0, (stamp, 123456), user)
    run('server-fullname-replay', fullname(user, stamp - 1), 2)
    run('server-fullname-expired', fullname(b'unix.expired@franken.invalid', stamp - 400), 1)
    run('server-fullname-invalid-usec', fullname(b'unix.usec@franken.invalid', stamp, 1000000), 3)
    run('server-fullname-bad-window', fullname(b'unix.window@franken.invalid', stamp, window_verifier=301), 1)
    run('server-nickname', nickname(first.nickname, stamp + 1), 0, (stamp + 1, 123456), user)
    run('server-nickname-retransmit', nickname(first.nickname, stamp + 1), 0, (stamp + 1, 123456), user)
    run('server-nickname-replay', nickname(first.nickname, stamp), 4)
    run('server-nickname-expired', nickname(first.nickname, stamp - 400), 4)
    run('server-nickname-invalid-usec', nickname(first.nickname, stamp + 2, 1000000), 4)
    run('server-unknown-nickname', nickname(64, stamp), 1)
    pair = fullname(b'unix.shortverf@franken.invalid', stamp)
    run('server-short-verifier', (pair[0], pair[1][:11]), 1)
    run('server-missing-public-key', fullname(b'unix.nokey@franken.invalid', stamp), 1)
    refuse_key[0] = True
    run('server-keyserver-rejected', fullname(b'unix.keyretry@franken.invalid', stamp), 1)
    refuse_key[0] = False
    run('server-keyserver-retry', fullname(b'unix.keyretry@franken.invalid', stamp), 0,
        (stamp, 123456), b'unix.keyretry@franken.invalid')

    before = calls(0)
    mapped('ucred-fullname', first.cooked_address, (1001, 42, [17, 88]), tail=True)
    assert calls(0) == before + 1
    mode(4)
    mapped('ucred-cache-hit', first.cooked_address, (1001, 42, [17, 88]), tail=True)
    assert calls(0) == before + 1
    fresh = run('server-fullname-refresh', fullname(user, stamp + 3), 0, (stamp + 3, 123456), user)
    mapped('ucred-refresh-invalidates-mapping', fresh.cooked_address, (2002, 84, [29, 93]), tail=True)
    assert calls(0) == before + 2
    mode(0)
    host_name = b'unix.host@franken.invalid'
    host_call = run('server-host-authentication', fullname(host_name, stamp), 0, (stamp, 123456), host_name)
    before = calls(0)
    mapped('ucred-host-is-not-a-user', host_call.cooked_address, None)
    mapped('ucred-initial-miss-is-retried', host_call.cooked_address, None)
    assert calls(0) == before + 2

    large_name = b'unix.large@franken.invalid'
    large = run('server-large-mapping-authentication', fullname(large_name, stamp), 0,
                (stamp, 123456), large_name)
    mode(3)
    prefix = list(range(100, 100 + 32767))
    # GNU's first lookup gives NSS the public NGROUPS-sized buffer. Judge its
    # reported prefix, then prime the independent cached-publication oracle.
    mapped('ucred-large-mapping-prime', large.cooked_address, (1001, 42, prefix))
    mapped('ucred-large-mapping-cached-prefix', large.cooked_address, (1001, 42, prefix), tail=True)
    mode(0)

    if not candidate:
        # The existing service suite independently records GNU's broken raw
        # constructor/header serialization. Do not turn that unavailable
        # transport oracle into fabricated raw-exchange parity here.
        check('server-hooks-completed', not hook_errors
              and any(kind == 'decrypt' for kind, _ in hook_calls))
        print(json.dumps({'provider': args.provider, 'rows': rows, 'native_extensions': [],
                          'nss_user_calls': calls(0), 'nss_key_calls': calls(1),
                          'key_hook_calls': len(hook_calls), 'raw_dispatches': 0, 'unix_dispatches': 0,
                          'raw_oracle': 'unavailable: GNU raw serialization; retained in check_rpc_svc.py'}))
        return

    if candidate:
        key_reentry[0] = lambda: run(
            'keyserver-reentry-inner', fullname(b'unix.key-inner@franken.invalid', stamp), 0,
            (stamp, 123456), b'unix.key-inner@franken.invalid', extension=True)
        run('keyserver-reentry-outer', fullname(b'unix.key-outer@franken.invalid', stamp), 0,
            (stamp, 123456), b'unix.key-outer@franken.invalid', extension=True)

        reentrant_name = b'unix.nss-reentry@franken.invalid'
        reentrant = run('nss-reentry-initial', fullname(reentrant_name, stamp), 0,
                        (stamp, 123456), reentrant_name, extension=True)

        @C.CFUNCTYPE(None, C.c_char_p)
        def reenter_mapping(name):
            try:
                assert name == reentrant_name
                lookup_callback(None)
                run('nss-reentry-refresh', fullname(reentrant_name, stamp + 1), 0,
                    (stamp + 1, 123456), reentrant_name, extension=True)
            except BaseException as failure:
                hook_errors.append(repr(failure))

        lookup_callback(C.cast(reenter_mapping, C.c_void_p))
        mapped('nss-reentry-discards-stale-result', reentrant.cooked_address, None, extension=True)
        lookup_callback(None)
        mapped('nss-reentry-next-lookup', reentrant.cooked_address, (1001, 42, [17, 88]),
               tail=True, extension=True)

    # The integrated memory transport must run the same server authenticator,
    # publish an owned reply verifier, and let the real AUTH_DES client validate.
    program = 0x3123da51
    service = create_service()
    check('raw-des-service', bool(service), extension=True)
    own = C.create_string_buffer(256)
    assert getname(own) == 1
    dispatches, dispatch_errors, last_proof = [], [], [None]
    dispatch_label = ['raw-des']

    @C.CFUNCTYPE(None, C.c_void_p, C.c_void_p)
    def dispatch(request_pointer, transport_pointer):
        try:
            request = C.cast(request_pointer, C.POINTER(Request)).contents
            transport = C.cast(transport_pointer, C.POINTER(Transport)).contents
            credential = C.cast(request.cooked, C.POINTER(DesCredential)).contents
            assert request.credential.flavor == 3 and credential.fullname.name == own.value
            assert credential.kind == 0 and bytes(credential.fullname.key) == KEY
            operation = transport.ops[2]
            if candidate:
                provider(operation, args.library, candidate_base)
            getargs = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_void_p)(operation)
            argument = C.c_uint()
            assert getargs(transport_pointer, xdr_uint, C.byref(argument)) == 1
            mapped(dispatch_label[0] + '-ucred-' + str(len(dispatches)), request.cooked,
                   (1001, 42, [17, 88]), tail=True, extension=True)
            last_proof[0] = C.string_at(transport.verifier.base, transport.verifier.length)
            answer = C.c_uint(argument.value + 7)
            assert reply(transport_pointer, xdr_uint, C.byref(answer)) == 1
            dispatches.append(argument.value)
        except BaseException as failure:
            dispatch_errors.append(repr(failure))

    assert register(service, program, 1, C.cast(dispatch, C.c_void_p), 0) == 1
    client = create_client(program, 1)
    server_name = C.create_string_buffer(NAME)
    public = C.create_string_buffer(b'a' * 48 + b'\0', 49)
    public_object = NetObject(49, C.addressof(public))
    key = C.create_string_buffer(KEY, 8)
    auth = create_auth(server_name, C.byref(public_object), 300, None, key)
    check('raw-des-client', bool(client) and bool(auth) and not hook_errors, extension=True)
    client_value = C.cast(client, C.POINTER(Client)).contents
    client_value.auth = auth
    if candidate:
        provider(client_value.ops[0], args.library, candidate_base)
        for index in (1, 2, 4):
            provider(C.cast(auth, C.POINTER(Auth)).contents.ops[index], args.library, candidate_base)
    invoke = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_ulong, C.c_void_p,
                        C.c_void_p, C.c_void_p, C.c_void_p, Timeval)(client_value.ops[0])
    for index in range(2):
        argument, answer = C.c_uint(40 + index), C.c_uint()
        rc = invoke(client, 1, xdr_uint, C.byref(argument), xdr_uint, C.byref(answer), Timeval(1, 0))
        check('raw-des-call-' + str(index), rc == 0 and answer.value == argument.value + 7
              and not dispatch_errors, (rc, answer.value, dispatch_errors), extension=True)
        transport = C.cast(service, C.POINTER(Transport)).contents
        assert C.string_at(transport.verifier.base, transport.verifier.length) == last_proof[0]
    assert dispatches == [40, 41]
    run('server-unrelated-auth-after-raw-reply', fullname(b'unix.proof-life@franken.invalid', stamp),
        0, (stamp, 123456), b'unix.proof-life@franken.invalid', extension=True)
    transport = C.cast(service, C.POINTER(Transport)).contents
    check('raw-des-proof-lifetime',
          C.string_at(transport.verifier.base, transport.verifier.length) == last_proof[0],
          extension=True)
    client_value.auth = null_auth()
    destroy = C.CFUNCTYPE(None, C.c_void_p)(C.cast(auth, C.POINTER(Auth)).contents.ops[4])
    destroy(auth)
    unregister(program, 1)
    check('raw-des-hooks-completed', not hook_errors and not dispatch_errors
          and any(kind == 'encrypt' for kind, _ in hook_calls)
          and any(kind == 'decrypt' for kind, _ in hook_calls), extension=True)

    # Unix peer credentials must not overwrite AUTH_DES's wire verifier. The
    # first exchange exercises public SVC_RECV + _authenticate; the second uses
    # normal service dispatch. Both clients use the actual native stream path.
    raw_dispatches = len(dispatches)
    dispatches = []
    dispatch_label[0] = 'unix-des'

    class UnixAddress(C.Structure):
        _fields_ = [('family', C.c_ushort), ('path', C.c_char * 108)]

    left, right = socket.socketpair()
    server_fd = right.detach()
    service = create_unix_service(server_fd, 0, 0)
    check('unix-des-service', bool(service)
          and register(service, program, 1, C.cast(dispatch, C.c_void_p), 0) == 1, extension=True)
    address = UnixAddress(socket.AF_UNIX, b'borrowed-auth-des-socket')
    descriptor = C.c_int(left.fileno())
    client = create_unix_client(C.byref(address), program, 1, C.byref(descriptor), 0, 0)
    auth = create_auth(server_name, C.byref(public_object), 300, None, key)
    check('unix-des-client', bool(client) and bool(auth)
          and descriptor.value == left.fileno(), extension=True)
    client_value = C.cast(client, C.POINTER(Client)).contents
    client_value.auth = auth
    provider(client_value.ops[0], args.library, candidate_base)
    provider(client_value.ops[4], args.library, candidate_base)
    transport = C.cast(service, C.POINTER(Transport)).contents
    provider(transport.ops[0], args.library, candidate_base)
    provider(transport.ops[5], args.library, candidate_base)
    receive = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p)(transport.ops[0])

    def serve_unix():
        try:
            for index in range(2):
                ready, _, _ = select.select([server_fd], [], [], 3)
                assert ready, 'Unix RPC request did not arrive'
                if index == 0:
                    credential, verifier, cooked = (C.create_string_buffer(400) for _ in range(3))
                    message = Message()
                    message.credential.base = C.addressof(credential)
                    message.verifier.base = C.addressof(verifier)
                    assert receive(service, C.byref(message)) == 1
                    check('unix-des-receive-preserves-wire-proof',
                          message.credential.flavor == 3 and message.verifier.flavor == 3
                          and message.verifier.length == 12, extension=True)
                    request = Request(message.program, message.version, message.procedure,
                                      message.credential, C.addressof(cooked), service)
                    assert authenticate(C.byref(request), C.byref(message)) == 0
                    held.append((credential, verifier, cooked, message, request))
                    dispatch(C.byref(request), service)
                else:
                    dispatch_ready(server_fd)
        except BaseException as failure:
            dispatch_errors.append(repr(failure))

    server_thread = threading.Thread(target=serve_unix, daemon=True)
    server_thread.start()
    invoke = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_ulong, C.c_void_p,
                        C.c_void_p, C.c_void_p, C.c_void_p, Timeval)(client_value.ops[0])
    for index in range(2):
        argument, answer = C.c_uint(50 + index), C.c_uint()
        rc = invoke(client, 1, xdr_uint, C.byref(argument), xdr_uint, C.byref(answer), Timeval(2, 0))
        check('unix-des-call-' + str(index), rc == 0 and answer.value == argument.value + 7
              and not dispatch_errors, (rc, answer.value, dispatch_errors), extension=True)
    server_thread.join(timeout=4)
    check('unix-des-dispatch-completed', not server_thread.is_alive()
          and dispatches == [50, 51] and not dispatch_errors, dispatch_errors, extension=True)
    transport = C.cast(service, C.POINTER(Transport)).contents
    check('unix-des-proof-lifetime',
          C.string_at(transport.verifier.base, transport.verifier.length) == last_proof[0],
          extension=True)
    client_value.auth = null_auth()
    C.CFUNCTYPE(None, C.c_void_p)(C.cast(auth, C.POINTER(Auth)).contents.ops[4])(auth)
    C.CFUNCTYPE(None, C.c_void_p)(client_value.ops[4])(client)
    os.fstat(left.fileno())  # A borrowed client descriptor remains caller-owned.
    left.close()
    unregister(program, 1)
    C.CFUNCTYPE(None, C.c_void_p)(transport.ops[5])(service)
    try:
        os.close(server_fd)
    except OSError as failure:
        assert failure.errno == 9  # Owned-service teardown may already close it.
    check('unix-des-teardown', not hook_errors and not dispatch_errors, extension=True)

    check('server-hooks-completed', not hook_errors
          and any(kind == 'decrypt' for kind, _ in hook_calls))
    print(json.dumps({'provider': args.provider, 'rows': rows, 'native_extensions': extensions,
                      'nss_user_calls': calls(0), 'nss_key_calls': calls(1),
                      'key_hook_calls': len(hook_calls), 'raw_dispatches': raw_dispatches,
                      'unix_dispatches': len(dispatches)}))


def server_main(args):
    if not args.output or (not args.host_only and not args.library):
        raise ValueError('server oracle requires --output and a library, or --host-only')
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    repository = Path(__file__).resolve().parent.parent
    fixture = repository / 'tests/integration/fixture_rpc_auth_des_module.c'
    module = out / 'libnss_rpcdes.so.2'
    subprocess.run(['gcc', '-shared', '-fPIC', '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-Wl,-soname,libnss_rpcdes.so.2', str(fixture), '-o', str(module)], check=True)
    library = args.library.resolve() if args.library else None
    clean = {key: value for key, value in os.environ.items()
             if key not in ('LD_PRELOAD', 'LD_AUDIT') and not key.startswith(('FRANKENLIBC_', 'RPC_IDENTITY_'))}
    report = {'scope': 'GNU server oracle only' if args.host_only else 'GNU and deployed AUTH_DES servers',
              'library_sha256': hashlib.sha256(library.read_bytes()).hexdigest() if library else None,
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'module_fixture_sha256': hashlib.sha256(fixture.read_bytes()).hexdigest(),
              'host_checks': 0, 'candidate_checks': 0, 'native_extension_checks': 0,
              'provider_negatives': 0, 'optimization_negatives': 0, 'runs': []}
    optimized = subprocess.run(
        [sys.executable, '-O', str(Path(__file__).resolve()), '--server-only', '--worker',
         '--provider', 'host', '--module', str(module)],
        env=clean, capture_output=True, text=True, timeout=10)
    (out / 'optimization-negative.stdout').write_text(optimized.stdout)
    (out / 'optimization-negative.stderr').write_text(optimized.stderr)
    if optimized.returncode == 0 or 'AUTH_DES oracle requires Python assertions' not in optimized.stderr:
        raise RuntimeError('optimized Python did not trip the mandatory oracle guard')
    report['optimization_negatives'] = 1
    scenarios = [('host', 'host', None, False)]
    if not args.host_only:
        scenarios += [('strict', 'candidate', 'strict', False),
                      ('hardened', 'candidate', 'hardened', False),
                      ('provider-negative', 'candidate', 'strict', True)]
    for label, provider_name, mode, negative in scenarios:
        command = [sys.executable, str(Path(__file__).resolve())]
        if library:
            command.append(str(library))
        command += ['--worker', '--server-only', '--provider', provider_name, '--module', str(module)]
        if provider_name == 'candidate':
            root = out / ('root-' + label)
            (root / 'etc').mkdir(parents=True)
            (root / 'etc/nsswitch.conf').write_text('publickey: rpcdes\n')
            command += ['--root', str(root)]
        if negative:
            command.append('--force-host')
        environment = dict(clean)
        if mode:
            environment.update(FRANKENLIBC_MODE=mode, FRANKENLIBC_THREAD_NATIVE='0')
        run = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=30)
        (out / (label + '.stdout')).write_text(run.stdout)
        (out / (label + '.stderr')).write_text(run.stderr)
        if negative:
            assert run.returncode == 90 and 'WRONG AUTH_DES PROVIDER' in run.stderr
            report['provider_negatives'] += 1
            continue
        if run.returncode:
            raise RuntimeError(f'{label} server failed {run.returncode}: {run.stderr}')
        record = json.loads(run.stdout)
        assert len(record['rows']) == 27
        if provider_name == 'candidate':
            assert record['rows'] == report['runs'][0]['rows']
            assert len(record['native_extensions']) == 25
            assert record['raw_dispatches'] == record['unix_dispatches'] == 2
        else:
            assert not record['native_extensions'] and record['raw_dispatches'] == 0
        report['host_checks' if provider_name == 'host' else 'candidate_checks'] += len(record['rows'])
        report['native_extension_checks'] += len(record['native_extensions'])
        report['runs'].append(record)
    assert report['host_checks'] == 27
    if not args.host_only:
        assert report['candidate_checks'] == 2 * report['host_checks']
        assert report['native_extension_checks'] == 50 and report['provider_negatives'] == 1
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({name: report[name] for name in (
        'host_checks', 'candidate_checks', 'native_extension_checks', 'provider_negatives',
        'optimization_negatives')}))
    return 0


def main():
    if not __debug__:
        raise RuntimeError('AUTH_DES oracle requires Python assertions; remove -O/PYTHONOPTIMIZE')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', nargs='?', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--host-only', action='store_true')
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--server-only', action='store_true',
                        help='Run hermetic server authentication, identity mapping and raw dispatch.')
    parser.add_argument('--provider', choices=('host', 'candidate'))
    parser.add_argument('--module', type=Path)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--force-host', action='store_true')
    args = parser.parse_args()
    if args.worker:
        try:
            (server_worker if args.server_only else worker)(args)
        except RuntimeError as failure:
            if 'WRONG AUTH_DES PROVIDER' in str(failure):
                print(str(failure), file=sys.stderr)
                return 90
            raise
        return 0
    if args.server_only:
        return server_main(args)
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
