#!/usr/bin/env python3
"""Controlled A/AAAA/PTR peers for the real C ABI; no external network."""
from __future__ import annotations

import argparse
import ipaddress
import os
import socket
import struct
import subprocess
import threading
from collections import Counter


def wire_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\0"


def rr(owner: bytes, kind: int, data: bytes) -> bytes:
    return owner + struct.pack("!HHIH", kind, 1, 30, len(data)) + data


V4_REVERSE = ipaddress.ip_address("192.0.2.9").reverse_pointer
V6_REVERSE = ipaddress.ip_address("2001:db8::9").reverse_pointer


def respond(query: bytes, transport: str, seen: Counter) -> bytes:
    if len(query) < 17 or struct.unpack_from("!H", query, 4)[0] != 1:
        raise ValueError("expected one complete DNS question")
    position, labels = 12, []
    while query[position]:
        length = query[position]
        if length > 63 or position + 1 + length >= len(query):
            raise ValueError("invalid query label")
        labels.append(query[position + 1:position + 1 + length].decode("ascii"))
        position += 1 + length
    kind, klass = struct.unpack_from("!HH", query, position + 1)
    if klass != 1 or kind not in (1, 12, 28):
        raise ValueError("unexpected query type/class")
    name = ".".join(labels).lower()
    seen[(name, transport)] += 1
    question = query[12:position + 5]
    flags, records = 0x8180, []
    if kind == 12:
        if name in (V4_REVERSE, V6_REVERSE):
            if transport == "udp":
                flags |= 0x0200
            else:
                target = "ptr-edge.local.test" if name == V4_REVERSE else "ptr-v6.local.test"
                records = [rr(b"\xc0\x0c", 5, wire_name(target))]
        elif name in ("ptr-edge.local.test", "ptr-v6.local.test"):
            # Compress the target's local.test suffix against the current
            # question. Offsets are message-relative, not relative to RDATA.
            label = b"peer" if name == "ptr-edge.local.test" else b"v6-peer"
            suffix = 13 + len(name.split(".")[0])
            target = bytes([len(label)]) + label + struct.pack("!H", 0xc000 | suffix)
            records = [rr(wire_name("unrelated.test"), 12, wire_name("forged.test")),
                       rr(b"\xc0\x0c", 12, target)]
        elif name == "10.2.0.192.in-addr.arpa":
            records = [rr(b"\xc0\x0c", 12, wire_name("peer.foreign.test"))]
        elif name.endswith(".2.0.192.in-addr.arpa") and 206 <= int(name.split(".")[0]) <= 211:
            targets = {
                206: [b"\0"],
                207: [b"\x03a.b\0"],
                208: [b"\x03a\0b\0"],
                209: [wire_name("_service.Host-.test")],
                210: [b"\x03a.b\0", wire_name("valid.test")],
                211: [wire_name("valid.test"), b"\x03a.b\0"],
            }
            records = [rr(b"\xc0\x0c", 12, target) for target in targets[int(name.split(".")[0])]]
        elif name == "201.2.0.192.in-addr.arpa":
            flags |= 3
        elif name == "202.2.0.192.in-addr.arpa":
            flags |= 2
        elif name == "203.2.0.192.in-addr.arpa":
            flags |= 5
        elif name == "204.2.0.192.in-addr.arpa":
            records = [rr(b"\xc0\x0c", 5, b"\xc0\x0c")]
        elif name == "205.2.0.192.in-addr.arpa":
            records = [rr(b"\xc0\x0c", 12, b"\xc0"), rr(b"\0", 1, bytes([192, 0, 2, 9]))]
        else:
            # Includes files-only and numeric-only controls: any unexpected
            # request is a failing assertion, never an accidental NXDOMAIN.
            raise ValueError(f"unexpected reverse DNS query: {name}")
    elif name in ("alias.test", "v6alias.test"):
        if transport == "udp":
            flags |= 0x0200
        else:
            target = "edge.test" if kind == 1 else "v6edge.test"
            records = [rr(b"\xc0\x0c", 5, wire_name(target))]
    elif name in ("edge.test", "v6edge.test"):
        good = "192.0.2.9" if kind == 1 else "2001:db8::9"
        bad = "203.0.113.99" if kind == 1 else "2001:db8::bad"
        records = [rr(wire_name("foreign.test"), kind, ipaddress.ip_address(bad).packed),
                   rr(b"\xc0\x0c", kind, ipaddress.ip_address(good).packed)]
    elif name == "missing.test":
        flags |= 3
    elif name == "temporary.test":
        flags |= 2
    elif name == "refused.test":
        flags |= 5
    elif name == "cycle.test":
        records = [rr(b"\xc0\x0c", 5, b"\xc0\x0c")]
    else:
        raise ValueError(f"unexpected forward DNS query: {name}")
    return query[:2] + struct.pack("!HHHHH", flags, 1, len(records), 0, 0) + question + b"".join(records)


def read_exact(stream: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = stream.recv(length - len(chunks))
        if not chunk:
            raise EOFError("short TCP query")
        chunks.extend(chunk)
    return bytes(chunks)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("client")
    parser.add_argument("library")
    parser.add_argument("--tcp-only", action="store_true")
    parser.add_argument("--preload", action="store_true")
    args = parser.parse_args()
    stop = threading.Event()
    seen: Counter = Counter()
    failures: list[BaseException] = []
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    udp.bind(("127.0.0.1", 53))
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("127.0.0.1", 53))
    tcp.listen(8)
    udp.settimeout(0.2)
    tcp.settimeout(0.2)

    def serve_udp() -> None:
        try:
            while not stop.is_set():
                try:
                    query, peer = udp.recvfrom(65535)
                except socket.timeout:
                    continue
                if args.tcp_only:
                    raise AssertionError("use-vc sent a UDP query")
                udp.sendto(respond(query, "udp", seen), peer)
        except BaseException as error:
            failures.append(error)

    def serve_tcp() -> None:
        try:
            while not stop.is_set():
                try:
                    stream, _ = tcp.accept()
                except socket.timeout:
                    continue
                with stream:
                    stream.settimeout(3)
                    length = struct.unpack("!H", read_exact(stream, 2))[0]
                    reply = respond(read_exact(stream, length), "tcp", seen)
                    framed = struct.pack("!H", len(reply)) + reply
                    for offset in range(0, len(framed), 7):
                        stream.sendall(framed[offset:offset + 7])
        except BaseException as error:
            failures.append(error)

    workers = [threading.Thread(target=serve_udp), threading.Thread(target=serve_tcp)]
    for worker in workers:
        worker.start()
    try:
        environment = os.environ.copy()
        environment.pop("FRANKENLIBC_TEST_TCP_ONLY", None)
        if args.tcp_only:
            environment["FRANKENLIBC_TEST_TCP_ONLY"] = "1"
        command = [args.client, args.library]
        if args.preload:
            environment["LD_PRELOAD"] = args.library
            command.append("--preloaded")
        subprocess.run(command, check=True, timeout=30, env=environment)
    finally:
        stop.set()
        for worker in workers:
            worker.join(timeout=4)
        udp.close()
        tcp.close()
    if failures:
        raise failures[0]
    for alias, count in [("alias.test", 1), ("v6alias.test", 1), (V4_REVERSE, 3), (V6_REVERSE, 1)]:
        assert seen[(alias, "tcp")] == count, (alias, seen)
        assert seen[(alias, "udp")] == (0 if args.tcp_only else count), (alias, seen)
    transport = "tcp" if args.tcp_only else "udp"
    for canonical, count in [("edge.test", 1), ("v6edge.test", 1), ("ptr-edge.local.test", 3), ("ptr-v6.local.test", 1)]:
        assert seen[(canonical, transport)] == count, (canonical, seen)
    for last in range(206, 212):
        owner = f"{last}.2.0.192.in-addr.arpa"
        assert seen[(owner, transport)] == 2, (owner, seen)
        other = "udp" if transport == "tcp" else "tcp"
        assert seen[(owner, other)] == 0, (owner, seen)
    print("DNS fixture: forward/PTR TCP fallback, alias follow-up, files and no-query controls passed", flush=True)


if __name__ == "__main__":
    main()
