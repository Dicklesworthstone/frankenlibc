#!/usr/bin/env python3
"""Controlled DNS peer for the native resolver C ABI test; no external network."""
from __future__ import annotations

import argparse
import ipaddress
import socket
import struct
import subprocess
import threading
from collections import Counter


def wire_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\0"


def rr(owner: bytes, kind: int, data: bytes) -> bytes:
    return owner + struct.pack("!HHIH", kind, 1, 30, len(data)) + data


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
    if klass != 1 or kind not in (1, 28):
        raise ValueError("unexpected query type/class")
    name = ".".join(labels).lower()
    seen[(name, transport)] += 1
    question = query[12:position + 5]
    flags, records = 0x8180, []
    if name in ("alias.test", "v6alias.test"):
        if transport == "udp":
            flags |= 0x0200
        else:
            target = "edge.test" if kind == 1 else "v6edge.test"
            records = [rr(b"\xc0\x0c", 5, wire_name(target))]
    elif name in ("edge.test", "v6edge.test"):
        good = "192.0.2.9" if kind == 1 else "2001:db8::9"
        bad = "203.0.113.99" if kind == 1 else "2001:db8::bad"
        records = [
            rr(wire_name("foreign.test"), kind, ipaddress.ip_address(bad).packed),
            rr(b"\xc0\x0c", kind, ipaddress.ip_address(good).packed),
        ]
    elif name == "missing.test":
        flags |= 3
    elif name == "temporary.test":
        flags |= 2
    else:
        raise ValueError(f"unexpected DNS name: {name}")
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
                    # Exercise partial frame delivery at the public ABI too.
                    for offset in range(0, len(framed), 7):
                        stream.sendall(framed[offset:offset + 7])
        except BaseException as error:
            failures.append(error)

    workers = [threading.Thread(target=serve_udp), threading.Thread(target=serve_tcp)]
    for worker in workers:
        worker.start()
    try:
        subprocess.run([args.client, args.library], check=True, timeout=20)
    finally:
        stop.set()
        for worker in workers:
            worker.join(timeout=4)
        udp.close()
        tcp.close()
    if failures:
        raise failures[0]
    for alias in ("alias.test", "v6alias.test"):
        assert seen[(alias, "tcp")] == 1, (alias, seen)
        assert seen[(alias, "udp")] == (0 if args.tcp_only else 1), (alias, seen)
    transport = "tcp" if args.tcp_only else "udp"
    for canonical in ("edge.test", "v6edge.test"):
        assert seen[(canonical, transport)] == 1, (canonical, seen)
    print("DNS fixture: TCP fallback/use-vc and absolute CNAME follow-up observed", flush=True)


if __name__ == "__main__":
    main()
