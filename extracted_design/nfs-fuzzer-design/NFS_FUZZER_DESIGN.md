# NFS Protocol Fuzzer Design Document

A comprehensive guide for building an NFS v3/v4 fuzzer using boofuzz, designed for handoff to Claude Code or similar agentic coding tools.

## Executive Summary

This document describes how to build a network fuzzer for NFS (Network File System) protocols. NFS is a high-value target because:

- Black Duck's Defensics has found kernel CVEs in Linux NFSD
- The protocol is complex (layered: TCP → Sun RPC → NFS procedures)
- Widely deployed in enterprise environments
- Both userspace (nfs-ganesha) and kernel (NFSD) implementations exist

The fuzzer will be written in Rust (preferred) or Python with boofuzz, targeting NFSv3 (RFC 1813) and NFSv4 (RFC 7530/8881).

---

## Protocol Architecture

### The NFS Stack

```
┌─────────────────────────────────────────┐
│              NFS Procedures              │
│  (LOOKUP, READ, WRITE, GETATTR, etc.)   │
├─────────────────────────────────────────┤
│              Sun RPC (ONC RPC)           │
│    RFC 5531 - XDR encoding, auth        │
├─────────────────────────────────────────┤
│           TCP Record Marking             │
│   4-byte header: [last_frag|length]     │
├─────────────────────────────────────────┤
│                  TCP                     │
└─────────────────────────────────────────┘
```

### TCP Record Marking (Critical for framing)

Every RPC message over TCP is prefixed with a 4-byte record mark:

```
┌───────────────────────────────────────┐
│ Bit 31: Last Fragment (1 = yes)       │
│ Bits 0-30: Fragment Length            │
└───────────────────────────────────────┘
```

For fuzzing, we typically set bit 31 = 1 (single fragment) and bits 0-30 = length of RPC message.

**Rust representation:**
```rust
fn make_record_mark(length: u32, last_fragment: bool) -> u32 {
    if last_fragment {
        0x80000000 | length
    } else {
        length
    }
}
```

### Sun RPC Call Message (RFC 5531)

Every NFS call is wrapped in an RPC CALL message:

```
┌────────────────────────────────────────┐
│ XID (4 bytes) - Transaction ID         │
├────────────────────────────────────────┤
│ Message Type (4 bytes) - 0 = CALL      │
├────────────────────────────────────────┤
│ RPC Version (4 bytes) - always 2       │
├────────────────────────────────────────┤
│ Program Number (4 bytes)               │
│   100003 = NFS                         │
│   100005 = MOUNT                       │
│   100000 = PORTMAP                     │
├────────────────────────────────────────┤
│ Program Version (4 bytes)              │
│   3 = NFSv3, 4 = NFSv4                 │
├────────────────────────────────────────┤
│ Procedure Number (4 bytes)             │
├────────────────────────────────────────┤
│ Auth Credentials (variable)            │
├────────────────────────────────────────┤
│ Auth Verifier (variable)               │
├────────────────────────────────────────┤
│ Procedure-specific arguments           │
└────────────────────────────────────────┘
```

**All integers are big-endian (network byte order).**

### XDR Encoding Basics

Sun RPC uses XDR (External Data Representation) for encoding:

| Type | Encoding |
|------|----------|
| int32/uint32 | 4 bytes, big-endian |
| int64/uint64 | 8 bytes, big-endian |
| opaque<n> | n bytes, padded to 4-byte boundary |
| string | 4-byte length + chars + padding |
| array | 4-byte count + elements |

**Padding rule:** Everything is padded to 4-byte boundaries.

```rust
fn xdr_pad_length(len: usize) -> usize {
    (4 - (len % 4)) % 4
}
```

### Authentication Flavours

```rust
const AUTH_NONE: u32 = 0;      // No auth
const AUTH_SYS: u32 = 1;       // Unix-style (UID/GID)
const AUTH_SHORT: u32 = 2;     // Short-hand verifier
const AUTH_DES: u32 = 3;       // DES-based (obsolete)
const RPCSEC_GSS: u32 = 6;     // Kerberos/GSS-API
```

For fuzzing, start with AUTH_NONE or AUTH_SYS. AUTH_SYS includes:
- stamp (4 bytes)
- machine name (XDR string)
- uid (4 bytes)  
- gid (4 bytes)
- auxiliary gids (XDR array of uint32)

---

## NFS Version 3 (RFC 1813)

### Program Numbers

```rust
const NFS_PROGRAM: u32 = 100003;
const NFS_V3: u32 = 3;
```

### NFSv3 Procedures

| Number | Name | Args |
|--------|------|------|
| 0 | NULL | none |
| 1 | GETATTR | fhandle3 |
| 2 | SETATTR | fhandle3, sattr3, sattrguard3 |
| 3 | LOOKUP | dirop3 (fhandle3 + name) |
| 4 | ACCESS | fhandle3, access_bits |
| 5 | READLINK | fhandle3 |
| 6 | READ | fhandle3, offset, count |
| 7 | WRITE | fhandle3, offset, count, stable, data |
| 8 | CREATE | dirop3, createhow3 |
| 9 | MKDIR | dirop3, sattr3 |
| 10 | SYMLINK | dirop3, symlinkdata3 |
| 11 | MKNOD | dirop3, mknoddata3 |
| 12 | REMOVE | dirop3 |
| 13 | RMDIR | dirop3 |
| 14 | RENAME | dirop3, dirop3 |
| 15 | LINK | fhandle3, dirop3 |
| 16 | READDIR | fhandle3, cookie, cookieverf, count |
| 17 | READDIRPLUS | fhandle3, cookie, cookieverf, dircount, maxcount |
| 18 | FSSTAT | fhandle3 |
| 19 | FSINFO | fhandle3 |
| 20 | PATHCONF | fhandle3 |
| 21 | COMMIT | fhandle3, offset, count |

### Key Data Types

**fhandle3** - File handle (up to 64 bytes):
```
┌──────────────────────┐
│ length (4 bytes)     │
├──────────────────────┤
│ opaque data (≤64)    │
│ + padding            │
└──────────────────────┘
```

**filename3** - XDR string, variable length

**dirop3** - Directory operation:
```
fhandle3 (directory handle)
filename3 (name to look up)
```

### Interesting Fuzzing Targets in NFSv3

1. **File handle parsing** - Malformed lengths, oversized handles
2. **Filename handling** - Long names, null bytes, path traversal attempts
3. **Offset/count fields** - Integer overflow potential
4. **Cookie handling in READDIR** - State management bugs
5. **Attribute parsing in SETATTR** - Complex nested structures

---

## NFS Version 4 (RFC 7530 / RFC 8881)

### Key Difference: COMPOUND Operations

NFSv4 uses a single COMPOUND procedure that batches multiple operations:

```
┌─────────────────────────────┐
│ RPC Header (program=100003) │
│ Version = 4, Procedure = 1  │
├─────────────────────────────┤
│ COMPOUND4args:              │
│   tag (XDR string)          │
│   minorversion (uint32)     │
│   argarray (op list)        │
└─────────────────────────────┘
```

### NFSv4 Operations (inside COMPOUND)

| OpCode | Name | Purpose |
|--------|------|---------|
| 3 | ACCESS | Check access rights |
| 4 | CLOSE | Close stateful file |
| 6 | COMMIT | Commit cached data |
| 7 | CREATE | Create non-regular file |
| 9 | GETATTR | Get attributes |
| 10 | GETFH | Get current filehandle |
| 15 | LOOKUP | Look up filename |
| 16 | LOOKUPP | Look up parent |
| 18 | OPEN | Open/create file |
| 22 | PUTFH | Set current filehandle |
| 23 | PUTPUBFH | Set public filehandle |
| 24 | PUTROOTFH | Set root filehandle |
| 25 | READ | Read file data |
| 27 | READDIR | Read directory |
| 29 | REMOVE | Remove file |
| 30 | RENAME | Rename file/dir |
| 33 | SAVEFH | Save current filehandle |
| 37 | SETATTR | Set attributes |
| 38 | WRITE | Write data |

### NFSv4 State Model

NFSv4 is stateful (unlike v3). Important concepts:
- **clientid** - Assigned during SETCLIENTID
- **stateid** - Returned from OPEN, used for READ/WRITE
- **seqid** - Sequence numbers for operations

This stateful nature creates more attack surface but requires more setup.

---

## Recommended Fuzzing Approach

### Phase 1: Stateless NFSv3 Fuzzing

Start simple with procedures that don't require session state:

1. **NULL** - Should always work, test RPC framing
2. **GETATTR** - Just needs a filehandle (can be garbage)
3. **LOOKUP** - Directory handle + filename
4. **FSINFO** - Root filehandle
5. **FSSTAT** - Root filehandle

### Phase 2: Obtain Valid Handles via MOUNT

The MOUNT protocol (program 100005) provides initial file handles:

```
MOUNT procedure 1 (MNT):
  Input: dirpath (string like "/export/share")
  Output: fhandle3 (the root handle for that export)
```

Sequence:
1. Connect to mountd (typically port 635 or check portmapper)
2. Call MNT with export path
3. Use returned handle for NFS operations

### Phase 3: Stateful NFSv4 Fuzzing

Requires session establishment:
1. SETCLIENTID → get clientid
2. SETCLIENTID_CONFIRM → confirm session
3. PUTROOTFH → set current handle to root
4. OPEN → open a file, get stateid
5. Now can fuzz READ/WRITE with valid state

### Mutation Strategies

Focus mutations on:

| Field | Mutation Type | Why |
|-------|--------------|-----|
| Record mark length | Overflow, mismatch | Framing bugs |
| XID | Reuse, max values | State confusion |
| Procedure number | Invalid values | Dispatch bugs |
| Auth length | Overflow | Buffer overflows |
| File handle length | 0, 65, MAX_INT | Bounds checking |
| Filename | Long, nulls, UTF-8 | String handling |
| Offset/count | Negative, MAX_INT64 | Integer overflow |
| Array counts | 0, huge values | Memory allocation |

---

## Implementation Guide

### Rust Implementation (Preferred)

Recommended crates:
- `tokio` - Async networking
- `bytes` - Buffer handling
- `rand` - Random mutations
- `arbitrary` / `proptest` - Structured fuzzing

Project structure:
```
nfs-fuzzer/
├── Cargo.toml
├── src/
│   ├── main.rs           # CLI and orchestration
│   ├── lib.rs
│   ├── xdr.rs            # XDR encoding primitives
│   ├── rpc.rs            # Sun RPC message construction
│   ├── nfsv3.rs          # NFSv3 procedures
│   ├── nfsv4.rs          # NFSv4 COMPOUND operations
│   ├── mount.rs          # MOUNT protocol
│   ├── mutations.rs      # Mutation strategies
│   └── connection.rs     # TCP handling
└── tests/
    └── integration.rs
```

Key implementation notes:
- All network bytes are big-endian
- Everything aligns to 4-byte boundaries
- Lengths in record marks exclude the 4-byte header itself
- Handle both single and multi-fragment messages

### Python/boofuzz Implementation

If Rust isn't feasible, use boofuzz:

```python
from boofuzz import *

def define_rpc_header():
    """Common RPC CALL header for all NFS procedures."""
    s_initialize("rpc_header")
    
    with s_block("record_mark"):
        # Bit 31 = last fragment, bits 0-30 = length
        s_dword(0x80000000, endian=">", name="rm_flags")  # Will need size callback
    
    with s_block("rpc_call"):
        s_dword(0x12345678, endian=">", name="xid", fuzzable=True)
        s_dword(0, endian=">", name="msg_type")  # CALL
        s_dword(2, endian=">", name="rpc_version")
        s_dword(100003, endian=">", name="program")  # NFS
        s_dword(3, endian=">", name="version")  # NFSv3
        s_dword(0, endian=">", name="procedure")  # NULL
        
        # AUTH_NONE credentials
        s_dword(0, endian=">", name="cred_flavor")
        s_dword(0, endian=">", name="cred_length")
        
        # AUTH_NONE verifier
        s_dword(0, endian=">", name="verf_flavor")
        s_dword(0, endian=">", name="verf_length")
```

The challenge with boofuzz is handling the record mark length calculation. Options:
1. Use a callback to calculate size post-mutation
2. Use the `s_size` primitive with careful block nesting
3. Send oversized record marks (the target should handle gracefully)

---

## Test Targets

### nfs-ganesha (Userspace, Recommended for Initial Testing)

```bash
# Debian
sudo apt install nfs-ganesha nfs-ganesha-vfs

# Basic config for testing (/etc/ganesha/ganesha.conf)
EXPORT {
    Export_Id = 1;
    Path = /tmp/nfs-test;
    Pseudo = /test;
    Access_Type = RW;
    Squash = No_root_squash;
    FSAL {
        Name = VFS;
    }
}

# Create export directory
mkdir -p /tmp/nfs-test

# Start (foreground for debugging)
sudo ganesha.nfsd -F -L /dev/stdout
```

### Linux NFSD (Kernel)

```bash
# Debian
sudo apt install nfs-kernel-server

# Export configuration (/etc/exports)
/tmp/nfs-test *(rw,sync,no_subtree_check,no_root_squash)

# Create and start
mkdir -p /tmp/nfs-test
sudo exportfs -ra
sudo systemctl start nfs-server
```

### Building with ASAN (for nfs-ganesha)

```bash
git clone https://github.com/nfs-ganesha/nfs-ganesha.git
cd nfs-ganesha
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug \
         -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer" \
         -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address"
make -j$(nproc)
```

---

## Monitoring and Crash Detection

### Process Monitoring

```bash
# Watch for crashes
while true; do
    if ! pgrep -x ganesha.nfsd > /dev/null; then
        echo "$(date): ganesha crashed!"
        # Log last test case
    fi
    sleep 1
done
```

### ASAN Output

With ASAN-enabled builds, crashes produce detailed traces:
```
==12345==ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 4 at 0x...
    #0 0x... in parse_fhandle src/nfs3.c:123
    #1 0x... in nfs3_lookup src/nfs3.c:456
```

### Network Capture

```bash
# Capture NFS traffic for replay
sudo tcpdump -i lo -w nfs-fuzz.pcap port 2049
```

---

## Responsible Disclosure

### nfs-ganesha
- GitHub Issues for non-security bugs
- security@nfs-ganesha.org for vulnerabilities
- 90-day disclosure timeline is reasonable

### Linux Kernel (NFSD)
- security@kernel.org
- Follow kernel security process
- Longer timelines often needed

### Report Template

```markdown
## Vulnerability Summary
[One sentence description]

## Affected Component
[e.g., nfs-ganesha 4.2, nfs3_lookup procedure]

## Impact
[Crash/DoS/RCE potential]

## Reproduction Steps
1. Start NFS server with [config]
2. Run: [command or attach PoC]
3. Server crashes with [error]

## Technical Details
[Stack trace, ASAN output, analysis]

## Suggested Fix
[If known]

## Timeline
- [Date]: Bug discovered
- [Date]: Report sent
```

---

## Appendix: Quick Reference

### Constants

```rust
// RPC
const RPC_VERSION: u32 = 2;
const MSG_TYPE_CALL: u32 = 0;
const MSG_TYPE_REPLY: u32 = 1;

// Programs
const PORTMAP_PROGRAM: u32 = 100000;
const NFS_PROGRAM: u32 = 100003;
const MOUNT_PROGRAM: u32 = 100005;

// Versions
const NFS_V3: u32 = 3;
const NFS_V4: u32 = 4;
const NFS_V41: u32 = 1;  // Minor version for 4.1
const MOUNT_V3: u32 = 3;

// Auth
const AUTH_NONE: u32 = 0;
const AUTH_SYS: u32 = 1;

// Ports
const NFS_PORT: u16 = 2049;
const PORTMAP_PORT: u16 = 111;
```

### Minimal NULL Procedure Packet (NFSv3)

```
Record Mark:    80 00 00 28   (last fragment, 40 bytes)
XID:            00 00 00 01
Message Type:   00 00 00 00   (CALL)
RPC Version:    00 00 00 02
Program:        00 01 86 A3   (100003 = NFS)
Version:        00 00 00 03   (NFSv3)
Procedure:      00 00 00 00   (NULL)
Cred Flavor:    00 00 00 00   (AUTH_NONE)
Cred Length:    00 00 00 00
Verf Flavor:    00 00 00 00   (AUTH_NONE)
Verf Length:    00 00 00 00
```

Total: 4 + 40 = 44 bytes

---

## Next Steps for Claude Code

1. Create the Rust project structure
2. Implement XDR encoding primitives
3. Build RPC header construction
4. Implement NFSv3 NULL procedure first
5. Add LOOKUP, GETATTR, FSINFO
6. Create mutation engine
7. Add connection management with reconnect
8. Implement result logging
9. Add NFSv4 COMPOUND support
10. Build ASAN monitoring integration

Start with `cargo new nfs-fuzzer` and work through each module incrementally, testing against nfs-ganesha in a local container.
