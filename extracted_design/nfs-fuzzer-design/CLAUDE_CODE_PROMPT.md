# NFS Fuzzer Project - Claude Code Instructions

## Project Goal

Build an NFS v3/v4 protocol fuzzer in Rust. The fuzzer should send malformed NFS packets to discover vulnerabilities in NFS server implementations.

## Key Documents

Read `NFS_FUZZER_DESIGN.md` thoroughly before starting. It contains:
- Complete protocol specification for NFS over Sun RPC
- XDR encoding rules
- All NFSv3 and NFSv4 procedure definitions
- Test target setup (nfs-ganesha, Linux NFSD)
- Mutation strategies

## Implementation Order

### Phase 1: Foundation
1. Create project: `cargo new nfs-fuzzer`
2. Add dependencies to Cargo.toml:
   ```toml
   [dependencies]
   tokio = { version = "1", features = ["full"] }
   bytes = "1"
   rand = "0.8"
   clap = { version = "4", features = ["derive"] }
   thiserror = "1"
   tracing = "0.1"
   tracing-subscriber = "0.3"
   ```
3. Implement `src/xdr.rs` - XDR encoding primitives (see design doc)
4. Implement `src/rpc.rs` - RPC CALL message construction

### Phase 2: NFSv3 Procedures
5. Implement `src/nfsv3.rs`:
   - NULL procedure (test connectivity)
   - GETATTR (with fuzzable file handle)
   - LOOKUP (directory handle + filename)
   - FSINFO, FSSTAT
6. Implement `src/mount.rs` for obtaining real file handles

### Phase 3: Fuzzing Logic
7. Implement `src/mutations.rs`:
   - Length field mutations (0, huge, off-by-one)
   - String mutations (long, nulls, binary)
   - Integer mutations (negative, MAX, overflow)
8. Implement `src/connection.rs`:
   - TCP connection with reconnect on failure
   - Response parsing (at least enough to detect errors)
9. Wire it all together in `src/main.rs`

### Phase 4: NFSv4 (Optional Extension)
10. Implement `src/nfsv4.rs`:
    - COMPOUND operation wrapper
    - PUTROOTFH, LOOKUP, GETATTR operations
    - Session establishment (SETCLIENTID etc.)

## Code Quality Requirements

- All network integers must be big-endian (use `to_be_bytes()`)
- All XDR data must be padded to 4-byte boundaries
- Handle connection failures gracefully (reconnect and continue)
- Log every sent packet for reproducibility
- Include unit tests for XDR encoding

## Testing

Test against nfs-ganesha running locally:
```bash
# In one terminal
docker run --rm -it -p 2049:2049 \
  -v /tmp/nfs-export:/export \
  --cap-add SYS_ADMIN \
  erichough/nfs-server

# In another terminal
cargo run -- --target 127.0.0.1 --port 2049
```

## Important Notes

- **Never** run against production systems
- Start with NULL procedure to verify connectivity
- Record mark length calculation is critical - get this right first
- AUTH_NONE is sufficient for initial fuzzing
- The file handle format varies by server - start with random bytes

## Example Minimal Packet

The design doc has a hex dump of a minimal NULL procedure packet. Use this to verify your RPC header construction is correct before moving to fuzzing.
