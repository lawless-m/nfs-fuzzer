//! Sun RPC (ONC RPC) message construction
//! 
//! RFC 5531 defines the RPC protocol used by NFS.

use crate::xdr::XdrEncoder;
use bytes::BytesMut;
use std::sync::atomic::{AtomicU32, Ordering};

// Global XID counter for unique transaction IDs
static XID_COUNTER: AtomicU32 = AtomicU32::new(1);

/// Generate a unique transaction ID
pub fn next_xid() -> u32 {
    XID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// RPC message types
pub mod msg_type {
    pub const CALL: u32 = 0;
    pub const REPLY: u32 = 1;
}

/// RPC program numbers
pub mod program {
    pub const PORTMAP: u32 = 100000;
    pub const NFS: u32 = 100003;
    pub const MOUNT: u32 = 100005;
}

/// RPC version (always 2 for current RPC)
pub const RPC_VERSION: u32 = 2;

/// Authentication flavours
pub mod auth_flavor {
    pub const AUTH_NONE: u32 = 0;
    pub const AUTH_SYS: u32 = 1;  // Unix-style auth
    pub const AUTH_SHORT: u32 = 2;
    pub const AUTH_DES: u32 = 3;
    pub const RPCSEC_GSS: u32 = 6;
}

/// Build AUTH_NONE credentials (no authentication)
pub fn auth_none() -> Vec<u8> {
    let mut enc = XdrEncoder::new();
    enc.put_u32(auth_flavor::AUTH_NONE);
    enc.put_u32(0); // length = 0
    enc.into_bytes().to_vec()
}

/// Build AUTH_SYS credentials (Unix-style UID/GID)
pub fn auth_sys(machine_name: &str, uid: u32, gid: u32, gids: &[u32]) -> Vec<u8> {
    // First encode the auth body
    let mut body = XdrEncoder::new();
    body.put_u32(0); // stamp (arbitrary)
    body.put_string(machine_name);
    body.put_u32(uid);
    body.put_u32(gid);
    body.put_u32(gids.len() as u32);
    for &g in gids {
        body.put_u32(g);
    }
    
    // Now wrap with flavor and length
    let mut enc = XdrEncoder::new();
    enc.put_u32(auth_flavor::AUTH_SYS);
    enc.put_u32(body.len() as u32);
    enc.put_raw(body.as_bytes());
    
    enc.into_bytes().to_vec()
}

/// RPC CALL message builder
pub struct RpcCall {
    enc: XdrEncoder,
    record_mark_offset: Option<usize>,
    body_start: usize,
}

impl RpcCall {
    /// Create a new RPC CALL message
    /// 
    /// If `include_record_mark` is true, prepends TCP record marking header
    pub fn new(
        xid: u32,
        program: u32,
        version: u32,
        procedure: u32,
        include_record_mark: bool,
    ) -> Self {
        let mut enc = XdrEncoder::with_capacity(512);
        
        // TCP record mark (will be filled in at the end)
        let record_mark_offset = if include_record_mark {
            Some(enc.reserve_u32())
        } else {
            None
        };
        
        let body_start = enc.len();
        
        // RPC header
        enc.put_u32(xid);
        enc.put_u32(msg_type::CALL);
        enc.put_u32(RPC_VERSION);
        enc.put_u32(program);
        enc.put_u32(version);
        enc.put_u32(procedure);
        
        Self {
            enc,
            record_mark_offset,
            body_start,
        }
    }

    /// Add authentication credentials
    pub fn with_auth(mut self, cred: &[u8], verf: &[u8]) -> Self {
        self.enc.put_raw(cred);
        self.enc.put_raw(verf);
        self
    }

    /// Add AUTH_NONE for both credentials and verifier
    pub fn with_auth_none(self) -> Self {
        let auth = auth_none();
        self.with_auth(&auth, &auth)
    }

    /// Add AUTH_SYS credentials with AUTH_NONE verifier
    pub fn with_auth_sys(self, machine: &str, uid: u32, gid: u32) -> Self {
        let cred = auth_sys(machine, uid, gid, &[]);
        let verf = auth_none();
        self.with_auth(&cred, &verf)
    }

    /// Add procedure-specific arguments (raw XDR-encoded data)
    pub fn with_args(mut self, args: &[u8]) -> Self {
        self.enc.put_raw(args);
        self
    }

    /// Access the encoder for adding custom data
    pub fn encoder(&mut self) -> &mut XdrEncoder {
        &mut self.enc
    }

    /// Finalize and return the complete message
    pub fn build(mut self) -> BytesMut {
        // Fill in record mark if present
        if let Some(offset) = self.record_mark_offset {
            let body_len = (self.enc.len() - self.body_start) as u32;
            // Set high bit (last fragment) and length
            let record_mark = 0x80000000 | body_len;
            self.enc.fill_u32(offset, record_mark);
        }
        
        self.enc.into_bytes()
    }
}

/// Helper to build a simple RPC call with no arguments
pub fn simple_rpc_call(
    program: u32,
    version: u32,
    procedure: u32,
) -> BytesMut {
    RpcCall::new(next_xid(), program, version, procedure, true)
        .with_auth_none()
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_nfs_null() {
        let msg = simple_rpc_call(program::NFS, 3, 0);
        
        // Should be: 4 (record mark) + 24 (header) + 8 (auth_none) + 8 (verf_none) = 44 bytes
        assert_eq!(msg.len(), 44);
        
        // Check record mark: 0x80000028 (last fragment, 40 bytes)
        assert_eq!(&msg[0..4], &[0x80, 0x00, 0x00, 0x28]);
        
        // Check program number (offset 16-19 in body, 20-23 overall)
        // 100003 = 0x000186A3
        assert_eq!(&msg[16..20], &[0x00, 0x01, 0x86, 0xA3]);
    }

    #[test]
    fn test_auth_sys() {
        let auth = auth_sys("fuzzer", 0, 0, &[]);
        
        // Flavor (4) + length (4) + stamp (4) + name_len (4) + "fuzzer" (6) + pad (2) + uid (4) + gid (4) + gid_count (4)
        // = 4 + 4 + 4 + 4 + 8 + 4 + 4 + 4 = 36 bytes
        assert_eq!(auth.len(), 36);
    }
}
