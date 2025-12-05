//! XDR (External Data Representation) encoding primitives
//! 
//! RFC 4506 defines XDR, used by Sun RPC and NFS.
//! All integers are big-endian, all data is padded to 4-byte boundaries.

use bytes::{BufMut, BytesMut};

/// Calculate padding needed to align to 4-byte boundary
#[inline]
pub fn xdr_pad_len(len: usize) -> usize {
    (4 - (len % 4)) % 4
}

/// XDR encoder - builds wire-format data
pub struct XdrEncoder {
    buf: BytesMut,
}

impl XdrEncoder {
    pub fn new() -> Self {
        Self {
            buf: BytesMut::with_capacity(1024),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(capacity),
        }
    }

    /// Encode a 32-bit unsigned integer
    pub fn put_u32(&mut self, value: u32) {
        self.buf.put_u32(value); // bytes crate uses big-endian by default for put_u32
    }

    /// Encode a 32-bit signed integer
    pub fn put_i32(&mut self, value: i32) {
        self.buf.put_i32(value);
    }

    /// Encode a 64-bit unsigned integer (hyper)
    pub fn put_u64(&mut self, value: u64) {
        self.buf.put_u64(value);
    }

    /// Encode a 64-bit signed integer
    pub fn put_i64(&mut self, value: i64) {
        self.buf.put_i64(value);
    }

    /// Encode a boolean as XDR (0 or 1, 4 bytes)
    pub fn put_bool(&mut self, value: bool) {
        self.put_u32(if value { 1 } else { 0 });
    }

    /// Encode opaque data (fixed length, with padding)
    pub fn put_opaque_fixed(&mut self, data: &[u8]) {
        self.buf.put_slice(data);
        let pad = xdr_pad_len(data.len());
        for _ in 0..pad {
            self.buf.put_u8(0);
        }
    }

    /// Encode opaque data (variable length: 4-byte length + data + padding)
    pub fn put_opaque(&mut self, data: &[u8]) {
        self.put_u32(data.len() as u32);
        self.put_opaque_fixed(data);
    }

    /// Encode a string (same as variable-length opaque)
    pub fn put_string(&mut self, s: &str) {
        self.put_opaque(s.as_bytes());
    }

    /// Encode raw bytes without any XDR wrapping (for pre-encoded data)
    pub fn put_raw(&mut self, data: &[u8]) {
        self.buf.put_slice(data);
    }

    /// Reserve space for a value to be filled in later (returns offset)
    pub fn reserve_u32(&mut self) -> usize {
        let offset = self.buf.len();
        self.put_u32(0);
        offset
    }

    /// Fill in a previously reserved u32 value
    pub fn fill_u32(&mut self, offset: usize, value: u32) {
        let bytes = value.to_be_bytes();
        self.buf[offset..offset + 4].copy_from_slice(&bytes);
    }

    /// Get the current length of encoded data
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Consume encoder and return the buffer
    pub fn into_bytes(self) -> BytesMut {
        self.buf
    }

    /// Get a reference to the buffer
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
}

impl Default for XdrEncoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_len() {
        assert_eq!(xdr_pad_len(0), 0);
        assert_eq!(xdr_pad_len(1), 3);
        assert_eq!(xdr_pad_len(2), 2);
        assert_eq!(xdr_pad_len(3), 1);
        assert_eq!(xdr_pad_len(4), 0);
        assert_eq!(xdr_pad_len(5), 3);
    }

    #[test]
    fn test_u32() {
        let mut enc = XdrEncoder::new();
        enc.put_u32(0x12345678);
        assert_eq!(enc.as_bytes(), &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_string() {
        let mut enc = XdrEncoder::new();
        enc.put_string("foo");
        // Length (3) + "foo" + 1 byte padding
        assert_eq!(enc.as_bytes(), &[0, 0, 0, 3, b'f', b'o', b'o', 0]);
    }

    #[test]
    fn test_opaque_padding() {
        let mut enc = XdrEncoder::new();
        enc.put_opaque(&[1, 2, 3, 4, 5]); // 5 bytes needs 3 padding
        assert_eq!(enc.len(), 4 + 5 + 3); // length + data + padding = 12
    }
}
