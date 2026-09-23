//! The byte format shared with the Dart side.
//!
//! Everything crossing the FFI boundary is a flat, little-endian, length-prefixed
//! blob. There is no JSON and no base64: keys and ciphertext are already bytes, and
//! re-encoding them would cost more than the format saves.
//!
//! Two shapes are used:
//!   * a *field list* — `u32 count`, then `u32 tag, u32 len, bytes` per field.
//!     Used for anything with a fixed schema, like a prekey bundle.
//!   * a *record list* — `u32 count`, then `u32 kind, u32 key_len, key,
//!     u32 val_len, val` per record. `val_len == u32::MAX` means "deleted".
//!     Used for everything Dart has to persist.

/// `val_len` sentinel meaning the row should be deleted rather than written.
pub const TOMBSTONE: u32 = u32::MAX;

pub struct Writer {
    buf: Vec<u8>,
    count: u32,
}

impl Writer {
    pub fn new() -> Self {
        // Leave room for the count, which is only known at the end.
        Self {
            buf: vec![0, 0, 0, 0],
            count: 0,
        }
    }

    pub fn field(&mut self, tag: u32, value: &[u8]) {
        self.buf.extend_from_slice(&tag.to_le_bytes());
        self.buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(value);
        self.count += 1;
    }

    pub fn field_u32(&mut self, tag: u32, value: u32) {
        self.field(tag, &value.to_le_bytes());
    }

    pub fn record(&mut self, kind: u32, key: &[u8], value: Option<&[u8]>) {
        self.buf.extend_from_slice(&kind.to_le_bytes());
        self.buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(key);
        match value {
            Some(value) => {
                self.buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
                self.buf.extend_from_slice(value);
            }
            None => self.buf.extend_from_slice(&TOMBSTONE.to_le_bytes()),
        }
        self.count += 1;
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.buf[..4].copy_from_slice(&self.count.to_le_bytes());
        self.buf
    }
}

pub struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, String> {
        if data.len() < 4 {
            return Err("truncated frame: missing count".into());
        }
        Ok(Self { data, at: 4 })
    }

    pub fn count(&self) -> u32 {
        u32::from_le_bytes(self.data[..4].try_into().expect("checked in new"))
    }

    fn u32(&mut self) -> Result<u32, String> {
        let end = self.at + 4;
        if end > self.data.len() {
            return Err("truncated frame: expected a length".into());
        }
        let value = u32::from_le_bytes(self.data[self.at..end].try_into().expect("4 bytes"));
        self.at = end;
        Ok(value)
    }

    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let len = self.u32()? as usize;
        let end = self.at + len;
        if end > self.data.len() {
            return Err("truncated frame: value runs past the end".into());
        }
        let value = &self.data[self.at..end];
        self.at = end;
        Ok(value)
    }

    /// Read the next field as `(tag, value)`.
    pub fn field(&mut self) -> Result<(u32, &'a [u8]), String> {
        let tag = self.u32()?;
        Ok((tag, self.bytes()?))
    }

    /// Read the next record as `(kind, key, value)`, where `None` is a tombstone.
    #[allow(dead_code)] // the record reader lives on the Dart side; kept for symmetry
    pub fn record(&mut self) -> Result<(u32, &'a [u8], Option<&'a [u8]>), String> {
        let kind = self.u32()?;
        let key = self.bytes()?;
        let len = self.u32()?;
        if len == TOMBSTONE {
            return Ok((kind, key, None));
        }
        let end = self.at + len as usize;
        if end > self.data.len() {
            return Err("truncated frame: record value runs past the end".into());
        }
        let value = &self.data[self.at..end];
        self.at = end;
        Ok((kind, key, Some(value)))
    }
}

/// Read a field list into `(tag, value)` pairs.
pub fn fields(data: &[u8]) -> Result<Vec<(u32, &[u8])>, String> {
    let mut reader = Reader::new(data)?;
    let count = reader.count();
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        out.push(reader.field()?);
    }
    Ok(out)
}

pub fn u32_field(value: &[u8]) -> Result<u32, String> {
    if value.len() != 4 {
        return Err(format!("expected a 4-byte number, got {} bytes", value.len()));
    }
    Ok(u32::from_le_bytes(value.try_into().expect("4 bytes")))
}
