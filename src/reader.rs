use std::{cmp, io::Read, mem, ptr};

use anyhow::{bail, Result};

/// Fast buffer reader never removing read data from its internal buffer. It
/// does not offer traditional accessors from io::Read and instead returns
/// structured data references to its inner buffer, saving a copy.
pub(crate) struct ReaderBuf<R: Read> {
    /// Inner reader, implementing io::Read.
    inner: R,
    /// Inner buffer, holding the data (both already read + buffered).
    buffer: Vec<u8>,
    /// Cursor keeping track of already read data in the buffer.
    cursor: usize,
    /// Minimum length to read from the inner reader when filling the inner
    /// buffer. Low values might impact performances when the data is not
    /// already mapped into memory.
    min_read: usize,
}

impl<R: Read> ReaderBuf<R> {
    /// Create a new ReaderBuf with default values.
    ///
    /// Warning: min_read is initialized to 0.
    #[allow(dead_code)]
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            buffer: Vec::new(),
            cursor: 0,
            min_read: 0,
        }
    }

    /// Create a new ReaderBuf with default values and with an explicit inner
    /// buffer capacity.
    ///
    /// Warning: min_read is initialized to 0.
    #[allow(dead_code)]
    pub(crate) fn with_capacity(capacity: usize, inner: R) -> Self {
        Self {
            inner,
            buffer: Vec::with_capacity(capacity),
            cursor: 0,
            min_read: 0,
        }
    }

    /// Unwraps the inner reader.
    pub(crate) fn into_inner(self) -> R {
        let inner = unsafe { ptr::read(&self.inner) };
        mem::forget(self);
        inner
    }

    /// Get a reference to the inner reader.
    #[allow(dead_code)]
    pub(crate) fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Get a mutable reference to the inner reader.
    pub(crate) fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Set the minimum length to read from the inner reader when filling the
    /// inner buffer (min_read).
    pub(crate) fn set_min_read(&mut self, len: usize) {
        self.min_read = len;
    }

    /// Returns a reference to the start of the inner buffer.
    pub(crate) fn buf(&self) -> &[u8] {
        &self.buffer
    }

    /// Read at most `len` bytes (advancing the inner cursor and filling the
    /// inner buffer if needed) and returns a pointer to a byte array to access
    /// the data read).
    pub(crate) fn read(&mut self, len: usize) -> Result<&[u8]> {
        let diff = len.saturating_sub(self.headlen());
        let len = match diff {
            x if x > 0 => {
                let read = self.fill_buffer(diff)?;
                // read could be > diff, if diff < self.min_read.
                len - diff.saturating_sub(read)
            }
            // diff == 0.
            _ => len,
        };

        let ptr = &self.buffer[self.cursor..(self.cursor + len)];
        self.cursor += len;

        Ok(ptr)
    }

    /// Read `len` bytes (advancing the inner cursor and filling the inner
    /// buffer if needed) and returns a pointer to a byte array to access the
    /// data read.
    ///
    /// Returns an error if not enough data could be read.
    pub(crate) fn read_exact(&mut self, len: usize) -> Result<&[u8]> {
        let diff = len.saturating_sub(self.headlen());
        if diff > 0 {
            self.fill_buffer_exact(diff)?;
        }

        let ptr = &self.buffer[self.cursor..(self.cursor + len)];
        self.cursor += len;

        Ok(ptr)
    }

    /// Read `mem::size_of::<T>()` bytes (advancing the inner cursor and filling
    /// the inner buffer if needed) and returns a pointer to a structured type
    /// `T` to access the data read.
    ///
    /// Returns an error if not enough data could be read.
    pub(crate) fn read_as<T>(&mut self) -> Result<&T> {
        let diff = mem::size_of::<T>().saturating_sub(self.headlen());
        if diff > 0 {
            self.fill_buffer_exact(diff)?;
        }

        let ptr: &T = unsafe { mem::transmute(&self.buffer[self.cursor]) };
        self.cursor += mem::size_of::<T>();

        Ok(ptr)
    }

    /// Length of the inner buffer, aka. read + unread data.
    pub(crate) fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Length of the head in the inner buffer, aka. unread data.
    fn headlen(&self) -> usize {
        self.len() - self.cursor
    }

    /// Read at least `requested_len` bytes to the internal buffer an return how
    /// many bytes were read.
    fn fill_buffer(&mut self, requested_len: usize) -> Result<usize> {
        // Compute how much we'd like to read.
        let len = cmp::max(requested_len, self.min_read);
        let end = self.len();

        // Resize the internal buffer to accept the additional data.
        self.buffer.resize(self.buffer.len() + len, 0);

        // Try to read `len` bytes.
        let read = match self.inner.read(&mut self.buffer[end..]) {
            Ok(read) => read,
            Err(e) => {
                match e.kind() {
                    // Special case if the read would block. This means we can't
                    // read data right now, so just report that.
                    std::io::ErrorKind::WouldBlock => return Ok(0),
                    _ => return Err(e.into()),
                }
            }
        };

        // If we read less than requested, truncate the internal buffer. This is
        // mandatory as the previous `resize()` call also modified the buffer
        // length.
        let diff = len.saturating_sub(read);
        if diff > 0 {
            self.buffer.truncate(self.buffer.len() - diff);
        }

        Ok(read)
    }

    /// Read `requested_len` bytes to the internal buffer an return an error if
    /// the underlying reader couldn't provide the requested read lenght.
    fn fill_buffer_exact(&mut self, len: usize) -> Result<()> {
        let read = self.fill_buffer(len)?;
        if read < len {
            bail!("Could not read enough data from the inner reader");
        }
        Ok(())
    }
}

impl<R: Read + Clone> Clone for ReaderBuf<R> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            buffer: self.buffer.clone(),
            cursor: self.cursor,
            min_read: self.min_read,
        }
    }
}

#[cfg(test)]
impl<'a> ReaderBuf<&'a [u8]> {
    /// Creates a new ReaderBuf from a byte array, for testing purposes.
    pub(crate) fn from_bytes(bytes: &'a [u8]) -> Self {
        Self {
            inner: bytes,
            buffer: Vec::new(),
            cursor: 0,
            min_read: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ReaderBuf as B;

    #[test]
    fn reader() {
        let data: Vec<u8> = (1..=30).collect();
        let mut rb = B::from_bytes(&data);

        // We haven't read anything yet.
        assert_eq!(rb.buf(), &[] as &[u8]);

        // Reading 3 bytes using read_exact.
        assert_eq!(rb.read_exact(3).unwrap(), &(1..=3).collect::<Vec<u8>>());
        assert_eq!(rb.buf(), &(1..=3).collect::<Vec<u8>>());

        // Reading 7 bytes using read.
        assert_eq!(rb.read(7).unwrap(), &(4..=10).collect::<Vec<u8>>());
        assert_eq!(rb.buf(), &(1..=10).collect::<Vec<u8>>());

        // Setting min read.
        rb.set_min_read(12);
        assert_eq!(rb.read(5).unwrap(), &(11..=15).collect::<Vec<u8>>());
        assert_eq!(rb.buf(), &(1..=22).collect::<Vec<u8>>());

        // Read should still be within the buffered data.
        assert_eq!(rb.read(7).unwrap(), &(16..=22).collect::<Vec<u8>>());
        assert_eq!(rb.buf(), &(1..=22).collect::<Vec<u8>>());

        // Trying to read more than the available data (7 bytes left).
        assert_eq!(rb.read(10).unwrap(), &(23..=30).collect::<Vec<u8>>());
        assert_eq!(rb.buf(), &(1..=30).collect::<Vec<u8>>());

        // No data left.
        assert_eq!(rb.read(1).unwrap(), &[] as &[u8]);
        assert!(rb.read_exact(1).is_err());
    }

    #[test]
    fn exact_read_and_min_sz() {
        let data: Vec<u8> = (1..=5).collect();
        let mut rb = B::from_bytes(&data);
        rb.set_min_read(12);

        // Even though the min read size is > 5, we only want an error if the
        // exact read size cannot be read.
        assert_eq!(rb.read_exact(5).unwrap(), &(1..=5).collect::<Vec<u8>>());

        // Now it can fail.
        assert!(rb.read_exact(1).is_err());
    }
}
