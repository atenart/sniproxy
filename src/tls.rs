use std::{
    io::{Read, Write},
    mem,
};

use anyhow::{Result, bail};

use crate::reader::ReaderBuf;

pub const RECORD_MAX_LEN: usize = 16 * 1024;

/// Main representation of a TLS connection. We do not parse all the fields and extensions, nor we
/// read all the data from it. This is mostly used to get to the extensions we care about so we can
/// make a decision on what to do with a new TLS connection.
#[derive(Default)]
pub(crate) struct Tls {
    /// Server name indication hostname, if found.
    sni_hostname: Option<String>,
    /// Is the ALPN extension
    alpn_is_challenge: bool,
}

impl Tls {
    pub(crate) fn from<R: Read>(reader: &mut ReaderBuf<R>) -> Result<Tls> {
        // Start by parsing the message up to the extensions.
        //
        // As soon as we know it's likely to be a TLS record, extend the reader
        // min read to match (MAX_TLS_LEN - RECORD_HDR_LEN).
        Self::parse_plaintext_record_header(reader)?;
        reader.set_min_read(RECORD_MAX_LEN - 5);
        Self::parse_handshake_header(reader)?;
        Self::parse_client_hello(reader)?;

        // Now we can access the extensions and see if we can find something interesting.
        let mut len = Self::read_vector_size(reader, 2)?;

        // No extension, which is valid.
        if len == 0 {
            return Ok(Tls::default());
        }

        // We have a len but it can't even hold the extension description.
        if len < 2 {
            bail!("Invalid extensions section length ({} < 2)", len);
        }

        // Loop while we have potential valid extension headers.
        // https://www.rfc-editor.org/rfc/rfc8446#section-4.2
        let mut tls = Tls::default();
        while len >= 4 {
            // Extension type: u16
            // Vector size:    u16
            let header = reader.read_as::<[u8; 4]>()?;
            len -= mem::size_of_val(header);

            let r#type = u16::from_be_bytes(header[0..=1].try_into()?);
            let size = u16::from_be_bytes(header[2..=3].try_into()?) as usize;

            // Check we can't go past the extension section.
            if size > len {
                bail!(
                    "Invalid extension: goes past the buffer len ({} > {})",
                    size,
                    len
                );
            }

            // Extension is empty, can happen e.g. on session_ticket
            if size == 0 {
                continue;
            }

            // Read the extension data. Even if we do not support the extension, we can't seek as
            // we need to replay the TLS message.
            let extension = reader.read_exact(size)?;
            len -= size;

            // Specific handling depending on the extension type.
            match r#type {
                // Server name indication.
                0 => tls.sni_hostname = Some(Self::sni_ext_get_hostname(extension)?),
                // Application layer protocol negotiation.
                16 => tls.alpn_is_challenge = Self::alpn_ext_is_challenge(extension)?,
                _ => (),
            }
        }

        Ok(tls)
    }

    /// Parse a TLS plaintext record header.
    /// https://www.rfc-editor.org/rfc/rfc8446#section-5.1
    fn parse_plaintext_record_header<R: Read>(reader: &mut ReaderBuf<R>) -> Result<()> {
        // Record header:
        //   type:   u8
        //   major:  u8
        //   minor:  u8
        //   length: u16
        let record = reader.read_as::<[u8; 5]>()?;

        // Check if record type is 22, aka handshake.
        if record[0] != 22 {
            bail!("Record is not a TLS handshake.");
        }

        // Check the TLS version is supported.
        // 3.1: TLS 1.0, 3.2: TLS 1.1, 3.3: TLS 1.2 & TLS 1.3
        if record[1] != 3 || (record[2] < 1 || record[2] > 3) {
            bail!("TLS version not supported: {}.{}.", record[1], record[2]);
        }

        // Check the length does not exceed the maximum authorized.
        if u16::from_be_bytes(record[3..=4].try_into()?) > RECORD_MAX_LEN as u16 {
            bail!("TLS record length exceed the maximum authorized.");
        }

        Ok(())
    }

    /// Parse a TLS handshake header.
    /// https://www.rfc-editor.org/rfc/rfc8446#section-4
    fn parse_handshake_header<R: Read>(reader: &mut ReaderBuf<R>) -> Result<()> {
        // Handshake header:
        //   Message Type: u8
        //   Message Len:  [u8; 3]
        let handshake = reader.read_as::<[u8; 4]>()?;

        // Check we're dealing with a ClientHello message.
        if handshake[0] != 1 {
            bail!(
                "TLS handshake is not a ClientHello message ({})",
                handshake[0]
            );
        }

        // We're not checking the length here as we'll try to read it anyway.

        Ok(())
    }

    /// Parse a TLS client hello message up to the extensions section.
    /// https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2
    ///
    /// CLientHello header:
    ///   Version:      u16
    ///   Random bytes: [u8; 32]
    ///   Session id:
    ///   Cipher suite:
    ///   Compression method:
    ///   Extensions:
    fn parse_client_hello<R: Read>(reader: &mut ReaderBuf<R>) -> Result<()> {
        // Start by parsing the two first fields (version & random) as they have a fixed length,
        // which is not true for later fields.
        let hello = reader.read_as::<[u8; 34]>()?;

        // Check the version. 0x301: TLS 1.0, 0x302: TLS 1.1, 0x303: >= TLS 1.2.
        match u16::from_be_bytes(hello[0..=1].try_into()?) {
            0x301..=0x303 => (),
            x => bail!("Invalid client version in ClientHello ({:#x})", x),
        }

        // Read the session id.
        let len = Self::read_vector(reader, 1)?.len();
        if len > 32 {
            bail!("Session id has an invalid length ({} > 32)", len);
        }

        // Read the cipher suites.
        let len = Self::read_vector(reader, 2)?.len();
        if len < 2 {
            bail!("Cipher suites length is too small ({} < 2)", len);
        } else if len % 2 != 0 {
            bail!("Cipher suites length is invalid ({} % 2 != 0)", len);
        }

        // Read the compression methods.
        let len = Self::read_vector(reader, 1)?.len();
        if len < 1 {
            bail!("Compression methods length is too small ({} < 1)", len);
        }

        // We reached the extensions (or none, which is also valid).
        Ok(())
    }

    /// Parse and read a vector size field. Takes the length of the field size as a parameter.
    fn read_vector_size<R: Read>(reader: &mut ReaderBuf<R>, len: usize) -> Result<usize> {
        Ok(match len {
            1 => *reader.read_as::<u8>()? as usize,
            2 => {
                let size = reader.read_as::<[u8; 2]>()?;
                u16::from_be_bytes(*size) as usize
            }
            x => bail!("Vector length unsupported ({})", x),
        })
    }

    /// Parse the server name indication extension, look for an host name and return it if found.
    /// https://www.rfc-editor.org/rfc/rfc6066#section-3
    fn sni_ext_get_hostname(ext: &[u8]) -> Result<String> {
        let buf_len = ext.len();

        // No need to go further if we can't even read the field size below.
        if buf_len < 2 {
            bail!("SNI extension len is too small ({} < 2)", buf_len);
        }

        // Retrieve the size of the extension and take into account the len field itself.
        let len = u16::from_be_bytes(ext[0..=1].try_into()?) as usize + mem::size_of::<u16>();
        // We read the extension size above, initialize the cursor to go past it.
        let mut cursor = mem::size_of::<u16>();

        // Check the buffer we are working on matches the size it contains.
        if len != buf_len {
            bail!(
                "SNI extension len does not match the buffer one ({} != {})",
                len,
                buf_len
            );
        }

        // Go through the names as defined in RFC 6066. Only name type 0 is valid for now and the
        // RFC states "The ServerNameList MUST NOT contain more than one name of the same
        // name_type". Because of this we're taking a shortcut below and do not actually loop
        // through the names.
        //
        // https://www.rfc-editor.org/rfc/rfc6066#section-3

        // Check we won't go past the buffer.
        if cursor + mem::size_of::<u8>() /* type */ + mem::size_of::<u16>() /* size */ > len {
            bail!("Reached the end of the SNI extension buffer while processing");
        }

        // First parse the name type.
        let r#type = ext[cursor];
        cursor += mem::size_of::<u8>();

        // Then its size.
        let size = u16::from_be_bytes(ext[cursor..(cursor + 2)].try_into()?) as usize;
        cursor += mem::size_of::<u16>();

        // Only type 0 (host name) is valid so far.
        if r#type != 0 {
            bail!("Unknown name type in the SNI extension ({})", r#type);
        }

        // Check we won't go past the buffer.
        if cursor + size > len {
            bail!("Reached the end of the SNI extension buffer while processing");
        }

        // As only one name type is allowed and only one name per type can be found, check we
        // reached the end of the buffer.
        if cursor + size != len {
            bail!("SNI extension has more than one name");
        }

        // Finally retrieve the SNI.
        Ok(String::from_utf8(ext[cursor..(cursor + size)].into())?)
    }

    /// Parse the ALPN extension, look for TLS challenge strings and return true if found.
    ///
    /// https://www.rfc-editor.org/rfc/rfc8737
    fn alpn_ext_is_challenge(ext: &[u8]) -> Result<bool> {
        let buf_len = ext.len();

        // No need to go further if we can't even read the field size below.
        if buf_len < 2 {
            bail!("ALPN extension len is too small ({} < 2)", buf_len);
        }

        // Retrieve the size of the extension and take into account the len field itself.
        let len = u16::from_be_bytes(ext[0..=1].try_into()?) as usize + mem::size_of::<u16>();
        // We read the extension size above, initialize the cursor to go past it.
        let mut cursor = mem::size_of::<u16>();

        // Check the buffer we are working on matches the size it contains.
        if len != buf_len {
            bail!(
                "ALPN extension len does not match the buffer one ({} != {})",
                len,
                buf_len
            );
        }

        // Go through the protocol names as defined in RFC7301.
        //
        // We're not looping through the names below and instead look for the first valid one.
        // We're taking this shortcut as RFC8737 explicitly states "the ACME server MUST provide
        // an ALPN extension with the single protocol name 'acme-tls/1'".
        //
        // https://datatracker.ietf.org/doc/html/rfc7301#section-3.1
        // https://www.rfc-editor.org/rfc/rfc8737#section-3

        // Check we won't go past the buffer.
        if cursor + mem::size_of::<u8>() /* size */ > len {
            bail!("Reached the end of the ALPN extension buffer while processing");
        }

        // First parse the name string size.
        let size = ext[cursor] as usize;
        cursor += mem::size_of::<u8>();

        // Check we won't go past the buffer.
        if cursor + size > len {
            println!("{cursor} + {size} > {len}");
            bail!("Reached the end of the ALPN extension buffer while processing");
        }

        // Finally retrieve the protocol name.
        let name = String::from_utf8(ext[cursor..(cursor + size)].into())?;
        cursor += size;

        // Check if the protocol name is for tls-alpn-01 and is the only protocol listed in the
        // extension. https://www.rfc-editor.org/rfc/rfc8737#section-3
        if cursor == len && name == "acme-tls/1" {
            return Ok(true);
        }

        Ok(false)
    }

    /// Parse and read a vector, and return a Vec<u8> with its data. Takes the length of the field
    /// size as a parameter.
    fn read_vector<R: Read>(reader: &mut ReaderBuf<R>, len: usize) -> Result<Vec<u8>> {
        let size = Self::read_vector_size(reader, len)?;

        // Valid, can be checked for specific cases outside this helper.
        if size == 0 {
            return Ok(Vec::new());
        }

        // Finally read the vector data.
        Ok(reader.read_exact(size)?.to_vec())
    }

    /// Get the hostname we read from the SNI extension, if any. None is a valid valid regarding the
    /// TLS spec.
    pub(crate) fn hostname(&self) -> Option<&String> {
        self.sni_hostname.as_ref()
    }

    /// Check if the ALPN extension was a valid tls-alpn-01 challenge, if any.
    pub(crate) fn is_challenge(&self) -> bool {
        self.alpn_is_challenge
    }
}

/// https://www.rfc-editor.org/rfc/rfc8446#section-6
pub(crate) enum AlertDescription {
    AccessDenied = 49,
    InternalError = 80,
    UnrecognizedName = 112,
}

/// Send a fatal alert message with the provided desc code to the remote end.
pub(crate) fn alert<T: Write>(writer: &mut T, desc: AlertDescription) -> Result<()> {
    // Send back a crafted alert message.
    // https://www.rfc-editor.org/rfc/rfc8446#section-5.1
    // https://www.rfc-editor.org/rfc/rfc8446#section-6
    //
    // - Content type: 21
    // - TLS version: 3.x
    // - Length: 2
    // - Level: 2 (fatal)
    // - Desc.
    writer.write_all(&[21, 3, 0, 0, 2, 2, desc as u8])?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::reader::ReaderBuf as B;

    // Valid record, including an SNI but no ALPN extension.
    pub(crate) const RECORD_SNI: &[u8] = &[
        22, 3, 1, 1, 54, 1, 0, 1, 50, 3, 3, 203, 69, 166, 24, 168, 5, 235, 3, 40, 94, 250, 34, 63,
        198, 156, 194, 25, 13, 0, 80, 200, 213, 125, 74, 215, 165, 193, 219, 143, 84, 201, 35, 32,
        232, 149, 249, 110, 18, 24, 36, 194, 152, 145, 10, 139, 7, 175, 172, 173, 61, 56, 71, 185,
        191, 71, 213, 156, 229, 62, 54, 91, 75, 253, 9, 104, 0, 72, 19, 2, 19, 3, 19, 1, 19, 4,
        192, 44, 192, 48, 204, 169, 204, 168, 192, 173, 192, 43, 192, 47, 192, 172, 192, 35, 192,
        39, 192, 10, 192, 20, 192, 9, 192, 19, 0, 157, 192, 157, 0, 156, 192, 156, 0, 61, 0, 60, 0,
        53, 0, 47, 0, 159, 204, 170, 192, 159, 0, 158, 192, 158, 0, 107, 0, 103, 0, 57, 0, 51, 0,
        255, 1, 0, 0, 161, 0, 0, 0, 16, 0, 14, 0, 0, 11, 101, 120, 97, 109, 112, 108, 101, 46, 110,
        101, 116, 0, 11, 0, 4, 3, 0, 1, 2, 0, 10, 0, 22, 0, 20, 0, 29, 0, 23, 0, 30, 0, 25, 0, 24,
        1, 0, 1, 1, 1, 2, 1, 3, 1, 4, 0, 35, 0, 0, 0, 22, 0, 0, 0, 23, 0, 0, 0, 13, 0, 34, 0, 32,
        4, 3, 5, 3, 6, 3, 8, 7, 8, 8, 8, 9, 8, 10, 8, 11, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1, 3, 3,
        3, 1, 0, 43, 0, 5, 4, 3, 4, 3, 3, 0, 45, 0, 2, 1, 1, 0, 51, 0, 38, 0, 36, 0, 29, 0, 32,
        240, 147, 220, 154, 241, 161, 127, 109, 148, 66, 113, 35, 83, 38, 72, 28, 160, 33, 215,
        192, 53, 121, 246, 185, 203, 110, 197, 32, 128, 254, 152, 97,
    ];

    // Valid record, including an SNI and an ALPN extension.
    pub(crate) const RECORD_SNI_ALPN: &[u8] = &[
        22, 3, 1, 1, 71, 1, 0, 1, 67, 3, 3, 200, 84, 240, 198, 191, 79, 87, 134, 132, 184, 32, 142,
        147, 79, 172, 138, 254, 33, 184, 196, 224, 73, 186, 162, 178, 28, 93, 80, 154, 180, 197,
        117, 32, 105, 182, 50, 2, 25, 6, 98, 98, 89, 78, 89, 134, 43, 34, 138, 16, 244, 31, 185,
        254, 246, 209, 12, 203, 31, 69, 37, 134, 237, 216, 165, 5, 0, 72, 19, 2, 19, 3, 19, 1, 19,
        4, 192, 44, 192, 48, 204, 169, 204, 168, 192, 173, 192, 43, 192, 47, 192, 172, 192, 35,
        192, 39, 192, 10, 192, 20, 192, 9, 192, 19, 0, 157, 192, 157, 0, 156, 192, 156, 0, 61, 0,
        60, 0, 53, 0, 47, 0, 159, 204, 170, 192, 159, 0, 158, 192, 158, 0, 107, 0, 103, 0, 57, 0,
        51, 0, 255, 1, 0, 0, 178, 0, 0, 0, 16, 0, 14, 0, 0, 11, 101, 120, 97, 109, 112, 108, 101,
        46, 110, 101, 116, 0, 11, 0, 4, 3, 0, 1, 2, 0, 10, 0, 22, 0, 20, 0, 29, 0, 23, 0, 30, 0,
        25, 0, 24, 1, 0, 1, 1, 1, 2, 1, 3, 1, 4, 0, 35, 0, 0, 0, 16, 0, 13, 0, 11, 10, 97, 99, 109,
        101, 45, 116, 108, 115, 47, 49, 0, 22, 0, 0, 0, 23, 0, 0, 0, 13, 0, 34, 0, 32, 4, 3, 5, 3,
        6, 3, 8, 7, 8, 8, 8, 9, 8, 10, 8, 11, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1, 3, 3, 3, 1, 0,
        43, 0, 5, 4, 3, 4, 3, 3, 0, 45, 0, 2, 1, 1, 0, 51, 0, 38, 0, 36, 0, 29, 0, 32, 205, 54,
        119, 60, 111, 182, 114, 106, 157, 109, 117, 208, 183, 128, 208, 86, 101, 69, 206, 87, 119,
        236, 20, 71, 211, 71, 215, 186, 239, 195, 3, 21,
    ];

    // Valid record, no extension.
    pub(crate) const RECORD_NO_EXT: &[u8] = &[
        22, 3, 1, 1, 34, 1, 0, 1, 30, 3, 3, 174, 236, 43, 233, 60, 1, 225, 235, 52, 225, 121, 90,
        72, 102, 153, 32, 127, 186, 243, 82, 5, 211, 126, 210, 140, 62, 55, 13, 105, 153, 87, 230,
        32, 242, 103, 97, 74, 54, 19, 236, 162, 139, 127, 239, 150, 191, 164, 241, 242, 223, 41,
        73, 93, 70, 173, 109, 216, 49, 64, 180, 72, 158, 82, 151, 159, 0, 72, 19, 2, 19, 3, 19, 1,
        19, 4, 192, 44, 192, 48, 204, 169, 204, 168, 192, 173, 192, 43, 192, 47, 192, 172, 192, 35,
        192, 39, 192, 10, 192, 20, 192, 9, 192, 19, 0, 157, 192, 157, 0, 156, 192, 156, 0, 61, 0,
        60, 0, 53, 0, 47, 0, 159, 204, 170, 192, 159, 0, 158, 192, 158, 0, 107, 0, 103, 0, 57, 0,
        51, 0, 255, 1, 0, 0, 141, 0, 11, 0, 4, 3, 0, 1, 2, 0, 10, 0, 22, 0, 20, 0, 29, 0, 23, 0,
        30, 0, 25, 0, 24, 1, 0, 1, 1, 1, 2, 1, 3, 1, 4, 0, 35, 0, 0, 0, 22, 0, 0, 0, 23, 0, 0, 0,
        13, 0, 34, 0, 32, 4, 3, 5, 3, 6, 3, 8, 7, 8, 8, 8, 9, 8, 10, 8, 11, 8, 4, 8, 5, 8, 6, 4, 1,
        5, 1, 6, 1, 3, 3, 3, 1, 0, 43, 0, 5, 4, 3, 4, 3, 3, 0, 45, 0, 2, 1, 1, 0, 51, 0, 38, 0, 36,
        0, 29, 0, 32, 87, 236, 148, 113, 132, 227, 66, 188, 129, 107, 224, 171, 174, 68, 70, 34,
        200, 235, 65, 252, 62, 213, 12, 28, 115, 126, 46, 52, 72, 108, 158, 10,
    ];

    #[test]
    fn vector() {
        // Valid vectors with no data.
        assert!(Tls::read_vector(&mut B::from_bytes(&[0]), 1).is_ok());
        assert!(Tls::read_vector(&mut B::from_bytes(&[0, 0]), 2).is_ok());

        // Valid vectors with data.
        assert!(Tls::read_vector(&mut B::from_bytes(&[1, 42]), 1).is_ok());
        assert!(Tls::read_vector(&mut B::from_bytes(&[5, 42, 0, 10, 255, 3]), 1).is_ok());
        let vector = [vec![255], vec![42; 255]].concat();
        assert!(Tls::read_vector(&mut B::from_bytes(&vector), 1).is_ok());
        assert!(Tls::read_vector(&mut B::from_bytes(&[0, 1, 42]), 2).is_ok());
        assert!(Tls::read_vector(&mut B::from_bytes(&[0, 3, 42, 13, 37]), 2).is_ok());
        let vector = [vec![1, 0], vec![10; 256]].concat();
        assert!(Tls::read_vector(&mut B::from_bytes(&vector), 2).is_ok());
        let vector = [vec![255, 255], vec![99; 255 << 16 | 255]].concat();
        assert!(Tls::read_vector(&mut B::from_bytes(&vector), 2).is_ok());

        // Empty vectors.
        assert!(Tls::read_vector(&mut B::from_bytes(&[]), 1).is_err());
        assert!(Tls::read_vector(&mut B::from_bytes(&[]), 2).is_err());

        // Vectors too small.
        assert!(Tls::read_vector(&mut B::from_bytes(&[0]), 2).is_err());
        assert!(Tls::read_vector(&mut B::from_bytes(&[1]), 1).is_err());
        assert!(Tls::read_vector(&mut B::from_bytes(&[2, 0]), 1).is_err());
        assert!(Tls::read_vector(&mut B::from_bytes(&[255, 0]), 1).is_err());
        assert!(Tls::read_vector(&mut B::from_bytes(&[0, 1]), 2).is_err());
        assert!(Tls::read_vector(&mut B::from_bytes(&[0, 3, 0, 0]), 2).is_err());
        assert!(Tls::read_vector(&mut B::from_bytes(&[255, 255, 0]), 2).is_err());
    }

    #[test]
    fn record() {
        // Valid record headers, using different TLS versions and lengths.
        assert!(Tls::parse_plaintext_record_header(&mut B::from_bytes(&[22, 3, 1, 0, 0])).is_ok());
        assert!(Tls::parse_plaintext_record_header(&mut B::from_bytes(&[22, 3, 2, 0, 0])).is_ok());
        assert!(Tls::parse_plaintext_record_header(&mut B::from_bytes(&[22, 3, 3, 0, 0])).is_ok());
        assert!(Tls::parse_plaintext_record_header(&mut B::from_bytes(&[22, 3, 1, 64, 0])).is_ok());
        assert!(Tls::parse_plaintext_record_header(&mut B::from_bytes(&[22, 3, 2, 0, 42])).is_ok());
        assert!(
            Tls::parse_plaintext_record_header(&mut B::from_bytes(&[22, 3, 3, 13, 37])).is_ok()
        );

        // Invalid records.
        assert!(Tls::parse_plaintext_record_header(&mut B::from_bytes(&[0, 0, 0, 0, 0])).is_err());
        assert!(
            Tls::parse_plaintext_record_header(&mut B::from_bytes(&[255, 1, 0, 0, 0])).is_err()
        );

        // Invalid versions.
        assert!(Tls::parse_plaintext_record_header(&mut B::from_bytes(&[22, 0, 3, 0, 0])).is_err());
        assert!(
            Tls::parse_plaintext_record_header(&mut B::from_bytes(&[22, 255, 3, 0, 0])).is_err()
        );
        assert!(Tls::parse_plaintext_record_header(&mut B::from_bytes(&[22, 3, 0, 0, 0])).is_err());
        assert!(Tls::parse_plaintext_record_header(&mut B::from_bytes(&[22, 3, 4, 0, 0])).is_err());
        assert!(
            Tls::parse_plaintext_record_header(&mut B::from_bytes(&[22, 3, 255, 0, 0])).is_err()
        );

        // Invalid length field.
        assert!(
            Tls::parse_plaintext_record_header(&mut B::from_bytes(&[22, 3, 3, 64, 1])).is_err()
        );
        assert!(
            Tls::parse_plaintext_record_header(&mut B::from_bytes(&[22, 3, 3, 255, 255])).is_err()
        );

        // Not enough data in the reader.
        assert!(Tls::parse_plaintext_record_header(&mut B::from_bytes(&[22, 3, 3, 0])).is_err());
        assert!(Tls::parse_plaintext_record_header(&mut B::from_bytes(&[22, 3, 3])).is_err());
        assert!(Tls::parse_plaintext_record_header(&mut B::from_bytes(&[22, 3])).is_err());
        assert!(Tls::parse_plaintext_record_header(&mut B::from_bytes(&[22])).is_err());
        assert!(Tls::parse_plaintext_record_header(&mut B::from_bytes(&[])).is_err());
    }

    #[test]
    fn handshake() {
        // Client Hello empty message.
        assert!(Tls::parse_handshake_header(&mut B::from_bytes(&[1, 0, 0, 0])).is_ok());
        assert!(Tls::parse_handshake_header(&mut B::from_bytes(&[1, 255, 255, 255])).is_ok());

        // Invalid messages (non-client hello).
        assert!(Tls::parse_handshake_header(&mut B::from_bytes(&[0, 0, 0, 0])).is_err());
        assert!(Tls::parse_handshake_header(&mut B::from_bytes(&[42, 0, 0, 0])).is_err());
        assert!(Tls::parse_handshake_header(&mut B::from_bytes(&[255, 0, 0, 0])).is_err());

        // Not enough data in the reader.
        assert!(Tls::parse_handshake_header(&mut B::from_bytes(&[1, 0, 0])).is_err());
        assert!(Tls::parse_handshake_header(&mut B::from_bytes(&[1, 0])).is_err());
        assert!(Tls::parse_handshake_header(&mut B::from_bytes(&[1])).is_err());
        assert!(Tls::parse_handshake_header(&mut B::from_bytes(&[])).is_err());
    }

    #[test]
    fn client_hello() {
        let protocol_version = vec![0x3, 0x3];
        #[rustfmt::skip]
        let random = vec![
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0,
        ];
        let session_id = vec![0x0];
        let cipher_suites = vec![0x0, 0x2, 0x0, 0x0];
        let compression_methods = vec![0x1, 0x0];

        // Full ClientHello message (w/o extensions).
        let hello = [
            protocol_version.clone(),
            random.clone(),
            session_id.clone(),
            cipher_suites.clone(),
            compression_methods.clone(),
        ]
        .concat();

        // Valid protocol versions.
        let mut buf = hello.clone();
        assert!(Tls::parse_client_hello(&mut B::from_bytes(&buf)).is_ok());
        buf[1] = 0x1;
        assert!(Tls::parse_client_hello(&mut B::from_bytes(&buf)).is_ok());
        buf[1] = 0x2;
        assert!(Tls::parse_client_hello(&mut B::from_bytes(&buf)).is_ok());

        // Invalid protocol versions.
        let mut buf = hello.clone();
        buf[0] = 1;
        assert!(Tls::parse_client_hello(&mut B::from_bytes(&buf)).is_err());
        buf[0] = 0;
        assert!(Tls::parse_client_hello(&mut B::from_bytes(&buf)).is_err());
        buf[0] = 255;
        assert!(Tls::parse_client_hello(&mut B::from_bytes(&buf)).is_err());
        buf[0] = 3;
        buf[1] = 0;
        assert!(Tls::parse_client_hello(&mut B::from_bytes(&buf)).is_err());
        buf[1] = 4;
        assert!(Tls::parse_client_hello(&mut B::from_bytes(&buf)).is_err());
        buf[1] = 255;
        assert!(Tls::parse_client_hello(&mut B::from_bytes(&buf)).is_err());

        // Invalid random.
        let invalid = vec![
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];
        let buf = [
            protocol_version.clone(),
            invalid,
            session_id.clone(),
            cipher_suites.clone(),
            compression_methods.clone(),
        ]
        .concat();
        assert!(Tls::parse_client_hello(&mut B::from_bytes(&buf)).is_err());

        let invalid = vec![
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];
        let buf = [
            protocol_version.clone(),
            invalid,
            session_id.clone(),
            cipher_suites.clone(),
            compression_methods.clone(),
        ]
        .concat();
        assert!(Tls::parse_client_hello(&mut B::from_bytes(&buf)).is_err());

        // Valid longer session ids.
        let valid = vec![0x1, 0x42];
        let buf = [
            protocol_version.clone(),
            random.clone(),
            valid,
            cipher_suites.clone(),
            compression_methods.clone(),
        ]
        .concat();
        assert!(Tls::parse_client_hello(&mut B::from_bytes(&buf)).is_ok());

        let valid = vec![0x3, 0x42, 0x13, 0x37];
        let buf = [
            protocol_version.clone(),
            random.clone(),
            valid,
            cipher_suites.clone(),
            compression_methods.clone(),
        ]
        .concat();
        assert!(Tls::parse_client_hello(&mut B::from_bytes(&buf)).is_ok());

        // Invalid session id.
        let mut buf = hello.clone();
        buf[34] = 33;
        assert!(Tls::parse_client_hello(&mut B::from_bytes(&buf)).is_err());
        buf[34] = 255;
        assert!(Tls::parse_client_hello(&mut B::from_bytes(&buf)).is_err());
        buf[34] = 16; /* Valid len but buffer too small */
        assert!(Tls::parse_client_hello(&mut B::from_bytes(&buf)).is_err());

        // Invalid cipher suites.
        let mut buf = hello.clone();
        buf[36] = 0;
        assert!(Tls::parse_client_hello(&mut B::from_bytes(&buf)).is_err());
        buf[36] = 3;
        assert!(Tls::parse_client_hello(&mut B::from_bytes(&buf)).is_err());
        buf[35] = 3;
        buf[36] = 5;
        assert!(Tls::parse_client_hello(&mut B::from_bytes(&buf)).is_err());

        // Invalid compression method.
        let mut buf = hello.clone();
        buf[39] = 0;
        assert!(Tls::parse_client_hello(&mut B::from_bytes(&buf)).is_err());
        buf[39] = 255; /* Valid len but buffer too small */
        assert!(Tls::parse_client_hello(&mut B::from_bytes(&buf)).is_err());
    }

    #[test]
    fn sni_hostname() {
        // Valid, single SNI record.
        let sni = &[
            0, 14, 0, 0, 11, 101, 120, 97, 109, 112, 108, 101, 46, 110, 101, 116,
        ];
        assert!(Tls::sni_ext_get_hostname(sni).unwrap() == "example.net");

        // Invalid lengths.
        assert!(Tls::sni_ext_get_hostname(&[]).is_err());
        assert!(Tls::sni_ext_get_hostname(&[0]).is_err());
        assert!(Tls::sni_ext_get_hostname(&[0, 0]).is_err());
        assert!(Tls::sni_ext_get_hostname(&[255, 255]).is_err());
        assert!(Tls::sni_ext_get_hostname(&[0, 10, 0, 0]).is_err());
        assert!(Tls::sni_ext_get_hostname(&[0, 10, 0, 0, 0]).is_err());
        assert!(Tls::sni_ext_get_hostname(&[0, 10, 0, 255, 255]).is_err());

        // Invalid SNI length.
        let sni = &[
            0, 15, 1, 0, 11, 101, 120, 97, 109, 112, 108, 101, 46, 110, 101, 116,
        ];
        assert!(Tls::sni_ext_get_hostname(sni).is_err());
        let sni = &[
            0, 13, 1, 0, 12, 101, 120, 97, 109, 112, 108, 101, 46, 110, 101, 116,
        ];
        assert!(Tls::sni_ext_get_hostname(sni).is_err());
        let sni = &[
            0, 14, 1, 0, 13, 101, 120, 97, 109, 112, 108, 101, 46, 110, 101, 116,
        ];
        assert!(Tls::sni_ext_get_hostname(sni).is_err());

        // Invalid SNI types.
        let sni = &[
            0, 14, 1, 0, 11, 101, 120, 97, 109, 112, 108, 101, 46, 110, 101, 116,
        ];
        assert!(Tls::sni_ext_get_hostname(sni).is_err());
        let sni = &[
            0, 14, 255, 0, 11, 101, 120, 97, 109, 112, 108, 101, 46, 110, 101, 116,
        ];
        assert!(Tls::sni_ext_get_hostname(sni).is_err());

        // Invalid, multiple SNI records.
        #[rustfmt::skip]
        let sni = &[
            0, 26,
            1, 0, 13, 101, 120, 97, 109, 112, 108, 101, 46, 110, 101, 116,
            0, 0, 9, 108, 111, 99, 97, 108, 104, 111, 115, 116,
        ];
        assert!(Tls::sni_ext_get_hostname(sni).is_err());
    }

    #[test]
    fn alpn_tls_challenge() {
        // Valid tls-alpn-01 challenge record.
        let alpn = &[0, 11, 10, 97, 99, 109, 101, 45, 116, 108, 115, 47, 49];
        assert!(Tls::alpn_ext_is_challenge(alpn).unwrap() == true);

        // Valid non tls-alpn-01 challenge record.
        assert!(Tls::alpn_ext_is_challenge(&[0, 3, 2, 104, 50]).unwrap() == false);

        // Invalid lengths.
        assert!(Tls::alpn_ext_is_challenge(&[]).is_err());
        assert!(Tls::alpn_ext_is_challenge(&[0]).is_err());
        assert!(Tls::alpn_ext_is_challenge(&[0, 0]).is_err());
        assert!(Tls::alpn_ext_is_challenge(&[255, 255]).is_err());
        assert!(Tls::alpn_ext_is_challenge(&[0, 10, 0]).is_err());
        assert!(Tls::alpn_ext_is_challenge(&[0, 10, 255]).is_err());

        // Invalid ALPN length.
        let alpn = &[0, 12, 10, 97, 99, 109, 101, 45, 116, 108, 115, 47];
        assert!(Tls::alpn_ext_is_challenge(alpn).is_err());
        let alpn = &[0, 11, 10, 97, 99, 109, 101, 45, 116, 108, 115, 47];
        assert!(Tls::alpn_ext_is_challenge(alpn).is_err());
        let alpn = &[0, 11, 11, 97, 99, 109, 101, 45, 116, 108, 115, 47, 49];
        assert!(Tls::alpn_ext_is_challenge(alpn).is_err());

        // Multiple ALPN records. Valid, but not for tls-alpn-01.
        #[rustfmt::skip]
        let alpn = &[
            0, 14,
            10, 97, 99, 109, 101, 45, 116, 108, 115, 47, 49,
            2, 104, 50,
        ];
        assert!(Tls::alpn_ext_is_challenge(alpn).unwrap() == false);
    }

    #[test]
    fn tls() {
        let tls = Tls::from(&mut B::from_bytes(RECORD_SNI)).unwrap();
        assert!(tls.hostname().unwrap() == "example.net");
        assert!(tls.is_challenge() == false);

        let tls = Tls::from(&mut B::from_bytes(RECORD_SNI_ALPN)).unwrap();
        assert!(tls.hostname().unwrap() == "example.net");
        assert!(tls.is_challenge() == true);

        let tls = Tls::from(&mut B::from_bytes(RECORD_NO_EXT)).unwrap();
        assert!(tls.hostname().is_none());
        assert!(tls.is_challenge() == false);
    }
}
