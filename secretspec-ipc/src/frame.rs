use crate::ABSOLUTE_MAX_FRAME_BYTES;
use crate::error::{Error, Result};
use zeroize::Zeroizing;

/// Runtime-independent incremental length-prefix decoder used by native and
/// differential tests. It never allocates a claimed oversized payload.
#[derive(Debug)]
pub struct FrameDecoder {
    limit: usize,
    prefix: [u8; 4],
    prefix_len: usize,
    payload: Option<Zeroizing<Vec<u8>>>,
    payload_len: usize,
}

impl FrameDecoder {
    pub fn new(limit: usize) -> Result<Self> {
        validate_limit(limit)?;
        Ok(Self {
            limit,
            prefix: [0; 4],
            prefix_len: 0,
            payload: None,
            payload_len: 0,
        })
    }

    pub const fn limit(&self) -> usize {
        self.limit
    }

    pub fn set_limit(&mut self, limit: usize) -> Result<()> {
        validate_limit(limit)?;
        if self.prefix_len != 0 || self.payload.is_some() {
            return Err(Error::Protocol("cannot change a frame limit mid-frame"));
        }
        self.limit = limit;
        Ok(())
    }

    pub fn push(&mut self, mut bytes: &[u8]) -> Result<Vec<Zeroizing<Vec<u8>>>> {
        let mut frames = Vec::new();
        while !bytes.is_empty() {
            if self.payload.is_none() {
                let needed = 4 - self.prefix_len;
                let copied = needed.min(bytes.len());
                self.prefix[self.prefix_len..self.prefix_len + copied]
                    .copy_from_slice(&bytes[..copied]);
                self.prefix_len += copied;
                bytes = &bytes[copied..];
                if self.prefix_len < 4 {
                    continue;
                }
                let length = u32::from_be_bytes(self.prefix) as usize;
                validate_payload_length(length, self.limit)?;
                self.payload = Some(Zeroizing::new(vec![0; length]));
                self.payload_len = 0;
            }

            let payload = self.payload.as_mut().expect("allocated above");
            let needed = payload.len() - self.payload_len;
            let copied = needed.min(bytes.len());
            payload[self.payload_len..self.payload_len + copied].copy_from_slice(&bytes[..copied]);
            self.payload_len += copied;
            bytes = &bytes[copied..];

            if self.payload_len == payload.len() {
                let complete = self.payload.take().expect("present above");
                std::str::from_utf8(&complete)
                    .map_err(|_| Error::Protocol("frame payload is not valid UTF-8"))?;
                frames.push(complete);
                self.prefix_len = 0;
                self.payload_len = 0;
                self.prefix = [0; 4];
            }
        }
        Ok(frames)
    }

    /// Report EOF. EOF between frames is clean; any partial prefix or payload
    /// is a truncated-frame violation.
    pub fn finish_eof(&self) -> Result<()> {
        if self.prefix_len == 0 && self.payload.is_none() {
            Ok(())
        } else {
            Err(Error::Protocol("truncated frame"))
        }
    }
}

pub fn encode(payload: &[u8], limit: usize) -> Result<Vec<u8>> {
    validate_payload_length(payload.len(), limit)?;
    std::str::from_utf8(payload)
        .map_err(|_| Error::Protocol("frame payload is not valid UTF-8"))?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn validate_limit(limit: usize) -> Result<()> {
    if limit == 0 || limit > ABSOLUTE_MAX_FRAME_BYTES {
        Err(Error::Protocol("frame limit is outside the absolute bound"))
    } else {
        Ok(())
    }
}

fn validate_payload_length(length: usize, limit: usize) -> Result<()> {
    if length == 0 {
        return Err(Error::Protocol("zero-length frame"));
    }
    if length > limit || length > ABSOLUTE_MAX_FRAME_BYTES {
        return Err(Error::Protocol("frame exceeds the active limit"));
    }
    Ok(())
}

#[cfg(feature = "tokio")]
pub async fn read_frame<R>(reader: &mut R, limit: usize) -> Result<Option<Zeroizing<Vec<u8>>>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    validate_limit(limit)?;
    let mut prefix = [0_u8; 4];
    let mut prefix_len = 0;
    while prefix_len < prefix.len() {
        let read = reader.read(&mut prefix[prefix_len..]).await?;
        if read == 0 {
            return if prefix_len == 0 {
                Ok(None)
            } else {
                Err(Error::Protocol("truncated frame prefix"))
            };
        }
        prefix_len += read;
    }

    let length = u32::from_be_bytes(prefix) as usize;
    validate_payload_length(length, limit)?;
    let mut payload = Zeroizing::new(vec![0_u8; length]);
    let mut payload_len = 0;
    while payload_len < length {
        let read = reader.read(&mut payload[payload_len..]).await?;
        if read == 0 {
            return Err(Error::Protocol("truncated frame payload"));
        }
        payload_len += read;
    }
    std::str::from_utf8(&payload)
        .map_err(|_| Error::Protocol("frame payload is not valid UTF-8"))?;
    Ok(Some(payload))
}

#[cfg(feature = "tokio")]
pub async fn write_frame<W>(writer: &mut W, payload: &[u8], limit: usize) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let frame = Zeroizing::new(encode(payload, limit)?);
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_every_chunk_boundary_and_multiple_frames() {
        let first = encode(br#"{"a":1}"#, 1024).unwrap();
        let second = encode(br#"{"b":2}"#, 1024).unwrap();
        let all = [first, second].concat();
        let mut decoder = FrameDecoder::new(1024).unwrap();
        let mut decoded = Vec::new();
        for byte in all {
            decoded.extend(decoder.push(&[byte]).unwrap());
        }
        decoder.finish_eof().unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].as_slice(), br#"{"a":1}"#);
        assert_eq!(decoded[1].as_slice(), br#"{"b":2}"#);
    }

    #[test]
    fn rejects_size_before_allocating_payload() {
        let mut decoder = FrameDecoder::new(4096).unwrap();
        assert!(decoder.push(&4097_u32.to_be_bytes()).is_err());
    }

    #[test]
    fn distinguishes_clean_and_truncated_eof() {
        FrameDecoder::new(4096).unwrap().finish_eof().unwrap();
        let mut decoder = FrameDecoder::new(4096).unwrap();
        decoder.push(&[0, 0]).unwrap();
        assert!(decoder.finish_eof().is_err());
    }
}
