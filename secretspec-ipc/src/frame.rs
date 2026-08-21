use crate::ABSOLUTE_MAX_FRAME_BYTES;
use crate::error::{Error, Result};
use zeroize::Zeroizing;

/// Incremental bounded NDJSON decoder. A frame is one non-empty UTF-8 JSON
/// object followed by LF; the limit applies to JSON bytes, not the delimiter.
#[derive(Debug)]
pub struct FrameDecoder {
    limit: usize,
    payload: Zeroizing<Vec<u8>>,
}

impl FrameDecoder {
    pub fn new(limit: usize) -> Result<Self> {
        validate_limit(limit)?;
        Ok(Self {
            limit,
            payload: Zeroizing::new(Vec::new()),
        })
    }

    pub const fn limit(&self) -> usize {
        self.limit
    }

    pub fn set_limit(&mut self, limit: usize) -> Result<()> {
        validate_limit(limit)?;
        if !self.payload.is_empty() {
            return Err(Error::Protocol("cannot change a frame limit mid-frame"));
        }
        self.limit = limit;
        Ok(())
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Zeroizing<Vec<u8>>>> {
        let mut frames = Vec::new();
        for &byte in bytes {
            if byte == b'\n' {
                if self.payload.is_empty() {
                    return Err(Error::Protocol("zero-length frame"));
                }
                std::str::from_utf8(&self.payload)
                    .map_err(|_| Error::Protocol("frame payload is not valid UTF-8"))?;
                frames.push(std::mem::replace(
                    &mut self.payload,
                    Zeroizing::new(Vec::new()),
                ));
            } else {
                if self.payload.len() >= self.limit {
                    return Err(Error::Protocol("frame exceeds the active limit"));
                }
                self.payload.push(byte);
            }
        }
        Ok(frames)
    }

    pub fn finish_eof(&self) -> Result<()> {
        if self.payload.is_empty() {
            Ok(())
        } else {
            Err(Error::Protocol("truncated frame"))
        }
    }
}

pub fn encode(payload: &[u8], limit: usize) -> Result<Vec<u8>> {
    validate_payload(payload, limit)?;
    let mut frame = Vec::with_capacity(payload.len() + 1);
    frame.extend_from_slice(payload);
    frame.push(b'\n');
    Ok(frame)
}

fn validate_limit(limit: usize) -> Result<()> {
    if limit == 0 || limit > ABSOLUTE_MAX_FRAME_BYTES {
        Err(Error::Protocol("frame limit is outside the absolute bound"))
    } else {
        Ok(())
    }
}

fn validate_payload(payload: &[u8], limit: usize) -> Result<()> {
    validate_limit(limit)?;
    if payload.is_empty() {
        return Err(Error::Protocol("zero-length frame"));
    }
    if payload.len() > limit {
        return Err(Error::Protocol("frame exceeds the active limit"));
    }
    if payload.contains(&b'\n') || payload.contains(&b'\r') {
        return Err(Error::Protocol("frame payload must be single-line JSON"));
    }
    std::str::from_utf8(payload)
        .map_err(|_| Error::Protocol("frame payload is not valid UTF-8"))?;
    Ok(())
}

#[cfg(feature = "tokio")]
pub async fn read_frame<R>(reader: &mut R, limit: usize) -> Result<Option<Zeroizing<Vec<u8>>>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    validate_limit(limit)?;
    let mut payload = Zeroizing::new(Vec::new());
    let mut byte = [0_u8; 1];
    loop {
        let read = reader.read(&mut byte).await?;
        if read == 0 {
            return if payload.is_empty() {
                Ok(None)
            } else {
                Err(Error::Protocol("truncated frame"))
            };
        }
        if byte[0] == b'\n' {
            validate_payload(&payload, limit)?;
            return Ok(Some(payload));
        }
        if payload.len() >= limit {
            return Err(Error::Protocol("frame exceeds the active limit"));
        }
        payload.push(byte[0]);
    }
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
        let all = [
            encode(br#"{\"a\":1}"#, 1024).unwrap(),
            encode(br#"{\"b\":2}"#, 1024).unwrap(),
        ]
        .concat();
        let mut decoder = FrameDecoder::new(1024).unwrap();
        let mut decoded = Vec::new();
        for byte in all {
            decoded.extend(decoder.push(&[byte]).unwrap());
        }
        decoder.finish_eof().unwrap();
        assert_eq!(decoded.len(), 2);
    }
    #[test]
    fn rejects_a_missing_delimiter_at_the_bound() {
        let mut decoder = FrameDecoder::new(4).unwrap();
        assert!(decoder.push(b"12345").is_err());
    }
}
