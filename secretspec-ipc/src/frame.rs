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
pub(crate) struct AsyncFrameReader<R> {
    reader: tokio::io::BufReader<R>,
}

#[cfg(feature = "tokio")]
impl<R> AsyncFrameReader<R>
where
    R: tokio::io::AsyncRead + Unpin,
{
    pub(crate) fn new(reader: R) -> Self {
        Self {
            reader: tokio::io::BufReader::new(reader),
        }
    }

    pub(crate) async fn read_frame(&mut self, limit: usize) -> Result<Option<Zeroizing<Vec<u8>>>> {
        use tokio::io::AsyncBufReadExt;
        let mut decoder = FrameDecoder::new(limit)?;
        loop {
            let (consumed, mut frames) = {
                let available = self.reader.fill_buf().await?;
                if available.is_empty() {
                    decoder.finish_eof()?;
                    return Ok(None);
                }
                let consumed = available
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(available.len(), |position| position + 1);
                (consumed, decoder.push(&available[..consumed])?)
            };
            self.reader.consume(consumed);
            if let Some(frame) = frames.pop() {
                debug_assert!(frames.is_empty());
                return Ok(Some(frame));
            }
        }
    }
}

/// Read one frame from a one-shot or already-buffered stream.
///
/// Long-lived protocol loops use `AsyncFrameReader` so buffered bytes after
/// the delimiter are retained for the next call. This compatibility helper
/// intentionally avoids reading past the delimiter because it cannot retain
/// state owned by a raw `AsyncRead` caller.
#[cfg(feature = "tokio")]
pub async fn read_frame<R>(reader: &mut R, limit: usize) -> Result<Option<Zeroizing<Vec<u8>>>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut decoder = FrameDecoder::new(limit)?;
    let mut byte = [0_u8; 1];
    loop {
        match reader.read(&mut byte).await? {
            0 => {
                decoder.finish_eof()?;
                return Ok(None);
            }
            _ => {
                let mut frames = decoder.push(&byte)?;
                if let Some(frame) = frames.pop() {
                    return Ok(Some(frame));
                }
            }
        }
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

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn async_reader_reuses_one_buffered_chunk_across_frames() {
        use std::pin::Pin;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Context, Poll};
        use tokio::io::{AsyncRead, ReadBuf};

        struct CountingReader {
            bytes: Vec<u8>,
            position: usize,
            reads: Arc<AtomicUsize>,
        }

        impl AsyncRead for CountingReader {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _context: &mut Context<'_>,
                buffer: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                self.reads.fetch_add(1, Ordering::Relaxed);
                let available = &self.bytes[self.position..];
                let read = available.len().min(buffer.remaining());
                buffer.put_slice(&available[..read]);
                self.position += read;
                Poll::Ready(Ok(()))
            }
        }

        let reads = Arc::new(AtomicUsize::new(0));
        let source = CountingReader {
            bytes: b"{\"a\":1}\n{\"b\":2}\n".to_vec(),
            position: 0,
            reads: Arc::clone(&reads),
        };
        let mut reader = AsyncFrameReader::new(source);
        let first = reader.read_frame(1024).await.unwrap().unwrap();
        let second = reader.read_frame(1024).await.unwrap().unwrap();
        assert_eq!(&*first, b"{\"a\":1}");
        assert_eq!(&*second, b"{\"b\":2}");
        assert_eq!(reads.load(Ordering::Relaxed), 1);
    }
}
