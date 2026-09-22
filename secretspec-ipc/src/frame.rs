use crate::ABSOLUTE_MAX_FRAME_BYTES;
use crate::error::{Error, Result};
use zeroize::Zeroizing;

/// Incremental bounded NDJSON decoder. A frame is one non-empty UTF-8 JSON
/// object followed by LF; the limit applies to JSON bytes, not the delimiter.
pub struct FrameDecoder {
    limit: usize,
    payload: Zeroizing<Vec<u8>>,
}

// A partial frame is secret-bearing protocol data, so only its shape is shown.
impl std::fmt::Debug for FrameDecoder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FrameDecoder")
            .field("limit", &self.limit)
            .field("buffered", &self.payload.len())
            .finish()
    }
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
                self.reserve_one();
                self.payload.push(byte);
            }
        }
        Ok(frames)
    }

    /// Grow into a fresh zeroizing allocation instead of letting `Vec`
    /// reallocate, which would free the old copy of the payload unwiped.
    fn reserve_one(&mut self) {
        if self.payload.len() < self.payload.capacity() {
            return;
        }
        let capacity = self
            .payload
            .capacity()
            .saturating_mul(2)
            .clamp(256.min(self.limit), self.limit);
        let mut grown = Zeroizing::new(Vec::with_capacity(capacity));
        grown.extend_from_slice(&self.payload);
        self.payload = grown;
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
    // Kept across calls so `read_frame` is cancel safe: bytes of a partial
    // frame are consumed from the buffer before its delimiter arrives, and a
    // `select!` that drops the read future must not lose them.
    decoder: Option<FrameDecoder>,
}

#[cfg(feature = "tokio")]
impl<R> AsyncFrameReader<R>
where
    R: tokio::io::AsyncRead + Unpin,
{
    pub(crate) fn new(reader: R) -> Self {
        Self {
            reader: tokio::io::BufReader::new(reader),
            decoder: None,
        }
    }

    /// Cancel safe: dropping the returned future before it completes keeps any
    /// partially read frame for the next call.
    pub(crate) async fn read_frame(&mut self, limit: usize) -> Result<Option<Zeroizing<Vec<u8>>>> {
        use tokio::io::AsyncBufReadExt;
        match &mut self.decoder {
            Some(decoder) if decoder.payload.is_empty() => decoder.set_limit(limit)?,
            Some(_) => {}
            None => self.decoder = Some(FrameDecoder::new(limit)?),
        }
        let decoder = self.decoder.as_mut().expect("decoder initialized above");
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

    #[test]
    fn decoder_debug_hides_the_buffered_payload() {
        let mut decoder = FrameDecoder::new(1024).unwrap();
        decoder.push(b"{\"value\":\"hunter2").unwrap();
        let debug = format!("{decoder:?}");
        assert!(!debug.contains("hunter2"), "{debug}");
        assert!(debug.contains("buffered"), "{debug}");
    }

    #[test]
    fn decoder_grows_to_the_limit_without_exceeding_it() {
        let mut decoder = FrameDecoder::new(1000).unwrap();
        let payload = vec![b'a'; 1000];
        decoder.push(&payload).unwrap();
        assert!(decoder.payload.capacity() <= 1000);
        assert!(decoder.push(b"a").is_err());
        let frames = decoder.push(b"").unwrap();
        assert!(frames.is_empty());
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn async_reader_keeps_a_partial_frame_when_the_read_is_cancelled() {
        use tokio::io::AsyncWriteExt;
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut reader = AsyncFrameReader::new(reader);
        writer.write_all(b"{\"a\":").await.unwrap();
        // The biased read consumes the available half frame, then pends and
        // loses the race, which drops its future mid-frame.
        tokio::select! {
            biased;
            _ = reader.read_frame(1024) => panic!("half a frame must not complete"),
            _ = std::future::ready(()) => {}
        }
        writer.write_all(b"1}\n").await.unwrap();
        let frame = reader.read_frame(1024).await.unwrap().unwrap();
        assert_eq!(&*frame, b"{\"a\":1}");
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
