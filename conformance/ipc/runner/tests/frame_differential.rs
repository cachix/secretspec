use proptest::prelude::*;
use secretspec_ipc::frame::FrameDecoder;

fn reference_decode(bytes: &[u8], limit: usize) -> Result<Vec<Vec<u8>>, ()> {
    let mut cursor = 0;
    let mut frames = Vec::new();
    while cursor < bytes.len() {
        if bytes.len() - cursor < 4 {
            return Err(());
        }
        let length = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        if length == 0 || length > limit || bytes.len() - cursor < length {
            return Err(());
        }
        let payload = bytes[cursor..cursor + length].to_vec();
        std::str::from_utf8(&payload).map_err(|_| ())?;
        frames.push(payload);
        cursor += length;
    }
    Ok(frames)
}

proptest! {
    #[test]
    fn incremental_codec_matches_independent_reference(
        payloads in prop::collection::vec("[ -~]{1,128}", 1..8),
        chunks in prop::collection::vec(1usize..64, 1..64),
    ) {
        let mut bytes = Vec::new();
        for payload in &payloads {
            bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            bytes.extend_from_slice(payload.as_bytes());
        }
        let expected = reference_decode(&bytes, 4096).unwrap();
        let mut decoder = FrameDecoder::new(4096).unwrap();
        let mut actual = Vec::new();
        let mut cursor = 0;
        for chunk in chunks {
            let end = (cursor + chunk).min(bytes.len());
            actual.extend(decoder.push(&bytes[cursor..end]).unwrap());
            cursor = end;
            if cursor == bytes.len() { break; }
        }
        if cursor != bytes.len() {
            actual.extend(decoder.push(&bytes[cursor..]).unwrap());
        }
        decoder.finish_eof().unwrap();
        let actual = actual.into_iter().map(|value| value.to_vec()).collect::<Vec<_>>();
        prop_assert_eq!(actual, expected);
    }
}
