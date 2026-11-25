use secretspec::{RedactionStream, Redactor, SecretBytes};

#[test]
fn independent_streams_share_patterns_without_sharing_pending_bytes() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Redactor>();
    assert_send_sync::<RedactionStream>();

    let redactor = Redactor::new([SecretBytes::from_utf8("demo-token")]).unwrap();
    let mut stdout = redactor.stream();
    let mut stderr = redactor.clone().stream();
    let mut out = b"stdout: ".to_vec();
    let mut err = b"stderr: ".to_vec();
    stdout.push(b"demo-", &mut out);
    assert_eq!(out, b"stdout: ");
    stderr.push(b"demo-token", &mut err);
    stdout.push(b"token!", &mut out);
    stdout.finish(&mut out);
    stderr.finish(&mut err);
    assert_eq!(out, b"stdout: [REDACTED]!");
    assert_eq!(err, b"stderr: [REDACTED]");
    assert_eq!(redactor.redact(b"demo-token"), b"[REDACTED]");
}

#[test]
fn arbitrary_chunk_sizes_preserve_binary_bytes_and_overlapping_matches() {
    let redactor = Redactor::new([
        SecretBytes::from_utf8("abcd"),
        SecretBytes::from_utf8("cdef"),
        SecretBytes::from_slice(b"\xff\0\n"),
    ])
    .unwrap();
    // The first match crosses an internal chunk boundary. The caller's chunk
    // is larger than the private filter buffer and includes non-UTF-8 bytes.
    let mut input = vec![b'x'; 8190];
    input.extend_from_slice(b"abcdef!");
    input.extend_from_slice(&[b'y'; 16384]);
    input.extend_from_slice(b"\xff\0\n\x80");
    let mut expected = vec![b'x'; 8190];
    expected.extend_from_slice(b"[REDACTED]!");
    expected.extend_from_slice(&[b'y'; 16384]);
    expected.extend_from_slice(b"[REDACTED]\x80");
    assert_eq!(redactor.redact(&input), expected);
}

#[test]
fn eof_releases_unfinished_prefix_and_empty_patterns_pass_through() {
    let redactor = Redactor::new([SecretBytes::from_utf8("demo-token")]).unwrap();
    let mut stream = redactor.stream();
    let mut output = Vec::new();
    stream.push(b"demo-", &mut output);
    assert!(output.is_empty());
    stream.finish(&mut output);
    assert_eq!(output, b"demo-");

    let empty = Redactor::new([SecretBytes::from_slice(b"")]).unwrap();
    assert!(empty.is_empty());
    assert_eq!(empty.redact(b"arbitrary\xff\0"), b"arbitrary\xff\0");
    assert!(!redactor.is_empty());
}

#[test]
fn debug_and_limit_errors_do_not_disclose_patterns_or_pending_bytes() {
    let value = "sensitive-api-fixture";
    let redactor = Redactor::new([SecretBytes::from_utf8(value)]).unwrap();
    let mut stream = redactor.stream();
    stream.push(b"sensitive-api-", &mut Vec::new());
    assert!(!format!("{redactor:?} {stream:?}").contains("sensitive"));

    let error = Redactor::new([SecretBytes::from_utf8(value.repeat(65536))]).unwrap_err();
    assert!(error.to_string().contains("64 KiB"));
    assert!(!error.to_string().contains(value));
}

#[test]
fn region_boundaries_emit_prefixes_and_prevent_cross_region_matches() {
    let redactor = Redactor::new([SecretBytes::from_utf8("token")]).unwrap();
    let mut stream = redactor.stream();
    let mut output = b"prefix: ".to_vec();
    stream.push(b"tok", &mut output);
    assert_eq!(output, b"prefix: ");
    stream.end_region(&mut output);
    assert_eq!(output, b"prefix: tok");
    output.clear();
    stream.push(b"en", &mut output);
    stream.end_region(&mut output);
    assert_eq!(output, b"en");
    output.clear();
    stream.push(b"to", &mut output);
    assert!(output.is_empty());
    stream.push(b"ken", &mut output);
    stream.finish(&mut output);
    assert_eq!(output, b"[REDACTED]");
}

#[test]
fn region_boundaries_reset_overlapping_matches_and_mask_state() {
    let redactor = Redactor::new(["abc", "abcdef", "cdef"].map(SecretBytes::from_utf8)).unwrap();
    let mut stream = redactor.stream();
    let mut output = Vec::new();
    stream.push(b"abc", &mut output);
    assert!(output.is_empty());
    stream.end_region(&mut output);
    assert_eq!(output, b"[REDACTED]");
    output.clear();
    stream.push(b"abcdef", &mut output);
    stream.end_region(&mut output);
    assert_eq!(output, b"[REDACTED]");
    output.clear();
    stream.push(b"plain", &mut output);
    stream.finish(&mut output);
    assert_eq!(output, b"plain");
}

#[test]
fn empty_region_boundaries_are_repeatable_and_preserve_stream_reuse() {
    for values in [vec![], vec![SecretBytes::from_utf8("token")]] {
        let redactor = Redactor::new(values).unwrap();
        let mut stream = redactor.stream();
        let mut output = b"existing".to_vec();
        stream.end_region(&mut output);
        stream.end_region(&mut output);
        assert_eq!(output, b"existing");
        output.clear();
        stream.push(b"hello", &mut output);
        stream.end_region(&mut output);
        stream.end_region(&mut output);
        stream.finish(&mut output);
        assert_eq!(output, b"hello");
    }
}

#[test]
fn every_region_split_matches_independently_filtered_regions() {
    let redactor = Redactor::new([
        SecretBytes::from_utf8("token"),
        SecretBytes::from_utf8("abc"),
        SecretBytes::from_utf8("abcdef"),
        SecretBytes::from_utf8("cdef"),
        SecretBytes::from_utf8("🔑"),
        SecretBytes::from_slice(b"\xff\0"),
    ])
    .unwrap();
    let mut input = "token abcdef 🔑 tok".as_bytes().to_vec();
    input.extend_from_slice(b"\xff\0 token");
    for split in 0..=input.len() {
        let mut stream = redactor.stream();
        let mut output = Vec::new();
        for region in [&input[..split], &input[split..]] {
            for chunk in region.chunks(1) {
                stream.push(chunk, &mut output);
            }
            stream.end_region(&mut output);
            output.push(b'|');
        }
        stream.finish(&mut output);
        let mut expected = redactor.redact(&input[..split]);
        expected.push(b'|');
        expected.extend_from_slice(&redactor.redact(&input[split..]));
        expected.push(b'|');
        assert_eq!(output, expected, "region split {split}");
    }
}
