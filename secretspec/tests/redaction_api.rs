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
