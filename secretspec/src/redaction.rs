//! Byte-oriented output filtering for command runners and Rust embedders.
use crate::SecretBytes;
use secrecy::zeroize::{Zeroize, Zeroizing};
use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_PATTERN_BYTES: usize = 64 * 1024;
const CHUNK: usize = 8192;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const MASK: &[u8] = b"[REDACTED]";

/// A reusable set of exact secret bytes to mask in output (0.22+).
///
/// Clones share immutable patterns. Create a separate [`RedactionStream`] for
/// each output channel, or use [`Self::redact`] for a complete byte sequence.
/// Matching supports arbitrary bytes, overlaps, and multiline values. This
/// reduces accidental disclosure; transformed values and other output channels
/// remain outside its protection.
///
/// Use [`crate::ValidatedSecrets::redactor`] for values captured during validation
/// before `as_path` materialization, including hidden dependencies. Constructing a
/// redactor from an already materialized environment would mask paths instead
/// of file contents.
///
/// ```
/// use secretspec::{Redactor, SecretBytes};
///
/// let redactor = Redactor::new([SecretBytes::from_utf8("demo-token")])?;
/// let mut stream = redactor.stream();
/// let mut output = Vec::new();
/// stream.push(b"value=demo-", &mut output);
/// stream.push(b"token!", &mut output);
/// stream.finish(&mut output);
/// assert_eq!(output, b"value=[REDACTED]!");
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Clone)]
pub struct Redactor {
    matcher: Arc<Matcher>,
}

impl fmt::Debug for Redactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redactor").finish_non_exhaustive()
    }
}

impl Redactor {
    /// Build a redactor from known secret values (0.22+).
    ///
    /// Empty and duplicate values are ignored. Returns an error when distinct
    /// nonempty values exceed 64 KiB combined. An empty set passes bytes through.
    pub fn new(values: impl IntoIterator<Item = SecretBytes>) -> io::Result<Self> {
        let matcher = Matcher::new(values.into_iter().collect())?.unwrap_or_else(|| {
            Arc::new(Matcher {
                nodes: vec![Node::default()],
                longest: 0,
            })
        });
        Ok(Self { matcher })
    }

    /// Whether there are no nonempty values to mask (0.22+).
    pub fn is_empty(&self) -> bool {
        self.matcher.longest == 0
    }

    /// Start independent state for one continuous output stream (0.22+).
    ///
    /// Keep this state across reads so secrets split between chunks are masked.
    /// Use separate streams for stdout and stderr, and finish each only at EOF.
    pub fn stream(&self) -> RedactionStream {
        RedactionStream {
            filter: Filter::new(Arc::clone(&self.matcher)),
        }
    }

    /// Mask a complete byte sequence, including its final suffix (0.22+).
    ///
    /// For incremental output, use [`Self::stream`] instead: independent calls
    /// cannot recognize values split across call boundaries.
    pub fn redact(&self, input: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        let mut stream = self.stream();
        stream.push(input, &mut output);
        stream.finish(&mut output);
        output
    }
}

/// Incremental byte filtering for a single output stream (0.22+).
///
/// Bytes that could begin a secret are retained until subsequent input or EOF
/// disambiguates them. Output is appended to the caller's buffer, which may be
/// drained and reused after every push. Dropping the stream discards its pending
/// suffix; call [`Self::finish`] at EOF to emit the complete filtered output.
pub struct RedactionStream {
    filter: Filter,
}

impl fmt::Debug for RedactionStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedactionStream").finish_non_exhaustive()
    }
}

impl RedactionStream {
    /// Append safe output for a chunk of any size (0.22+).
    ///
    /// This does not flush a trailing candidate prefix. Write only the emitted
    /// bytes to the output destination; never forward the original chunk.
    pub fn push(&mut self, input: &[u8], output: &mut Vec<u8>) {
        for chunk in input.chunks(CHUNK) {
            self.filter.push(chunk, false, output);
        }
    }

    /// Finish at EOF and append any remaining filtered output (0.22+).
    ///
    /// Consumes the stream so completed state cannot accidentally be reused.
    pub fn finish(mut self, output: &mut Vec<u8>) {
        self.filter.push(&[], true, output);
    }
}

#[derive(Default)]
struct Node {
    edges: Vec<(u8, usize)>,
    failure: usize,
    depth: usize,
    longest_match: usize,
    // Length of the longest suffix that is a proper prefix of any pattern.
    retain: usize,
}

impl Node {
    fn edge(&self, byte: u8) -> Option<usize> {
        self.edges.iter().find(|(b, _)| *b == byte).map(|(_, n)| *n)
    }
}

/// Sparse Aho-Corasick automaton. Keeping the longest match ending at each
/// position suffices to cover every matching byte, including overlapping values.
pub(crate) struct Matcher {
    nodes: Vec<Node>,
    longest: usize,
}

impl Drop for Matcher {
    fn drop(&mut self) {
        for node in &mut self.nodes {
            for (byte, _) in &mut node.edges {
                byte.zeroize();
            }
        }
    }
}

impl Matcher {
    pub(crate) fn new(mut patterns: Vec<SecretBytes>) -> io::Result<Option<Arc<Self>>> {
        patterns.retain(|p| !p.expose_secret().is_empty());
        patterns.sort_by(|a, b| a.expose_secret().cmp(b.expose_secret()));
        patterns.dedup_by(|a, b| a.expose_secret() == b.expose_secret());
        let total = patterns.iter().try_fold(0usize, |total, p| {
            total.checked_add(p.expose_secret().len())
        });
        if total.is_none_or(|n| n > MAX_PATTERN_BYTES) {
            return Err(io::Error::other(
                "redaction values exceed the 64 KiB combined limit",
            ));
        }
        if patterns.is_empty() {
            return Ok(None);
        }
        let mut matcher = Self {
            nodes: vec![Node::default()],
            longest: 0,
        };
        for pattern in patterns {
            let bytes = pattern.expose_secret();
            matcher.longest = matcher.longest.max(bytes.len());
            let mut state = 0;
            for &byte in bytes {
                state = match matcher.nodes[state].edge(byte) {
                    Some(next) => next,
                    None => {
                        let next = matcher.nodes.len();
                        let depth = matcher.nodes[state].depth + 1;
                        matcher.nodes.push(Node {
                            depth,
                            ..Node::default()
                        });
                        matcher.nodes[state].edges.push((byte, next));
                        next
                    }
                };
            }
            matcher.nodes[state].longest_match = bytes.len();
        }
        let mut queue: VecDeque<_> = matcher.nodes[0].edges.iter().map(|(_, n)| *n).collect();
        while let Some(state) = queue.pop_front() {
            let failure = matcher.nodes[state].failure;
            matcher.nodes[state].longest_match = matcher.nodes[state]
                .longest_match
                .max(matcher.nodes[failure].longest_match);
            matcher.nodes[state].retain = if matcher.nodes[state].edges.is_empty() {
                matcher.nodes[failure].retain
            } else {
                matcher.nodes[state].depth
            };
            for (byte, next) in matcher.nodes[state].edges.clone() {
                let mut fallback = failure;
                while fallback != 0 && matcher.nodes[fallback].edge(byte).is_none() {
                    fallback = matcher.nodes[fallback].failure;
                }
                matcher.nodes[next].failure = matcher.nodes[fallback].edge(byte).unwrap_or(0);
                queue.push_back(next);
            }
        }
        Ok(Some(Arc::new(matcher)))
    }
}

struct Filter {
    matcher: Arc<Matcher>,
    state: usize,
    position: u64,
    pending: Zeroizing<Vec<u8>>,
    intervals: VecDeque<(u64, u64)>,
    in_mask: bool,
}

impl Filter {
    fn new(matcher: Arc<Matcher>) -> Self {
        Self {
            pending: Zeroizing::new(Vec::with_capacity(matcher.longest + CHUNK)),
            matcher,
            state: 0,
            position: 0,
            intervals: VecDeque::new(),
            in_mask: false,
        }
    }

    // Call with at most CHUNK bytes so raw buffers never need to reallocate.
    fn push(&mut self, input: &[u8], eof: bool, output: &mut Vec<u8>) {
        assert!(input.len() <= CHUNK);
        self.pending.extend_from_slice(input);
        for &byte in input {
            while self.state != 0 && self.matcher.nodes[self.state].edge(byte).is_none() {
                self.state = self.matcher.nodes[self.state].failure;
            }
            self.state = self.matcher.nodes[self.state].edge(byte).unwrap_or(0);
            self.position += 1;
            let length = self.matcher.nodes[self.state].longest_match;
            if length != 0 {
                let mut start = self.position - length as u64;
                while let Some(&(previous, end)) = self.intervals.back() {
                    if end < start {
                        break;
                    }
                    start = start.min(previous);
                    self.intervals.pop_back();
                }
                self.intervals.push_back((start, self.position));
            }
        }
        let retained = if eof {
            0
        } else {
            self.matcher.nodes[self.state].retain
        };
        let emit = self.pending.len() - retained;
        let start = self.position - self.pending.len() as u64;
        for i in 0..emit {
            let position = start + i as u64;
            while self
                .intervals
                .front()
                .is_some_and(|(_, end)| *end <= position)
            {
                self.intervals.pop_front();
            }
            let covered = self
                .intervals
                .front()
                .is_some_and(|(start, _)| *start <= position);
            if covered {
                if !self.in_mask {
                    output.extend_from_slice(MASK);
                }
            } else {
                output.push(self.pending[i]);
            }
            self.in_mask = covered;
        }
        // Wipe both emitted bytes and the old suffix copy after shifting.
        self.pending[..emit].zeroize();
        self.pending.copy_within(emit.., 0);
        self.pending[retained..].zeroize();
        self.pending.truncate(retained);
    }
}

async fn pump(
    mut source: impl AsyncRead + Unpin,
    mut target: impl AsyncWrite + Unpin,
    matcher: Arc<Matcher>,
) -> io::Result<()> {
    let mut stream = Redactor { matcher }.stream();
    let mut input = Zeroizing::new([0u8; CHUNK]);
    let mut output = Zeroizing::new(Vec::new());
    loop {
        let count = source.read(&mut input[..]).await?;
        output.clear();
        if count == 0 {
            stream.finish(&mut output);
            target.write_all(&output).await?;
            target.flush().await?;
            return Ok(());
        }
        stream.push(&input[..count], &mut output);
        target.write_all(&output).await?;
        target.flush().await?;
    }
}

/// Supervise both pipes and the child together. Dropping the futures closes
/// pipe readers even when descendants retain writers; no detached pump threads.
pub(crate) fn run(
    command: Command,
    matcher: Arc<Matcher>,
    on_spawn: impl FnOnce(io::Result<u32>) + Send,
) -> io::Result<ExitStatus> {
    crate::provider::block_on(async move {
        let mut command = tokio::process::Command::from(command);
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let spawned = command.spawn();
        on_spawn(
            spawned
                .as_ref()
                .map(|child| child.id().expect("live child"))
                .map_err(|e| io::Error::new(e.kind(), "could not start command")),
        );
        let mut child = spawned?;
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let pumps = async {
            tokio::try_join!(
                pump(stdout, tokio::io::stdout(), Arc::clone(&matcher)),
                pump(stderr, tokio::io::stderr(), matcher),
            )?;
            Ok::<_, io::Error>(())
        };
        tokio::pin!(pumps);
        let result = async {
            tokio::select! {
                result = &mut pumps => { result?; child.wait().await }
                status = child.wait() => {
                    let status = status?;
                    tokio::time::timeout(DRAIN_TIMEOUT, &mut pumps).await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "timed out draining redacted child output"))??;
                    Ok(status)
                }
            }
        }.await;
        if result.is_err() {
            // kill() also waits, reaping the direct child after a pump failure.
            let _ = child.kill().await;
        }
        result
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Whole-input reference: enumerate matches independently, then merge their
    // intervals before rendering. No streaming state or suffix logic is reused.
    fn reference(input: &[u8], patterns: &[Vec<u8>]) -> Vec<u8> {
        let mut intervals = Vec::new();
        for pattern in patterns.iter().filter(|p| !p.is_empty()) {
            for (start, window) in input.windows(pattern.len()).enumerate() {
                if window == pattern {
                    intervals.push((start, start + pattern.len()));
                }
            }
        }
        intervals.sort();
        let mut merged: Vec<(usize, usize)> = Vec::new();
        for (start, end) in intervals {
            if let Some(last) = merged.last_mut().filter(|last| last.1 >= start) {
                last.1 = last.1.max(end);
            } else {
                merged.push((start, end));
            }
        }
        let mut result = Vec::new();
        let mut cursor = 0;
        for (start, end) in merged {
            result.extend_from_slice(&input[cursor..start]);
            result.extend_from_slice(MASK);
            cursor = end;
        }
        result.extend_from_slice(&input[cursor..]);
        result
    }

    fn check(input: &[u8], values: &[&[u8]]) {
        let patterns: Vec<_> = values.iter().map(|p| p.to_vec()).collect();
        let expected = reference(input, &patterns);
        let Some(matcher) = Matcher::new(
            patterns
                .iter()
                .map(|p| SecretBytes::from_slice(p))
                .collect(),
        )
        .unwrap() else {
            assert_eq!(expected, input);
            return;
        };
        // Exercise every possible placement of read boundaries.
        for cuts in 0..(1usize << input.len().saturating_sub(1)) {
            let mut r = Filter::new(Arc::clone(&matcher));
            let mut actual = Vec::new();
            let mut start = 0;
            for end in 1..input.len() {
                if cuts & (1 << (end - 1)) != 0 {
                    r.push(&input[start..end], false, &mut actual);
                    assert!(r.pending.len() < r.matcher.longest);
                    start = end;
                }
            }
            r.push(&input[start..], false, &mut actual);
            r.push(&[], true, &mut actual);
            assert_eq!(actual, expected, "input={input:?}, cuts={cuts}");
        }
    }

    #[test]
    fn every_partition_with_overlapping_patterns() {
        for len in 0..=9 {
            for bits in 0..(1usize << len) {
                let input: Vec<_> = (0..len)
                    .map(|i| if bits & (1 << i) == 0 { b'a' } else { b'b' })
                    .collect();
                check(&input, &[b"aba", b"bab", b"ababa", b"aa", b"aba"]);
            }
        }
    }

    #[test]
    fn binary_unicode_multiline_and_prefixes() {
        check(b"x\xffa\x00b!", &[b"a\x00b"]);
        check("a🔑é!".as_bytes(), &["🔑é".as_bytes()]);
        check(b"a\nsecret\nb", &[b"\nsecret\n"]);
        check(b"xabcdef!", &[b"abc", b"abcdef"]);
        check(b"xabcdef!", &[b"abcd", b"cdef"]);
        check(b"xxab", &[b"abc"]); // Unfinished match at EOF is ordinary text.
        check(b"aaaaa", &[b"a", b"aa"]);
        check(b"unchanged", &[b"", b"much-longer-than-input"]);
        check(b"unchanged", &[]);
    }

    #[test]
    fn safe_prompts_are_immediate_and_candidate_prefixes_are_retained() {
        let matcher = Matcher::new(vec![SecretBytes::from_utf8("demo-token")])
            .unwrap()
            .unwrap();
        let mut filter = Filter::new(matcher);
        let mut output = Vec::new();
        filter.push(b"Prompt: ", false, &mut output);
        assert_eq!(output, b"Prompt: ");
        output.clear();
        filter.push(b"dem", false, &mut output);
        assert!(output.is_empty());
        filter.push(b"o-token!", false, &mut output);
        assert_eq!(output, b"[REDACTED]!");
    }

    #[test]
    fn repetitive_matches_and_newline_free_streams_keep_bounded_state() {
        let matcher = Matcher::new(vec![SecretBytes::from_vec(vec![b'a'; 4096])])
            .unwrap()
            .unwrap();
        let mut filter = Filter::new(matcher);
        let mut output = Vec::new();
        for _ in 0..1024 {
            filter.push(&[b'a'; CHUNK], false, &mut output);
            assert!(filter.pending.len() < 4096);
            assert!(filter.intervals.len() <= 1);
        }
        filter.push(&[], true, &mut output);
        assert_eq!(output, MASK);
    }

    #[test]
    fn oversized_patterns_are_rejected_and_empty_values_are_ignored() {
        assert!(
            Matcher::new(vec![SecretBytes::from_vec(vec![
                b'a';
                MAX_PATTERN_BYTES + 1
            ])])
            .is_err()
        );
        assert!(
            Matcher::new(vec![SecretBytes::from_vec(vec![])])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn write_failure_is_returned_without_raw_fallback() {
        crate::provider::block_on(async {
            let matcher = Matcher::new(vec![SecretBytes::from_utf8("secret")])
                .unwrap()
                .unwrap();
            let (target, receiver) = tokio::io::duplex(16);
            drop(receiver);
            let error = pump(&b"secret"[..], target, matcher).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        });
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_patterns_and_chunk_sizes_match_whole_input(
            input in proptest::collection::vec(0u8..4, 0..256),
            values in proptest::collection::vec(proptest::collection::vec(0u8..4, 0..16), 0..12),
            chunk in 1usize..32,
        ) {
            let expected = reference(&input, &values);
            if let Some(matcher) = Matcher::new(values.iter().map(|v| SecretBytes::from_slice(v)).collect()).unwrap() {
                let mut filter = Filter::new(matcher);
                let mut actual = Vec::new();
                for part in input.chunks(chunk) {
                    filter.push(part, false, &mut actual);
                }
                filter.push(&[], true, &mut actual);
                proptest::prop_assert_eq!(actual, expected);
            } else {
                proptest::prop_assert_eq!(input, expected);
            }
        }
    }
}
