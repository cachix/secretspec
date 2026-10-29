use super::RedactionStream;
use anstyle_parse::state::{Action, State, state_change};
use std::fmt;

/// Incremental redaction for terminal output (0.22+).
///
/// Preserves 7-bit ANSI escape syntax, including CSI parameters and OSC command
/// numbers. Text and string-control payloads are masked independently. Escape
/// boundaries interrupt matching, so styled or otherwise transformed secrets
/// are outside this filter's protection. Eight-bit C1 controls are not parsed.
/// Like [`RedactionStream`], this appends output, retains candidate prefixes
/// across reads, and must be finished at EOF. Dropping discards pending text.
pub struct TerminalRedactionStream {
    text: RedactionStream,
    state: State,
    payload: Payload,
    dcs_query: Option<bool>,
    text_active: bool,
}

impl fmt::Debug for TerminalRedactionStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TerminalRedactionStream")
            .finish_non_exhaustive()
    }
}

// Policy for string payloads, independent of VT syntax and transitions.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Payload {
    Text,
    Syntax,
    OscCommand(u16),
    HyperlinkParams,
}

impl Payload {
    fn osc_text(&mut self, byte: u8) -> bool {
        match *self {
            Self::OscCommand(command) => match byte {
                b'0'..=b'9' => {
                    *self = Self::OscCommand(
                        command
                            .saturating_mul(10)
                            .saturating_add((byte - b'0') as u16),
                    );
                    false
                }
                b';' => {
                    *self = match command {
                        8 => Self::HyperlinkParams,
                        // Palette and dynamic-color controls contain parameters.
                        4..=6 | 10..=19 | 104..=106 | 110..=119 => Self::Syntax,
                        _ => Self::Text,
                    };
                    false
                }
                _ => {
                    *self = Self::Text;
                    true
                }
            },
            Self::HyperlinkParams if byte == b';' => {
                *self = Self::Text;
                false
            }
            Self::Syntax => false,
            _ => true,
        }
    }
}

impl TerminalRedactionStream {
    pub(super) fn new(text: RedactionStream) -> Self {
        Self {
            text,
            state: State::Ground,
            payload: Payload::Text,
            dcs_query: None,
            text_active: false,
        }
    }

    /// Append filtered terminal bytes, preserving state across reads (0.22+).
    pub fn push(&mut self, input: &[u8], output: &mut Vec<u8>) {
        let mut start = None;
        for (index, &byte) in input.iter().enumerate() {
            if self.is_text(byte) {
                start.get_or_insert(index);
                self.text_active = true;
            } else {
                if let Some(start) = start.take() {
                    self.text.push(&input[start..index], output);
                }
                self.end_text(output);
                output.push(byte);
            }
        }
        if let Some(start) = start {
            self.text.push(&input[start..], output);
        }
    }

    /// Finish at EOF, appending any remaining filtered text (0.22+).
    pub fn finish(self, output: &mut Vec<u8>) {
        self.text.finish(output);
    }

    fn end_text(&mut self, output: &mut Vec<u8>) {
        if self.text_active {
            // Finish this logical text region without allocating a new buffer
            // for each escape sequence. Syntax must follow all preceding text.
            let filter = &mut self.text.filter;
            filter.push(&[], true, output);
            filter.state = 0;
            filter.position = 0;
            filter.intervals.clear();
            filter.in_mask = false;
            self.text_active = false;
        }
    }

    // The dependency owns all escape, cancellation, and ignored-byte
    // transitions. We only classify its actions as text or control payload.
    fn is_text(&mut self, byte: u8) -> bool {
        let previous = self.state;
        // As documented by state_change, C1 controls are unsupported here so
        // UTF-8 and arbitrary non-ASCII text bytes stay in the byte matcher.
        if byte >= 0x80 {
            return match previous {
                State::Ground => true,
                State::OscString => self.payload.osc_text(byte),
                State::DcsPassthrough | State::SosPmApcString => self.payload != Payload::Syntax,
                _ => false,
            };
        }
        let (next, action) = state_change(previous, byte);
        self.state = if next == State::Anywhere {
            previous
        } else {
            next
        };

        match next {
            State::OscString => self.payload = Payload::OscCommand(0),
            State::SosPmApcString => self.payload = Payload::Text,
            State::DcsEntry => self.dcs_query = None,
            State::DcsPassthrough => {
                // DECRQSS has exactly the header "$q" and a syntax-only body.
                self.payload = if self.dcs_query == Some(true) && byte == b'q' {
                    Payload::Syntax
                } else {
                    Payload::Text
                };
            }
            _ => {}
        }
        if matches!(
            previous,
            State::DcsEntry | State::DcsParam | State::DcsIntermediate
        ) && matches!(action, Action::Collect | Action::Param)
        {
            self.dcs_query = Some(self.dcs_query.is_none() && byte == b'$');
        }

        match previous {
            State::Ground => self.state == State::Ground,
            State::OscString if action == Action::OscPut => self.payload.osc_text(byte),
            State::DcsPassthrough | State::SosPmApcString if self.state == previous => {
                self.payload != Payload::Syntax
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Redactor, SecretBytes};

    fn check(patterns: &[&str], input: &[u8], expected: &[u8]) {
        let redactor = Redactor::new(patterns.iter().map(|s| SecretBytes::from_utf8(*s))).unwrap();
        // Exercise every two-way split, including splits in escape introducers,
        // parameter headers, secret bytes, and string terminators.
        for split in 0..=input.len() {
            let mut stream = redactor.terminal_stream();
            let mut output = Vec::new();
            stream.push(&input[..split], &mut output);
            stream.push(&input[split..], &mut output);
            stream.finish(&mut output);
            assert_eq!(output, expected, "split {split}");
        }
        let mut stream = redactor.terminal_stream();
        let mut output = Vec::new();
        for byte in input.chunks(1) {
            stream.push(byte, &mut output);
        }
        stream.finish(&mut output);
        assert_eq!(output, expected, "byte-at-a-time");
    }

    #[test]
    fn preserves_csi_and_escape_syntax_but_masks_numeric_text() {
        check(
            &["0", "1", "2004", "1049", "B"],
            b"\x1b[?2004h\x1b[1;31m2004\x1b[0m\x1b[?1049h\x1b(BB",
            b"\x1b[?2004h\x1b[1;31m[REDACTED]\x1b[0m\x1b[?1049h\x1b(B[REDACTED]",
        );
    }

    #[test]
    fn preserves_osc_color_parameters_and_terminal_status_queries() {
        let input = b"\x1b]10;rgb:0000/ffff/0000\x1b\\\x1b]4;0;?\x07\x1bP$qm\x1b\\";
        check(&["0", "4", "10", "ff", "?", "m"], input, input);
        check(&["0"], b"\x1b]0;0\x07", b"\x1b]0;[REDACTED]\x07");
        // A DCS with a different header remains a filtered payload.
        check(&["m"], b"\x1bP1$qm\x1b\\", b"\x1bP1$q[REDACTED]\x1b\\");
    }

    #[test]
    fn masks_osc_titles_links_and_unknown_payloads() {
        check(
            &["0", "8", "token"],
            b"\x1b]0;token\x07\x1b]8;id=token;https://example/token\x1b\\token\x1b]8;;\x1b\\\x1b]999;token\x07",
            b"\x1b]0;[REDACTED]\x07\x1b]8;id=[REDACTED];https://example/[REDACTED]\x1b\\[REDACTED]\x1b]8;;\x1b\\\x1b]999;[REDACTED]\x07",
        );
    }

    #[test]
    fn hyperlink_separator_is_syntax_but_url_semicolons_are_text() {
        check(
            &[";", "token"],
            b"\x1b]8;id=token;https://example/x;y\x1b\\",
            b"\x1b]8;id=[REDACTED];https://example/x[REDACTED]y\x1b\\",
        );
    }

    #[test]
    fn masks_string_payloads_preserving_dcs_headers_and_st() {
        for prefix in [b"\x1bP1;2q".as_slice(), b"\x1b_", b"\x1b^", b"\x1bX"] {
            let mut input = prefix.to_vec();
            input.extend_from_slice(b"token\x1b\\");
            let mut expected = prefix.to_vec();
            expected.extend_from_slice(b"[REDACTED]\x1b\\");
            check(&["1", "2", "q", "token"], &input, &expected);
        }
    }

    #[test]
    fn eof_and_cancellation_do_not_lose_or_expose_pending_payload() {
        check(&["token"], b"\x1b]0;token tok", b"\x1b]0;[REDACTED] tok");
        check(&["token"], b"\x1b]0;token\x1b", b"\x1b]0;[REDACTED]\x1b");
        check(&["token"], b"\x1b[31\x18token", b"\x1b[31\x18[REDACTED]");
        check(
            &["token"],
            b"\x1b]0;token\x1atoken",
            b"\x1b]0;[REDACTED]\x1a[REDACTED]",
        );
    }

    #[test]
    fn interrupted_strings_restart_escape_parsing_before_redacting_text() {
        for prefix in [
            b"\x1b]10;?".as_slice(),
            b"\x1bP$qm",
            b"\x1b]0;title",
            b"\x1b]8;id=link",
            b"\x1b]8;;url",
            b"\x1b_",
            b"\x1b^",
            b"\x1bX",
        ] {
            let mut input = prefix.to_vec();
            input.extend_from_slice(b"\x1b[0mprivate");
            let mut expected = prefix.to_vec();
            expected.extend_from_slice(b"\x1b[0m[REDACTED]");
            check(&["private", "0"], &input, &expected);
        }
        // Restart into another string control as well as CSI.
        check(
            &["private"],
            b"\x1b]10;?\x1b]0;private\x07private",
            b"\x1b]10;?\x1b]0;[REDACTED]\x07[REDACTED]",
        );
    }

    #[test]
    fn ignored_controls_do_not_end_escape_or_header_parsing() {
        check(&["1"], b"\x1b[3\x7f1mX", b"\x1b[3\x7f1mX");
        for control in (0x00..=0x1f)
            .chain([0x7f])
            .filter(|b| !matches!(b, 0x18 | 0x1a | 0x1b))
        {
            for (prefix, suffix) in [
                (b"\x1b".as_slice(), b"[31mX".as_slice()),
                (b"\x1b(".as_slice(), b"BX".as_slice()),
                (b"\x1b[3".as_slice(), b"1mX".as_slice()),
                (b"\x1bP$".as_slice(), b"qm\x1b\\X".as_slice()),
            ] {
                let mut input = prefix.to_vec();
                input.push(control);
                input.extend_from_slice(suffix);
                check(&["1", "B", "m"], &input, &input);
            }
        }
        check(&["private"], b"\x1b(\x18private", b"\x1b(\x18[REDACTED]");
    }

    #[test]
    fn independent_text_regions_do_not_match_across_control_boundaries() {
        check(&["token"], b"tok\x1b[0men", b"tok\x1b[0men");
        check(
            &["token"],
            b"tok\x1b]0;en\x07token",
            b"tok\x1b]0;en\x07[REDACTED]",
        );
        check(&["token"], b"tok\x1b[0mtoken", b"tok\x1b[0m[REDACTED]");
    }

    #[test]
    fn retains_utf8_and_multiline_byte_matching() {
        check(
            &["Û", "line\nline"],
            "Û line\nline".as_bytes(),
            b"[REDACTED] [REDACTED]",
        );
        // C1-looking continuation bytes in UTF-8 must not become controls.
        check(&["Ûtoken"], "Ûtoken".as_bytes(), b"[REDACTED]");
    }

    #[test]
    fn utf8_continuations_do_not_terminate_string_payloads() {
        // Ü contains byte 0x9c, which the low-level table also recognizes as
        // eight-bit ST in DCS/APC/SOS/PM. This API supports seven-bit controls.
        for prefix in [
            b"\x1b]0;".as_slice(),
            b"\x1b]8;;",
            b"\x1bP1;2q",
            b"\x1b_",
            b"\x1b^",
            b"\x1bX",
        ] {
            let mut input = prefix.to_vec();
            input.extend_from_slice("Ütoken🔑".as_bytes());
            input.extend_from_slice(b"\x1b\\after");
            let mut expected = prefix.to_vec();
            expected.extend_from_slice(b"[REDACTED]\x1b\\after");
            check(&["Ütoken🔑"], &input, &expected);
        }
    }

    #[test]
    fn structured_and_ignored_csi_headers_return_to_text_masking() {
        for header in [
            b"\x1b[38:2::1:0:1m".as_slice(),
            b"\x1b[1$0m", // A parameter after an intermediate enters CSI-ignore.
            b"\x1b[1?0m", // An invalid private marker enters CSI-ignore.
        ] {
            let mut input = header.to_vec();
            input.extend_from_slice(b"private");
            let mut expected = header.to_vec();
            expected.extend_from_slice(b"[REDACTED]");
            check(&["0", "1", "private"], &input, &expected);
        }
    }

    #[test]
    fn ground_text_preserves_byte_matching_without_utf8_reencoding() {
        let redactor = Redactor::new([
            SecretBytes::from_vec(b"\xff\x9b\x00\x18\x1a".to_vec()),
            SecretBytes::from_utf8("private"),
        ])
        .unwrap();
        let input = b"before \xff\x9b\x00\x18\x1a private \x80after";
        for split in 0..=input.len() {
            let mut stream = redactor.terminal_stream();
            let mut output = Vec::new();
            stream.push(&input[..split], &mut output);
            stream.push(&input[split..], &mut output);
            stream.finish(&mut output);
            assert_eq!(output, b"before [REDACTED] [REDACTED] \x80after");
        }
    }

    #[test]
    fn syntax_streaming_and_debug_do_not_buffer_or_expose_values() {
        let redactor = Redactor::new([SecretBytes::from_utf8("private")]).unwrap();
        let mut stream = redactor.terminal_stream();
        let mut output = Vec::new();
        stream.push(b"\x1b[", &mut output);
        for _ in 0..100_000 {
            stream.push(b"1;", &mut output);
            assert!(stream.text.filter.pending.is_empty());
            output.clear();
        }
        stream.push(b"mprivate", &mut output);
        assert!(!format!("{stream:?}").contains("private"));
        stream.finish(&mut output);
        assert_eq!(output, b"m[REDACTED]");
    }
}
