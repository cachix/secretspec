use super::RedactionStream;
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
    text_active: bool,
}

impl fmt::Debug for TerminalRedactionStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TerminalRedactionStream")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
enum State {
    Ground,
    Escape,
    Intermediate,
    Csi,
    OscCommand { command: u16 },
    Osc8Params,
    DcsHeader { query_prefix: u8 },
    SyntaxString { osc: bool },
    String { osc: bool },
}

impl TerminalRedactionStream {
    pub(super) fn new(text: RedactionStream) -> Self {
        Self {
            text,
            state: State::Ground,
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

    // Return whether this byte belongs to a redacted text region. Syntax bytes
    // are forwarded immediately, so even unterminated controls use bounded
    // memory. Only ESC-prefixed controls are recognized: treating raw C1 bytes
    // as controls would misclassify UTF-8 continuation bytes.
    fn is_text(&mut self, byte: u8) -> bool {
        use State::*;
        match self.state {
            Ground => {
                if byte == 0x1b {
                    self.state = Escape;
                    false
                } else {
                    true
                }
            }
            Escape => {
                self.state = match byte {
                    b'[' => Csi,
                    b']' => OscCommand { command: 0 },
                    b'P' => DcsHeader { query_prefix: 0 },
                    b'X' | b'^' | b'_' => String { osc: false },
                    0x20..=0x2f => Intermediate,
                    0x00..=0x17 | 0x19 | 0x1c..=0x1f | 0x7f => Escape,
                    0x1b => Escape,
                    _ => Ground,
                };
                false
            }
            Intermediate => {
                if byte == 0x1b {
                    self.state = Escape;
                } else if matches!(byte, 0x00..=0x17 | 0x19 | 0x1c..=0x1f | 0x7f) {
                    // Executed C0 controls and ignored DEL do not end an escape.
                } else if !(0x20..=0x2f).contains(&byte) {
                    self.state = Ground;
                }
                false
            }
            Csi | DcsHeader { .. } => {
                if byte == 0x7f {
                    return false; // DEL is ignored without changing parser state.
                }
                if byte == 0x1b {
                    self.state = Escape;
                } else if byte == 0x18 || byte == 0x1a {
                    self.state = Ground;
                } else if (0x40..=0x7e).contains(&byte) {
                    self.state = match self.state {
                        DcsHeader { query_prefix: 1 } if byte == b'q' => {
                            SyntaxString { osc: false }
                        }
                        DcsHeader { .. } => String { osc: false },
                        _ => Ground,
                    };
                } else if byte >= 0x7f {
                    self.state = Ground;
                    return true;
                } else if let DcsHeader { query_prefix } = &mut self.state {
                    if byte >= 0x20 {
                        *query_prefix = if *query_prefix == 0 && byte == b'$' {
                            1
                        } else {
                            2
                        };
                    }
                }
                false
            }
            OscCommand { command } => {
                self.state = match byte {
                    b'0'..=b'9' => OscCommand {
                        command: command
                            .saturating_mul(10)
                            .saturating_add((byte - b'0') as u16),
                    },
                    b';' if command == 8 => Osc8Params,
                    // Palette/dynamic-color settings and their resets carry
                    // terminal parameters, never title or hyperlink text.
                    b';' if matches!(command, 4..=6 | 10..=19 | 104..=106 | 110..=119) => {
                        SyntaxString { osc: true }
                    }
                    b';' => String { osc: true },
                    0x07 | 0x18 | 0x1a => Ground,
                    0x1b => Escape,
                    _ => {
                        self.state = String { osc: true };
                        return true;
                    }
                };
                false
            }
            Osc8Params => match byte {
                b';' => {
                    self.state = String { osc: true };
                    false
                }
                0x1b => {
                    self.state = Escape;
                    false
                }
                0x07 | 0x18 | 0x1a => {
                    self.state = Ground;
                    false
                }
                _ => true,
            },
            // ESC terminates the current string and starts a new escape. Its
            // next byte may be ST's backslash, CSI's '[', or another control.
            SyntaxString { osc } => {
                self.state = match byte {
                    0x1b => Escape,
                    0x18 | 0x1a => Ground,
                    0x07 if osc => Ground,
                    _ => SyntaxString { osc },
                };
                false
            }
            String { osc } => match byte {
                0x1b => {
                    self.state = Escape;
                    false
                }
                0x18 | 0x1a => {
                    self.state = Ground;
                    false
                }
                0x07 if osc => {
                    self.state = Ground;
                    false
                }
                _ => true,
            },
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
