//! Selecting one value out of an INI document.
//!
//! An INI pointer is an RFC 6901 pointer restricted to the two depths an INI
//! document can address: `/key` for an unsectioned key and `/section/key` for a
//! key in a named section. The grammar, the message that states it, and the
//! lookup that depends on it live together here, so a pointer accepted at
//! config time is exactly one that resolution can follow.

/// The one description of the accepted pointer shape, used to reject every
/// other shape at config time.
const POINTER_SHAPE: &str = "`extract.pointer` for INI must be `/key` for an unsectioned key or `/section/key` for a named section";

/// Validate a pointer without reference to any particular document. The shape
/// is checked before the shared RFC 6901 escape grammar, so a pointer that is
/// not a value selector is reported as such rather than as a JSON Pointer that
/// may also be empty.
pub(crate) fn validate_pointer(pointer: &str) -> Result<(), String> {
    pointer_parts(pointer).ok_or(POINTER_SHAPE)?;
    crate::config::validate_json_pointer(pointer)
}

/// Select the value a pointer names from an INI document. The error names only
/// the pointer and the parser location, never the document or the value.
pub(crate) fn select(document: &str, pointer: &str) -> Result<String, String> {
    let document = ini::Ini::load_from_str_noescape(document).map_err(|error| {
        format!(
            "stored value is not valid INI at line {}, column {}: {}",
            error.line, error.col, error.msg
        )
    })?;
    pointer_parts(pointer)
        .and_then(|(section, key)| document.get_from(section, &key))
        .map(str::to_owned)
        .ok_or_else(|| format!("INI pointer '{pointer}' did not match the stored document"))
}

/// Split a pointer into its optional section and its key, with RFC 6901
/// escapes resolved. `None` for any shape other than `/key` or `/section/key`.
fn pointer_parts(pointer: &str) -> Option<(Option<String>, String)> {
    let path = pointer.strip_prefix('/')?;
    let (section, key) = match path.split_once('/') {
        Some((section, key)) => (Some(section), key),
        None => (None, path),
    };
    if section == Some("") || key.is_empty() || key.contains('/') {
        return None;
    }
    Some((section.map(unescape_segment), unescape_segment(key)))
}

/// Resolve the two RFC 6901 escapes in one pointer segment: `~1` is a literal
/// `/` and `~0` is a literal `~`.
fn unescape_segment(segment: &str) -> String {
    segment.replace("~1", "/").replace("~0", "~")
}
