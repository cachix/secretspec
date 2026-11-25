/// Joins two provider-native path fragments with exactly one forward slash at
/// their boundary.
///
/// Only boundary slashes are normalized: leading and interior slashes keep
/// their meaning. This is deliberately separate from [`std::path::Path`],
/// whose platform-specific separators are wrong for remote provider paths.
pub(crate) fn join_slash_path(left: &str, right: &str) -> String {
    format!(
        "{}/{}",
        left.trim_end_matches('/'),
        right.trim_start_matches('/')
    )
}

#[cfg(test)]
mod tests {
    use super::join_slash_path;

    #[test]
    fn joins_with_exactly_one_boundary_slash() {
        for (left, right, expected) in [
            ("base", "child", "base/child"),
            ("base/", "child", "base/child"),
            ("base///", "//child", "base/child"),
            ("/", "child", "/child"),
            ("///", "/child", "/child"),
            ("", "child", "/child"),
            ("base", "", "base/"),
        ] {
            assert_eq!(join_slash_path(left, right), expected);
        }
    }

    #[test]
    fn preserves_slashes_away_from_the_boundary() {
        assert_eq!(
            join_slash_path("/base//nested/", "/child//nested/"),
            "/base//nested/child//nested/"
        );
    }
}
