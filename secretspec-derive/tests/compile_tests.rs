// These tests verify that the macro generates compilable code
// and handles errors appropriately.
//
// Each case asserts a `compile_error!` whose text embeds the underlying
// filesystem error string, which differs by OS ("No such file or directory" on
// Unix, "The system cannot find the file/path specified" on Windows, sometimes
// with a different error number). trybuild compares one `.stderr` snapshot per
// `.rs` file with no per-platform variant, so the Windows cases use their own
// identical `.rs` sources under `tests/ui/windows/` paired with Windows
// snapshots. Everything else about the cases is the same.

#[cfg(not(windows))]
const UI_DIR: &str = "tests/ui";
#[cfg(windows)]
const UI_DIR: &str = "tests/ui/windows";

#[test]
fn test_file_not_found() {
    // This should produce a compile error
    let t = trybuild::TestCases::new();
    t.compile_fail(format!("{UI_DIR}/file_not_found.rs"));
}

#[test]
fn test_invalid_toml() {
    // This should produce a compile error
    let t = trybuild::TestCases::new();
    t.compile_fail(format!("{UI_DIR}/invalid_toml.rs"));
}

#[test]
fn test_invalid_toml_embedded() {
    // This should produce a compile error with embedded TOML
    let t = trybuild::TestCases::new();
    t.compile_fail(format!("{UI_DIR}/invalid_toml_embedded.rs"));
}
