use secretspec_derive::declare_secrets;

// This should fail because the file doesn't exist
declare_secrets!("this/file/does/not/exist.toml");

fn main() {}
