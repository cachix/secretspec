use secretspec_derive::declare_secrets;

// This should fail because the TOML is invalid
declare_secrets!("invalid_toml_embedded.txt");

fn main() {}