#[rustler::nif(schedule = "DirtyIo")]
fn resolve(request_json: String) -> String {
    secretspec::resolve_json(&request_json)
}

#[rustler::nif(schedule = "DirtyIo")]
fn call(request_json: String) -> String {
    secretspec::call_json(&request_json)
}

#[rustler::nif]
fn abi_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

rustler::init!("Elixir.SecretSpec.Native");
