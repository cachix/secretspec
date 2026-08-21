use proptest::prelude::*;
use secretspec_ipc::frame::{FrameDecoder, encode};
use secretspec_ipc::jsonrpc::Envelope;
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

fn schema_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../schema/ipc/v1")
}

#[test]
fn schemas_openrpc_and_fixtures_are_valid_json() {
    let root = schema_root();
    let schemas = [
        "common.schema.json",
        "resolver.schema.json",
        "provider.schema.json",
    ]
    .map(|name| {
        let bytes = fs::read(root.join(name)).unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(value.is_object(), "{name}");
        (name, value)
    });
    for name in ["resolver.openrpc.json", "provider.openrpc.json"] {
        let bytes = fs::read(root.join(name)).unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(value.is_object(), "{name}");
    }

    let registry = schemas
        .iter()
        .fold(jsonschema::Registry::new(), |registry, (_, schema)| {
            let uri = schema["$id"].as_str().expect("schema has an absolute $id");
            registry.add(uri, schema).expect("schema resource is valid")
        })
        .prepare()
        .expect("schema registry resolves every reference");

    for role in ["wire", "resolver", "provider"] {
        for entry in fs::read_dir(root.join("fixtures").join(role)).unwrap() {
            let path = entry.unwrap().path();
            let bytes = fs::read(&path).unwrap();
            Envelope::parse(&bytes).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            let envelope: Value = serde_json::from_slice(&bytes).unwrap();
            if envelope.get("method").is_some() && envelope.get("id").is_some() {
                let request_schema = json!({
                    "$ref": concat!(
                        "https://secretspec.dev/schema/ipc/v1/common.schema.json",
                        "#/$defs/RequestEnvelope"
                    )
                });
                let validator = jsonschema::options()
                    .with_registry(&registry)
                    .build(&request_schema)
                    .unwrap();
                validator.validate(&envelope).unwrap_or_else(|error| {
                    panic!("{} is not a request envelope: {error}", path.display())
                });
            }
            let (schema_ref, instance) = fixture_schema(role, &path, &envelope);
            let root_schema = json!({ "$ref": schema_ref });
            let validator = jsonschema::options()
                .with_registry(&registry)
                .build(&root_schema)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            if let Err(error) = validator.validate(instance) {
                panic!("{} does not match {schema_ref}: {error}", path.display());
            }
        }
    }
}

#[test]
fn method_catalogs_match_openrpc() {
    let root = schema_root();
    let cases = [
        (
            "resolver.openrpc.json",
            "resolver.",
            // The full catalog rather than the advertised set: the document
            // describes the optional mutation methods too.
            secretspec_ipc::protocol::resolver::method::ALL,
        ),
        (
            "provider.openrpc.json",
            "provider.",
            secretspec_ipc::protocol::provider::method::ALL,
        ),
        // The callbacks the endpoint sends the other way. Documented in the
        // resolver's own OpenRPC document because that is the protocol they
        // belong to, and pinned here so the two catalogs cannot drift.
        (
            "resolver.openrpc.json",
            "client.",
            secretspec_ipc::protocol::callback::method::ALL,
        ),
    ];
    for (document, prefix, catalog) in cases {
        let value: Value = serde_json::from_slice(&fs::read(root.join(document)).unwrap()).unwrap();
        let mut documented: Vec<_> = value["methods"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|method| method["name"].as_str())
            .filter(|name| name.starts_with(prefix))
            .collect();
        let mut implemented = catalog.to_vec();
        documented.sort_unstable();
        implemented.sort_unstable();
        assert_eq!(implemented, documented, "{document}");
    }
}

fn fixture_schema<'a>(role: &str, path: &Path, envelope: &'a Value) -> (&'static str, &'a Value) {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap();
    match (role, name) {
        ("wire", "error.json") => (
            "https://secretspec.dev/schema/ipc/v1/common.schema.json#/$defs/ErrorResponseEnvelope",
            envelope,
        ),
        ("wire", "cancel.json") => (
            concat!(
                "https://secretspec.dev/schema/ipc/v1/common.schema.json",
                "#/$defs/CancelParams"
            ),
            &envelope["params"],
        ),
        ("wire", "shutdown.json") => (
            concat!(
                "https://secretspec.dev/schema/ipc/v1/common.schema.json",
                "#/$defs/EmptyParams"
            ),
            &envelope["params"],
        ),
        ("resolver", "initialize-request.json") => (
            "https://secretspec.dev/schema/ipc/v1/resolver.schema.json#/$defs/InitializeParams",
            &envelope["params"],
        ),
        ("resolver", "initialize-result.json") => (
            "https://secretspec.dev/schema/ipc/v1/resolver.schema.json#/$defs/InitializeResult",
            &envelope["result"],
        ),
        ("resolver", "get-request.json") => (
            "https://secretspec.dev/schema/ipc/v1/resolver.schema.json#/$defs/GetParams",
            &envelope["params"],
        ),
        ("resolver", "get-value-result.json") => (
            "https://secretspec.dev/schema/ipc/v1/resolver.schema.json#/$defs/GetResult",
            &envelope["result"],
        ),
        ("resolver", "release-request.json") => (
            "https://secretspec.dev/schema/ipc/v1/resolver.schema.json#/$defs/ReleaseParams",
            &envelope["params"],
        ),
        ("resolver", "set-request.json") => (
            "https://secretspec.dev/schema/ipc/v1/resolver.schema.json#/$defs/SetParams",
            &envelope["params"],
        ),
        ("resolver", "set-result.json") => (
            "https://secretspec.dev/schema/ipc/v1/resolver.schema.json#/$defs/SetResult",
            &envelope["result"],
        ),
        ("resolver", "prompt-request.json") => (
            "https://secretspec.dev/schema/ipc/v1/resolver.schema.json#/$defs/PromptParams",
            &envelope["params"],
        ),
        ("resolver", "prompt-result.json") => (
            "https://secretspec.dev/schema/ipc/v1/resolver.schema.json#/$defs/PromptResult",
            &envelope["result"],
        ),
        ("resolver", "reject-request.json") => (
            "https://secretspec.dev/schema/ipc/v1/resolver.schema.json#/$defs/RejectParams",
            &envelope["params"],
        ),
        ("resolver", "reject-result.json") => (
            "https://secretspec.dev/schema/ipc/v1/resolver.schema.json#/$defs/RejectResult",
            &envelope["result"],
        ),
        ("resolver", "delete-request.json") => (
            "https://secretspec.dev/schema/ipc/v1/resolver.schema.json#/$defs/DeleteParams",
            &envelope["params"],
        ),
        ("resolver", "delete-result.json") => (
            "https://secretspec.dev/schema/ipc/v1/resolver.schema.json#/$defs/DeleteResult",
            &envelope["result"],
        ),
        ("provider", "initialize-request.json") => (
            "https://secretspec.dev/schema/ipc/v1/provider.schema.json#/$defs/InitializeParams",
            &envelope["params"],
        ),
        ("provider", "initialize-result.json") => (
            "https://secretspec.dev/schema/ipc/v1/provider.schema.json#/$defs/InitializeResult",
            &envelope["result"],
        ),
        ("provider", "resolve-address-request.json") => (
            "https://secretspec.dev/schema/ipc/v1/provider.schema.json#/$defs/AddressParams",
            &envelope["params"],
        ),
        ("provider", "get-request.json") => (
            "https://secretspec.dev/schema/ipc/v1/provider.schema.json#/$defs/AddressParams",
            &envelope["params"],
        ),
        ("provider", "get-result.json") => (
            "https://secretspec.dev/schema/ipc/v1/provider.schema.json#/$defs/GetResult",
            &envelope["result"],
        ),
        _ => panic!("fixture {role}/{name} has no schema assertion"),
    }
}

proptest! {
    #[test]
    fn every_chunking_round_trips(payload in "\\{\\\"[a-z]{0,64}\\\":([0-9]{1,6}|true|null)\\}", chunks in prop::collection::vec(1usize..16, 1..32)) {
        let frame = encode(payload.as_bytes(), 4096).unwrap();
        let mut decoder = FrameDecoder::new(4096).unwrap();
        let mut offset = 0;
        let mut output = Vec::new();
        for size in chunks {
            if offset == frame.len() { break; }
            let end = (offset + size).min(frame.len());
            output.extend(decoder.push(&frame[offset..end]).unwrap());
            offset = end;
        }
        if offset < frame.len() {
            output.extend(decoder.push(&frame[offset..]).unwrap());
        }
        decoder.finish_eof().unwrap();
        prop_assert_eq!(output.len(), 1);
        prop_assert_eq!(output[0].as_slice(), payload.as_bytes());
    }
}
