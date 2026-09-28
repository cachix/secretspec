use secretspec_ipc::jsonrpc::{Envelope, Request, RequestId, Response};
use secretspec_ipc::protocol::provider::SetExpiringParams;
use secretspec_ipc::{InteractionReference, MAX_JSON_INTEGER, RpcError};
use serde_json::{Value, json};
use std::path::Path;

#[test]
fn wire_integer_boundary_is_enforced_in_requests_and_errors() {
    let accepted = MAX_JSON_INTEGER.to_string();
    let rejected = [
        "1.5".to_owned(),
        "-1".to_owned(),
        (MAX_JSON_INTEGER + 1).to_string(),
        u64::MAX.to_string(),
    ];

    let request = |deadline: &str| {
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"resolver.get","_meta":{{"deadline_unix_ms":{deadline}}},"params":{{}}}}"#
        )
    };
    assert!(Envelope::parse(request(&accepted).as_bytes()).is_ok());
    for deadline in &rejected {
        assert!(
            Envelope::parse(request(deadline).as_bytes()).is_err(),
            "accepted deadline {deadline}"
        );
    }

    let error = |retry: &str| {
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"error":{{"code":-32004,"message":"unavailable","data":{{"kind":"unavailable","retryable":true,"retry_after_ms":{retry}}}}}}}"#
        )
    };
    assert!(Envelope::parse(error(&accepted).as_bytes()).is_ok());
    for retry in &rejected {
        assert!(
            Envelope::parse(error(retry).as_bytes()).is_err(),
            "accepted retry delay {retry}"
        );
    }
}

#[test]
fn typed_fields_and_raw_results_cannot_emit_unsafe_integers() {
    let id = RequestId::new(1).unwrap();
    assert!(Request::new(id, "resolver.get", MAX_JSON_INTEGER, json!({})).is_ok());
    assert!(Request::new(id, "resolver.get", MAX_JSON_INTEGER + 1, json!({})).is_err());

    let address = r#"{"kind":"native","coordinates":{"item":"example"}}"#;
    let params = |ttl: &str| format!(r#"{{"address":{address},"value":"example","ttl_ms":{ttl}}}"#);
    assert!(
        serde_json::from_str::<SetExpiringParams>(&params(&MAX_JSON_INTEGER.to_string())).is_ok()
    );
    for value in [
        "1.5".to_owned(),
        "-1".to_owned(),
        (MAX_JSON_INTEGER + 1).to_string(),
        u64::MAX.to_string(),
    ] {
        assert!(
            serde_json::from_str::<SetExpiringParams>(&params(&value)).is_err(),
            "accepted TTL {value}"
        );
    }

    let response = Response::success(id, json!({"expires_at_unix_ms": MAX_JSON_INTEGER}));
    assert!(Envelope::Response(response).to_vec().is_ok());
    let response = Response::success(id, json!({"expires_at_unix_ms": u64::MAX}));
    assert!(Envelope::Response(response).to_vec().is_err());
    assert!(serde_json::to_value(RpcError::unavailable(Some(u64::MAX))).is_err());
    assert!(
        serde_json::to_value(InteractionReference::authorization(
            "approval",
            Some(u64::MAX)
        ))
        .is_err()
    );

    let result: Value = json!({"future_field": u64::MAX});
    assert!(
        Envelope::parse(format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#).as_bytes())
            .is_err()
    );
}

#[test]
fn schemas_agree_on_portable_integer_boundaries() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../schema/ipc/v1");
    let fields: &[(&str, &[&str])] = &[
        (
            "common.schema.json",
            &[
                "/$defs/DeadlineUnixMs",
                "/$defs/ErrorData/properties/retry_after_ms",
                "/$defs/InteractionReference/properties/expires_at_unix_ms",
            ],
        ),
        (
            "provider.schema.json",
            &[
                "/$defs/ApplicationContext/properties/requested_authorization_duration_ms",
                "/$defs/SetExpiringParams/properties/ttl_ms",
                "/$defs/ClearResult/properties/cleared",
            ],
        ),
        (
            "resolver.schema.json",
            &["/$defs/InitializeApplication/properties/requested_authorization_duration_ms"],
        ),
    ];
    for (file, pointers) in fields {
        let schema: Value =
            serde_json::from_slice(&std::fs::read(root.join(file)).unwrap()).unwrap();
        for pointer in *pointers {
            let validator = jsonschema::validator_for(schema.pointer(pointer).unwrap()).unwrap();
            assert!(
                validator.is_valid(&json!(MAX_JSON_INTEGER)),
                "{file}{pointer}"
            );
            for rejected in [
                json!(1.5),
                json!(-1),
                json!(MAX_JSON_INTEGER + 1),
                json!(u64::MAX),
            ] {
                assert!(
                    !validator.is_valid(&rejected),
                    "{file}{pointer} accepted {rejected}"
                );
            }
        }
    }
}
