use crate::protocol::{PROVIDER_PROTOCOL, Product, RESOLVER_PROTOCOL};
use crate::{ABSOLUTE_MAX_FRAME_BYTES, Error, Result};
use serde_json::{Map, Value, json};

const COMMON_SCHEMA: &str = include_str!("../schema/ipc/v1/common.schema.json");
const RESOLVER_SCHEMA: &str = include_str!("../schema/ipc/v1/resolver.schema.json");
const PROVIDER_SCHEMA: &str = include_str!("../schema/ipc/v1/provider.schema.json");
const RESOLVER_OPENRPC: &str = include_str!("../schema/ipc/v1/resolver.openrpc.json");
const PROVIDER_OPENRPC: &str = include_str!("../schema/ipc/v1/provider.openrpc.json");

/// Build the endpoint's self-contained OpenRPC discovery document.
///
/// The checked-in OpenRPC files use relative references because they are also
/// published as standalone artifacts. Runtime discovery cannot assume a
/// network connection or a source checkout, so every common and role-specific
/// schema definition is embedded under `components.schemas` and every `$ref`
/// is rewritten to point into the returned document.
pub(crate) fn openrpc(
    protocol: &str,
    versions: &[u32],
    product: &Product,
    methods: &[String],
) -> Result<Value> {
    let (document_source, schema_source, namespace) = match protocol {
        RESOLVER_PROTOCOL => (RESOLVER_OPENRPC, RESOLVER_SCHEMA, "resolver"),
        PROVIDER_PROTOCOL => (PROVIDER_OPENRPC, PROVIDER_SCHEMA, "provider"),
        _ => return Err(Error::Protocol("unknown application protocol")),
    };

    let mut document: Value = parse(document_source)?;
    rewrite_refs(&mut document, namespace);

    let common_schema: Value = parse(COMMON_SCHEMA)?;
    let application_schema: Value = parse(schema_source)?;
    let mut schemas = Map::new();
    append_definitions(&mut schemas, &common_schema, "common")?;
    append_definitions(&mut schemas, &application_schema, namespace)?;

    let root = document
        .as_object_mut()
        .ok_or(Error::Protocol("OpenRPC document is not an object"))?;
    let components = root
        .entry("components")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or(Error::Protocol("OpenRPC components is not an object"))?;
    components.insert("schemas".to_string(), Value::Object(schemas));
    root.insert(
        "x-secretspec".to_string(),
        json!({
            "protocol": protocol,
            "versions": versions,
            "server": product,
            "methods": methods,
            "absolute_max_frame_bytes": ABSOLUTE_MAX_FRAME_BYTES,
        }),
    );

    let encoded = serde_json::to_vec(&document)
        .map_err(|_| Error::Protocol("failed to serialize OpenRPC document"))?;
    if encoded.len() > ABSOLUTE_MAX_FRAME_BYTES {
        return Err(Error::Protocol("OpenRPC document exceeds the frame limit"));
    }
    Ok(document)
}

fn parse(source: &str) -> Result<Value> {
    serde_json::from_str(source)
        .map_err(|_| Error::Protocol("embedded protocol description is invalid"))
}

fn append_definitions(
    output: &mut Map<String, Value>,
    schema: &Value,
    namespace: &str,
) -> Result<()> {
    let definitions = schema
        .get("$defs")
        .and_then(Value::as_object)
        .ok_or(Error::Protocol("embedded schema has no definitions"))?;
    for (name, definition) in definitions {
        let mut definition = definition.clone();
        rewrite_refs(&mut definition, namespace);
        output.insert(format!("{namespace}.{name}"), definition);
    }
    Ok(())
}

fn rewrite_refs(value: &mut Value, local_namespace: &str) {
    match value {
        Value::Array(items) => {
            for item in items {
                rewrite_refs(item, local_namespace);
            }
        }
        Value::Object(object) => {
            if let Some(Value::String(reference)) = object.get_mut("$ref") {
                if let Some(rewritten) = rewrite_reference(reference, local_namespace) {
                    *reference = rewritten;
                }
            }
            for item in object.values_mut() {
                rewrite_refs(item, local_namespace);
            }
        }
        _ => {}
    }
}

fn rewrite_reference(reference: &str, local_namespace: &str) -> Option<String> {
    if let Some(name) = reference.strip_prefix("#/$defs/") {
        return Some(format!("#/components/schemas/{local_namespace}.{name}"));
    }
    for namespace in ["common", "resolver", "provider"] {
        let prefix = format!("{namespace}.schema.json#/$defs/");
        if let Some(name) = reference.strip_prefix(&prefix) {
            return Some(format!("#/components/schemas/{namespace}.{name}"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_internal_refs(value: &Value) {
        match value {
            Value::Array(items) => items.iter().for_each(assert_internal_refs),
            Value::Object(object) => {
                if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                    assert!(
                        reference.starts_with("#/components/"),
                        "runtime discovery retained an external reference: {reference}"
                    );
                }
                object.values().for_each(assert_internal_refs);
            }
            _ => {}
        }
    }

    #[test]
    fn discovery_documents_are_self_contained_and_bounded() {
        let product = Product {
            name: "test-endpoint".to_string(),
            version: "1".to_string(),
        };
        for (protocol, methods) in [
            (RESOLVER_PROTOCOL, vec!["resolver.get".to_string()]),
            (
                PROVIDER_PROTOCOL,
                vec!["provider.resolve_address".to_string()],
            ),
        ] {
            let document = openrpc(protocol, &[1], &product, &methods).unwrap();
            assert_internal_refs(&document);
            assert_eq!(document["x-secretspec"]["protocol"], protocol);
            assert_eq!(document["x-secretspec"]["server"]["name"], "test-endpoint");
            assert!(serde_json::to_vec(&document).unwrap().len() < ABSOLUTE_MAX_FRAME_BYTES);
        }
    }
}
