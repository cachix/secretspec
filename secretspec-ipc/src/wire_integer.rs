use crate::MAX_JSON_INTEGER;
use crate::error::{Error, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

pub(crate) fn validate_value(value: &Value) -> Result<()> {
    match value {
        Value::Number(number) => {
            if number
                .as_u64()
                .is_some_and(|value| value > MAX_JSON_INTEGER)
                || number
                    .as_i64()
                    .is_some_and(|value| value < -(MAX_JSON_INTEGER as i64))
                || number
                    .as_f64()
                    .is_some_and(|value| value.abs() > MAX_JSON_INTEGER as f64)
            {
                return Err(Error::Protocol(
                    "JSON number is outside the version 1 safe range",
                ));
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_value(value)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                validate_value(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) mod unsigned {
    use super::*;

    pub fn serialize<S: Serializer>(
        value: &u64,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        if *value > MAX_JSON_INTEGER {
            return Err(serde::ser::Error::custom(
                "JSON integer exceeds the version 1 safe range",
            ));
        }
        value.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<u64, D::Error> {
        let value = u64::deserialize(deserializer)?;
        if value > MAX_JSON_INTEGER {
            return Err(serde::de::Error::custom(
                "JSON integer exceeds the version 1 safe range",
            ));
        }
        Ok(value)
    }
}

pub(crate) mod optional {
    use super::*;

    pub fn serialize<S: Serializer>(
        value: &Option<u64>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        if value.is_some_and(|value| value > MAX_JSON_INTEGER) {
            return Err(serde::ser::Error::custom(
                "JSON integer exceeds the version 1 safe range",
            ));
        }
        value.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Option<u64>, D::Error> {
        let value = Option::<u64>::deserialize(deserializer)?;
        if value.is_some_and(|value| value > MAX_JSON_INTEGER) {
            return Err(serde::de::Error::custom(
                "JSON integer exceeds the version 1 safe range",
            ));
        }
        Ok(value)
    }
}

pub(crate) mod count {
    use super::*;

    pub fn serialize<S: Serializer>(
        value: &usize,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        if (*value as u128) > MAX_JSON_INTEGER as u128 {
            return Err(serde::ser::Error::custom(
                "JSON integer exceeds the version 1 safe range",
            ));
        }
        value.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<usize, D::Error> {
        let value = usize::deserialize(deserializer)?;
        if (value as u128) > MAX_JSON_INTEGER as u128 {
            return Err(serde::de::Error::custom(
                "JSON integer exceeds the version 1 safe range",
            ));
        }
        Ok(value)
    }
}
