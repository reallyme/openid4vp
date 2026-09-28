// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;
use std::collections::BTreeSet;

use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::request::{
    general_jws_from_json_value, unsigned_request_from_json_value, DigitalCredentialGetRequest,
    DigitalCredentialGetRequestData, DigitalCredentialRequestOptions,
};

impl<'de> Deserialize<'de> for DigitalCredentialGetRequestData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        RequestDataWire::deserialize(deserializer)?.into_untyped_data()
    }
}

impl<'de> Deserialize<'de> for DigitalCredentialGetRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct EntryWire {
            protocol: String,
            data: RequestDataWire,
        }

        let wire = EntryWire::deserialize(deserializer)?;
        let data = wire.data.into_data_for_protocol(&wire.protocol)?;
        let request = Self {
            protocol: wire.protocol,
            data,
        };
        request
            .validate()
            .map_err(|_| serde::de::Error::custom("invalid DC API request protocol/data pair"))?;
        Ok(request)
    }
}

impl<'de> Deserialize<'de> for DigitalCredentialRequestOptions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct OptionsWire {
            requests: Vec<DigitalCredentialGetRequest>,
        }

        let wire = OptionsWire::deserialize(deserializer)?;
        Self::new(wire.requests)
            .map_err(|_| serde::de::Error::custom("invalid DC API request options"))
    }
}

struct RequestDataWire {
    members: JsonMap<String, JsonValue>,
    ignored_unsigned_members: bool,
}

impl RequestDataWire {
    fn into_data_for_protocol<E>(self, protocol: &str) -> Result<DigitalCredentialGetRequestData, E>
    where
        E: serde::de::Error,
    {
        match protocol {
            "openid4vp-v1-unsigned" => self.into_unsigned(),
            "openid4vp-v1-signed" => self.into_signed(),
            "openid4vp-v1-multisigned" => self.into_multisigned(),
            _ => Err(E::custom("unsupported DC API protocol")),
        }
    }

    fn into_untyped_data<E>(self) -> Result<DigitalCredentialGetRequestData, E>
    where
        E: serde::de::Error,
    {
        if self.members.contains_key("request") {
            let is_multisigned = self
                .members
                .get("request")
                .is_some_and(JsonValue::is_object);
            if is_multisigned {
                self.into_multisigned()
            } else {
                self.into_signed()
            }
        } else {
            self.into_unsigned()
        }
    }

    fn into_unsigned<E>(self) -> Result<DigitalCredentialGetRequestData, E>
    where
        E: serde::de::Error,
    {
        let request = unsigned_request_from_json_value(JsonValue::Object(self.members))
            .map_err(|_| E::custom("invalid unsigned DC API request"))?;
        Ok(DigitalCredentialGetRequestData::Unsigned(Box::new(request)))
    }

    fn into_signed<E>(mut self) -> Result<DigitalCredentialGetRequestData, E>
    where
        E: serde::de::Error,
    {
        if self.ignored_unsigned_members || self.members.len() != 1 {
            return Err(E::custom("invalid signed DC API request data"));
        }
        let request = self
            .members
            .remove("request")
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .ok_or_else(|| E::custom("signed DC API request must contain a compact JWS"))?;
        Ok(DigitalCredentialGetRequestData::Signed { request })
    }

    fn into_multisigned<E>(mut self) -> Result<DigitalCredentialGetRequestData, E>
    where
        E: serde::de::Error,
    {
        if self.ignored_unsigned_members || self.members.len() != 1 {
            return Err(E::custom("invalid multi-signed DC API request data"));
        }
        let value = self
            .members
            .remove("request")
            .ok_or_else(|| E::custom("multi-signed DC API request is missing request"))?;
        let request = general_jws_from_json_value(value)
            .map_err(|_| E::custom("invalid multi-signed DC API request"))?;
        Ok(DigitalCredentialGetRequestData::Multisigned { request })
    }
}

impl<'de> Deserialize<'de> for RequestDataWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(RequestDataVisitor)
    }
}

struct RequestDataVisitor;

impl<'de> Visitor<'de> for RequestDataVisitor {
    type Value = RequestDataWire;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an OpenID4VP DC API request data object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        let mut members = JsonMap::new();
        let mut ignored_unsigned_members = false;
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom(
                    "duplicate DC API request data member",
                ));
            }
            if key == "client_id" || key == "expected_origins" {
                map.next_value::<IgnoredAny>()?;
                ignored_unsigned_members = true;
            } else {
                members.insert(key, map.next_value()?);
            }
        }
        Ok(RequestDataWire {
            members,
            ignored_unsigned_members,
        })
    }
}
