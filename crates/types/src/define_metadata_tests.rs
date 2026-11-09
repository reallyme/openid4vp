// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde_json::json;
use zeroize::Zeroize;

use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};

use crate::define_metadata::ClientMetadata;
use crate::OpenId4vpTypeErrorReason;

fn query(format: &str) -> Option<DcqlQuery> {
    Some(DcqlQuery {
        credentials: vec![CredentialQuery {
            id: QueryId::parse("credential").ok()?,
            format: CredentialFormat::new(format.to_owned()).ok()?,
            multiple: false,
            meta: serde_json::Map::new(),
            trusted_authorities: None,
            require_cryptographic_holder_binding: true,
            claims: None,
            claim_sets: None,
        }],
        credential_sets: None,
    })
}

#[test]
fn redacts_and_zeroizes_raw_client_metadata() {
    let mut metadata = ClientMetadata {
        raw: json!({"subject_hint": "sensitive-value"}),
    };

    let debug = format!("{metadata:?}");
    assert!(!debug.contains("sensitive-value"));
    assert!(debug.contains("<redacted>"));

    metadata.zeroize();
    assert!(metadata.raw.is_null());
}

#[test]
fn client_metadata_uses_the_final_protocol_object_shape() {
    let raw = json!({
        "encrypted_response_enc_values_supported": ["A256GCM"],
        "jwks": {"keys": []},
        "vp_formats_supported": {
            "dc+sd-jwt": {"sd-jwt_alg_values": ["ES256"], "kb-jwt_alg_values": ["ES256"]},
            "mso_mdoc": {"issuerauth_alg_values": [-7], "deviceauth_alg_values": [-7]}
        },
        "future_extension": {"enabled": true}
    });
    let metadata = ClientMetadata { raw: raw.clone() };

    let encoded = serde_json::to_value(&metadata);
    assert!(encoded.is_ok());
    if let Ok(encoded) = encoded {
        assert_eq!(encoded, raw.clone());
    }

    let decoded = serde_json::from_value::<ClientMetadata>(raw.clone());
    assert!(decoded.is_ok());
    if let Ok(decoded) = decoded {
        assert!(decoded.raw.get("raw").is_none());
        assert!(decoded.raw.get("vp_formats_supported").is_some());
        assert!(decoded.raw.get("future_extension").is_some());
    }
}

#[test]
fn validates_dcql_format_and_known_algorithm_member_shapes() {
    let metadata = ClientMetadata {
        raw: json!({
            "vp_formats_supported": {
                "dc+sd-jwt": {
                    "sd-jwt_alg_values": ["ES256"],
                    "kb-jwt_alg_values": ["ES256"]
                },
                "mso_mdoc": {
                    "issuerauth_alg_values": [-7],
                    "deviceauth_alg_values": [-7, -65537]
                }
            }
        }),
    };

    let sd_jwt_query = query(CredentialFormat::DC_SD_JWT);
    assert!(sd_jwt_query.is_some());
    if let Some(sd_jwt_query) = sd_jwt_query {
        assert!(metadata.validate_for_dcql(&sd_jwt_query).is_ok());
    }

    let mdoc_query = query(CredentialFormat::MSO_MDOC);
    assert!(mdoc_query.is_some());
    if let Some(mdoc_query) = mdoc_query {
        assert!(metadata.validate_for_dcql(&mdoc_query).is_ok());
    }
}

#[test]
fn rejects_dcql_format_missing_from_verifier_metadata() {
    let metadata = ClientMetadata {
        raw: json!({
            "vp_formats_supported": {
                "dc+sd-jwt": {"sd-jwt_alg_values": ["ES256"]}
            }
        }),
    };

    let query = query(CredentialFormat::MSO_MDOC);
    assert!(query.is_some());
    if let Some(query) = query {
        let result = metadata.validate_for_dcql(&query);
        assert!(result.is_err());
        if let Err(error) = result {
            assert_eq!(
                error.reason(),
                OpenId4vpTypeErrorReason::UnsupportedMetadataCapability
            );
        }
    }
}

#[test]
fn rejects_empty_or_wrongly_typed_algorithm_capabilities() {
    for capabilities in [
        json!({"sd-jwt_alg_values": []}),
        json!({"sd-jwt_alg_values": ["ES256", 7]}),
        json!({"kb-jwt_alg_values": "ES256"}),
    ] {
        let metadata = ClientMetadata {
            raw: json!({"vp_formats_supported": {"dc+sd-jwt": capabilities}}),
        };

        let query = query(CredentialFormat::DC_SD_JWT);
        assert!(query.is_some());
        if let Some(query) = query {
            let result = metadata.validate_for_dcql(&query);
            assert!(result.is_err());
            if let Err(error) = result {
                assert_eq!(
                    error.reason(),
                    OpenId4vpTypeErrorReason::UnsupportedMetadataCapability
                );
            }
        }
    }
}

#[test]
fn rejects_metadata_capabilities_that_exceed_processing_bounds() {
    let mut formats = serde_json::Map::new();
    for index in 0..33_u8 {
        formats.insert(
            format!("com.example.format-{index}"),
            json!({"future_algorithm_member": []}),
        );
    }
    let metadata = ClientMetadata {
        raw: json!({"vp_formats_supported": formats}),
    };
    let extension_query = query("com.example.format-0");
    assert!(extension_query.is_some());
    if let Some(extension_query) = extension_query {
        assert!(metadata.validate_for_dcql(&extension_query).is_err());
    }

    let metadata = ClientMetadata {
        raw: json!({
            "vp_formats_supported": {
                "dc+sd-jwt": {"sd-jwt_alg_values": vec!["ES256"; 33]}
            }
        }),
    };
    let query = query(CredentialFormat::DC_SD_JWT);
    assert!(query.is_some());
    if let Some(query) = query {
        assert!(metadata.validate_for_dcql(&query).is_err());
    }
}

#[test]
fn accepts_extension_format_with_object_capabilities() {
    let metadata = ClientMetadata {
        raw: json!({
            "vp_formats_supported": {
                "com.example.custom": {"future_algorithm_member": ["example"]}
            }
        }),
    };

    let query = query("com.example.custom");
    assert!(query.is_some());
    if let Some(query) = query {
        assert!(metadata.validate_for_dcql(&query).is_ok());
    }
}
