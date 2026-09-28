// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde_json::json;
use zeroize::Zeroize;

use crate::define_metadata::ClientMetadata;

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
