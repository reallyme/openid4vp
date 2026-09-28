// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_jose::jwe::{decrypt_compact_jwe_bytes, CompactJwePolicy, P256EcdhEsJweKeyResolver};
use reallyme_openid4vp_dcql::QueryId;
use reallyme_openid4vp_types::{
    AuthorizationRequestObject, AuthorizationResponse, ClientMetadata, PresentationValue,
};

use super::{
    encrypt_authorization_response_with_jose, response_encryption_key_thumbprint_sha256,
    MAX_ENCRYPTION_KEYS,
};
use crate::{VerifiedWalletRequest, WalletErrorReason};

#[test]
fn encrypts_with_selected_ecdh_es_key_and_json_content_type() {
    let keypair = reallyme_crypto::p256::generate_p256_keypair();
    assert!(keypair.is_ok());
    let Ok((public_key, private_key)) = keypair else {
        return;
    };
    let request = request_with_metadata(serde_json::json!({
        "jwks": {"keys": [
            {"kty":"OKP","crv":"Ed25519","x":"AA","alg":"EdDSA","kid":"skip"},
            p256_jwk(&public_key)
        ]},
        "encrypted_response_enc_values_supported": ["A128GCM"]
    }));
    assert!(request.is_some());
    let Some(request) = request else {
        return;
    };
    let response = response_with_state(Some("fedcba9876543210".to_owned()));
    assert!(response.is_some());
    let Some(response) = response else {
        return;
    };
    let encrypted = encrypt_authorization_response_with_jose(&request, &response);
    assert!(encrypted.is_ok());
    if let Ok(compact) = encrypted {
        let decrypted = decrypt_compact_jwe_bytes(
            &compact,
            &CompactJwePolicy::openid4vp_direct_post_jwt(),
            &P256EcdhEsJweKeyResolver::new(&private_key),
        );
        assert!(decrypted.is_ok());
        if let Ok(decrypted) = decrypted {
            let decoded: Result<AuthorizationResponse, _> = serde_json::from_slice(&decrypted);
            assert!(decoded.is_ok());
        }
    }
}

#[test]
fn selected_key_thumbprint_matches_release_v5_3_1_transcript_vector() {
    let request = request_with_metadata(serde_json::json!({
        "jwks": {"keys": [
            {"kty":"OKP","crv":"Ed25519","x":"AA","alg":"EdDSA","kid":"skip"},
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
                "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc",
                "use": "enc",
                "alg": "ECDH-ES",
                "kid": "1"
            }
        ]},
        "encrypted_response_enc_values_supported": ["A128GCM"]
    }));
    assert!(request.is_some());
    let Some(request) = request else {
        return;
    };

    let thumbprint = response_encryption_key_thumbprint_sha256(&request);
    assert_eq!(
        thumbprint,
        Ok([
            0x42, 0x83, 0xec, 0x92, 0x7a, 0xe0, 0xf2, 0x08, 0xda, 0xaa, 0x2d, 0x02, 0x6a, 0x81,
            0x4f, 0x2b, 0x22, 0xdc, 0xa5, 0x2c, 0xf8, 0x5f, 0xfa, 0x8f, 0x3f, 0x86, 0x26, 0xc6,
            0xbd, 0x66, 0x90, 0x47,
        ])
    );
}

#[test]
fn rejects_private_keys_unsupported_encryption_and_oversized_sets() {
    let keypair = reallyme_crypto::p256::generate_p256_keypair();
    assert!(keypair.is_ok());
    let Ok((public_key, _private_key)) = keypair else {
        return;
    };
    let response = response_with_state(None);
    assert!(response.is_some());
    let Some(response) = response else {
        return;
    };

    let mut private = p256_jwk(&public_key);
    private["d"] = serde_json::Value::String("private-material".to_owned());
    let request = request_with_metadata(serde_json::json!({
        "jwks":{"keys":[private]},
        "encrypted_response_enc_values_supported":["A128GCM"]
    }));
    assert!(request.is_some());
    if let Some(request) = request {
        let result = encrypt_authorization_response_with_jose(&request, &response);
        assert_eq!(
            result.map_err(|error| error.reason()),
            Err(WalletErrorReason::InvalidResponseEncryptionKey)
        );
        let thumbprint = response_encryption_key_thumbprint_sha256(&request);
        assert_eq!(
            thumbprint.map_err(|error| error.reason()),
            Err(WalletErrorReason::InvalidResponseEncryptionKey)
        );
    }

    let request = request_with_metadata(serde_json::json!({
        "jwks":{"keys":[p256_jwk(&public_key)]},
        "encrypted_response_enc_values_supported":["A192GCM"]
    }));
    assert!(request.is_some());
    if let Some(request) = request {
        let result = encrypt_authorization_response_with_jose(&request, &response);
        assert_eq!(
            result.map_err(|error| error.reason()),
            Err(WalletErrorReason::UnsupportedResponseEncryptionAlgorithm)
        );
    }

    let keys = vec![p256_jwk(&public_key); MAX_ENCRYPTION_KEYS + 1];
    let request = request_with_metadata(serde_json::json!({
        "jwks":{"keys":keys},
        "encrypted_response_enc_values_supported":["A128GCM"]
    }));
    assert!(request.is_some());
    if let Some(request) = request {
        let result = encrypt_authorization_response_with_jose(&request, &response);
        assert_eq!(
            result.map_err(|error| error.reason()),
            Err(WalletErrorReason::MissingResponseEncryptionMetadata)
        );
        let thumbprint = response_encryption_key_thumbprint_sha256(&request);
        assert_eq!(
            thumbprint.map_err(|error| error.reason()),
            Err(WalletErrorReason::MissingResponseEncryptionMetadata)
        );
    }
}

#[test]
fn selects_a256gcm_and_rejects_missing_key_algorithm_or_unsupported_content_encryption() {
    let keypair = reallyme_crypto::p256::generate_p256_keypair();
    assert!(keypair.is_ok());
    let Ok((public_key, private_key)) = keypair else {
        return;
    };
    let jwk = p256_jwk(&public_key);
    let response = response_with_state(None);
    assert!(response.is_some());
    let Some(response) = response else {
        return;
    };
    let request = request_with_metadata(serde_json::json!({
        "jwks":{"keys":[jwk.clone()]},
        "encrypted_response_enc_values_supported":["A128GCM", "A256GCM"]
    }));
    assert!(request.is_some());
    if let Some(request) = request {
        let encrypted = encrypt_authorization_response_with_jose(&request, &response);
        assert!(encrypted.is_ok());
        if let Ok(compact) = encrypted {
            let decrypted = decrypt_compact_jwe_bytes(
                &compact,
                &CompactJwePolicy::openid4vp_direct_post_jwt(),
                &P256EcdhEsJweKeyResolver::new(&private_key),
            );
            assert!(decrypted.is_ok());
        }
    }

    let mut missing_key_alg = jwk.clone();
    if let Some(object) = missing_key_alg.as_object_mut() {
        object.remove("alg");
    }
    let missing_key_alg = request_with_metadata(serde_json::json!({
        "jwks":{"keys":[missing_key_alg]},
        "encrypted_response_enc_values_supported":["A128GCM"]
    }));
    assert!(missing_key_alg.is_some());
    if let Some(request) = missing_key_alg {
        let result = encrypt_authorization_response_with_jose(&request, &response);
        assert_eq!(
            result.map_err(|error| error.reason()),
            Err(WalletErrorReason::InvalidResponseEncryptionKey)
        );
    }

    let unsupported_enc = request_with_metadata(serde_json::json!({
        "jwks":{"keys":[jwk]},
        "encrypted_response_enc_values_supported":["A192GCM"]
    }));
    assert!(unsupported_enc.is_some());
    if let Some(request) = unsupported_enc {
        let result = encrypt_authorization_response_with_jose(&request, &response);
        assert_eq!(
            result.map_err(|error| error.reason()),
            Err(WalletErrorReason::UnsupportedResponseEncryptionAlgorithm)
        );
    }
}

#[test]
fn defaults_to_a128gcm_and_rejects_oversized_coordinates_before_decoding() {
    let keypair = reallyme_crypto::p256::generate_p256_keypair();
    assert!(keypair.is_ok());
    let Ok((public_key, private_key)) = keypair else {
        return;
    };
    let response = response_with_state(None);
    assert!(response.is_some());
    let Some(response) = response else {
        return;
    };
    let request = request_with_metadata(serde_json::json!({
        "jwks":{"keys":[p256_jwk(&public_key)]}
    }));
    assert!(request.is_some());
    if let Some(request) = request {
        let encrypted = encrypt_authorization_response_with_jose(&request, &response);
        assert!(encrypted.is_ok());
        if let Ok(compact) = encrypted {
            let decrypted = decrypt_compact_jwe_bytes(
                &compact,
                &CompactJwePolicy::openid4vp_direct_post_jwt(),
                &P256EcdhEsJweKeyResolver::new(&private_key),
            );
            assert!(decrypted.is_ok());
        }
    }

    let mut oversized = p256_jwk(&public_key);
    oversized["x"] = serde_json::Value::String("A".repeat(4096));
    let request = request_with_metadata(serde_json::json!({
        "jwks":{"keys":[oversized]},
        "encrypted_response_enc_values_supported":["A128GCM"]
    }));
    assert!(request.is_some());
    if let Some(request) = request {
        let result = encrypt_authorization_response_with_jose(&request, &response);
        assert_eq!(
            result.map_err(|error| error.reason()),
            Err(WalletErrorReason::InvalidResponseEncryptionKey)
        );
    }

    let mut padded = p256_jwk(&public_key);
    if let Some(x) = padded.get("x").and_then(serde_json::Value::as_str) {
        let mut non_canonical = x.to_owned();
        non_canonical.push('=');
        padded["x"] = serde_json::Value::String(non_canonical);
    }
    let request = request_with_metadata(serde_json::json!({
        "jwks":{"keys":[padded, p256_jwk(&public_key)]},
        "encrypted_response_enc_values_supported":["A128GCM"]
    }));
    assert!(request.is_some());
    if let Some(request) = request {
        let encrypted = encrypt_authorization_response_with_jose(&request, &response);
        assert!(encrypted.is_ok());
    }
}

fn p256_jwk(public_key: &[u8]) -> serde_json::Value {
    let uncompressed = reallyme_crypto::p256::decompress_public_key(public_key).ok();
    let x = uncompressed
        .as_deref()
        .and_then(|key| key.get(1..33))
        .map(bytes_to_base64url);
    let y = uncompressed
        .as_deref()
        .and_then(|key| key.get(33..65))
        .map(bytes_to_base64url);
    serde_json::json!({
        "kty":"EC",
        "crv":"P-256",
        "x":x,
        "y":y,
        "alg":"ECDH-ES",
        "use":"enc",
        "kid":"response-key"
    })
}

fn request_with_metadata(metadata: serde_json::Value) -> Option<VerifiedWalletRequest> {
    let parsed: Result<AuthorizationRequestObject, _> = serde_json::from_value(serde_json::json!({
        "client_id": "x509_hash:verifier.example",
        "response_type": "vp_token",
        "response_mode": "direct_post.jwt",
        "response_uri": "https://verifier.example/response",
        "nonce": "high-entropy-request-nonce",
        "dcql_query": {
            "credentials": [{
                "id": "credential",
                "format": "dc+sd-jwt",
                "meta": {"vct_values": ["urn:eudi:pid:1"]}
            }]
        }
    }));
    let Ok(mut request) = parsed else {
        return None;
    };
    request.client_metadata = Some(ClientMetadata { raw: metadata });
    Some(VerifiedWalletRequest::for_test(request))
}

fn response_with_state(state: Option<String>) -> Option<AuthorizationResponse> {
    let Ok(query_id) = QueryId::parse("credential") else {
        return None;
    };
    AuthorizationResponse::single(
        query_id,
        vec![PresentationValue::Compact("presentation".to_owned())],
        state,
    )
    .ok()
}
