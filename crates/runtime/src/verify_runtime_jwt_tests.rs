// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn handles_valid_direct_post_jwt() {
    let service = VerifierRuntimeService::new(
        config_with_holder_binding()
            .with_response_jwt_decryptor(Arc::new(FixtureResponseJwtDecryptor)),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: format!("response={}", valid_compact_jwe()).into_bytes(),
    };

    let session = session();
    let store = FixtureSessionStore::new();
    let response = handle_direct_post_jwt_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session, 10).with_session_store(&store, "session"),
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(JSON_MEDIA_TYPE));
    assert_eq!(
        response.body,
        br#"{}"#
    );
}
#[test]
fn direct_post_jwt_decryption_is_bound_to_the_hosted_session_key() {
    let service = VerifierRuntimeService::new(
        config_with_holder_binding()
            .with_response_jwt_decryptor(Arc::new(SessionBoundResponseJwtDecryptor)),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: format!("response={}", valid_compact_jwe()).into_bytes(),
    };

    let accepted_session = session();
    let accepted_store = FixtureSessionStore::new();
    let accepted = handle_direct_post_jwt_http(
        &service,
        &request,
        DirectPostValidationContext::new(&accepted_session, 10)
            .with_response_decryption_key_id("expected-session-key")
            .with_session_store(&accepted_store, "session"),
    );
    let rejected_session = session();
    let rejected_store = FixtureSessionStore::new();
    let rejected = handle_direct_post_jwt_http(
        &service,
        &request,
        DirectPostValidationContext::new(&rejected_session, 10)
            .with_response_decryption_key_id("another-session-key")
            .with_session_store(&rejected_store, "session"),
    );

    assert_eq!(accepted.status, 200);
    assert_eq!(rejected.status, 400);
}

#[cfg(feature = "jose")]
#[test]
fn jose_decryptor_handles_valid_a128gcm_direct_post_jwt() -> Result<(), reallyme_jose::jwe::JweError>
{
    let compact = compact_jwe_dir_a128gcm(
        &TEST_JWE_KEY,
        &[9u8; 12],
        br#"{"vp_token":{"pid":["presentation"]},"state":"fedcba9876543210"}"#,
    )?;
    let decryptor = JoseAuthorizationResponseJwtDecryptor::new(
        crate::SessionBoundDirectJweKeyResolver::platform(&TEST_JWE_KEY),
    );
    let service = VerifierRuntimeService::new(
        config_with_holder_binding().with_response_jwt_decryptor(Arc::new(decryptor)),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: format!("response={compact}").into_bytes(),
    };

    let session = session();
    let store = FixtureSessionStore::new();
    let response = handle_direct_post_jwt_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session, 10).with_session_store(&store, "session"),
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(JSON_MEDIA_TYPE));
    assert_eq!(
        response.body,
        br#"{}"#
    );
    Ok(())
}

#[cfg(all(feature = "jose", feature = "native"))]
#[test]
fn jose_decryptor_handles_valid_ecdh_es_direct_post_jwt() -> Result<(), reallyme_jose::jwe::JweError>
{
    let compact =
        compact_jwe_ecdh_es_a128gcm(br#"{"vp_token":{"pid":["presentation"]},"state":"fedcba9876543210"}"#)?;
    let decryptor = JoseAuthorizationResponseJwtDecryptor::new(FixtureEcdhEsP256Resolver);
    let service = VerifierRuntimeService::new(
        config_with_holder_binding().with_response_jwt_decryptor(Arc::new(decryptor)),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: format!("response={compact}").into_bytes(),
    };

    let session = session();
    let store = FixtureSessionStore::new();
    let response = handle_direct_post_jwt_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session, 10).with_session_store(&store, "session"),
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(JSON_MEDIA_TYPE));
    assert_eq!(
        response.body,
        br#"{}"#
    );
    Ok(())
}

#[test]
fn rejects_direct_post_jwt_without_decryptor() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: format!("response={}", valid_compact_jwe()).into_bytes(),
    };

    let response = handle_direct_post_jwt_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
    assert!(!response.body.is_empty());
}

#[test]
fn rejects_malformed_direct_post_jwt_before_decryption() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new()
            .with_response_jwt_decryptor(Arc::new(FixtureResponseJwtDecryptor)),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"response=header.payload.signature".to_vec(),
    };

    let response = handle_direct_post_jwt_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn rejects_direct_post_jwt_with_non_base64url_segment() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new()
            .with_response_jwt_decryptor(Arc::new(FixtureResponseJwtDecryptor)),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"response=eyJhbGciOiJFQ0RILUVTIn0..a+b.b.c".to_vec(),
    };

    let response = handle_direct_post_jwt_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn rejects_direct_post_jwt_mixed_error_and_encrypted_response() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new()
            .with_response_jwt_decryptor(Arc::new(FixtureResponseJwtDecryptor)),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: format!(
            "error=access_denied&response={}&state=fedcba9876543210",
            valid_compact_jwe()
        )
        .into_bytes(),
    };

    let response = handle_direct_post_jwt_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn rejects_duplicate_direct_post_jwt_response_fields() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new()
            .with_response_jwt_decryptor(Arc::new(FixtureResponseJwtDecryptor)),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: format!(
            "response={}&response={}",
            valid_compact_jwe(),
            valid_compact_jwe()
        )
        .into_bytes(),
    };

    let response = handle_direct_post_jwt_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn direct_post_jwt_rejects_plaintext_success_downgrade() {
    let service = VerifierRuntimeService::new(config_with_holder_binding());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"vp_token=%7B%22pid%22%3A%5B%22presentation%22%5D%7D&state=fedcba9876543210".to_vec(),
    };

    let response = handle_direct_post_jwt_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn direct_post_jwt_accepts_plain_authorization_error_fallback() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"error=wallet_unavailable&state=fedcba9876543210".to_vec(),
    };

    let response = handle_direct_post_jwt_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(JSON_MEDIA_TYPE));
}

#[test]
fn verifier_http_runtime_routes_request_object_endpoint() {
    let signer = Arc::new(CapturingSigner::default());
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(
            VerifierRuntimeConfig::new().with_signer(signer.clone()),
        )),
        Arc::new(FixtureSessionStore::new()),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: Some(REQUEST_OBJECT_MEDIA_TYPE.to_owned()),
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"wallet_nonce=0123456789abcdef".to_vec(),
    };

    let response = runtime.handle(
        VerifierHttpEndpoint::RequestObject {
            request_object_key: "request",
        },
        &request,
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(REQUEST_OBJECT_MEDIA_TYPE));
    assert_eq!(response.body, valid_compact_jws().as_bytes());
    let wallet_nonces = signer
        .wallet_nonces
        .lock()
        .expect("fixture signer lock is available");
    assert_eq!(wallet_nonces.as_slice(), &[Some("0123456789abcdef".to_owned())]);
}

#[test]
fn verifier_http_runtime_signs_post_without_an_optional_wallet_nonce() {
    let signer = Arc::new(CapturingSigner::default());
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(
            VerifierRuntimeConfig::new().with_signer(signer.clone()),
        )),
        Arc::new(FixtureSessionStore::new()),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: Some(REQUEST_OBJECT_MEDIA_TYPE.to_owned()),
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: Vec::new(),
    };

    let response = runtime.handle(
        VerifierHttpEndpoint::RequestObject {
            request_object_key: "request",
        },
        &request,
    );

    assert_eq!(response.status, 200);
    let wallet_nonces = signer
        .wallet_nonces
        .lock()
        .expect("fixture signer lock is available");
    assert_eq!(wallet_nonces.as_slice(), &[None]);
}

#[test]
fn verifier_http_runtime_rejects_get_for_a_deferred_post_request_object() {
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(
            VerifierRuntimeConfig::new().with_signer(Arc::new(FixtureSigner)),
        )),
        Arc::new(FixtureSessionStore::new()),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Get,
        accept: Some(REQUEST_OBJECT_MEDIA_TYPE.to_owned()),
        content_type: None,
        body: Vec::new(),
    };

    let response = runtime.handle(
        VerifierHttpEndpoint::RequestObject {
            request_object_key: "request",
        },
        &request,
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn verifier_http_runtime_rejects_post_for_a_signed_get_request_object() {
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(
            VerifierRuntimeConfig::new().with_signer(Arc::new(FixtureSigner)),
        )),
        Arc::new(FixtureSessionStore::new()),
        Arc::new(SignedFixtureRequestObjectStore),
        Arc::new(FixtureClock),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: Some(REQUEST_OBJECT_MEDIA_TYPE.to_owned()),
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"wallet_nonce=0123456789abcdef".to_vec(),
    };

    let response = runtime.handle(
        VerifierHttpEndpoint::RequestObject {
            request_object_key: "request",
        },
        &request,
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn verifier_http_runtime_records_request_object_retrievals() {
    let recorder = Arc::new(FixtureEvidenceRecorder::default());
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(
            VerifierRuntimeConfig::new().with_signer(Arc::new(FixtureSigner)),
        )),
        Arc::new(FixtureSessionStore::new()),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    )
    .with_evidence_recorder(recorder.clone());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: Some(REQUEST_OBJECT_MEDIA_TYPE.to_owned()),
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"wallet_nonce=0123456789abcdef".to_vec(),
    };

    for _ in 0..2 {
        let response = runtime.handle(
            VerifierHttpEndpoint::RequestObject {
                request_object_key: "request",
            },
            &request,
        );
        assert_eq!(response.status, 200);
    }

    let records = recorder
        .records
        .lock()
        .expect("fixture evidence lock is available");
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|(key, observation)| {
        key == "request"
            && observation.kind == VerifierEvidenceObservationKind::RequestObjectRetrieval
            && observation.outcome == VerifierEvidenceOutcome::Accepted
            && observation.http_status == 200
    }));
}

#[test]
fn verifier_http_runtime_records_rejected_direct_post() {
    let recorder = Arc::new(FixtureEvidenceRecorder::default());
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(config_with_holder_binding())),
        Arc::new(FixtureSessionStore::new()),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    )
    .with_evidence_recorder(recorder.clone());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"malformed".to_vec(),
    };

    let response = runtime.handle(
        VerifierHttpEndpoint::DirectPost {
            session_key: "session",
        },
        &request,
    );

    assert_eq!(response.status, 400);
    let records = recorder
        .records
        .lock()
        .expect("fixture evidence lock is available");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].0, "session");
    assert_eq!(
        records[0].1,
        VerifierEvidenceObservation {
            kind: VerifierEvidenceObservationKind::DirectPostValidation,
            outcome: VerifierEvidenceOutcome::Rejected,
            http_status: 400,
        }
    );
}

#[test]
fn verifier_http_runtime_fails_closed_when_evidence_recording_fails() {
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(
            VerifierRuntimeConfig::new().with_signer(Arc::new(FixtureSigner)),
        )),
        Arc::new(FixtureSessionStore::new()),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    )
    .with_evidence_recorder(Arc::new(FailingEvidenceRecorder));
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: Some(REQUEST_OBJECT_MEDIA_TYPE.to_owned()),
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"wallet_nonce=0123456789abcdef".to_vec(),
    };

    let response = runtime.handle(
        VerifierHttpEndpoint::RequestObject {
            request_object_key: "request",
        },
        &request,
    );

    assert_eq!(response.status, 500);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn verifier_http_runtime_consumes_session_after_direct_post() {
    let sessions = Arc::new(FixtureSessionStore::new());
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(config_with_holder_binding())),
        sessions.clone(),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"vp_token=%7B%22pid%22%3A%5B%22presentation%22%5D%7D&state=fedcba9876543210".to_vec(),
    };

    let first = runtime.handle(
        VerifierHttpEndpoint::DirectPost {
            session_key: "session",
        },
        &request,
    );
    let replay = runtime.handle(
        VerifierHttpEndpoint::DirectPost {
            session_key: "session",
        },
        &request,
    );

    assert_eq!(first.status, 200);
    assert_eq!(replay.status, 400);
    assert_eq!(replay.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
    let (persisted_session, persisted_result, response_code) = sessions
        .persisted_outcome()
        .expect("accepted result is committed atomically with session consumption");
    assert_eq!(persisted_session.state.as_deref(), Some("fedcba9876543210"));
    assert_eq!(persisted_result.presentations().len(), 1);
    use sha2::Digest;
    assert_eq!(
        persisted_result.inbound_body_sha256(),
        &<[u8; 32]>::from(sha2::Sha256::digest(request.body.as_slice()))
    );
    assert_eq!(
        persisted_result.presentations()[0].query_id().as_str(),
        "pid"
    );
    assert_eq!(
        persisted_result.presentations()[0]
            .holder_binding()
            .trust_provenance(),
        VerifiedTrustProvenance::VerifiedDerivedProof
    );
    assert!(response_code.len() >= crate::MIN_RESPONSE_CODE_CHARS);
}

include!("verify_runtime_follow_back_tests.rs");

#[cfg(feature = "jose")]
fn compact_jwe_dir_a128gcm(
    key: &[u8; 16],
    nonce: &[u8; 12],
    payload: &[u8],
) -> Result<String, reallyme_jose::jwe::JweError> {
    let protected = reallyme_codec::base64url::bytes_to_base64url(
        &serde_json::to_vec(&serde_json::json!({"alg":"dir","enc":"A128GCM"}))
            .map_err(|_| reallyme_jose::jwe::JweError::InvalidHeader)?,
    );
    compact_jwe_a128gcm(&protected, "", key, nonce, payload)
}

#[cfg(all(feature = "jose", feature = "native"))]
fn compact_jwe_ecdh_es_a128gcm(payload: &[u8]) -> Result<String, reallyme_jose::jwe::JweError> {
    let (recipient_public_key, _recipient_secret) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&TEST_P256_RECIPIENT_SECRET)
            .map_err(|_| reallyme_jose::jwe::JweError::InvalidContentEncryptionKey)?;
    let (ephemeral_public_key, _ephemeral_secret) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&TEST_P256_EPHEMERAL_SECRET)
            .map_err(|_| reallyme_jose::jwe::JweError::InvalidContentEncryptionKey)?;
    let epk = p256_public_key_to_epk(&ephemeral_public_key)?;
    let apu = reallyme_codec::base64url::bytes_to_base64url(b"wallet.example");
    let apv = reallyme_codec::base64url::bytes_to_base64url(b"verifier.example");
    let protected_header = reallyme_jose::jwe::CompactJweProtectedHeader {
        alg: reallyme_jose::jwe::JweKeyManagementAlgorithm::EcdhEs,
        enc: reallyme_jose::jwe::JweContentEncryptionAlgorithm::A128Gcm,
        kid: Some("verifier-key-1".to_owned()),
        apu: Some(apu.clone()),
        apv: Some(apv.clone()),
        epk: Some(epk.clone()),
        typ: None,
        cty: None,
    };
    let shared_secret = reallyme_crypto::p256::derive_p256_shared_secret(
        &TEST_P256_EPHEMERAL_SECRET,
        &recipient_public_key,
    )
    .map_err(|_| reallyme_jose::jwe::JweError::Decrypt)?;
    let cek = reallyme_jose::jwe::derive_ecdh_es_content_encryption_key(
        &shared_secret,
        &protected_header,
    )?;
    let cek = <&[u8; 16]>::try_from(cek.as_slice())
        .map_err(|_| reallyme_jose::jwe::JweError::InvalidContentEncryptionKey)?;
    let protected = reallyme_codec::base64url::bytes_to_base64url(
        &serde_json::to_vec(&serde_json::json!({
            "alg": "ECDH-ES",
            "enc": "A128GCM",
            "kid": "verifier-key-1",
            "apu": apu,
            "apv": apv,
            "epk": epk,
        }))
        .map_err(|_| reallyme_jose::jwe::JweError::InvalidHeader)?,
    );
    compact_jwe_a128gcm(&protected, "", cek, &[10u8; 12], payload)
}

#[cfg(all(feature = "jose", feature = "native"))]
fn p256_public_key_to_epk(
    public_key: &[u8],
) -> Result<serde_json::Value, reallyme_jose::jwe::JweError> {
    let uncompressed = reallyme_crypto::p256::decompress_public_key(public_key)
        .map_err(|_| reallyme_jose::jwe::JweError::InvalidHeader)?;
    let uncompressed = <&[u8; 65]>::try_from(uncompressed.as_slice())
        .map_err(|_| reallyme_jose::jwe::JweError::InvalidHeader)?;
    if uncompressed[0] != 4 {
        return Err(reallyme_jose::jwe::JweError::InvalidHeader);
    }
    Ok(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": reallyme_codec::base64url::bytes_to_base64url(&uncompressed[1..33]),
        "y": reallyme_codec::base64url::bytes_to_base64url(&uncompressed[33..65]),
    }))
}

#[cfg(all(feature = "jose", feature = "native"))]
fn p256_public_key_from_epk(
    epk: &serde_json::Value,
) -> Result<Vec<u8>, reallyme_jose::jwe::JweError> {
    let kty = epk_member(epk, "kty")?;
    let crv = epk_member(epk, "crv")?;
    if kty != "EC" || crv != "P-256" {
        return Err(reallyme_jose::jwe::JweError::InvalidHeader);
    }
    let x = decode_p256_coordinate(epk_member(epk, "x")?)?;
    let y = decode_p256_coordinate(epk_member(epk, "y")?)?;
    let mut public_key = [0u8; 65];
    public_key[0] = 4;
    public_key[1..33].copy_from_slice(&x);
    public_key[33..65].copy_from_slice(&y);
    reallyme_crypto::p256::compress_public_key(&public_key)
        .map_err(|_| reallyme_jose::jwe::JweError::InvalidHeader)
}

#[cfg(all(feature = "jose", feature = "native"))]
fn epk_member<'a>(
    epk: &'a serde_json::Value,
    name: &str,
) -> Result<&'a str, reallyme_jose::jwe::JweError> {
    epk.get(name)
        .and_then(serde_json::Value::as_str)
        .ok_or(reallyme_jose::jwe::JweError::InvalidHeader)
}

#[cfg(all(feature = "jose", feature = "native"))]
fn decode_p256_coordinate(input: &str) -> Result<[u8; 32], reallyme_jose::jwe::JweError> {
    let bytes = reallyme_codec::base64url::base64url_to_bytes(input)
        .map_err(|_| reallyme_jose::jwe::JweError::InvalidHeader)?;
    <[u8; 32]>::try_from(bytes).map_err(|_| reallyme_jose::jwe::JweError::InvalidHeader)
}

#[cfg(feature = "jose")]
fn compact_jwe_a128gcm(
    protected: &str,
    encrypted_key: &str,
    key: &[u8; 16],
    nonce: &[u8; 12],
    payload: &[u8],
) -> Result<String, reallyme_jose::jwe::JweError> {
    let key = reallyme_crypto::aes::Aes128GcmKey::from_slice(key)
        .map_err(|_| reallyme_jose::jwe::JweError::InvalidContentEncryptionKey)?;
    let nonce_value = reallyme_crypto::aes::Aes128GcmNonce::from_slice(nonce)
        .map_err(|_| reallyme_jose::jwe::JweError::InvalidContentCipherInput)?;
    let ciphertext_with_tag =
        reallyme_crypto::aes::encrypt_aes128_gcm(&reallyme_crypto::aes::Aes128GcmEncryptRequest {
            key: &key,
            nonce: nonce_value,
            aad: protected.as_bytes(),
            plaintext: payload,
        })
        .map_err(|_| reallyme_jose::jwe::JweError::Decrypt)?;

    let ciphertext_and_tag = ciphertext_with_tag.as_bytes();
    let tag_len = reallyme_jose::jwe::JweContentEncryptionAlgorithm::A128Gcm.tag_len();
    let split_at = ciphertext_and_tag
        .len()
        .checked_sub(tag_len)
        .ok_or(reallyme_jose::jwe::JweError::LengthOverflow)?;
    let ciphertext = reallyme_codec::base64url::bytes_to_base64url(&ciphertext_and_tag[..split_at]);
    let tag = reallyme_codec::base64url::bytes_to_base64url(&ciphertext_and_tag[split_at..]);
    let iv = reallyme_codec::base64url::bytes_to_base64url(nonce);
    Ok(format!("{protected}.{encrypted_key}.{iv}.{ciphertext}.{tag}"))
}
