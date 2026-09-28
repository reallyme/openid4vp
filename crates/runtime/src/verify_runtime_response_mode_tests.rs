// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn verifier_http_runtime_routes_direct_post_jwt_endpoint() {
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(
            config_with_holder_binding()
                .with_response_jwt_decryptor(Arc::new(FixtureResponseJwtDecryptor)),
        )),
        Arc::new(FixtureSessionStore::with_response_mode(
            ResponseMode::DirectPostJwt,
        )),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: format!("response={}", valid_compact_jwe()).into_bytes(),
    };

    let response = runtime.handle(
        VerifierHttpEndpoint::DirectPostJwt {
            session_key: "session",
        },
        &request,
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(JSON_MEDIA_TYPE));
}

#[test]
fn verifier_http_runtime_releases_encrypted_session_after_decryption_failure() {
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(
            config_with_holder_binding()
                .with_response_jwt_decryptor(Arc::new(FixtureResponseJwtDecryptor)),
        )),
        Arc::new(FixtureSessionStore::with_response_mode(
            ResponseMode::DirectPostJwt,
        )),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    );
    let rejected_request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"response=YQ..YQ.YQ.YQ".to_vec(),
    };

    let rejected = runtime.handle(
        VerifierHttpEndpoint::DirectPostJwt {
            session_key: "session",
        },
        &rejected_request,
    );
    let valid_request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: format!("response={}", valid_compact_jwe()).into_bytes(),
    };
    let accepted = runtime.handle(
        VerifierHttpEndpoint::DirectPostJwt {
            session_key: "session",
        },
        &valid_request,
    );

    assert_eq!(rejected.status, 400);
    assert_eq!(accepted.status, 200);
}

#[test]
fn verifier_http_runtime_rejects_plaintext_route_for_encrypted_session() {
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(
            config_with_holder_binding()
                .with_response_jwt_decryptor(Arc::new(FixtureResponseJwtDecryptor)),
        )),
        Arc::new(FixtureSessionStore::with_response_mode(
            ResponseMode::DirectPostJwt,
        )),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    );
    let plaintext = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"vp_token=%7B%22pid%22%3A%5B%22presentation%22%5D%7D&state=fedcba9876543210".to_vec(),
    };
    let encrypted = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: format!("response={}", valid_compact_jwe()).into_bytes(),
    };

    let rejected = runtime.handle(
        VerifierHttpEndpoint::DirectPost {
            session_key: "session",
        },
        &plaintext,
    );
    let accepted = runtime.handle(
        VerifierHttpEndpoint::DirectPostJwt {
            session_key: "session",
        },
        &encrypted,
    );

    assert_eq!(rejected.status, 400);
    assert_eq!(accepted.status, 200);
}

#[test]
fn verifier_http_runtime_rejects_encrypted_route_for_plaintext_session() {
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(config_with_holder_binding())),
        Arc::new(FixtureSessionStore::new()),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    );
    let encrypted = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: format!("response={}", valid_compact_jwe()).into_bytes(),
    };
    let plaintext = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"vp_token=%7B%22pid%22%3A%5B%22presentation%22%5D%7D&state=fedcba9876543210".to_vec(),
    };

    let rejected = runtime.handle(
        VerifierHttpEndpoint::DirectPostJwt {
            session_key: "session",
        },
        &encrypted,
    );
    let accepted = runtime.handle(
        VerifierHttpEndpoint::DirectPost {
            session_key: "session",
        },
        &plaintext,
    );

    assert_eq!(rejected.status, 400);
    assert_eq!(accepted.status, 200);
}

#[test]
fn authorization_error_does_not_consume_or_redirect_the_session() {
    let sessions = Arc::new(FixtureSessionStore::new());
    let recorder = Arc::new(FixtureEvidenceRecorder::default());
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(config_with_holder_binding())),
        sessions.clone(),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    )
    .with_evidence_recorder(recorder.clone());
    let error = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"error=access_denied&state=fedcba9876543210".to_vec(),
    };
    let success = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"vp_token=%7B%22pid%22%3A%5B%22presentation%22%5D%7D&state=fedcba9876543210".to_vec(),
    };

    let error_response = runtime.handle(
        VerifierHttpEndpoint::DirectPost {
            session_key: "session",
        },
        &error,
    );
    let repeated_error_response = runtime.handle(
        VerifierHttpEndpoint::DirectPost {
            session_key: "session",
        },
        &error,
    );
    assert!(sessions.persisted_outcome().is_none());
    let success_response = runtime.handle(
        VerifierHttpEndpoint::DirectPost {
            session_key: "session",
        },
        &success,
    );

    assert_eq!(error_response.status, 200);
    assert_eq!(error_response.body, b"{}");
    assert_eq!(repeated_error_response.status, 200);
    assert_eq!(success_response.status, 200);
    let records = recorder
        .records
        .lock()
        .expect("fixture evidence lock is available");
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].1.outcome, VerifierEvidenceOutcome::Rejected);
    assert_eq!(records[1].1.outcome, VerifierEvidenceOutcome::Rejected);
    assert_eq!(records[2].1.outcome, VerifierEvidenceOutcome::Accepted);
}
