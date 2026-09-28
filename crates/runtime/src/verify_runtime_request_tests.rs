// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn builds_unsigned_authorization_request() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());

    let result = service.build_authorization_request_proto(&build_request(false));

    assert!(result.request.as_option().is_some());
    assert!(result.request_jwt.is_none());
    assert!(result.binding.as_option().is_some());
    assert!(result.problem.as_option().is_none());
}

#[test]
fn builds_signed_authorization_request_with_injected_signer() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_signer(Arc::new(FixtureSigner)),
    );

    let result = service.build_authorization_request_proto(&build_request(true));

    assert_eq!(result.request_jwt.as_deref(), Some(valid_compact_jws()));
    assert!(result.request.as_option().is_none());
    assert!(result.binding.as_option().is_some());
    assert!(result.problem.as_option().is_none());
}

#[test]
fn reports_problem_when_signer_is_missing() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());

    let result = service.build_authorization_request_proto(&build_request(true));
    let problem = result.problem.as_option().expect("problem is returned");

    assert_eq!(
        problem.kind.as_known(),
        Some(pb::ProblemKind::UnsupportedFeature)
    );
    assert!(result.request_jwt.is_none());
}

#[test]
fn rejects_stateless_authorization_response_validation() {
    let service = VerifierRuntimeService::new(config_with_holder_binding());
    let request = pb::ValidateAuthorizationResponseRequest {
        session: buffa::MessageField::some(
            session_record_to_proto(&session()).expect("test session maps to proto"),
        ),
        response: buffa::MessageField::some(
            authorization_response_to_proto(&response("fedcba9876543210")).expect("response maps to proto"),
        ),
        now_unix: 10,
        __buffa_unknown_fields: Default::default(),
    };

    let result = service.validate_authorization_response_proto(&request);

    let problem = result.problem.as_option().expect("problem is returned");
    assert!(!result.valid);
    assert_eq!(
        problem.kind.as_known(),
        Some(pb::ProblemKind::UnsupportedFeature)
    );
}

#[test]
fn maps_response_validation_failure_to_problem() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let request = pb::ValidateAuthorizationResponseRequest {
        session: buffa::MessageField::some(
            session_record_to_proto(&session()).expect("test session maps to proto"),
        ),
        response: buffa::MessageField::some(
            authorization_response_to_proto(&response("other")).expect("response maps to proto"),
        ),
        now_unix: 10,
        __buffa_unknown_fields: Default::default(),
    };

    let result = service.validate_authorization_response_proto(&request);
    let problem = result.problem.as_option().expect("problem is returned");

    assert!(!result.valid);
    assert_eq!(
        problem.kind.as_known(),
        Some(pb::ProblemKind::UnsupportedFeature)
    );
}

#[test]
fn builds_digital_credential_request_options() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let mut request = authorization_request();
    request.response_mode = Some(ResponseMode::DcApiJwt);
    request.client_id = None;
    request.response_uri = None;
    let proto_request = pb::BuildDigitalCredentialRequestOptionsRequest {
        requests: vec![pb::DigitalCredentialGetRequest {
            protocol: "openid4vp-v1-unsigned".to_owned(),
            data: Some(pb::digital_credential_get_request::Data::UnsignedRequest(
                Box::new(authorization_request_to_proto(&request).expect("request maps to proto")),
            )),
            __buffa_unknown_fields: Default::default(),
        }],
        __buffa_unknown_fields: Default::default(),
    };

    let result = service.build_digital_credential_request_options_proto(&proto_request);

    assert!(result.problem.as_option().is_none());
    let options = result.options.as_option().expect("options are returned");
    assert_eq!(options.requests.len(), 1);
    assert_eq!(options.requests[0].protocol, "openid4vp-v1-unsigned");
}

#[test]
fn rejects_plain_dc_api_authorization_response_without_negotiated_session_context() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let plaintext = reallyme_openid4vp_dc_api::DcApiAuthorizationResponse {
        data: response("fedcba9876543210"),
    };
    let request = pb::DecodeDcApiAuthorizationResponseRequest {
        response: Some(DcApiResponseOneof::Plaintext(Box::new(
            dc_api_authorization_response_to_proto(&plaintext).expect("DC API response maps"),
        ))),
        __buffa_unknown_fields: Default::default(),
    };

    let result = service.decode_dc_api_authorization_response_proto(&request);

    assert!(result.problem.as_option().is_some());
    assert!(result.response.as_option().is_none());
}

#[cfg(feature = "jose")]
#[test]
fn decodes_encrypted_dc_api_authorization_response_with_jose(
) -> Result<(), reallyme_jose::jwe::JweError> {
    let compact = compact_jwe_dir_a128gcm(
        &TEST_JWE_KEY,
        &[9u8; 12],
        br#"{"vp_token":{"pid":["presentation"]},"state":"fedcba9876543210"}"#,
    )?;
    let encrypted = reallyme_openid4vp_dc_api::EncryptedDcApiAuthorizationResponse::new(compact)
        .map_err(|_| reallyme_jose::jwe::JweError::InvalidPayloadJson)?;
    let decryptor = JoseAuthorizationResponseJwtDecryptor::new(
        crate::SessionBoundDirectJweKeyResolver::platform(&TEST_JWE_KEY),
    );
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_response_jwt_decryptor(Arc::new(decryptor)),
    );
    let request = pb::DecodeDcApiAuthorizationResponseRequest {
        response: Some(DcApiResponseOneof::Encrypted(Box::new(
            encrypted_dc_api_authorization_response_to_proto(&encrypted),
        ))),
        __buffa_unknown_fields: Default::default(),
    };

    let result = service.decode_dc_api_authorization_response_proto(&request);

    assert!(result.problem.as_option().is_some());
    assert!(result.response.as_option().is_none());
    Ok(())
}

#[cfg(all(feature = "jose", feature = "native"))]
#[test]
fn decodes_encrypted_dc_api_authorization_response_with_ecdh_es_jose(
) -> Result<(), reallyme_jose::jwe::JweError> {
    let compact =
        compact_jwe_ecdh_es_a128gcm(br#"{"vp_token":{"pid":["presentation"]},"state":"fedcba9876543210"}"#)?;
    let encrypted = reallyme_openid4vp_dc_api::EncryptedDcApiAuthorizationResponse::new(compact)
        .map_err(|_| reallyme_jose::jwe::JweError::InvalidPayloadJson)?;
    let decryptor = JoseAuthorizationResponseJwtDecryptor::new(FixtureEcdhEsP256Resolver);
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_response_jwt_decryptor(Arc::new(decryptor)),
    );
    let request = pb::DecodeDcApiAuthorizationResponseRequest {
        response: Some(DcApiResponseOneof::Encrypted(Box::new(
            encrypted_dc_api_authorization_response_to_proto(&encrypted),
        ))),
        __buffa_unknown_fields: Default::default(),
    };

    let result = service.decode_dc_api_authorization_response_proto(&request);

    assert!(result.problem.as_option().is_some());
    assert!(result.response.as_option().is_none());
    Ok(())
}

#[test]
fn serves_request_object_by_get() {
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Get,
        accept: Some(REQUEST_OBJECT_MEDIA_TYPE.to_owned()),
        content_type: None,
        body: Vec::new(),
    };

    let response = serve_request_object_http(&request, "header.payload.signature", None)
        .expect("request object is served");

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(REQUEST_OBJECT_MEDIA_TYPE));
    assert_eq!(response.cache_control, Some("no-store"));
    assert_eq!(response.body, valid_compact_jws().as_bytes());
}

#[test]
fn serves_request_object_by_post_with_wallet_nonce() {
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: Some("application/*".to_owned()),
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"wallet_nonce=0123456789abcdef".to_vec(),
    };

    let response = serve_request_object_http(&request, "header.payload.signature", Some("0123456789abcdef"))
        .expect("request object is served");

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(REQUEST_OBJECT_MEDIA_TYPE));
}

#[test]
fn serves_request_object_post_with_bounded_wallet_metadata() {
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: Some("application/*".to_owned()),
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"wallet_metadata=%7B%22request_uri_methods_supported%22%3A%5B%22post%22%5D%7D"
            .to_vec(),
    };

    let response = serve_request_object_http(&request, "header.payload.signature", None)
        .expect("valid wallet metadata is accepted");

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(REQUEST_OBJECT_MEDIA_TYPE));
}

#[test]
fn serves_request_object_post_without_optional_parameters() {
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: Some(REQUEST_OBJECT_MEDIA_TYPE.to_owned()),
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: Vec::new(),
    };

    let response = serve_request_object_http(&request, "header.payload.signature", None)
        .expect("wallet nonce and metadata are both optional");

    assert_eq!(response.status, 200);
}

#[test]
fn rejects_request_object_post_wallet_nonce_mismatch() {
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: Some(REQUEST_OBJECT_MEDIA_TYPE.to_owned()),
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"wallet_nonce=other".to_vec(),
    };

    let err = serve_request_object_http(&request, "header.payload.signature", Some("0123456789abcdef"))
        .expect_err("wallet_nonce mismatch is rejected");

    assert_eq!(err.reason(), RuntimeErrorReason::WalletNonceMismatch);
}

#[test]
fn rejects_request_object_post_without_an_expected_wallet_nonce() {
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: Some(REQUEST_OBJECT_MEDIA_TYPE.to_owned()),
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"wallet_nonce=0123456789abcdef".to_vec(),
    };

    let error = serve_request_object_http(&request, "header.payload.signature", None)
        .expect_err("POST cannot serve a Request Object without nonce binding");

    assert_eq!(error.reason(), RuntimeErrorReason::WalletNonceMismatch);
}

#[test]
fn rejects_request_object_get_with_a_post_wallet_nonce_policy() {
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Get,
        accept: Some(REQUEST_OBJECT_MEDIA_TYPE.to_owned()),
        content_type: None,
        body: Vec::new(),
    };

    let error = serve_request_object_http(&request, "header.payload.signature", Some("0123456789abcdef"))
        .expect_err("GET cannot serve a POST-bound Request Object");

    assert_eq!(error.reason(), RuntimeErrorReason::WalletNonceMismatch);
}

#[test]
fn rejects_empty_request_object_post_wallet_nonce() {
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: Some(REQUEST_OBJECT_MEDIA_TYPE.to_owned()),
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"wallet_nonce=".to_vec(),
    };

    let error = serve_request_object_http(&request, "header.payload.signature", Some("0123456789abcdef"))
        .expect_err("empty wallet nonce is rejected");

    assert_eq!(error.reason(), RuntimeErrorReason::InvalidFormBody);
}

#[test]
fn ignores_bounded_unrecognized_request_object_post_parameters() {
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: Some(REQUEST_OBJECT_MEDIA_TYPE.to_owned()),
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"wallet_nonce=0123456789abcdef&ext%65nsion=untrusted&extension=second&empty=".to_vec(),
    };

    let response =
        serve_request_object_http(&request, "header.payload.signature", Some("0123456789abcdef"))
            .expect("bounded unknown POST fields are ignored");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, valid_compact_jws().as_bytes());
}

#[test]
fn rejects_duplicate_request_object_post_wallet_metadata() {
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: Some(REQUEST_OBJECT_MEDIA_TYPE.to_owned()),
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"wallet_metadata=%7B%7D&wallet_metadata=%7B%7D".to_vec(),
    };

    let error = serve_request_object_http(&request, "header.payload.signature", None)
        .expect_err("duplicate wallet metadata is rejected");

    assert_eq!(error.reason(), RuntimeErrorReason::DuplicateFormField);
}

#[test]
fn rejects_malformed_duplicate_and_non_object_wallet_metadata() {
    for body in [
        b"wallet_metadata=%7B".as_slice(),
        b"wallet_metadata=%7B%22a%22%3A1%2C%22a%22%3A2%7D".as_slice(),
        b"wallet_metadata=true".as_slice(),
    ] {
        let request = RuntimeHttpRequest {
            method: RuntimeHttpMethod::Post,
            accept: Some(REQUEST_OBJECT_MEDIA_TYPE.to_owned()),
            content_type: Some("application/x-www-form-urlencoded".to_owned()),
            body: body.to_vec(),
        };

        let error = serve_request_object_http(&request, "header.payload.signature", None)
            .expect_err("malicious wallet metadata is rejected");
        assert_eq!(error.reason(), RuntimeErrorReason::InvalidFormBody);
    }
}

#[test]
fn rejects_overdeep_and_oversized_wallet_metadata() {
    let mut overdeep = String::from("wallet_metadata=");
    for _ in 0..130 {
        overdeep.push_str("{\"a\":");
    }
    overdeep.push_str("true");
    for _ in 0..130 {
        overdeep.push('}');
    }
    let oversized = format!("wallet_metadata={{\"a\":\"{}\"}}", "a".repeat(12 * 1024));

    for body in [overdeep.into_bytes(), oversized.into_bytes()] {
        let request = RuntimeHttpRequest {
            method: RuntimeHttpMethod::Post,
            accept: Some(REQUEST_OBJECT_MEDIA_TYPE.to_owned()),
            content_type: Some("application/x-www-form-urlencoded".to_owned()),
            body,
        };

        let error = serve_request_object_http(&request, "header.payload.signature", None)
            .expect_err("resource-exhaustion wallet metadata is rejected");
        assert_eq!(error.reason(), RuntimeErrorReason::InvalidFormBody);
    }
}

#[test]
fn rejects_oversized_request_object_post_before_parsing() {
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: Some(REQUEST_OBJECT_MEDIA_TYPE.to_owned()),
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: vec![b'a'; (16 * 1024) + 1],
    };

    let error = serve_request_object_http(&request, "header.payload.signature", None)
        .expect_err("oversized request object POST is rejected");

    assert_eq!(error.reason(), RuntimeErrorReason::BodyTooLarge);
}

#[test]
fn handles_valid_direct_post() {
    let service = VerifierRuntimeService::new(config_with_holder_binding());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded; charset=utf-8".to_owned()),
        body: b"vp_token=%7B%22pid%22%3A%5B%22presentation%22%5D%7D&state=fedcba9876543210".to_vec(),
    };

    let session = session();
    let store = FixtureSessionStore::new();
    let response = handle_direct_post_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session, 10).with_session_store(&store, "session"),
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(JSON_MEDIA_TYPE));
    assert_eq!(response.cache_control, Some("no-store"));
    assert_eq!(
        response.body,
        br#"{}"#
    );
}

#[test]
fn successful_direct_post_requires_durable_verified_result_storage() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new()
            .with_holder_binding_verifier(Arc::new(FixtureHolderBindingVerifier)),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"vp_token=%7B%22pid%22%3A%5B%22presentation%22%5D%7D&state=fedcba9876543210".to_vec(),
    };

    let response = handle_direct_post_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 500);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn maps_direct_post_session_mismatch_to_problem_response() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"vp_token=%7B%22pid%22%3A%5B%22presentation%22%5D%7D&state=other".to_vec(),
    };

    let response = handle_direct_post_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
    assert!(!response.body.is_empty());
}

#[test]
fn maps_malformed_direct_post_form_to_problem_response() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"vp_token=%XY".to_vec(),
    };

    let response = handle_direct_post_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn rejects_duplicate_keys_inside_direct_post_vp_token() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body:
            b"vp_token=%7B%22pid%22%3A%5B%22one%22%5D%2C%22pid%22%3A%5B%22two%22%5D%7D&state=fedcba9876543210"
                .to_vec(),
    };

    let response = handle_direct_post_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn runtime_http_debug_redacts_sensitive_bodies() {
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"vp_token=private-presentation".to_vec(),
    };
    let response =
        RuntimeHttpResponse::with_body(200, JSON_MEDIA_TYPE, b"private-response-material".to_vec());

    let request_debug = format!("{request:?}");
    let response_debug = format!("{response:?}");
    assert!(!request_debug.contains("private-presentation"));
    assert!(!response_debug.contains("private-response-material"));
    assert!(request_debug.contains("<redacted>"));
    assert!(response_debug.contains("<redacted>"));
}

#[test]
fn handles_direct_post_authorization_error_response() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"error=access_denied&state=fedcba9876543210".to_vec(),
    };

    let response = handle_direct_post_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(JSON_MEDIA_TYPE));
    assert_eq!(response.body, b"{}");
}

#[test]
fn rejects_direct_post_authorization_error_state_mismatch() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"error=access_denied&state=other".to_vec(),
    };

    let response = handle_direct_post_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn rejects_mixed_direct_post_success_and_error_response() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body:
            b"error=access_denied&vp_token=%7B%22pid%22%3A%5B%22presentation%22%5D%7D&state=fedcba9876543210"
                .to_vec(),
    };

    let response = handle_direct_post_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn rejects_direct_post_authorization_error_with_bad_error_code() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"error=access+denied&state=fedcba9876543210".to_vec(),
    };

    let response = handle_direct_post_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn rejects_oversized_direct_post_body() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"error=access_denied&state=fedcba9876543210".to_vec(),
    };

    let response = handle_direct_post_http(
        &service,
        &request,
        DirectPostValidationContext::new(&session(), 10).with_max_body_bytes(4),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}
