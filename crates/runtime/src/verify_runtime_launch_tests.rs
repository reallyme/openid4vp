// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn prepares_authorization_request_launch() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_signer(Arc::new(FixtureSigner)),
    );
    let store = FixtureLaunchStore::default();

    let launch = service
        .prepare_authorization_request_launch(&authorization_launch_request(), &store, 10)
        .expect("launch preparation succeeds");

    assert_eq!(
        launch.authorization_endpoint,
        "https://suite.example/test/a/module/authorize"
    );
    assert_eq!(launch.parameters.len(), 3);
    assert_eq!(
        launch.parameters[0].name,
        AuthorizationRequestParameterName::ClientId
    );
    assert_eq!(launch.parameters[0].value, "x509_san_dns:verifier.example");
    assert_eq!(
        launch.parameters[1].name,
        AuthorizationRequestParameterName::RequestUri
    );
    assert_eq!(
        launch.parameters[1].value,
        "https://verifier.example/request/request-1"
    );
    assert_eq!(
        launch.parameters[2].name,
        AuthorizationRequestParameterName::RequestUriMethod
    );
    assert_eq!(launch.parameters[2].value, "post");

    let records = store
        .records
        .lock()
        .expect("fixture store lock is available");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].session_key, "session-1");
    assert_eq!(records[0].request_object_key, "request-1");
    assert_eq!(records[0].session.state.as_deref(), Some("fedcba9876543210"));
    assert_eq!(records[0].session.binding.nonce, "0123456789abcdef");
    assert_eq!(records[0].session.response_mode, ResponseMode::DirectPostJwt);
    assert_eq!(
        records[0]
            .session
            .mdoc_session_transcript
            .as_ref()
            .map(reallyme_openid4vp_verifier::RetainedMdocSessionTranscript::as_bytes),
        Some([0x83, 0xf6, 0xf6, 0x80].as_slice())
    );
    assert_eq!(
        records[0].session.binding.response_uri.as_deref(),
        Some("https://verifier.example/direct_post.jwt/session-1")
    );
    assert!(matches!(
        &records[0].request_object,
        HostedRequestObject::DeferredPost {
            authorization_request
        } if authorization_request.wallet_nonce.is_none()
    ));
}

#[test]
fn launch_rejects_response_modes_without_a_runtime_endpoint() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_signer(Arc::new(FixtureSigner)),
    );
    for response_mode in [ResponseMode::Fragment, ResponseMode::FormPost, ResponseMode::DcApi] {
        let store = FixtureLaunchStore::default();
        let mut request = authorization_launch_request();
        request.authorization_request.response_mode = Some(response_mode);

        let error = service
            .prepare_authorization_request_launch(&request, &store, 10)
            .expect_err("launch must retain only a response mode owned by this runtime");
        assert_eq!(error.reason(), RuntimeErrorReason::UnsupportedFeature);
        assert!(
            store
                .records
                .lock()
                .expect("fixture store lock is available")
                .is_empty()
        );
    }
}
#[test]
fn get_launch_stores_an_immediately_signed_request_object() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_signer(Arc::new(FixtureSigner)),
    );
    let store = FixtureLaunchStore::default();
    let mut request = authorization_launch_request();
    request.request_uri_method = RequestUriMethod::Get;

    let launch = service
        .prepare_authorization_request_launch(&request, &store, 10)
        .expect("GET launch preparation succeeds");

    assert_eq!(launch.parameters.len(), 2);
    let records = store
        .records
        .lock()
        .expect("fixture store lock is available");
    assert!(matches!(
        &records[0].request_object,
        HostedRequestObject::Signed { request_object_jwt }
            if request_object_jwt.as_str() == valid_compact_jws()
    ));
}

#[test]
fn launch_rejects_a_prebound_wallet_nonce() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_signer(Arc::new(FixtureSigner)),
    );
    let store = FixtureLaunchStore::default();
    let mut request = authorization_launch_request();
    request.authorization_request.wallet_nonce = Some("stale-wallet-nonce".to_owned());

    let error = service
        .prepare_authorization_request_launch(&request, &store, 10)
        .expect_err("a wallet nonce cannot be known at launch time");

    assert_eq!(error.reason(), RuntimeErrorReason::WalletNonceMismatch);
    assert!(
        store
            .records
            .lock()
            .expect("fixture store lock is available")
            .is_empty()
    );
}

#[test]
fn launch_requires_a_live_browser_binding_for_every_post_response_redirect() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_signer(Arc::new(FixtureSigner)),
    );
    let redirect = PostResponseRedirectUri::parse("https://verifier.example/result".to_owned())
        .expect("test redirect is valid");

    let mut missing_binding = authorization_launch_request();
    missing_binding.post_response_redirect_uri = Some(redirect.clone());
    let missing_error = service
        .prepare_authorization_request_launch(&missing_binding, &FixtureLaunchStore::default(), 10)
        .expect_err("redirect without initiating browser receipt is rejected");
    assert_eq!(
        missing_error.reason(),
        RuntimeErrorReason::InvalidFollowBackRequirement
    );

    let mut expired = authorization_launch_request();
    expired.post_response_redirect_uri = Some(redirect.clone());
    expired.follow_back_requirement = Some(
        FollowBackRequirement::new(BrowserSessionBinding::new([19_u8; 32]), 10)
            .expect("nonzero deadline is structurally valid"),
    );
    let expired_error = service
        .prepare_authorization_request_launch(&expired, &FixtureLaunchStore::default(), 10)
        .expect_err("expired initiating browser receipt is rejected");
    assert_eq!(
        expired_error.reason(),
        RuntimeErrorReason::InvalidFollowBackRequirement
    );

    let mut beyond_request_expiry = authorization_launch_request();
    beyond_request_expiry.post_response_redirect_uri = Some(redirect.clone());
    beyond_request_expiry.follow_back_requirement = Some(
        FollowBackRequirement::new(BrowserSessionBinding::new([19_u8; 32]), 101)
            .expect("nonzero deadline is structurally valid"),
    );
    let beyond_error = service
        .prepare_authorization_request_launch(
            &beyond_request_expiry,
            &FixtureLaunchStore::default(),
            10,
        )
        .expect_err("follow-back cannot outlive the signed request");
    assert_eq!(
        beyond_error.reason(),
        RuntimeErrorReason::InvalidFollowBackRequirement
    );

    let store = FixtureLaunchStore::default();
    let mut valid = authorization_launch_request();
    valid.post_response_redirect_uri = Some(redirect);
    valid.follow_back_requirement = Some(
        FollowBackRequirement::new(BrowserSessionBinding::new([19_u8; 32]), 20)
            .expect("test follow-back requirement is valid"),
    );
    service
        .prepare_authorization_request_launch(&valid, &store, 10)
        .expect("live, request-bounded follow-back is stored");
    let records = store
        .records
        .lock()
        .expect("fixture store lock is available");
    assert_eq!(
        records[0]
            .session
            .follow_back_requirement
            .as_ref()
            .map(FollowBackRequirement::expires_unix),
        Some(20)
    );
}

#[test]
fn builds_authorization_request_launch_response_body() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_signer(Arc::new(FixtureSigner)),
    );
    let store = FixtureLaunchStore::default();
    let launch = service
        .prepare_authorization_request_launch(&authorization_launch_request(), &store, 10)
        .expect("launch preparation succeeds");

    let response = authorization_request_launch_response(&launch).expect("launch response encodes");

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(JSON_MEDIA_TYPE));
    assert_eq!(response.cache_control, Some("no-store"));
    let body: serde_json::Value =
        serde_json::from_slice(&response.body).expect("response is valid json");
    assert_eq!(
        body["authorization_endpoint"],
        "https://suite.example/test/a/module/authorize"
    );
    assert_eq!(body["parameters"][0]["name"], "client_id");
    assert_eq!(
        body["parameters"][1]["value"],
        "https://verifier.example/request/request-1"
    );
}

#[test]
fn handles_authorization_request_launch_http() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_signer(Arc::new(FixtureSigner)),
    );
    let store = FixtureLaunchStore::default();
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some(JSON_MEDIA_TYPE.to_owned()),
        body: br#"{"authorization_endpoint":"https://suite.example/test/a/module/authorize","module_id":"module-1","plan_id":"oid4vp-1final-verifier-haip-test-plan","profile_id":"verifier-sd-jwt-vc-direct-post-jwt","module_name":"happy"}"#.to_vec(),
    };

    let response = handle_authorization_request_launch_http(
        &request,
        AuthorizationRequestLaunchHttpContext::new(&service, &FixtureLaunchPlanner, &store, 10),
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, Some(JSON_MEDIA_TYPE));
    let body: serde_json::Value =
        serde_json::from_slice(&response.body).expect("response is valid json");
    assert_eq!(
        body["authorization_endpoint"],
        "https://suite.example/test/a/module/authorize"
    );
    assert_eq!(
        body["parameters"][1]["value"],
        "https://verifier.example/request/module-1"
    );
    let records = store
        .records
        .lock()
        .expect("fixture store lock is available");
    assert_eq!(records[0].session_key, "module-1");
    assert_eq!(records[0].request_object_key, "module-1");
    let evidence_context = records[0]
        .evidence_context
        .as_ref()
        .expect("evidence context is committed with launch material");
    assert_eq!(
        evidence_context.plan_id(),
        "oid4vp-1final-verifier-haip-test-plan"
    );
    assert_eq!(
        evidence_context.profile_id(),
        "verifier-sd-jwt-vc-direct-post-jwt"
    );
    assert_eq!(evidence_context.module_id(), "module-1");
}

#[test]
fn launch_http_rejects_non_post() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_signer(Arc::new(FixtureSigner)),
    );
    let store = FixtureLaunchStore::default();
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Get,
        accept: None,
        content_type: Some(JSON_MEDIA_TYPE.to_owned()),
        body: Vec::new(),
    };

    let response = handle_authorization_request_launch_http(
        &request,
        AuthorizationRequestLaunchHttpContext::new(&service, &FixtureLaunchPlanner, &store, 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn launch_http_rejects_malformed_json() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_signer(Arc::new(FixtureSigner)),
    );
    let store = FixtureLaunchStore::default();
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some(JSON_MEDIA_TYPE.to_owned()),
        body: b"not-json".to_vec(),
    };

    let response = handle_authorization_request_launch_http(
        &request,
        AuthorizationRequestLaunchHttpContext::new(&service, &FixtureLaunchPlanner, &store, 10),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

#[test]
fn launch_preparation_requires_signer() {
    let service = VerifierRuntimeService::new(VerifierRuntimeConfig::new());
    let store = FixtureLaunchStore::default();

    let err = service
        .prepare_authorization_request_launch(&authorization_launch_request(), &store, 10)
        .expect_err("missing signer is rejected");

    assert_eq!(err.reason(), RuntimeErrorReason::MissingSigner);
}

#[test]
fn launch_preparation_surfaces_store_failure() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_signer(Arc::new(FixtureSigner)),
    );

    let err = service
        .prepare_authorization_request_launch(
            &authorization_launch_request(),
            &FailingLaunchStore,
            10,
        )
        .expect_err("store failure is rejected");

    assert_eq!(err.reason(), RuntimeErrorReason::LaunchStoreFailed);
}

#[test]
fn launch_http_rolls_back_provider_material_after_store_failure() {
    let service = VerifierRuntimeService::new(
        VerifierRuntimeConfig::new().with_signer(Arc::new(FixtureSigner)),
    );
    let planner = CapturingLaunchPlanner::default();
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some(JSON_MEDIA_TYPE.to_owned()),
        body: serde_json::to_vec(&serde_json::json!({
            "authorization_endpoint": "https://suite.example/test/a/module/authorize",
            "module_id": "module-1",
            "plan_id": "oid4vp-1final-verifier-haip-test-plan",
            "profile_id": "verifier-sd-jwt-vc-direct-post-jwt",
            "module_name": "oid4vp-1final-verifier-happy-flow"
        }))
        .expect("test request serializes"),
    };

    let response = handle_authorization_request_launch_http(
        &request,
        AuthorizationRequestLaunchHttpContext::new(&service, &planner, &FailingLaunchStore, 10),
    );

    assert_eq!(response.status, 500);
    assert_eq!(
        *planner
            .cancellations
            .lock()
            .expect("fixture cancellation lock is available"),
        vec!["module-1".to_owned()]
    );
}
