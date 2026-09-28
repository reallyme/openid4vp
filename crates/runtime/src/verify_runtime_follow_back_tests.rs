// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn verifier_http_runtime_releases_follow_back_result_only_to_initiating_browser() {
    let sessions = Arc::new(FixtureSessionStore::with_follow_back(20));
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(config_with_holder_binding())),
        sessions.clone(),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    );
    let direct_post = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"vp_token=%7B%22pid%22%3A%5B%22presentation%22%5D%7D&state=fedcba9876543210".to_vec(),
    };

    let accepted = runtime.handle(
        VerifierHttpEndpoint::DirectPost {
            session_key: "session",
        },
        &direct_post,
    );
    assert_eq!(accepted.status, 200);
    assert!(sessions.persisted_outcome().is_none());
    let code = ResponseCode::parse(
        sessions
            .pending_response_code()
            .expect("accepted result remains pending"),
    )
    .expect("stored response code is valid");
    let follow_back = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: None,
        body: Vec::new(),
    };

    let released = runtime.handle(
        VerifierHttpEndpoint::FollowBack {
            response_code: &code,
            browser_session: &BrowserSessionBinding::new([19_u8; 32]),
        },
        &follow_back,
    );
    assert_eq!(released.status, 204);
    assert!(sessions.persisted_outcome().is_some());
}

#[test]
fn verifier_http_runtime_rejects_wrong_browser_and_replayed_follow_back() {
    let sessions = Arc::new(FixtureSessionStore::with_follow_back(20));
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(config_with_holder_binding())),
        sessions.clone(),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    );
    let direct_post = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"vp_token=%7B%22pid%22%3A%5B%22presentation%22%5D%7D&state=fedcba9876543210".to_vec(),
    };
    let accepted = runtime.handle(
        VerifierHttpEndpoint::DirectPost {
            session_key: "session",
        },
        &direct_post,
    );
    assert_eq!(accepted.status, 200);
    let code = ResponseCode::parse(
        sessions
            .pending_response_code()
            .expect("accepted result remains pending"),
    )
    .expect("stored response code is valid");
    let follow_back = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: None,
        body: Vec::new(),
    };

    let wrong_browser = runtime.handle(
        VerifierHttpEndpoint::FollowBack {
            response_code: &code,
            browser_session: &BrowserSessionBinding::new([20_u8; 32]),
        },
        &follow_back,
    );
    assert_eq!(wrong_browser.status, 400);
    assert!(sessions.persisted_outcome().is_none());

    let released = runtime.handle(
        VerifierHttpEndpoint::FollowBack {
            response_code: &code,
            browser_session: &BrowserSessionBinding::new([19_u8; 32]),
        },
        &follow_back,
    );
    assert_eq!(released.status, 204);

    let replay = runtime.handle(
        VerifierHttpEndpoint::FollowBack {
            response_code: &code,
            browser_session: &BrowserSessionBinding::new([19_u8; 32]),
        },
        &follow_back,
    );
    assert_eq!(replay.status, 400);
}

#[test]
fn verifier_http_runtime_keeps_timed_out_follow_back_result_unreleased() {
    let sessions = Arc::new(FixtureSessionStore::with_follow_back(20));
    let accepting_runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(config_with_holder_binding())),
        sessions.clone(),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    );
    let direct_post = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"vp_token=%7B%22pid%22%3A%5B%22presentation%22%5D%7D&state=fedcba9876543210".to_vec(),
    };
    let accepted = accepting_runtime.handle(
        VerifierHttpEndpoint::DirectPost {
            session_key: "session",
        },
        &direct_post,
    );
    assert_eq!(accepted.status, 200);
    let code = ResponseCode::parse(
        sessions
            .pending_response_code()
            .expect("accepted result remains pending"),
    )
    .expect("stored response code is valid");
    let expired_runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(config_with_holder_binding())),
        sessions.clone(),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixedClock(21)),
    );
    let follow_back = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: None,
        body: Vec::new(),
    };

    let expired = expired_runtime.handle(
        VerifierHttpEndpoint::FollowBack {
            response_code: &code,
            browser_session: &BrowserSessionBinding::new([19_u8; 32]),
        },
        &follow_back,
    );

    assert_eq!(expired.status, 400);
    assert!(sessions.persisted_outcome().is_none());
}

#[test]
fn authorization_error_does_not_create_a_follow_back_result() {
    let sessions = Arc::new(FixtureSessionStore::with_follow_back(20));
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(config_with_holder_binding())),
        sessions.clone(),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    );
    let error_response = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"error=access_denied&state=fedcba9876543210".to_vec(),
    };

    let acknowledged = runtime.handle(
        VerifierHttpEndpoint::DirectPost {
            session_key: "session",
        },
        &error_response,
    );

    assert_eq!(acknowledged.status, 200);
    assert!(sessions.pending_response_code().is_none());
    assert!(sessions.persisted_outcome().is_none());
    assert!(sessions.load_session("session").is_ok());
}

#[test]
fn verifier_http_runtime_allows_only_one_concurrent_commit() {
    let sessions = Arc::new(FixtureSessionStore::new());
    let runtime = Arc::new(VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(config_with_holder_binding())),
        sessions.clone(),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    ));
    let request = Arc::new(RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"vp_token=%7B%22pid%22%3A%5B%22presentation%22%5D%7D&state=fedcba9876543210".to_vec(),
    });

    let mut statuses = std::thread::scope(|scope| {
        let first_runtime = runtime.clone();
        let first_request = request.clone();
        let first = scope.spawn(move || {
            first_runtime
                .handle(
                    VerifierHttpEndpoint::DirectPost {
                        session_key: "session",
                    },
                    &first_request,
                )
                .status
        });
        let second_runtime = runtime.clone();
        let second_request = request.clone();
        let second = scope.spawn(move || {
            second_runtime
                .handle(
                    VerifierHttpEndpoint::DirectPost {
                        session_key: "session",
                    },
                    &second_request,
                )
                .status
        });
        vec![
            first.join().unwrap_or(500),
            second.join().unwrap_or(500),
        ]
    });
    statuses.sort_unstable();

    assert_eq!(statuses, vec![200, 400]);
    assert!(sessions.persisted_outcome().is_some());
}

#[test]
fn verifier_http_runtime_releases_reservation_when_atomic_commit_fails() {
    let sessions = Arc::new(FailingCommitSessionStore::new());
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

    let response = runtime.handle(
        VerifierHttpEndpoint::DirectPost {
            session_key: "session",
        },
        &request,
    );

    assert_eq!(response.status, 500);
    assert!(sessions.load_session("session").is_ok());
    assert!(sessions.inner.persisted_outcome().is_none());
}

#[test]
fn verifier_http_runtime_does_not_consume_session_for_invalid_response() {
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(config_with_holder_binding())),
        Arc::new(FixtureSessionStore::new()),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    );
    let invalid = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"vp_token=%7B%22pid%22%3A%5B%22presentation%22%5D%7D&state=wrong-state-value".to_vec(),
    };
    let valid = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"vp_token=%7B%22pid%22%3A%5B%22presentation%22%5D%7D&state=fedcba9876543210".to_vec(),
    };

    let rejected = runtime.handle(
        VerifierHttpEndpoint::DirectPost {
            session_key: "session",
        },
        &invalid,
    );
    let accepted = runtime.handle(
        VerifierHttpEndpoint::DirectPost {
            session_key: "session",
        },
        &valid,
    );

    assert_eq!(rejected.status, 400);
    assert_eq!(accepted.status, 200);
}

#[test]
fn verifier_http_runtime_maps_missing_session_to_problem() {
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(VerifierRuntimeConfig::new())),
        Arc::new(FixtureSessionStore::new()),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    );
    let request = RuntimeHttpRequest {
        method: RuntimeHttpMethod::Post,
        accept: None,
        content_type: Some("application/x-www-form-urlencoded".to_owned()),
        body: b"vp_token=%7B%22pid%22%3A%5B%22presentation%22%5D%7D&state=fedcba9876543210".to_vec(),
    };

    let response = runtime.handle(
        VerifierHttpEndpoint::DirectPost {
            session_key: "missing",
        },
        &request,
    );

    assert_eq!(response.status, 404);
    assert_eq!(response.content_type, Some(PROBLEM_JSON_MEDIA_TYPE));
}

