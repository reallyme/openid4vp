// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn common_credential_root_private_persona_response_uses_active_request_and_policy() {
    let legacy = EvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
    };
    let common_credential_root = CommonCredentialRootEvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
        expected_request_time_unix: COMMON_CREDENTIAL_ROOT_NOW,
    };
    let verifier = ZkHolderBindingVerifier::new_with_common_credential_root(
        &legacy,
        &[TRUSTED_ISSUER],
        ZkVerificationRequirements {
            issuer_signed_validity: false,
            credential_status: false,
        },
        &common_credential_root,
        common_credential_root_policy(COMMON_CREDENTIAL_ROOT_STATUS_ROOT),
    );
    let session = common_credential_root_session();
    let response = AuthorizationResponse {
        vp_token: [(
            QueryId::parse("pid").expect("valid query id"),
            vec![common_credential_root_presentation(false)],
        )]
        .into_iter()
        .collect(),
        state: session.state.clone(),
    };

    let diagnostics = diagnose_authorization_response_with_options(
        &session,
        &response,
        COMMON_CREDENTIAL_ROOT_NOW,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&verifier),
        },
    )
    .expect("valid common-credential-root response is accepted");
    assert_eq!(diagnostics.verified_presentations().len(), 1);
    let disclosure = diagnostics.verified_presentations()[0]
        .holder_binding()
        .disclosures();
    let VerifiedDisclosureSet::ZkCommonCredentialRoot(verified) = disclosure else {
        assert!(matches!(disclosure, VerifiedDisclosureSet::ZkCommonCredentialRoot(_)));
        return;
    };
    assert_eq!(verified.persona_mode(), ZkCommonCredentialRootPersonaMode::PrivatePersona);
    assert_eq!(verified.claims()[0].claim_value(), COMMON_CREDENTIAL_ROOT_FIRST_VALUE);
    assert_eq!(verified.claims()[1].claim_value(), COMMON_CREDENTIAL_ROOT_SECOND_VALUE);
    assert_eq!(common_credential_root.calls.load(Ordering::SeqCst), 1);
    assert_eq!(legacy.calls.load(Ordering::SeqCst), 0);
}
#[test]
fn common_credential_root_rechecks_status_floor_after_backend_verification() {
    let mut secret = zeroize::Zeroizing::new([0_u8; 32]);
    secret[31] = 41;
    let (public_key, _) = reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&secret)
        .expect("test issuer key is valid");
    let status_verifier = TestIssuerStatusVerifier {
        issuer: "did:example:issuer",
        public_key: public_key.to_vec(),
    };
    let issuer_floor = TestIssuerStatusFloor::default();
    let root_floor = TestRootStatusFloor::default();
    let first = signed_issuer_status_list(&secret, [1; 32], 9);
    let second = signed_issuer_status_list(&secret, [2; 32], 9);
    let (snapshot, authority) = signed_status_snapshot(COMMON_CREDENTIAL_ROOT_STATUS_ROOT, 9, 200);
    let policy = ZkCommonCredentialRootVerificationPolicy::try_from_signed_snapshot_with_issuer_status(
        ZkCommonCredentialRootTrustPolicy {
            attestation_signer: attestation_key(0xa0),
            assurance_policy_id: COMMON_CREDENTIAL_ROOT_POLICY_ID,
            credential_issuers: [issuer_key(0xc0), issuer_key(0xc2)],
            status_feed_id: [0x5a; 32],
            status: ZkRootStatusTrustPolicy {
                authority,
                minimum_sequence: 2,
                maximum_age_seconds: 300,
            },
        },
        snapshot,
        &root_floor,
        [
            test_status_trust(
                &first,
                "https://issuer.example/first",
                &status_verifier,
                &issuer_floor,
            ),
            test_status_trust(
                &second,
                "https://issuer.example/second",
                &status_verifier,
                &issuer_floor,
            ),
        ],
        COMMON_CREDENTIAL_ROOT_NOW,
    )
    .expect("signed status admits the policy");
    let binding =
        build_zk_presentation_binding("0123456789abcdef", "x509_san_dns:verifier.example", None);
    let mut stages = common_credential_root_stages(binding.clone(), false);
    let status = policy.issuer_status.expect("two authenticated lists");
    for (slot, evidence) in status.iter().enumerate() {
        let stage = &mut stages[7 + slot].public_inputs;
        set_bytes(stage, 193, &evidence.expectation.root);
        set_u64(stage, 225, evidence.expectation.length);
        set_bytes(stage, 226, &evidence.expectation.list_id);
        set_bytes(stage, 258, &evidence.expectation.url_hash);
    }
    let presentation = encode_zk_presentation_value(ZkPresentation {
        type_: ZK_PRESENTATION_TYPE.to_owned(),
        profile: ZkPresentationProfile::CommonCredentialRootPrivatePersonaV1,
        proof_suite: ZkPresentationProofSuite::BarretenbergUltraHonkKeccakZkNoIpa,
        stages,
        derived_claims: Vec::new(),
        binding,
    })
    .expect("test presentation encodes");
    let backend = AdvancingRootEvidenceVerifier {
        floor: &root_floor,
        feed_id: [0x5a; 32],
        calls: AtomicUsize::new(0),
    };
    let legacy = EvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
    };
    let verifier = ZkHolderBindingVerifier::new_with_common_credential_root(
        &legacy,
        &[TRUSTED_ISSUER],
        ZkVerificationRequirements {
            issuer_signed_validity: true,
            credential_status: true,
        },
        &backend,
        policy,
    );
    let session = common_credential_root_session();
    let result = verifier.verify_holder_binding(
        &presentation,
        HolderBindingVerificationContext::new(
            &session,
            &session.dcql_query.credentials[0],
            COMMON_CREDENTIAL_ROOT_NOW,
        ),
    );
    assert_eq!(
        result.err().map(VerifierError::reason),
        Some(VerifierErrorReason::InvalidRootAssuranceStatus)
    );
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
}
#[test]
fn common_credential_root_uses_retained_request_time_for_delayed_response() {
    let legacy = EvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
    };
    let common_credential_root = CommonCredentialRootEvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
        expected_request_time_unix: COMMON_CREDENTIAL_ROOT_NOW,
    };
    let policy = common_credential_root_policy_for_window(
        COMMON_CREDENTIAL_ROOT_STATUS_ROOT,
        COMMON_CREDENTIAL_ROOT_NOW - 1,
        COMMON_CREDENTIAL_ROOT_NOW + 11,
        COMMON_CREDENTIAL_ROOT_NOW,
    );
    let verifier = ZkHolderBindingVerifier::new_with_common_credential_root(
        &legacy,
        &[TRUSTED_ISSUER],
        ZkVerificationRequirements {
            issuer_signed_validity: false,
            credential_status: false,
        },
        &common_credential_root,
        policy,
    );
    let session = common_credential_root_session();
    let response = AuthorizationResponse {
        vp_token: [(
            QueryId::parse("pid").expect("valid query id"),
            vec![common_credential_root_presentation(false)],
        )]
        .into_iter()
        .collect(),
        state: session.state.clone(),
    };

    diagnose_authorization_response_with_options(
        &session,
        &response,
        COMMON_CREDENTIAL_ROOT_NOW + 5,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&verifier),
        },
    )
    .expect("request-bound common-credential-root proof remains valid after proving delay");
    assert_eq!(common_credential_root.calls.load(Ordering::SeqCst), 1);
    assert_eq!(legacy.calls.load(Ordering::SeqCst), 0);
}
#[test]
fn common_credential_root_rejects_future_retained_request_time() {
    let legacy = EvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
    };
    let common_credential_root = CommonCredentialRootEvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
        expected_request_time_unix: COMMON_CREDENTIAL_ROOT_NOW + 1,
    };
    let verifier = ZkHolderBindingVerifier::new_with_common_credential_root(
        &legacy,
        &[TRUSTED_ISSUER],
        ZkVerificationRequirements {
            issuer_signed_validity: false,
            credential_status: false,
        },
        &common_credential_root,
        common_credential_root_policy(COMMON_CREDENTIAL_ROOT_STATUS_ROOT),
    );
    let mut session = common_credential_root_session();
    session.binding.request_time_unix = COMMON_CREDENTIAL_ROOT_NOW + 1;
    let response = AuthorizationResponse {
        vp_token: [(
            QueryId::parse("pid").expect("valid query id"),
            vec![common_credential_root_presentation(false)],
        )]
        .into_iter()
        .collect(),
        state: session.state.clone(),
    };

    let error = diagnose_authorization_response_with_options(
        &session,
        &response,
        COMMON_CREDENTIAL_ROOT_NOW,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&verifier),
        },
    )
    .expect_err("future retained request time must fail before proof verification");
    assert_eq!(error.reason(), VerifierErrorReason::InvalidBinding);
    assert_eq!(common_credential_root.calls.load(Ordering::SeqCst), 0);
    assert_eq!(legacy.calls.load(Ordering::SeqCst), 0);
}
#[test]
fn common_credential_root_rejects_response_after_proof_expiry() {
    let legacy = EvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
    };
    let common_credential_root = CommonCredentialRootEvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
        expected_request_time_unix: COMMON_CREDENTIAL_ROOT_NOW,
    };
    let policy = common_credential_root_policy_for_window(
        COMMON_CREDENTIAL_ROOT_STATUS_ROOT,
        COMMON_CREDENTIAL_ROOT_NOW - 1,
        COMMON_CREDENTIAL_ROOT_EXPIRY + 2,
        COMMON_CREDENTIAL_ROOT_NOW,
    );
    let verifier = ZkHolderBindingVerifier::new_with_common_credential_root(
        &legacy,
        &[TRUSTED_ISSUER],
        ZkVerificationRequirements {
            issuer_signed_validity: false,
            credential_status: false,
        },
        &common_credential_root,
        policy,
    );
    let session = common_credential_root_session();
    let response = AuthorizationResponse {
        vp_token: [(
            QueryId::parse("pid").expect("valid query id"),
            vec![common_credential_root_presentation(false)],
        )]
        .into_iter()
        .collect(),
        state: session.state.clone(),
    };

    let error = diagnose_authorization_response_with_options(
        &session,
        &response,
        COMMON_CREDENTIAL_ROOT_EXPIRY,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&verifier),
        },
    )
    .expect_err("expired common-credential-root session proof must fail even while session is retained");
    assert_eq!(error.reason(), VerifierErrorReason::InvalidZkPresentation);
    assert_eq!(common_credential_root.calls.load(Ordering::SeqCst), 0);
    assert_eq!(legacy.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn common_credential_root_accepts_issuer_status_requirement_with_both_status_proofs() {
    let legacy = EvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
    };
    let common_credential_root = CommonCredentialRootEvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
        expected_request_time_unix: COMMON_CREDENTIAL_ROOT_NOW,
    };
    let verifier = ZkHolderBindingVerifier::new_with_common_credential_root(
        &legacy,
        &[TRUSTED_ISSUER],
        ZkVerificationRequirements {
            issuer_signed_validity: false,
            credential_status: true,
        },
        &common_credential_root,
        common_credential_root_policy(COMMON_CREDENTIAL_ROOT_STATUS_ROOT),
    );
    let session = common_credential_root_session();
    verifier
        .verify_holder_binding(
            &common_credential_root_presentation(false),
            HolderBindingVerificationContext::new(
                &session,
                &session.dcql_query.credentials[0],
                COMMON_CREDENTIAL_ROOT_NOW,
            ),
        )
        .expect("both issuer status proofs meet the requirement");
    assert_eq!(common_credential_root.calls.load(Ordering::SeqCst), 1);
    assert_eq!(legacy.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn common_credential_root_accepts_issuer_signed_validity_requirement() {
    let legacy = EvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
    };
    let common_credential_root = CommonCredentialRootEvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
        expected_request_time_unix: COMMON_CREDENTIAL_ROOT_NOW,
    };
    let verifier = ZkHolderBindingVerifier::new_with_common_credential_root(
        &legacy,
        &[TRUSTED_ISSUER],
        ZkVerificationRequirements {
            issuer_signed_validity: true,
            credential_status: false,
        },
        &common_credential_root,
        common_credential_root_policy(COMMON_CREDENTIAL_ROOT_STATUS_ROOT),
    );
    let session = common_credential_root_session();
    verifier
        .verify_holder_binding(
            &common_credential_root_presentation(false),
            HolderBindingVerificationContext::new(
                &session,
                &session.dcql_query.credentials[0],
                COMMON_CREDENTIAL_ROOT_NOW,
            ),
        )
        .expect("issuer-signed credential validity proof meets requirement");
    assert_eq!(common_credential_root.calls.load(Ordering::SeqCst), 1);
    assert_eq!(legacy.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn common_credential_root_rejects_unadmitted_issuer_status_even_without_explicit_requirement() {
    let legacy = EvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
    };
    let common_credential_root = CommonCredentialRootEvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
        expected_request_time_unix: COMMON_CREDENTIAL_ROOT_NOW,
    };
    let mut policy = common_credential_root_policy(COMMON_CREDENTIAL_ROOT_STATUS_ROOT);
    policy.issuer_status = None;
    let verifier = ZkHolderBindingVerifier::new_with_common_credential_root(
        &legacy,
        &[TRUSTED_ISSUER],
        ZkVerificationRequirements {
            issuer_signed_validity: false,
            credential_status: false,
        },
        &common_credential_root,
        policy,
    );
    let session = common_credential_root_session();
    let error = verifier
        .verify_holder_binding(
            &common_credential_root_presentation(false),
            HolderBindingVerificationContext::new(
                &session,
                &session.dcql_query.credentials[0],
                COMMON_CREDENTIAL_ROOT_NOW,
            ),
        )
        .expect_err("unadmitted issuer status cannot enter the common-credential-root join");
    assert_eq!(error.reason(), VerifierErrorReason::InvalidCredentialStatus);
    assert_eq!(common_credential_root.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn common_credential_root_rejects_wrong_session_and_status_policy() {
    let legacy = EvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
    };
    let common_credential_root = CommonCredentialRootEvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
        expected_request_time_unix: COMMON_CREDENTIAL_ROOT_NOW,
    };
    let session = common_credential_root_session();
    let verifier = ZkHolderBindingVerifier::new_with_common_credential_root(
        &legacy,
        &[TRUSTED_ISSUER],
        ZkVerificationRequirements {
            issuer_signed_validity: false,
            credential_status: false,
        },
        &common_credential_root,
        common_credential_root_policy(COMMON_CREDENTIAL_ROOT_STATUS_ROOT),
    );
    let error = verifier
        .verify_holder_binding(
            &common_credential_root_presentation(true),
            HolderBindingVerificationContext::new(
                &session,
                &session.dcql_query.credentials[0],
                COMMON_CREDENTIAL_ROOT_NOW,
            ),
        )
        .expect_err("wrong selected-claim session binding fails closed");
    assert_eq!(error.reason(), VerifierErrorReason::InvalidZkPresentation);

    let wrong_status = ZkHolderBindingVerifier::new_with_common_credential_root(
        &legacy,
        &[TRUSTED_ISSUER],
        ZkVerificationRequirements {
            issuer_signed_validity: false,
            credential_status: false,
        },
        &common_credential_root,
        common_credential_root_policy([0x99; 32]),
    );
    let error = wrong_status
        .verify_holder_binding(
            &common_credential_root_presentation(false),
            HolderBindingVerificationContext::new(
                &session,
                &session.dcql_query.credentials[0],
                COMMON_CREDENTIAL_ROOT_NOW,
            ),
        )
        .expect_err("wrong authenticated status policy fails closed");
    assert_eq!(error.reason(), VerifierErrorReason::InvalidZkPresentation);
}

#[test]
fn common_credential_root_rejects_stale_status_root_snapshot() {
    let legacy = EvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
    };
    let common_credential_root = CommonCredentialRootEvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
        expected_request_time_unix: COMMON_CREDENTIAL_ROOT_NOW,
    };
    let policy = common_credential_root_policy_for_window(
        COMMON_CREDENTIAL_ROOT_STATUS_ROOT,
        COMMON_CREDENTIAL_ROOT_NOW - 2,
        COMMON_CREDENTIAL_ROOT_NOW,
        COMMON_CREDENTIAL_ROOT_NOW - 1,
    );
    let verifier = ZkHolderBindingVerifier::new_with_common_credential_root(
        &legacy,
        &[TRUSTED_ISSUER],
        ZkVerificationRequirements {
            issuer_signed_validity: false,
            credential_status: false,
        },
        &common_credential_root,
        policy,
    );
    let session = common_credential_root_session();
    let error = verifier
        .verify_holder_binding(
            &common_credential_root_presentation(false),
            HolderBindingVerificationContext::new(
                &session,
                &session.dcql_query.credentials[0],
                COMMON_CREDENTIAL_ROOT_NOW,
            ),
        )
        .expect_err("stale status-root snapshots must fail closed");

    assert_eq!(
        error.reason(),
        VerifierErrorReason::InvalidRootAssuranceStatus
    );
    assert_eq!(common_credential_root.calls.load(Ordering::SeqCst), 0);
    assert_eq!(legacy.calls.load(Ordering::SeqCst), 0);
}
