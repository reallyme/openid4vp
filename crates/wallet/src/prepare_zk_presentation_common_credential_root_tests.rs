// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn serializes_api_owned_bundle_for_verified_request() {
    let request = verified_request(false);
    let value = prepare_zk_presentation_from_bundle(
        &request,
        &WalletInvocationContext::ProtocolTransport,
        &QueryId::parse("pid").expect("test query id is valid"),
        &bundle(None),
    )
    .expect("matching bundle is encoded");
    let parsed = parse_zk_presentation_value(&value)
        .expect("wire value parses")
        .expect("wire value is a ZK presentation");
    assert_eq!(parsed.stages.len(), 4);
    assert!(parsed.derived_claims.is_empty());
    assert_eq!(parsed.binding, presentation_fixture().binding);
}
#[test]
fn serializes_common_credential_root_presentation_for_verified_request() {
    let request = verified_common_credential_root_request(false);
    let value = prepare_zk_presentation_from_common_credential_root(
        &request,
        &WalletInvocationContext::ProtocolTransport,
        &QueryId::parse("pid").expect("test query id is valid"),
        &common_credential_root_presentation(None),
    )
    .expect("matching common-credential-root presentation is encoded");
    let parsed = parse_zk_presentation_value(&value)
        .expect("wire value parses")
        .expect("wire value is a ZK presentation");
    assert_eq!(
        parsed.profile,
        ZkPresentationProfile::CommonCredentialRootPrivatePersonaV1
    );
    assert_eq!(parsed.stages.len(), 9);
    assert_eq!(
        parsed.stages[0].stage,
        ZkPresentationStageKind::RootAttestation
    );
    assert_eq!(
        parsed.stages[4].stage,
        ZkPresentationStageKind::SelectedClaim0
    );
    assert_eq!(
        parsed.stages[7].stage,
        ZkPresentationStageKind::IssuerCredentialStatus0
    );
    assert_eq!(
        parsed.stages[8].stage,
        ZkPresentationStageKind::IssuerCredentialStatus1
    );
    assert_eq!(parsed.binding, presentation_fixture().binding);
}
#[test]
fn enforces_common_credential_root_request_binding_and_stage_order() {
    let mut request = verified_common_credential_root_request(false);
    request.request_mut_for_test().nonce = "another-nonce".to_owned();
    let query_id = QueryId::parse("pid").expect("test query id is valid");
    let error = prepare_zk_presentation_from_common_credential_root(
        &request,
        &WalletInvocationContext::ProtocolTransport,
        &query_id,
        &common_credential_root_presentation(None),
    )
    .expect_err("mismatched nonce cannot be sent");
    assert_eq!(error.reason(), WalletErrorReason::ZkDerivationFailed);

    request.request_mut_for_test().nonce = "0123456789abcdef".to_owned();
    let mut presentation = common_credential_root_presentation(None);
    presentation.proofs.swap(0, 1);
    let error = prepare_zk_presentation_from_common_credential_root(
        &request,
        &WalletInvocationContext::ProtocolTransport,
        &query_id,
        &presentation,
    )
    .expect_err("common-credential-root proofs must remain in canonical slot order");
    assert_eq!(error.reason(), WalletErrorReason::ZkDerivationFailed);
}
#[test]
fn rejects_common_credential_root_proof_public_inputs_from_another_request_or_claim() {
    let request = verified_common_credential_root_request(false);
    let query_id = QueryId::parse("pid").expect("test query id is valid");
    let mut wrong_request = common_credential_root_presentation(None);
    let proof = &mut wrong_request.proofs[0];
    let circuit = proof.public_inputs.circuit_ref();
    let mut raw = proof.public_inputs.as_bytes().to_vec();
    set_common_credential_root_bytes32(&mut raw, 97, &[0x55; 32]);
    proof.public_inputs = ZkCommonCredentialRootRawPublicInputs::try_from_bytes(circuit, raw)
        .expect("test public inputs remain structurally valid");
    let error = prepare_zk_presentation_from_common_credential_root(
        &request,
        &WalletInvocationContext::ProtocolTransport,
        &query_id,
        &wrong_request,
    )
    .expect_err("a proof from another nonce is never sent");
    assert_eq!(error.reason(), WalletErrorReason::ZkDerivationFailed);

    let mut wrong_claim = common_credential_root_presentation(None);
    let proof = &mut wrong_claim.proofs[5];
    let circuit = proof.public_inputs.circuit_ref();
    let mut raw = proof.public_inputs.as_bytes().to_vec();
    set_common_credential_root_bytes32(&mut raw, 322, &[0x66; 32]);
    proof.public_inputs = ZkCommonCredentialRootRawPublicInputs::try_from_bytes(circuit, raw)
        .expect("test claim proof remains structurally valid");
    let error = prepare_zk_presentation_from_common_credential_root(
        &request,
        &WalletInvocationContext::ProtocolTransport,
        &query_id,
        &wrong_claim,
    )
    .expect_err("a proof for another claim is never sent");
    assert_eq!(error.reason(), WalletErrorReason::ZkDerivationFailed);
}
#[test]
fn enforces_common_credential_root_query_metadata_and_transaction_binding() {
    let request = verified_common_credential_root_request(true);
    let transaction = request
        .request()
        .transaction_data
        .as_ref()
        .expect("test has transaction data");
    let digest = TransactionDataHash::sha256_transaction_data(&transaction[0])
        .expect("test transaction data hashes")
        .digest;
    let query_id = QueryId::parse("pid").expect("test query id is valid");
    let value = prepare_zk_presentation_from_common_credential_root(
        &request,
        &WalletInvocationContext::ProtocolTransport,
        &query_id,
        &common_credential_root_presentation(Some(digest)),
    )
    .expect("exact common-credential-root transaction binding is accepted");
    assert!(parse_zk_presentation_value(&value)
        .expect("wire value parses")
        .is_some());

    let error = prepare_zk_presentation_from_common_credential_root(
        &request,
        &WalletInvocationContext::ProtocolTransport,
        &query_id,
        &common_credential_root_presentation(None),
    )
    .expect_err("missing common-credential-root transaction binding fails");
    assert_eq!(error.reason(), WalletErrorReason::ZkDerivationFailed);

    let mut request = verified_common_credential_root_request(false);
    request.request_mut_for_test().dcql_query.credentials[0]
        .meta
        .insert("claim_1_value_b64u".to_owned(), json!(""));
    let error = prepare_zk_presentation_from_common_credential_root(
        &request,
        &WalletInvocationContext::ProtocolTransport,
        &query_id,
        &common_credential_root_presentation(None),
    )
    .expect_err("empty common-credential-root claim values are not valid query policy");
    assert_eq!(error.reason(), WalletErrorReason::ZkDerivationFailed);
}

#[test]
fn rejects_bundle_bound_to_another_nonce_or_query_claim() {
    let mut request = verified_request(false);
    request.request_mut_for_test().nonce = "another-nonce".to_owned();
    let error = prepare_zk_presentation_from_bundle(
        &request,
        &WalletInvocationContext::ProtocolTransport,
        &QueryId::parse("pid").expect("test query id is valid"),
        &bundle(None),
    )
    .expect_err("mismatched nonce cannot be sent");
    assert_eq!(error.reason(), WalletErrorReason::ZkDerivationFailed);

    request.request_mut_for_test().nonce = "0123456789abcdef".to_owned();
    request.request_mut_for_test().dcql_query.credentials[0]
        .meta
        .insert(
            "claim_name_hash".to_owned(),
            json!("0404040404040404040404040404040404040404040404040404040404040404"),
        );
    let error = prepare_zk_presentation_from_bundle(
        &request,
        &WalletInvocationContext::ProtocolTransport,
        &QueryId::parse("pid").expect("test query id is valid"),
        &bundle(None),
    )
    .expect_err("wrong claim name cannot be sent");
    assert_eq!(error.reason(), WalletErrorReason::ZkDerivationFailed);
}

#[test]
fn enforces_exact_transaction_data_and_transport_binding() {
    let request = verified_request(true);
    let transaction = request
        .request()
        .transaction_data
        .as_ref()
        .expect("test has transaction data");
    let digest = TransactionDataHash::sha256_transaction_data(&transaction[0])
        .expect("test transaction data hashes")
        .digest;
    let query_id = QueryId::parse("pid").expect("test query id is valid");
    let value = prepare_zk_presentation_from_bundle(
        &request,
        &WalletInvocationContext::ProtocolTransport,
        &query_id,
        &bundle(Some(digest)),
    )
    .expect("exact transaction binding is accepted");
    assert!(parse_zk_presentation_value(&value)
        .expect("wire value parses")
        .is_some());
    let error = prepare_zk_presentation_from_bundle(
        &request,
        &WalletInvocationContext::ProtocolTransport,
        &query_id,
        &bundle(None),
    )
    .expect_err("missing transaction binding fails");
    assert_eq!(error.reason(), WalletErrorReason::ZkDerivationFailed);
    let error = prepare_zk_presentation_from_bundle(
        &request,
        &WalletInvocationContext::DigitalCredentialsApi(
            crate::VerifiedPlatformOrigin::from_browser_security_context(
                "https://verifier.example".to_owned(),
            )
            .expect("test origin is valid"),
        ),
        &query_id,
        &bundle(Some(digest)),
    )
    .expect_err("DC API origin cannot be substituted for a direct-post request");
    assert_eq!(error.reason(), WalletErrorReason::ZkDerivationFailed);
}

#[test]
fn binds_dc_api_presentation_to_authenticated_origin() {
    let mut request = verified_request(false);
    request.request_mut_for_test().response_mode = Some(ResponseMode::DcApi);
    let invocation = WalletInvocationContext::DigitalCredentialsApi(
        crate::VerifiedPlatformOrigin::from_browser_security_context(
            "https://verifier.example".to_owned(),
        )
        .expect("test origin is valid"),
    );
    let query_id = QueryId::parse("pid").expect("test query id is valid");
    let value = prepare_zk_presentation_from_bundle(
        &request,
        &invocation,
        &query_id,
        &bundle_for("origin:https://verifier.example", None),
    )
    .expect("DC API origin-bound bundle is encoded");
    assert!(parse_zk_presentation_value(&value)
        .expect("wire value parses")
        .is_some());
    let error =
        prepare_zk_presentation_from_bundle(&request, &invocation, &query_id, &bundle(None))
            .expect_err("client id cannot replace DC API origin");
    assert_eq!(error.reason(), WalletErrorReason::ZkDerivationFailed);
}

#[test]
fn rejects_wrong_claim_value_and_multiple_transaction_items() {
    let mut request = verified_request(false);
    request.request_mut_for_test().dcql_query.credentials[0]
        .meta
        .insert("claim_value_b64u".to_owned(), json!("Cg"));
    let query_id = QueryId::parse("pid").expect("test query id is valid");
    let error = prepare_zk_presentation_from_bundle(
        &request,
        &WalletInvocationContext::ProtocolTransport,
        &query_id,
        &bundle(None),
    )
    .expect_err("another claim value is not a valid answer");
    assert_eq!(error.reason(), WalletErrorReason::ZkDerivationFailed);

    let mut request = verified_request(true);
    let transaction = request
        .request()
        .transaction_data
        .as_ref()
        .expect("test request contains transaction data")[0]
        .clone();
    request
        .request_mut_for_test()
        .transaction_data
        .as_mut()
        .expect("test request contains transaction data")
        .push(transaction);
    let error = prepare_zk_presentation_from_bundle(
        &request,
        &WalletInvocationContext::ProtocolTransport,
        &query_id,
        &bundle(None),
    )
    .expect_err("two applicable transaction values cannot fit one public input");
    assert_eq!(error.reason(), WalletErrorReason::ZkDerivationFailed);
}
