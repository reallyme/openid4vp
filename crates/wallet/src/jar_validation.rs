// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Validate wallet-enforced OpenID4VP Request Object claims.
pub fn validate_wallet_request_object(
    request: &AuthorizationRequestObject,
    expected_origin: Option<&str>,
    now_unix: u64,
) -> Result<(), WalletError> {
    validate_wallet_request_object_with_transaction_data_policy(
        request,
        expected_origin,
        now_unix,
        WalletTransactionDataPolicy::deny_all(),
    )
}

/// Validate a Request Object with an explicit transaction-data allowlist.
pub fn validate_wallet_request_object_with_transaction_data_policy(
    request: &AuthorizationRequestObject,
    expected_origin: Option<&str>,
    now_unix: u64,
    transaction_data_policy: WalletTransactionDataPolicy<'_>,
) -> Result<(), WalletError> {
    let evidence = WalletRequestTrustEvidence::default();
    validate_wallet_request_object_with_evidence_and_transaction_data_policy(
        request,
        expected_origin,
        now_unix,
        &evidence,
        transaction_data_policy,
    )
}

/// Validate wallet-enforced OpenID4VP Request Object claims with trust evidence.
pub fn validate_wallet_request_object_with_trust(
    request: &AuthorizationRequestObject,
    expected_origin: Option<&str>,
    now_unix: u64,
    verifier_attestation: Option<&VerifiedVerifierAttestation>,
    request_signing_public_key: &[u8],
) -> Result<(), WalletError> {
    if let Some(attestation) = verifier_attestation {
        validate_verifier_attestation_binding(
            request,
            attestation,
            request_signing_public_key,
            now_unix,
        )?;
    }
    let evidence = WalletRequestTrustEvidence {
        client_identifier_binding: None,
        verifier_attestation: verifier_attestation.cloned(),
        client_metadata_reference: None,
        x509_certificate_binding: None,
    };
    validate_wallet_request_object_with_evidence(request, expected_origin, now_unix, &evidence)
}

/// Validate wallet-enforced OpenID4VP Request Object claims with trust evidence.
pub fn validate_wallet_request_object_with_evidence(
    request: &AuthorizationRequestObject,
    expected_origin: Option<&str>,
    now_unix: u64,
    evidence: &WalletRequestTrustEvidence,
) -> Result<(), WalletError> {
    validate_wallet_request_object_with_evidence_and_transaction_data_policy(
        request,
        expected_origin,
        now_unix,
        evidence,
        WalletTransactionDataPolicy::deny_all(),
    )
}

/// Validate wallet claims, trust evidence, and application transaction semantics.
pub fn validate_wallet_request_object_with_evidence_and_transaction_data_policy(
    request: &AuthorizationRequestObject,
    expected_origin: Option<&str>,
    now_unix: u64,
    evidence: &WalletRequestTrustEvidence,
    transaction_data_policy: WalletTransactionDataPolicy<'_>,
) -> Result<(), WalletError> {
    validate_wallet_request_object_with_evidence_and_policies(
        request,
        expected_origin,
        now_unix,
        evidence,
        WalletRequestTemporalPolicy::production(),
        transaction_data_policy,
    )
}

fn validate_wallet_request_object_with_evidence_and_policies(
    request: &AuthorizationRequestObject,
    expected_origin: Option<&str>,
    now_unix: u64,
    evidence: &WalletRequestTrustEvidence,
    temporal_policy: WalletRequestTemporalPolicy,
    transaction_data_policy: WalletTransactionDataPolicy<'_>,
) -> Result<(), WalletError> {
    let Some(client_id) = request.client_id.as_ref() else {
        return Err(WalletError::new(
            WalletErrorReason::InvalidClientIdentifierPrefix,
        ));
    };

    match client_id.prefix() {
        ClientIdentifierPrefix::None => {
            let policy = WalletClientIdentifierPolicy::production();
            if !policy.pre_registered_supported() {
                return Err(WalletError::new(
                    WalletErrorReason::UnsupportedClientIdentifierMode,
                ));
            }
        }
        ClientIdentifierPrefix::Origin => {
            return Err(WalletError::new(
                WalletErrorReason::UnsupportedClientIdentifierMode,
            ));
        }
        ClientIdentifierPrefix::RedirectUri => {
            return Err(WalletError::new(
                WalletErrorReason::InvalidClientIdentifierPrefix,
            ));
        }
        ClientIdentifierPrefix::OpenIdFederation
        | ClientIdentifierPrefix::DecentralizedIdentifier => {}
        ClientIdentifierPrefix::X509SanDns | ClientIdentifierPrefix::X509Hash => {}
        ClientIdentifierPrefix::VerifierAttestation => {
            let Some(attestation) = evidence.verifier_attestation.as_ref() else {
                return Err(WalletError::new(
                    WalletErrorReason::InvalidVerifierAttestation,
                ));
            };
            validate_verifier_attestation_claim_binding(request, attestation)?;
        }
    }
    validate_response_endpoint_binding(
        request,
        client_id,
        evidence.x509_certificate_binding.as_ref(),
    )?;

    if request.exp.is_some_and(|exp| exp <= now_unix) {
        return Err(WalletError::new(WalletErrorReason::RequestObjectExpired));
    }

    if request.nonce.is_empty() {
        return Err(WalletError::new(WalletErrorReason::InvalidRequestObject));
    }

    reallyme_openid4vp_dcql::validate_query(&request.dcql_query)
        .map_err(|_| WalletError::new(WalletErrorReason::InvalidRequestObject))?;

    if let Some(iat) = request.iat {
        let latest_iat = now_unix
            .checked_add(temporal_policy.max_future_iat_skew_seconds)
            .ok_or_else(|| WalletError::new(WalletErrorReason::InvalidRequestObject))?;
        if iat > latest_iat {
            return Err(WalletError::new(
                WalletErrorReason::RequestObjectIssuedInFuture,
            ));
        }
    }

    transaction_data_policy.validate(request)?;

    validate_client_metadata_reference_binding(
        request,
        evidence.client_metadata_reference.as_ref(),
        now_unix,
    )?;

    let is_dc_api = matches!(
        request.response_mode,
        Some(
            reallyme_openid4vp_types::ResponseMode::DcApi
                | reallyme_openid4vp_types::ResponseMode::DcApiJwt
        )
    );
    if is_dc_api != expected_origin.is_some() {
        return Err(WalletError::new(WalletErrorReason::InvalidPlatformOrigin));
    }

    if let Some(origin) = expected_origin {
        let Some(expected_origins) = request.expected_origins.as_ref() else {
            return Err(WalletError::new(WalletErrorReason::ExpectedOriginMismatch));
        };
        if !expected_origins.iter().any(|expected| expected == origin) {
            return Err(WalletError::new(WalletErrorReason::ExpectedOriginMismatch));
        }
    }

    Ok(())
}

fn validate_client_identifier_trust_binding(
    request: &AuthorizationRequestObject,
    evidence: &WalletRequestTrustEvidence,
) -> Result<(), WalletError> {
    let Some(client_id) = request.client_id.as_ref() else {
        return Err(WalletError::new(
            WalletErrorReason::InvalidClientIdentifierPrefix,
        ));
    };
    if matches!(
        client_id.prefix(),
        ClientIdentifierPrefix::OpenIdFederation | ClientIdentifierPrefix::DecentralizedIdentifier
    ) && evidence.client_identifier_binding.is_none()
    {
        return Err(WalletError::new(
            WalletErrorReason::InvalidClientIdentifierTrustBinding,
        ));
    }
    Ok(())
}

/// Enforce that a transport-level `client_id` matches signed Request Object claims.
pub fn validate_transport_client_id_binding(
    expected_client_id: Option<&str>,
    request: &AuthorizationRequestObject,
) -> Result<(), WalletError> {
    let expected = expected_client_id
        .ok_or_else(|| WalletError::new(WalletErrorReason::TransportClientIdentifierMismatch))?;
    let Some(actual) = request.client_id.as_ref() else {
        return Err(WalletError::new(
            WalletErrorReason::TransportClientIdentifierMismatch,
        ));
    };
    if actual.to_wire_value() != expected {
        return Err(WalletError::new(
            WalletErrorReason::TransportClientIdentifierMismatch,
        ));
    }
    Ok(())
}

/// Enforce that POST `request_uri` wallet_nonce is echoed by the signed Request Object.
pub fn validate_transport_wallet_nonce_binding(
    expected_wallet_nonce: Option<&str>,
    request: &AuthorizationRequestObject,
) -> Result<(), WalletError> {
    match (expected_wallet_nonce, request.wallet_nonce.as_deref()) {
        (Some(expected), Some(actual)) if constant_time_str_eq(expected, actual) => Ok(()),
        (Some(_), Some(_)) | (Some(_), None) => Err(WalletError::new(
            WalletErrorReason::TransportWalletNonceMismatch,
        )),
        (None, Some(_)) => Err(WalletError::new(WalletErrorReason::UnexpectedWalletNonce)),
        (None, None) => Ok(()),
    }
}

fn constant_time_str_eq(left: &str, right: &str) -> bool {
    bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}
