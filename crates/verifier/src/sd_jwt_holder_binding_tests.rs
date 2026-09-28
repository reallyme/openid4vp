// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_formats::sd_jwt::{
    SdJwtFormatError, SdJwtFormatErrorReason, SdJwtTrustProvider, SdJwtVerificationKeyMaterial,
};
use reallyme_openid4vp_types::{ClientIdentifier, PresentationValue};
use serde_json::Value as JsonValue;

use super::{
    map_sd_jwt_error, HolderBindingVerificationContext, HolderBindingVerifier,
    SdJwtHolderBindingVerifier, VerifierErrorReason,
};
use crate::{RequestBinding, SessionRecord};

struct FailingTrustProvider {
    reason: SdJwtFormatErrorReason,
}

impl SdJwtTrustProvider for FailingTrustProvider {
    fn resolve_verification_keys(
        &self,
        _compact: &str,
        _credential_query: &CredentialQuery,
        _now_unix: u64,
    ) -> Result<SdJwtVerificationKeyMaterial, SdJwtFormatError> {
        Err(SdJwtFormatError::new(self.reason))
    }

    fn verify_credential_status(
        &self,
        _issuer_payload: &JsonValue,
        _resolved_payload: &JsonValue,
    ) -> Result<(), SdJwtFormatError> {
        Err(SdJwtFormatError::new(self.reason))
    }
}

#[test]
fn maps_trust_failure_without_exposing_presentation_material() {
    let provider = FailingTrustProvider {
        reason: SdJwtFormatErrorReason::KeyResolutionFailed,
    };
    let verifier = SdJwtHolderBindingVerifier::new(&provider);
    let session = session();
    let context =
        HolderBindingVerificationContext::new(&session, &session.dcql_query.credentials[0], 10);

    let error = verifier
        .verify_holder_binding(&PresentationValue::Compact("bounded".to_owned()), context)
        .expect_err("unresolved issuer key must fail closed");

    assert_eq!(error.reason(), VerifierErrorReason::InvalidBinding);
    assert!(!format!("{error:?}").contains("bounded"));
}

#[test]
fn rejects_non_compact_values_before_trust_resolution() {
    let provider = FailingTrustProvider {
        reason: SdJwtFormatErrorReason::CredentialRevoked,
    };
    let verifier = SdJwtHolderBindingVerifier::new(&provider);
    let session = session();
    let context =
        HolderBindingVerificationContext::new(&session, &session.dcql_query.credentials[0], 10);

    let error = verifier
        .verify_holder_binding(&PresentationValue::Json(JsonValue::Null), context)
        .expect_err("SD-JWT VC requires compact serialization");

    assert_eq!(error.reason(), VerifierErrorReason::UnsupportedFormat);
}

#[test]
fn maps_issuer_validity_failure_to_stable_verifier_reason() {
    let error = map_sd_jwt_error(SdJwtFormatError::new(
        SdJwtFormatErrorReason::InvalidCredentialValidity,
    ));

    assert_eq!(
        error.reason(),
        VerifierErrorReason::InvalidCredentialValidity
    );
}

fn session() -> SessionRecord {
    SessionRecord {
        binding: RequestBinding {
            client_id: ClientIdentifier::parse("x509_san_dns:verifier.example")
                .expect("test client id parses"),
            nonce: "0123456789abcdef".to_owned(),
            response_uri: Some("https://verifier.example/response".to_owned()),
            redirect_uri: None,
            dc_api_origin: None,
            expiry_unix: 100,
            transaction_data_bindings: Vec::new(),
        },
        state: Some("fedcba9876543210".to_owned()),
        dcql_query: DcqlQuery {
            credentials: vec![CredentialQuery {
                id: QueryId::parse("pid").expect("test query id parses"),
                format: CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned())
                    .expect("test format parses"),
                multiple: false,
                meta: Default::default(),
                trusted_authorities: None,
                require_cryptographic_holder_binding: true,
                claims: None,
                claim_sets: None,
            }],
            credential_sets: None,
        },
        response_mode: reallyme_openid4vp_types::ResponseMode::DirectPost,
        mdoc_session_transcript: None,
        post_response_redirect_uri: None,
        follow_back_requirement: None,
    }
}
