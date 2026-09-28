// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_dc_api::{
    build_redirect_session_transcript, CanonicalMdocHandoverCborEncoder, OpenId4VpRedirectHandover,
};
use reallyme_openid4vp_dcql::{
    ClaimQuery, ClaimsPath, ClaimsPathComponent, CredentialFormat, CredentialQuery, DcqlQuery,
    QueryId,
};
use reallyme_openid4vp_formats::mdoc::{
    MdocCertificatePathValidation, MdocIssuerCertificateResolver, VerifiedMdocClaim,
    VerifiedMdocPresentation, VerifiedMdocStatusReference,
};
use reallyme_openid4vp_formats::sd_jwt::{
    SdJwtFormatError, SdJwtTrustProvider, SdJwtVerificationKeyMaterial,
};
use reallyme_openid4vp_types::{ClientIdentifier, PresentationValue};
use serde_json::{Map as JsonMap, Value as JsonValue};
use zeroize::Zeroizing;

use super::{
    validate_document_type, validate_mdoc_status, validate_supported_mdoc_query,
    HolderBindingVerificationContext, HolderBindingVerifier, MdocHolderBindingVerifier,
    MdocSessionTranscriptProvider, MdocStatusDecision, MdocStatusVerifier,
    OpenId4VpHolderBindingVerifier, RetainedMdocSessionTranscriptProvider, VerifierError,
    VerifierErrorReason,
};
use crate::{RequestBinding, RetainedMdocSessionTranscript, SessionRecord};

struct MissingIssuerKey;

impl MdocIssuerCertificateResolver for MissingIssuerKey {
    fn validate_issuer_certificate_path(
        &self,
        _certificate_path_der: &[Vec<u8>],
        _mso_signing_time_unix: u64,
    ) -> Option<MdocCertificatePathValidation> {
        None
    }
}

struct FixedTranscript;

struct FixedStatusDecision(MdocStatusDecision);

impl MdocStatusVerifier for FixedStatusDecision {
    fn verify_status(
        &self,
        _reference: &VerifiedMdocStatusReference,
        _now_unix: u64,
    ) -> MdocStatusDecision {
        self.0
    }
}

const VALID_STATUS: FixedStatusDecision = FixedStatusDecision(MdocStatusDecision::Valid);

impl MdocSessionTranscriptProvider for FixedTranscript {
    fn session_transcript(
        &self,
        _context: HolderBindingVerificationContext<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, VerifierError> {
        Ok(Zeroizing::new(vec![0x83, 0xf6, 0xf6, 0x80]))
    }

    fn validate_session_binding(
        &self,
        _context: HolderBindingVerificationContext<'_>,
        session_transcript_cbor: &[u8],
    ) -> Result<(), VerifierError> {
        if session_transcript_cbor == [0x83, 0xf6, 0xf6, 0x80] {
            return Ok(());
        }
        Err(VerifierError::new(VerifierErrorReason::InvalidBinding))
    }
}

struct FailingSdJwtTrust;

impl SdJwtTrustProvider for FailingSdJwtTrust {
    fn resolve_verification_keys(
        &self,
        _compact: &str,
        _credential_query: &CredentialQuery,
        _now_unix: u64,
    ) -> Result<SdJwtVerificationKeyMaterial, SdJwtFormatError> {
        Err(SdJwtFormatError::new(
            reallyme_openid4vp_formats::sd_jwt::SdJwtFormatErrorReason::KeyResolutionFailed,
        ))
    }

    fn verify_credential_status(
        &self,
        _issuer_payload: &JsonValue,
        _resolved_payload: &JsonValue,
    ) -> Result<(), SdJwtFormatError> {
        Ok(())
    }
}

#[test]
fn rejects_invalid_mdoc_before_returning_synthetic_binding_claims() {
    let verifier =
        MdocHolderBindingVerifier::new(&MissingIssuerKey, &FixedTranscript, &VALID_STATUS);
    let session = session(CredentialFormat::MSO_MDOC);
    let context = HolderBindingVerificationContext::new(
        &session,
        &session.dcql_query.credentials[0],
        1_700_000_001,
    );

    let error = verifier
        .verify_holder_binding(&PresentationValue::Compact("AA".to_owned()), context)
        .expect_err("malformed DeviceResponse must fail closed");

    assert_eq!(error.reason(), VerifierErrorReason::InvalidBinding);
}

#[test]
fn dispatches_from_dcql_format_instead_of_presentation_shape() {
    let verifier = OpenId4VpHolderBindingVerifier::new(
        &FailingSdJwtTrust,
        &MissingIssuerKey,
        &FixedTranscript,
        &VALID_STATUS,
    );
    let session = session(CredentialFormat::MSO_MDOC);
    let context = HolderBindingVerificationContext::new(
        &session,
        &session.dcql_query.credentials[0],
        1_700_000_001,
    );

    let error = verifier
        .verify_holder_binding(&PresentationValue::Compact("AA".to_owned()), context)
        .expect_err("malformed mdoc must use the mdoc verifier");

    assert_eq!(error.reason(), VerifierErrorReason::InvalidBinding);
}

#[test]
fn rejects_json_native_value_for_mdoc() {
    let verifier =
        MdocHolderBindingVerifier::new(&MissingIssuerKey, &FixedTranscript, &VALID_STATUS);
    let session = session(CredentialFormat::MSO_MDOC);
    let context = HolderBindingVerificationContext::new(
        &session,
        &session.dcql_query.credentials[0],
        1_700_000_001,
    );

    let error = verifier
        .verify_holder_binding(&PresentationValue::Json(JsonValue::Null), context)
        .expect_err("mdoc DeviceResponse must use base64url compact transport");

    assert_eq!(error.reason(), VerifierErrorReason::UnsupportedFormat);
}

#[test]
fn retained_transcript_provider_rebuilds_the_exact_redirect_handover() {
    let mut session = session(CredentialFormat::MSO_MDOC);
    let transcript = build_redirect_session_transcript(
        OpenId4VpRedirectHandover {
            client_id: session.binding.client_id.clone(),
            nonce: session.binding.nonce.clone(),
            jwk_thumbprint_sha256: None,
            response_uri: session
                .binding
                .response_uri
                .clone()
                .expect("test response URI is present"),
        },
        &CanonicalMdocHandoverCborEncoder,
    );
    let transcript = transcript.expect("test transcript builds");
    session.mdoc_session_transcript = Some(
        RetainedMdocSessionTranscript::new(transcript.as_bytes().to_vec())
            .expect("test transcript is bounded"),
    );
    let context = HolderBindingVerificationContext::new(
        &session,
        &session.dcql_query.credentials[0],
        1_700_000_001,
    );

    let transcript = RetainedMdocSessionTranscriptProvider
        .session_transcript(context)
        .expect("retained transcript is returned");

    RetainedMdocSessionTranscriptProvider
        .validate_session_binding(context, &transcript)
        .expect("reconstructed handover matches the retained transcript");

    let mut mismatched = transcript.to_vec();
    let first = mismatched.first_mut().expect("transcript is non-empty");
    *first ^= 1;
    let error = RetainedMdocSessionTranscriptProvider
        .validate_session_binding(context, &mismatched)
        .expect_err("a different transcript must fail closed");
    assert_eq!(error.reason(), VerifierErrorReason::InvalidBinding);

    session.mdoc_session_transcript = None;
    let missing_context = HolderBindingVerificationContext::new(
        &session,
        &session.dcql_query.credentials[0],
        1_700_000_001,
    );
    let error = RetainedMdocSessionTranscriptProvider
        .session_transcript(missing_context)
        .expect_err("missing retained transcript must fail closed");
    assert_eq!(error.reason(), VerifierErrorReason::InvalidBinding);
}

#[test]
fn accepts_only_the_exact_dcql_document_type() {
    let session = session(CredentialFormat::MSO_MDOC);
    let context = HolderBindingVerificationContext::new(
        &session,
        &session.dcql_query.credentials[0],
        1_700_000_001,
    );

    validate_document_type(context, &["org.iso.18013.5.1.mDL".to_owned()])
        .expect("exact requested document type is accepted");
    for document_types in [
        Vec::new(),
        vec!["org.example.other".to_owned()],
        vec![
            "org.iso.18013.5.1.mDL".to_owned(),
            "org.iso.18013.5.1.mDL".to_owned(),
        ],
    ] {
        let error = validate_document_type(context, &document_types)
            .expect_err("missing, mismatched, or repeated document types fail closed");
        assert_eq!(error.reason(), VerifierErrorReason::VpTokenQueryMismatch);
    }
}

#[test]
fn matches_mdoc_claim_paths_only_against_authenticated_disclosures() {
    let mut claims_session = session(CredentialFormat::MSO_MDOC);
    claims_session.dcql_query.credentials[0].claims = Some(vec![ClaimQuery {
        id: None,
        path: ClaimsPath(vec![
            ClaimsPathComponent::Name("org.iso.18013.5.1".to_owned()),
            ClaimsPathComponent::Name("family_name".to_owned()),
        ]),
        values: None,
        intent_to_retain: Some(false),
    }]);
    let claims_context = HolderBindingVerificationContext::new(
        &claims_session,
        &claims_session.dcql_query.credentials[0],
        1_700_000_001,
    );
    let verified = VerifiedMdocPresentation {
        document_count: 1,
        document_types: vec!["org.iso.18013.5.1.mDL".to_owned()],
        disclosed_claims: vec![VerifiedMdocClaim {
            document_index: 0,
            namespace: "org.iso.18013.5.1".to_owned(),
            element_identifier: "family_name".to_owned(),
        }],
        status_references: Vec::new(),
        has_unsupported_status_extension: false,
    };
    validate_supported_mdoc_query(claims_context, &verified)
        .expect("issuer-authenticated disclosure satisfies the requested claim");

    claims_session.dcql_query.credentials[0].claims = Some(vec![ClaimQuery {
        id: None,
        path: ClaimsPath(vec![
            ClaimsPathComponent::Name("org.iso.18013.5.1".to_owned()),
            ClaimsPathComponent::Name("given_name".to_owned()),
        ]),
        values: None,
        intent_to_retain: None,
    }]);
    let missing_context = HolderBindingVerificationContext::new(
        &claims_session,
        &claims_session.dcql_query.credentials[0],
        1_700_000_001,
    );
    let claims_error = validate_supported_mdoc_query(missing_context, &verified)
        .expect_err("a missing authenticated disclosure must fail closed");
    assert_eq!(
        claims_error.reason(),
        VerifierErrorReason::VpTokenQueryMismatch
    );

    let mut authority_session = session(CredentialFormat::MSO_MDOC);
    authority_session.dcql_query.credentials[0].trusted_authorities = Some(vec![]);
    let authority_context = HolderBindingVerificationContext::new(
        &authority_session,
        &authority_session.dcql_query.credentials[0],
        1_700_000_001,
    );
    let authority_error = validate_supported_mdoc_query(authority_context, &verified)
        .expect_err("mdoc authority constraints must fail closed");
    assert_eq!(
        authority_error.reason(),
        VerifierErrorReason::VpTokenQueryMismatch
    );
}

#[test]
fn enforces_every_authenticated_mdoc_status_reference() {
    let reference = VerifiedMdocStatusReference::StatusList {
        index: 7,
        uri: "https://issuer.example/status".to_owned(),
        certificate_der: None,
    };
    let presentation = VerifiedMdocPresentation {
        document_count: 1,
        document_types: vec!["org.iso.18013.5.1.mDL".to_owned()],
        disclosed_claims: Vec::new(),
        status_references: vec![reference],
        has_unsupported_status_extension: false,
    };

    validate_mdoc_status(&presentation, &VALID_STATUS, 10)
        .expect("fresh active status is accepted");
    for (decision, reason) in [
        (
            MdocStatusDecision::Revoked,
            VerifierErrorReason::CredentialRevoked,
        ),
        (
            MdocStatusDecision::Invalid,
            VerifierErrorReason::InvalidCredentialStatus,
        ),
        (
            MdocStatusDecision::Unavailable,
            VerifierErrorReason::CredentialStatusUnavailable,
        ),
        (
            MdocStatusDecision::Stale,
            VerifierErrorReason::InvalidCredentialStatus,
        ),
    ] {
        let error = validate_mdoc_status(&presentation, &FixedStatusDecision(decision), 10)
            .expect_err("non-valid status decision fails closed");
        assert_eq!(error.reason(), reason);
    }

    let unsupported = VerifiedMdocPresentation {
        document_count: 1,
        document_types: vec!["org.iso.18013.5.1.mDL".to_owned()],
        disclosed_claims: Vec::new(),
        status_references: Vec::new(),
        has_unsupported_status_extension: true,
    };
    let error = validate_mdoc_status(&unsupported, &VALID_STATUS, 10)
        .expect_err("unsupported authenticated status extensions fail closed");
    assert_eq!(error.reason(), VerifierErrorReason::InvalidCredentialStatus);
}

fn session(format: &str) -> SessionRecord {
    let mut meta = JsonMap::new();
    meta.insert(
        "doctype_value".to_owned(),
        JsonValue::String("org.iso.18013.5.1.mDL".to_owned()),
    );
    SessionRecord {
        binding: RequestBinding {
            client_id: ClientIdentifier::parse("x509_san_dns:verifier.example")
                .expect("test client id parses"),
            nonce: "0123456789abcdef".to_owned(),
            response_uri: Some("https://verifier.example/response".to_owned()),
            redirect_uri: None,
            dc_api_origin: None,
            expiry_unix: 1_800_000_000,
            transaction_data_bindings: Vec::new(),
        },
        state: Some("fedcba9876543210".to_owned()),
        dcql_query: DcqlQuery {
            credentials: vec![CredentialQuery {
                id: QueryId::parse("pid").expect("test query id parses"),
                format: CredentialFormat::new(format.to_owned()).expect("test format parses"),
                multiple: false,
                meta,
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
