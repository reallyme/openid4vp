// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::generate_keypair;
use reallyme_crypto::jwk::{ed25519_public_key_to_jwk, Jwk, JwkOptions};
use reallyme_jose::jwt::{encode_signed_jwt_with_header_options, JwtHeaderEncodeOptions};
use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, QueryId};
use reallyme_sd_jwt::{
    build_key_binding_jwt, serialize_sd_jwt_compact, KeyBindingJwtBuildOptions,
    MAX_SD_JWT_COMPACT_BYTES,
};
use serde_json::{json, Map as JsonMap, Value as JsonValue};
use zeroize::Zeroizing;

use super::{
    verify_sd_jwt_presentation, SdJwtFormatError, SdJwtFormatErrorReason, SdJwtIssuerIdentity,
    SdJwtIssuerKeySource, SdJwtPresentationVerificationInput, SdJwtTrustProvider,
    SdJwtVerificationKeyMaterial,
};

#[path = "sd_jwt_issuer_identity_tests.rs"]
mod issuer_identity_tests;
#[path = "sd_jwt_projection_tests.rs"]
mod projection_tests;
#[path = "sd_jwt_x5c_tests.rs"]
mod x5c_tests;

const EXAMPLE_VCT: &str = "https://credentials.example/pid";

struct TestKey {
    public: Vec<u8>,
    private: Zeroizing<Vec<u8>>,
    jwk: Jwk,
}

fn test_key() -> TestKey {
    let (public, private) =
        generate_keypair(Algorithm::Ed25519).expect("test Ed25519 key generation succeeds");
    let jwk = Jwk::Okp(
        ed25519_public_key_to_jwk(
            &public,
            JwkOptions {
                alg: true,
                use_sig: true,
                ..JwkOptions::default()
            },
        )
        .expect("test public key converts to JWK")
        .into(),
    );
    TestKey {
        public,
        private,
        jwk,
    }
}

struct FixtureTrustProvider {
    issuer_jwk: Jwk,
    issuer_public_key: Vec<u8>,
    holder_jwk: Jwk,
    holder_public_key: Vec<u8>,
    status_result: Result<(), SdJwtFormatError>,
    issuer_key_source: SdJwtIssuerKeySource,
    issuer_identity: String,
}

impl SdJwtTrustProvider for FixtureTrustProvider {
    fn resolve_verification_keys(
        &self,
        _compact: &str,
        _credential_query: &CredentialQuery,
        _now_unix: u64,
    ) -> Result<SdJwtVerificationKeyMaterial, SdJwtFormatError> {
        Ok(SdJwtVerificationKeyMaterial::new(
            self.issuer_jwk.clone(),
            self.issuer_public_key.clone(),
            self.holder_jwk.clone(),
            self.holder_public_key.clone(),
            self.issuer_key_source,
            SdJwtIssuerIdentity::new(self.issuer_identity.clone())?,
        ))
    }

    fn verify_credential_status(
        &self,
        _issuer_payload: &JsonValue,
        _resolved_payload: &JsonValue,
    ) -> Result<(), SdJwtFormatError> {
        self.status_result
    }
}

struct UnavailableTrustProvider;

impl SdJwtTrustProvider for UnavailableTrustProvider {
    fn resolve_verification_keys(
        &self,
        _compact: &str,
        _credential_query: &CredentialQuery,
        _now_unix: u64,
    ) -> Result<SdJwtVerificationKeyMaterial, SdJwtFormatError> {
        Err(SdJwtFormatError::new(
            SdJwtFormatErrorReason::KeyResolutionFailed,
        ))
    }

    fn verify_credential_status(
        &self,
        _issuer_payload: &JsonValue,
        _resolved_payload: &JsonValue,
    ) -> Result<(), SdJwtFormatError> {
        Err(SdJwtFormatError::new(
            SdJwtFormatErrorReason::InvalidCredentialStatus,
        ))
    }
}

#[test]
fn verifies_session_bound_sd_jwt_and_status() {
    let issuer = test_key();
    let holder = test_key();
    let compact = presentation(&issuer, &holder, "nonce-123");
    let provider = provider(&issuer, &holder, Ok(()));
    let query = credential_query(EXAMPLE_VCT);

    let verified = verify_sd_jwt_presentation(
        SdJwtPresentationVerificationInput {
            compact: &compact,
            expected_audience: "x509_hash:verifier.example",
            expected_nonce: "nonce-123",
            now_unix: 1_700_000_001,
            credential_query: &query,
        },
        &provider,
    )
    .expect("valid presentation verifies");

    assert_eq!(verified.audience, ["x509_hash:verifier.example"]);
    assert_eq!(verified.nonce, "nonce-123");
    assert_eq!(verified.issued_at_unix, 1_700_000_000);
    assert_eq!(verified.expiration_unix, 0);
    assert!(!verified.sd_hash.is_empty());
}

#[test]
fn rejects_invalid_issuer_signature() {
    let issuer = test_key();
    let holder = test_key();
    let compact = presentation(&issuer, &holder, "nonce-123");
    let (issuer_signed_jwt, key_binding_jwt) = compact
        .split_once('~')
        .expect("test presentation contains issuer and key-binding JWTs");
    let (signing_input, signature) = issuer_signed_jwt
        .rsplit_once('.')
        .expect("test issuer JWT contains a signature segment");
    let first = signature
        .chars()
        .next()
        .expect("test issuer signature is not empty");
    let replacement = if first == 'A' { 'B' } else { 'A' };
    let invalid_signature = format!(
        "{signing_input}.{replacement}{}~{key_binding_jwt}",
        &signature[first.len_utf8()..]
    );
    let provider = provider(&issuer, &holder, Ok(()));
    let query = credential_query(EXAMPLE_VCT);

    let error = verify_sd_jwt_presentation(
        SdJwtPresentationVerificationInput {
            compact: &invalid_signature,
            expected_audience: "x509_hash:verifier.example",
            expected_nonce: "nonce-123",
            now_unix: 1_700_000_001,
            credential_query: &query,
        },
        &provider,
    )
    .expect_err("an issuer signature substitution must fail closed");

    assert_eq!(
        error.reason(),
        SdJwtFormatErrorReason::InvalidCredentialSignature
    );
}

#[test]
fn rejects_disclosure_added_after_key_binding() {
    const UNBOUND_DISCLOSURE: &str = "WyJzYWx0IiwibmFtZSwiQWxpY2UiXQ";

    let issuer = test_key();
    let holder = test_key();
    let compact = presentation(&issuer, &holder, "nonce-123");
    let (issuer_signed_jwt, key_binding_jwt) = compact
        .split_once('~')
        .expect("test presentation contains issuer and key-binding JWTs");
    let invalid_disclosure_binding =
        format!("{issuer_signed_jwt}~{UNBOUND_DISCLOSURE}~{key_binding_jwt}");
    let provider = provider(&issuer, &holder, Ok(()));
    let query = credential_query(EXAMPLE_VCT);

    let error = verify_sd_jwt_presentation(
        SdJwtPresentationVerificationInput {
            compact: &invalid_disclosure_binding,
            expected_audience: "x509_hash:verifier.example",
            expected_nonce: "nonce-123",
            now_unix: 1_700_000_001,
            credential_query: &query,
        },
        &provider,
    )
    .expect_err("a disclosure absent from the signed sd_hash must fail closed");

    assert_eq!(error.reason(), SdJwtFormatErrorReason::InvalidPresentation);
}

#[test]
fn accepts_absent_optional_issuer_temporal_claims() {
    let issuer = test_key();
    let holder = test_key();
    let compact = presentation_with_issuer_times(&issuer, &holder, "nonce-123", None, None, None);
    let provider = provider(&issuer, &holder, Ok(()));
    let query = credential_query(EXAMPLE_VCT);

    verify_sd_jwt_presentation(
        SdJwtPresentationVerificationInput {
            compact: &compact,
            expected_audience: "x509_hash:verifier.example",
            expected_nonce: "nonce-123",
            now_unix: 1_700_000_001,
            credential_query: &query,
        },
        &provider,
    )
    .expect("optional issuer temporal claims may be absent");
}

#[test]
fn accepts_issuer_temporal_claims_at_clock_skew_boundaries() {
    let issuer = test_key();
    let holder = test_key();
    let compact = presentation_with_issuer_times(
        &issuer,
        &holder,
        "nonce-123",
        Some(json!(1_700_000_061_u64)),
        Some(json!(1_700_000_061_u64)),
        Some(json!(1_700_000_300_u64)),
    );
    let provider = provider(&issuer, &holder, Ok(()));
    let query = credential_query(EXAMPLE_VCT);

    verify_sd_jwt_presentation(
        SdJwtPresentationVerificationInput {
            compact: &compact,
            expected_audience: "x509_hash:verifier.example",
            expected_nonce: "nonce-123",
            now_unix: 1_700_000_001,
            credential_query: &query,
        },
        &provider,
    )
    .expect("issuer validity at the accepted skew boundary verifies");
}

#[test]
fn rejects_malformed_issuer_temporal_claims() {
    let issuer = test_key();
    let holder = test_key();
    let provider = provider(&issuer, &holder, Ok(()));
    let query = credential_query(EXAMPLE_VCT);
    let cases = [
        (Some(json!("1700000000")), None, None),
        (None, Some(json!(1_700_000_000.5_f64)), None),
        (None, None, Some(json!(-1_i64))),
        (Some(json!(0_u64)), None, None),
    ];

    for (issued_at, not_before, expiration) in cases {
        let compact = presentation_with_issuer_times(
            &issuer,
            &holder,
            "nonce-123",
            issued_at,
            not_before,
            expiration,
        );
        let error = verify_sd_jwt_presentation(
            SdJwtPresentationVerificationInput {
                compact: &compact,
                expected_audience: "x509_hash:verifier.example",
                expected_nonce: "nonce-123",
                now_unix: 1_700_000_001,
                credential_query: &query,
            },
            &provider,
        )
        .expect_err("invalid issuer NumericDate must fail closed");

        assert_eq!(
            error.reason(),
            SdJwtFormatErrorReason::InvalidCredentialValidity
        );
    }
}

#[test]
fn rejects_issuer_credential_that_is_not_yet_valid() {
    let issuer = test_key();
    let holder = test_key();
    let provider = provider(&issuer, &holder, Ok(()));
    let query = credential_query(EXAMPLE_VCT);

    for (issued_at, not_before) in [
        (Some(json!(1_700_000_062_u64)), None),
        (None, Some(json!(1_700_000_062_u64))),
    ] {
        let compact = presentation_with_issuer_times(
            &issuer,
            &holder,
            "nonce-123",
            issued_at,
            not_before,
            Some(json!(1_700_000_300_u64)),
        );
        let error = verify_sd_jwt_presentation(
            SdJwtPresentationVerificationInput {
                compact: &compact,
                expected_audience: "x509_hash:verifier.example",
                expected_nonce: "nonce-123",
                now_unix: 1_700_000_001,
                credential_query: &query,
            },
            &provider,
        )
        .expect_err("future issuer validity claim outside clock skew must fail");

        assert_eq!(
            error.reason(),
            SdJwtFormatErrorReason::InvalidCredentialValidity
        );
    }
}

#[test]
fn rejects_expired_issuer_credential() {
    let issuer = test_key();
    let holder = test_key();
    let compact = presentation_with_issuer_times(
        &issuer,
        &holder,
        "nonce-123",
        Some(json!(1_699_999_000_u64)),
        None,
        Some(json!(1_699_999_941_u64)),
    );
    let provider = provider(&issuer, &holder, Ok(()));
    let query = credential_query(EXAMPLE_VCT);

    let error = verify_sd_jwt_presentation(
        SdJwtPresentationVerificationInput {
            compact: &compact,
            expected_audience: "x509_hash:verifier.example",
            expected_nonce: "nonce-123",
            now_unix: 1_700_000_001,
            credential_query: &query,
        },
        &provider,
    )
    .expect_err("issuer credential at the expiration floor must fail");

    assert_eq!(
        error.reason(),
        SdJwtFormatErrorReason::InvalidCredentialValidity
    );
}

#[test]
fn rejects_nonce_mismatch() {
    let issuer = test_key();
    let holder = test_key();
    let compact = presentation(&issuer, &holder, "different-nonce");
    let provider = provider(&issuer, &holder, Ok(()));
    let query = credential_query(EXAMPLE_VCT);

    let error = verify_sd_jwt_presentation(
        SdJwtPresentationVerificationInput {
            compact: &compact,
            expected_audience: "x509_hash:verifier.example",
            expected_nonce: "nonce-123",
            now_unix: 1_700_000_001,
            credential_query: &query,
        },
        &provider,
    )
    .expect_err("nonce substitution must fail");

    assert_eq!(error.reason(), SdJwtFormatErrorReason::InvalidHolderBinding);
}

#[test]
fn rejects_audience_mismatch() {
    let issuer = test_key();
    let holder = test_key();
    let compact = presentation(&issuer, &holder, "nonce-123");
    let provider = provider(&issuer, &holder, Ok(()));
    let query = credential_query(EXAMPLE_VCT);

    let error = verify_sd_jwt_presentation(
        SdJwtPresentationVerificationInput {
            compact: &compact,
            expected_audience: "x509_hash:another-verifier.example",
            expected_nonce: "nonce-123",
            now_unix: 1_700_000_001,
            credential_query: &query,
        },
        &provider,
    )
    .expect_err("audience substitution must fail");

    assert_eq!(error.reason(), SdJwtFormatErrorReason::InvalidHolderBinding);
}

#[test]
fn rejects_non_final_or_missing_issuer_type() {
    let issuer = test_key();
    let holder = test_key();
    let provider = provider(&issuer, &holder, Ok(()));
    let query = credential_query(EXAMPLE_VCT);

    for issuer_type in [None, Some("JWT"), Some("vc+sd-jwt"), Some("example+sd-jwt")] {
        let compact = presentation_with_issuer_times_and_type(
            &issuer,
            &holder,
            "nonce-123",
            IssuerJwtFixtureOptions {
                issued_at: Some(json!(1_700_000_000_u64)),
                not_before: None,
                expiration: None,
                issuer_type,
                include_confirmation: true,
            },
        );
        let error = verify_sd_jwt_presentation(
            SdJwtPresentationVerificationInput {
                compact: &compact,
                expected_audience: "x509_hash:verifier.example",
                expected_nonce: "nonce-123",
                now_unix: 1_700_000_001,
                credential_query: &query,
            },
            &provider,
        )
        .expect_err("non-final issuer type must fail closed");

        assert_eq!(
            error.reason(),
            SdJwtFormatErrorReason::InvalidCredentialSignature
        );
    }
}

#[test]
fn rejects_stale_key_binding_proof() {
    let issuer = test_key();
    let holder = test_key();
    let compact = presentation(&issuer, &holder, "nonce-123");
    let provider = provider(&issuer, &holder, Ok(()));
    let query = credential_query(EXAMPLE_VCT);

    let error = verify_sd_jwt_presentation(
        SdJwtPresentationVerificationInput {
            compact: &compact,
            expected_audience: "x509_hash:verifier.example",
            expected_nonce: "nonce-123",
            now_unix: 1_700_001_000,
            credential_query: &query,
        },
        &provider,
    )
    .expect_err("stale key binding proof must fail");

    assert_eq!(error.reason(), SdJwtFormatErrorReason::InvalidHolderBinding);
}

#[test]
fn rejects_holder_key_that_differs_from_issuer_confirmation() {
    let issuer = test_key();
    let holder = test_key();
    let substituted_holder = test_key();
    let compact = presentation(&issuer, &holder, "nonce-123");
    let provider = provider(&issuer, &substituted_holder, Ok(()));
    let query = credential_query(EXAMPLE_VCT);

    let error = verify_sd_jwt_presentation(
        SdJwtPresentationVerificationInput {
            compact: &compact,
            expected_audience: "x509_hash:verifier.example",
            expected_nonce: "nonce-123",
            now_unix: 1_700_000_001,
            credential_query: &query,
        },
        &provider,
    )
    .expect_err("substituted holder key must fail");

    assert_eq!(error.reason(), SdJwtFormatErrorReason::InvalidHolderBinding);
}

#[test]
fn rejects_missing_issuer_confirmation_when_holder_binding_is_required() {
    let issuer = test_key();
    let holder = test_key();
    let compact = presentation_with_issuer_times_and_type(
        &issuer,
        &holder,
        "nonce-123",
        IssuerJwtFixtureOptions {
            issued_at: Some(json!(1_700_000_000_u64)),
            not_before: None,
            expiration: None,
            issuer_type: Some("dc+sd-jwt"),
            include_confirmation: false,
        },
    );
    let provider = provider(&issuer, &holder, Ok(()));
    let query = credential_query(EXAMPLE_VCT);

    let error = verify_sd_jwt_presentation(
        SdJwtPresentationVerificationInput {
            compact: &compact,
            expected_audience: "x509_hash:verifier.example",
            expected_nonce: "nonce-123",
            now_unix: 1_700_000_001,
            credential_query: &query,
        },
        &provider,
    )
    .expect_err("a key-binding JWT cannot replace issuer confirmation");

    assert_eq!(error.reason(), SdJwtFormatErrorReason::InvalidHolderBinding);
}

#[test]
fn rejects_status_failure_after_cryptographic_verification() {
    let issuer = test_key();
    let holder = test_key();
    let compact = presentation(&issuer, &holder, "nonce-123");
    let provider = provider(
        &issuer,
        &holder,
        Err(SdJwtFormatError::new(
            SdJwtFormatErrorReason::CredentialRevoked,
        )),
    );
    let query = credential_query(EXAMPLE_VCT);

    let error = verify_sd_jwt_presentation(
        SdJwtPresentationVerificationInput {
            compact: &compact,
            expected_audience: "x509_hash:verifier.example",
            expected_nonce: "nonce-123",
            now_unix: 1_700_000_001,
            credential_query: &query,
        },
        &provider,
    )
    .expect_err("revoked credential must fail");

    assert_eq!(error.reason(), SdJwtFormatErrorReason::CredentialRevoked);
}

#[test]
fn rejects_verified_credential_that_does_not_match_query_vct() {
    let issuer = test_key();
    let holder = test_key();
    let compact = presentation(&issuer, &holder, "nonce-123");
    let provider = provider(&issuer, &holder, Ok(()));
    let query = credential_query("https://credentials.example/another-type");

    let error = verify_sd_jwt_presentation(
        SdJwtPresentationVerificationInput {
            compact: &compact,
            expected_audience: "x509_hash:verifier.example",
            expected_nonce: "nonce-123",
            now_unix: 1_700_000_001,
            credential_query: &query,
        },
        &provider,
    )
    .expect_err("a cryptographically valid credential of another type must fail");

    assert_eq!(
        error.reason(),
        SdJwtFormatErrorReason::CredentialQueryMismatch
    );
}

#[test]
fn rejects_oversized_presentation_before_trust_resolution() {
    let oversized = "x".repeat(MAX_SD_JWT_COMPACT_BYTES + 1);
    let query = credential_query(EXAMPLE_VCT);

    let error = verify_sd_jwt_presentation(
        SdJwtPresentationVerificationInput {
            compact: &oversized,
            expected_audience: "x509_hash:verifier.example",
            expected_nonce: "nonce-123",
            now_unix: 1_700_000_001,
            credential_query: &query,
        },
        &UnavailableTrustProvider,
    )
    .expect_err("oversized presentation must fail before trust resolution");

    assert_eq!(error.reason(), SdJwtFormatErrorReason::InvalidPresentation);
}

#[test]
fn rejects_oversized_binding_values_before_trust_resolution() {
    let oversized = "x".repeat(8 * 1024 + 1);
    let query = credential_query(EXAMPLE_VCT);

    let error = verify_sd_jwt_presentation(
        SdJwtPresentationVerificationInput {
            compact: "bounded",
            expected_audience: "x509_hash:verifier.example",
            expected_nonce: &oversized,
            now_unix: 1_700_000_001,
            credential_query: &query,
        },
        &UnavailableTrustProvider,
    )
    .expect_err("oversized binding value must fail before trust resolution");

    assert_eq!(error.reason(), SdJwtFormatErrorReason::InvalidPresentation);
}

#[test]
fn presentation_input_debug_redacts_compact_and_binding_values() {
    let query = credential_query(EXAMPLE_VCT);
    let input = SdJwtPresentationVerificationInput {
        compact: "issuer~disclosure~holder",
        expected_audience: "x509_hash:verifier.example",
        expected_nonce: "secret-nonce",
        now_unix: 1_700_000_001,
        credential_query: &query,
    };
    let debug = format!("{input:?}");

    assert!(!debug.contains(input.compact));
    assert!(!debug.contains(input.expected_audience));
    assert!(!debug.contains(input.expected_nonce));
    assert!(debug.contains("<redacted>"));
}

fn provider(
    issuer: &TestKey,
    holder: &TestKey,
    status_result: Result<(), SdJwtFormatError>,
) -> FixtureTrustProvider {
    FixtureTrustProvider {
        issuer_jwk: issuer.jwk.clone(),
        issuer_public_key: issuer.public.clone(),
        holder_jwk: holder.jwk.clone(),
        holder_public_key: holder.public.clone(),
        status_result,
        issuer_key_source: SdJwtIssuerKeySource::Resolved,
        issuer_identity: "https://issuer.example".to_owned(),
    }
}

fn presentation(issuer: &TestKey, holder: &TestKey, nonce: &str) -> String {
    presentation_with_issuer_times(
        issuer,
        holder,
        nonce,
        Some(json!(1_700_000_000_u64)),
        None,
        None,
    )
}

fn presentation_with_issuer_times(
    issuer: &TestKey,
    holder: &TestKey,
    nonce: &str,
    issued_at: Option<JsonValue>,
    not_before: Option<JsonValue>,
    expiration: Option<JsonValue>,
) -> String {
    presentation_with_issuer_times_and_type(
        issuer,
        holder,
        nonce,
        IssuerJwtFixtureOptions {
            issued_at,
            not_before,
            expiration,
            issuer_type: Some("dc+sd-jwt"),
            include_confirmation: true,
        },
    )
}

struct IssuerJwtFixtureOptions<'a> {
    issued_at: Option<JsonValue>,
    not_before: Option<JsonValue>,
    expiration: Option<JsonValue>,
    issuer_type: Option<&'a str>,
    include_confirmation: bool,
}

fn presentation_with_issuer_times_and_type(
    issuer: &TestKey,
    holder: &TestKey,
    nonce: &str,
    options: IssuerJwtFixtureOptions<'_>,
) -> String {
    let mut issuer_payload = JsonMap::new();
    issuer_payload.insert("iss".to_owned(), json!("https://issuer.example"));
    issuer_payload.insert("vct".to_owned(), json!(EXAMPLE_VCT));
    issuer_payload.insert("_sd_alg".to_owned(), json!("sha-256"));
    if options.include_confirmation {
        issuer_payload.insert("cnf".to_owned(), json!({ "jwk": holder.jwk.clone() }));
    }
    for (claim_name, claim_value) in [
        ("iat", options.issued_at),
        ("nbf", options.not_before),
        ("exp", options.expiration),
    ] {
        if let Some(value) = claim_value {
            issuer_payload.insert(claim_name.to_owned(), value);
        }
    }
    let issuer_payload = JsonValue::Object(issuer_payload);
    let issuer_signed_jwt = encode_signed_jwt_with_header_options(
        &issuer_payload,
        &issuer.jwk,
        &issuer.private,
        &JwtHeaderEncodeOptions::new(options.issuer_type.map(str::to_owned)),
    )
    .expect("issuer JWT signs");
    let disclosures = Vec::new();
    let key_binding_jwt = build_key_binding_jwt(
        &issuer_signed_jwt,
        &disclosures,
        &KeyBindingJwtBuildOptions {
            holder_jwk: &holder.jwk,
            holder_private_key: &holder.private,
            audience: "x509_hash:verifier.example",
            nonce,
            issued_at_unix: 1_700_000_000,
        },
    )
    .expect("key binding JWT signs");
    let compact_without_key_binding =
        serialize_sd_jwt_compact(&issuer_signed_jwt, &disclosures).expect("SD-JWT serializes");
    format!("{compact_without_key_binding}{key_binding_jwt}")
}

fn credential_query(vct: &str) -> CredentialQuery {
    let mut meta = JsonMap::new();
    meta.insert("vct_values".to_owned(), json!([vct]));
    CredentialQuery {
        id: QueryId::parse("pid").expect("test query id parses"),
        format: CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned())
            .expect("test format parses"),
        multiple: false,
        meta,
        trusted_authorities: None,
        require_cryptographic_holder_binding: true,
        claims: None,
        claim_sets: None,
    }
}
