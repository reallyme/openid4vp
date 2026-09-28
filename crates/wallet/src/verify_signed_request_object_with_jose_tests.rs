// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_dc_api::JwsJsonGeneral;
use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_types::{
    AuthorizationRequestObject, ClientIdentifier, ClientIdentifierPrefix, ResponseMode,
    ResponseType,
};
use serde_json::Map as JsonMap;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    verify_multisigned_request_object, verify_signed_request_object, BoundedX509CertificateChain,
    JoseRequestObjectVerification, JoseRequestObjectVerificationResolver,
    JoseSignedRequestObjectVerifier, TrustedX509RequestObjectSigner,
    VerifiedClientIdentifierBinding, VerifiedPlatformOrigin, VerifiedVerifierAttestation,
    WalletAuthorizationRequest, WalletError, WalletErrorReason, WalletInvocationContext,
    X509RequestObjectTrustDecision, X509TrustDecisionContext,
};

const TEST_LEAF_CERTIFICATE_DER: &[u8] = b"test";

fn dc_api_invocation() -> WalletInvocationContext {
    WalletInvocationContext::DigitalCredentialsApi(
        VerifiedPlatformOrigin::from_browser_security_context("https://rp.example".to_owned())
            .expect("test origin is valid"),
    )
}

static TEST_P256_SECRET: [u8; 32] = [
    0x21, 0x4f, 0x8b, 0x6c, 0xa2, 0x9d, 0x33, 0x10, 0x95, 0x47, 0x66, 0x12, 0x72, 0x83, 0xaf, 0xee,
    0x0d, 0x19, 0x41, 0x5b, 0x7c, 0x22, 0xd4, 0x39, 0x51, 0x8a, 0xb0, 0x65, 0x2f, 0x91, 0xc3, 0x44,
];
static WRONG_P256_SECRET: [u8; 32] = [
    0x6a, 0x10, 0x45, 0xf2, 0x33, 0x9e, 0x80, 0x12, 0xab, 0x74, 0xc6, 0x28, 0xde, 0x91, 0x07, 0x5b,
    0x49, 0xef, 0x32, 0x18, 0x84, 0x2d, 0xbc, 0x60, 0x13, 0xa5, 0x77, 0xc9, 0x0e, 0x4b, 0x26, 0xd1,
];

impl<R> JoseSignedRequestObjectVerifier<R> {
    fn with_policy(
        resolver: R,
        expected_audience: String,
        temporal_policy: reallyme_jose::jwt::JwtTemporalValidationPolicy,
        header_validation: reallyme_jose::jwt::JwtHeaderValidationOptions<'static>,
    ) -> Self {
        Self {
            resolver,
            expected_audience: Zeroizing::new(expected_audience),
            temporal_policy,
            header_validation,
        }
    }
}

struct FixtureKeyResolver {
    jwk: reallyme_crypto::jwk::Jwk,
    public_key: Vec<u8>,
    verifier_attestation: Option<Result<VerifiedVerifierAttestation, WalletErrorReason>>,
    x509_dns_sans: Option<Vec<String>>,
    x509_leaf_public_key: Option<Vec<u8>>,
    x509_chain_override: Option<BoundedX509CertificateChain>,
}

impl JoseRequestObjectVerificationResolver for FixtureKeyResolver {
    fn resolve_request_object_verification(
        &self,
        _jwt: &str,
        claimed_client_identifier: Option<&ClientIdentifier>,
        x509_chain: Option<&BoundedX509CertificateChain>,
        _now_unix: u64,
    ) -> Result<JoseRequestObjectVerification, WalletError> {
        let mut verification =
            JoseRequestObjectVerification::new(self.jwk.clone(), self.public_key.clone());
        if let Some(client_id) = claimed_client_identifier.filter(|client_id| {
            matches!(
                client_id.prefix(),
                ClientIdentifierPrefix::DecentralizedIdentifier
                    | ClientIdentifierPrefix::OpenIdFederation
            )
        }) {
            verification = verification.with_client_identifier_binding(
                VerifiedClientIdentifierBinding::new(client_id.clone(), &self.public_key)?,
            );
        }
        if let Some(attestation) = self.verifier_attestation.as_ref() {
            verification = verification.with_verifier_attestation(match attestation {
                Ok(attestation) => attestation.clone(),
                Err(reason) => return Err(WalletError::new(*reason)),
            });
        }
        if let Some(dns_sans) = self.x509_dns_sans.as_ref() {
            let chain = match self.x509_chain_override.as_ref() {
                Some(chain) => chain.clone(),
                None => x509_chain.cloned().ok_or_else(|| {
                    WalletError::new(WalletErrorReason::MissingX509CertificateChain)
                })?,
            };
            let context = X509TrustDecisionContext::new(1, [1_u8; 32], [2_u8; 32], 10, 20)?;
            let signer = TrustedX509RequestObjectSigner::new(
                chain,
                self.x509_leaf_public_key
                    .clone()
                    .unwrap_or_else(|| self.public_key.clone()),
                dns_sans.clone(),
                context,
            )?;
            verification = verification
                .with_x509_trust_decision(X509RequestObjectTrustDecision::Trusted(signer));
        }
        Ok(verification)
    }
}

fn request(exp: u64, iat: u64) -> AuthorizationRequestObject {
    AuthorizationRequestObject {
        client_id: Some(
            ClientIdentifier::parse("decentralized_identifier:did:example:verifier")
                .expect("test client id is valid"),
        ),
        response_type: ResponseType::VpToken,
        response_mode: Some(ResponseMode::DcApiJwt),
        response_uri: None,
        redirect_uri: None,
        nonce: "0123456789abcdef".to_owned(),
        wallet_nonce: None,
        state: None,
        dcql_query: DcqlQuery {
            credentials: vec![CredentialQuery {
                id: QueryId::parse("pid").expect("test query id is valid"),
                format: CredentialFormat::new(CredentialFormat::MSO_MDOC.to_owned())
                    .expect("test format is valid"),
                multiple: false,
                meta: {
                    let mut meta = JsonMap::new();
                    meta.insert(
                        "doctype_value".to_owned(),
                        serde_json::json!("org.iso.18013.5.1.mDL"),
                    );
                    meta
                },
                trusted_authorities: None,
                require_cryptographic_holder_binding: true,
                claims: None,
                claim_sets: None,
            }],
            credential_sets: None,
        },
        transaction_data: None,
        client_metadata: None,
        client_metadata_uri: None,
        expected_origins: Some(vec!["https://rp.example".to_owned()]),
        iss: Some("decentralized_identifier:did:example:verifier".to_owned()),
        aud: Some(vec!["wallet".to_owned()]),
        iat: Some(iat),
        exp: Some(exp),
    }
}

fn key_resolver(secret: &[u8; 32]) -> FixtureKeyResolver {
    let (public_key, _secret_key) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(secret)
            .expect("test P-256 key is valid");
    let jwk = reallyme_crypto::jwk::p256_public_key_to_jwk(
        &public_key,
        reallyme_crypto::jwk::JwkOptions {
            alg: true,
            use_sig: true,
            use_enc: false,
            kid: Some("verifier-key-1".to_owned()),
        },
    )
    .expect("test JWK is valid");
    FixtureKeyResolver {
        jwk: reallyme_crypto::jwk::Jwk::Ec(jwk),
        public_key,
        verifier_attestation: None,
        x509_dns_sans: None,
        x509_leaf_public_key: None,
        x509_chain_override: None,
    }
}

fn key_resolver_with_attestation(
    verifier_attestation: Result<VerifiedVerifierAttestation, WalletErrorReason>,
) -> FixtureKeyResolver {
    let mut resolver = key_resolver(&TEST_P256_SECRET);
    resolver.verifier_attestation = Some(verifier_attestation);
    resolver
}

fn test_public_key() -> Vec<u8> {
    key_resolver(&TEST_P256_SECRET).public_key
}

fn verifier(resolver: FixtureKeyResolver) -> JoseSignedRequestObjectVerifier<FixtureKeyResolver> {
    JoseSignedRequestObjectVerifier::new(resolver, "wallet".to_owned())
}

fn signed_request_object() -> String {
    signed_request_object_for(&request(20, 10))
}

fn signed_request_object_for(request: &AuthorizationRequestObject) -> String {
    signed_request_object_for_typ(request, Some("oauth-authz-req+jwt".to_owned()))
}

fn signed_request_object_for_typ(
    request: &AuthorizationRequestObject,
    typ: Option<String>,
) -> String {
    let resolver = key_resolver(&TEST_P256_SECRET);
    reallyme_jose::jwt::encode_signed_jwt_with_header_options(
        request,
        &resolver.jwk,
        &TEST_P256_SECRET,
        &reallyme_jose::jwt::JwtHeaderEncodeOptions::new(typ),
    )
    .expect("test request object signs")
}

fn signed_request_object_with_embedded_jwk_header() -> String {
    let resolver = key_resolver(&TEST_P256_SECRET);
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "oauth-authz-req+jwt",
        "kid": "verifier-key-1",
        "jwk": resolver.jwk,
    });
    let protected = reallyme_codec::base64url::bytes_to_base64url(
        &serde_json::to_vec(&header).expect("test JOSE header serializes"),
    );
    let payload = reallyme_codec::base64url::bytes_to_base64url(
        &serde_json::to_vec(&request(20, 10)).expect("test request serializes"),
    );
    let signing_input = format!("{protected}.{payload}");
    let signature = reallyme_jose::jws::suites::es256::sign_p256_jose_prehash(
        &TEST_P256_SECRET,
        signing_input.as_bytes(),
    )
    .expect("test request signs");
    let encoded_signature = reallyme_codec::base64url::bytes_to_base64url(&signature);
    format!("{signing_input}.{encoded_signature}")
}

fn x509_hash_request() -> AuthorizationRequestObject {
    let digest = Sha256::digest(TEST_LEAF_CERTIFICATE_DER);
    let encoded_hash = reallyme_codec::base64url::bytes_to_base64url(&digest);
    let mut client_id = "x509_hash:".to_owned();
    client_id.push_str(&encoded_hash);
    let mut request = request(20, 10);
    request.client_id =
        Some(ClientIdentifier::parse(&client_id).expect("test x509 client id is valid"));
    request.iss = Some(client_id);
    request
}

fn signed_request_object_with_x5c_header(request: &AuthorizationRequestObject) -> String {
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "oauth-authz-req+jwt",
        "kid": "verifier-key-1",
        "x5c": ["dGVzdA=="],
    });
    signed_request_object_with_header_bytes(
        request,
        &serde_json::to_vec(&header).expect("test JOSE header serializes"),
    )
}

fn signed_request_object_with_header_bytes(
    request: &AuthorizationRequestObject,
    header: &[u8],
) -> String {
    let protected = reallyme_codec::base64url::bytes_to_base64url(header);
    let payload = reallyme_codec::base64url::bytes_to_base64url(
        &serde_json::to_vec(request).expect("test request serializes"),
    );
    let signing_input = format!("{protected}.{payload}");
    let signature = reallyme_jose::jws::suites::es256::sign_p256_jose_prehash(
        &TEST_P256_SECRET,
        signing_input.as_bytes(),
    )
    .expect("test request signs");
    let encoded_signature = reallyme_codec::base64url::bytes_to_base64url(&signature);
    format!("{signing_input}.{encoded_signature}")
}

fn multisigned_request_object_with_one_invalid_signature() -> Vec<u8> {
    let mut request = x509_hash_request();
    let client_id = request
        .client_id
        .as_ref()
        .expect("test request has a client identifier")
        .to_wire_value();
    request.client_id = None;
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "oauth-authz-req+jwt",
        "kid": "verifier-key-1",
        "client_id": client_id,
        "x5c": ["dGVzdA=="],
    });
    let protected = reallyme_codec::base64url::bytes_to_base64url(
        &serde_json::to_vec(&header).expect("test JOSE header serializes"),
    );
    let payload = reallyme_codec::base64url::bytes_to_base64url(
        &serde_json::to_vec(&request).expect("test request serializes"),
    );
    let signing_input = format!("{protected}.{payload}");
    let signature = reallyme_jose::jws::suites::es256::sign_p256_jose_prehash(
        &TEST_P256_SECRET,
        signing_input.as_bytes(),
    )
    .expect("test request signs");
    let encoded_signature = reallyme_codec::base64url::bytes_to_base64url(&signature);
    serde_json::to_vec(&serde_json::json!({
        "payload": payload,
        "signatures": [
            {
                "protected": protected,
                "signature": "aW52YWxpZA"
            },
            {
                "protected": protected,
                "signature": encoded_signature
            }
        ]
    }))
    .expect("test JWS JSON serializes")
}

fn verifier_attestation_request() -> AuthorizationRequestObject {
    let mut request = request(20, 10);
    request.client_id = Some(
        ClientIdentifier::parse("verifier_attestation:verifier.example")
            .expect("test verifier attestation client id is valid"),
    );
    request.iss = Some("verifier_attestation:verifier.example".to_owned());
    request.response_mode = Some(ResponseMode::FormPost);
    request.redirect_uri = Some("https://verifier.example/cb".to_owned());
    request.expected_origins = None;
    request
}

#[test]
fn verifies_signed_request_object_with_jose() {
    let jwt = signed_request_object();
    let verifier = verifier(key_resolver(&TEST_P256_SECRET));
    let verified = verify_signed_request_object(&verifier, &jwt, &dc_api_invocation(), 11)
        .expect("signed Request Object verifies");

    assert_eq!(verified.request().nonce, "0123456789abcdef");
}

#[test]
fn verifies_request_object_without_optional_temporal_claims() {
    let mut request =
        serde_json::to_value(request(20, 10)).expect("test Request Object serializes as JSON");
    let request = request
        .as_object_mut()
        .expect("test Request Object serializes as an object");
    request.remove("exp");
    request.remove("iat");
    let resolver = key_resolver(&TEST_P256_SECRET);
    let jwt = reallyme_jose::jwt::encode_signed_jwt_with_header_options(
        request,
        &resolver.jwk,
        &TEST_P256_SECRET,
        &reallyme_jose::jwt::JwtHeaderEncodeOptions::new(Some("oauth-authz-req+jwt".to_owned())),
    )
    .expect("test Request Object signs");
    let claims_policy = reallyme_jose::jwt::JwtClaimsValidationPolicy::new(
        super::request_object_temporal_policy(),
        "wallet",
        None,
        None,
    );
    let _: AuthorizationRequestObject =
        reallyme_jose::jwt::decode_verify_jwt_with_claims_validation_and_header_validation(
            &jwt,
            &resolver.jwk,
            &resolver.public_key,
            11,
            claims_policy,
            &super::request_object_header_validation(),
        )
        .expect("JOSE accepts absent optional temporal claims");
    let verifier = verifier(key_resolver(&TEST_P256_SECRET));

    let verified = verify_signed_request_object(&verifier, &jwt, &dc_api_invocation(), 11)
        .expect("optional temporal claims may be absent");

    assert_eq!(verified.request().nonce, "0123456789abcdef");
}

#[test]
fn rejects_expired_request_object_when_expiration_is_present() {
    let jwt = signed_request_object_for(&request(100, 10));
    let verifier = verifier(key_resolver(&TEST_P256_SECRET));

    let err = verify_signed_request_object(&verifier, &jwt, &dc_api_invocation(), 200)
        .expect_err("present expiration must remain enforced");

    assert_eq!(err.reason(), WalletErrorReason::RequestObjectExpired);
}

#[test]
fn rejects_request_object_with_future_issued_at_when_present() {
    let jwt = signed_request_object_for(&request(2_000, 1_000));
    let verifier = verifier(key_resolver(&TEST_P256_SECRET));

    let err = verify_signed_request_object(&verifier, &jwt, &dc_api_invocation(), 10)
        .expect_err("present issued-at must remain bounded");

    assert_eq!(err.reason(), WalletErrorReason::RequestObjectIssuedInFuture);
}

#[test]
fn applies_one_custom_future_iat_policy_across_both_validation_layers() {
    let temporal_policy =
        reallyme_jose::jwt::JwtTemporalValidationPolicy::new(false, false, false, 60, 5);
    let accepted_request = request(100, 15);
    let accepted_jwt = signed_request_object_for(&accepted_request);
    let accepted_verifier = JoseSignedRequestObjectVerifier::with_policy(
        key_resolver(&TEST_P256_SECRET),
        "wallet".to_owned(),
        temporal_policy,
        super::request_object_header_validation(),
    );

    verify_signed_request_object(&accepted_verifier, &accepted_jwt, &dc_api_invocation(), 10)
        .expect("iat at the custom future-skew boundary is accepted by both layers");

    let rejected_request = request(100, 16);
    let rejected_jwt = signed_request_object_for(&rejected_request);
    let rejected_verifier = JoseSignedRequestObjectVerifier::with_policy(
        key_resolver(&TEST_P256_SECRET),
        "wallet".to_owned(),
        temporal_policy,
        super::request_object_header_validation(),
    );
    let error =
        verify_signed_request_object(&rejected_verifier, &rejected_jwt, &dc_api_invocation(), 10)
            .expect_err("iat beyond the custom future-skew boundary is rejected");

    assert_eq!(
        error.reason(),
        WalletErrorReason::RequestObjectIssuedInFuture
    );
}

#[test]
fn rejects_signed_request_object_with_wrong_key() {
    let jwt = signed_request_object();
    let verifier = verifier(key_resolver(&WRONG_P256_SECRET));
    let err = verify_signed_request_object(&verifier, &jwt, &dc_api_invocation(), 11)
        .expect_err("wrong key must not verify");

    assert_eq!(
        err.reason(),
        WalletErrorReason::InvalidRequestObjectSignature
    );
}

#[test]
fn rejects_signed_request_object_for_another_wallet_audience() {
    let jwt = signed_request_object();
    let verifier = JoseSignedRequestObjectVerifier::new(
        key_resolver(&TEST_P256_SECRET),
        "another-wallet".to_owned(),
    );
    let err = verify_signed_request_object(&verifier, &jwt, &dc_api_invocation(), 11)
        .expect_err("a Request Object for another wallet must not verify");

    assert_eq!(err.reason(), WalletErrorReason::InvalidRequestObject);
}

#[test]
fn rejects_signed_request_object_without_typ() {
    let jwt = signed_request_object_for_typ(&request(20, 10), None);
    let verifier = verifier(key_resolver(&TEST_P256_SECRET));
    let err = verify_signed_request_object(&verifier, &jwt, &dc_api_invocation(), 11)
        .expect_err("missing typ is rejected");

    assert_eq!(err.reason(), WalletErrorReason::InvalidRequestObject);
}

#[test]
fn rejects_signed_request_object_with_generic_jwt_typ() {
    let jwt = signed_request_object_for_typ(&request(20, 10), Some("JWT".to_owned()));
    let verifier = verifier(key_resolver(&TEST_P256_SECRET));
    let err = verify_signed_request_object(&verifier, &jwt, &dc_api_invocation(), 11)
        .expect_err("generic JWT typ is rejected");

    assert_eq!(err.reason(), WalletErrorReason::InvalidRequestObject);
}

#[test]
fn rejects_signed_request_object_with_embedded_jwk_header() {
    let jwt = signed_request_object_with_embedded_jwk_header();
    let verifier = verifier(key_resolver(&TEST_P256_SECRET));
    let err = verify_signed_request_object(&verifier, &jwt, &dc_api_invocation(), 11)
        .expect_err("embedded JOSE keys must not be trusted by the wallet verifier");

    assert_eq!(err.reason(), WalletErrorReason::InvalidRequestObject);
}

#[test]
fn rejects_remote_or_critical_jose_key_selection_headers() {
    let request = request(20, 10);
    for forbidden_member in [
        serde_json::json!({"jku": "https://attacker.example/jwks.json"}),
        serde_json::json!({"x5u": "https://attacker.example/chain.pem"}),
        serde_json::json!({"crit": ["attacker-extension"]}),
    ] {
        let mut header = serde_json::json!({
            "alg": "ES256",
            "typ": "oauth-authz-req+jwt",
            "kid": "verifier-key-1",
        });
        let header_object = header
            .as_object_mut()
            .expect("test header literal is an object");
        let forbidden_object = forbidden_member
            .as_object()
            .expect("test forbidden-member literal is an object");
        for (name, value) in forbidden_object {
            header_object.insert(name.clone(), value.clone());
        }
        let encoded = serde_json::to_vec(&header).expect("test header serializes");
        let jwt = signed_request_object_with_header_bytes(&request, &encoded);
        let error = verify_signed_request_object(
            &verifier(key_resolver(&TEST_P256_SECRET)),
            &jwt,
            &dc_api_invocation(),
            11,
        )
        .expect_err("remote and critical JOSE selectors are rejected");
        assert_eq!(error.reason(), WalletErrorReason::InvalidRequestObject);
    }
}

#[test]
fn accepts_x509_request_with_x5c_and_matching_certificate_evidence() {
    let request = x509_hash_request();
    let jwt = signed_request_object_with_x5c_header(&request);
    let mut resolver = key_resolver(&TEST_P256_SECRET);
    resolver.x509_dns_sans = Some(Vec::new());

    let verified =
        verify_signed_request_object(&verifier(resolver), &jwt, &dc_api_invocation(), 11)
            .expect("x509 Request Object with matching x5c evidence verifies");

    assert_eq!(verified.request().nonce, "0123456789abcdef");
}

#[test]
fn accepts_multisigned_x509_request_when_one_signature_is_valid() {
    let general_jws = multisigned_request_object_with_one_invalid_signature();
    let general_jws = JwsJsonGeneral::from_json(&general_jws).expect("test JWS JSON is valid");
    let mut resolver = key_resolver(&TEST_P256_SECRET);
    resolver.x509_dns_sans = Some(Vec::new());

    let verified = verify_multisigned_request_object(
        &verifier(resolver),
        &general_jws,
        &dc_api_invocation(),
        11,
    )
    .expect("one valid X.509 signature accepts the multi-signed request");

    assert_eq!(
        verified
            .request()
            .client_id
            .as_ref()
            .map(ClientIdentifier::prefix),
        Some(ClientIdentifierPrefix::X509Hash)
    );
}

#[test]
fn rejects_non_x509_request_with_x5c_header() {
    let jwt = signed_request_object_with_x5c_header(&request(20, 10));
    let verifier = verifier(key_resolver(&TEST_P256_SECRET));

    let err = verify_signed_request_object(&verifier, &jwt, &dc_api_invocation(), 11)
        .expect_err("x5c is valid only for an X.509 client identifier");

    assert_eq!(err.reason(), WalletErrorReason::InvalidRequestObject);
}

#[test]
fn rejects_x509_request_when_resolver_omits_trust_decision() {
    let request = x509_hash_request();
    let jwt = signed_request_object_with_x5c_header(&request);
    let verifier = verifier(key_resolver(&TEST_P256_SECRET));

    let err = verify_signed_request_object(&verifier, &jwt, &dc_api_invocation(), 11)
        .expect_err("an x5c chain without a trust decision is indeterminate");

    assert_eq!(
        err.reason(),
        WalletErrorReason::X509TrustEvidenceUnavailable
    );
}

#[test]
fn rejects_x509_request_without_x5c_header() {
    let request = x509_hash_request();
    let jwt = signed_request_object_for(&request);
    let mut resolver = key_resolver(&TEST_P256_SECRET);
    resolver.x509_dns_sans = Some(Vec::new());

    let err = verify_signed_request_object(&verifier(resolver), &jwt, &dc_api_invocation(), 11)
        .expect_err("an X.509 client identifier requires an x5c header");

    assert_eq!(err.reason(), WalletErrorReason::MissingX509CertificateChain);
}

#[test]
fn rejects_malformed_and_oversized_x5c_headers_before_trust_resolution() {
    let request = x509_hash_request();
    let invalid_base64 = serde_json::json!({
        "alg": "ES256",
        "typ": "oauth-authz-req+jwt",
        "kid": "verifier-key-1",
        "x5c": ["not base64"],
    });
    let too_many = serde_json::json!({
        "alg": "ES256",
        "typ": "oauth-authz-req+jwt",
        "kid": "verifier-key-1",
        "x5c": vec!["dGVzdA=="; crate::MAX_X509_CHAIN_CERTIFICATES + 1],
    });
    let encoded_certificate_too_large = serde_json::json!({
        "alg": "ES256",
        "typ": "oauth-authz-req+jwt",
        "kid": "verifier-key-1",
        "x5c": ["A".repeat(super::header::MAX_X509_CERTIFICATE_BASE64_BYTES + 1)],
    });
    let malformed_after_valid_certificate = serde_json::json!({
        "alg": "ES256",
        "typ": "oauth-authz-req+jwt",
        "kid": "verifier-key-1",
        "x5c": ["dGVzdA==", "not base64"],
    });
    for header in [
        invalid_base64,
        too_many,
        encoded_certificate_too_large,
        malformed_after_valid_certificate,
    ] {
        let encoded = serde_json::to_vec(&header).expect("test header serializes");
        let jwt = signed_request_object_with_header_bytes(&request, &encoded);
        let err = verify_signed_request_object(
            &verifier(key_resolver(&TEST_P256_SECRET)),
            &jwt,
            &dc_api_invocation(),
            11,
        )
        .expect_err("malformed x5c is rejected");
        assert_eq!(
            err.reason(),
            WalletErrorReason::MalformedX509CertificateChain
        );
    }
}

#[test]
fn rejects_oversized_and_non_compact_jws_before_resolver_use() {
    let verifier = verifier(key_resolver(&TEST_P256_SECRET));
    let oversized = "a".repeat(super::header::MAX_SIGNED_REQUEST_OBJECT_BYTES + 1);
    let oversized_error =
        verify_signed_request_object(&verifier, &oversized, &dc_api_invocation(), 11)
            .expect_err("oversized compact JWS is rejected");
    assert_eq!(
        oversized_error.reason(),
        WalletErrorReason::RequestObjectTooLarge
    );

    for malformed in ["header.payload", "header..signature", "a.b.c.d"] {
        let error = verify_signed_request_object(&verifier, malformed, &dc_api_invocation(), 11)
            .expect_err("malformed compact JWS is rejected");
        assert_eq!(error.reason(), WalletErrorReason::InvalidRequestObject);
    }
}

#[test]
fn rejects_duplicate_x5c_header_members_before_resolver_use() {
    let request = x509_hash_request();
    let header = br#"{"alg":"ES256","typ":"oauth-authz-req+jwt","kid":"verifier-key-1","x5c":["dGVzdA=="],"x5c":["dGVzdA=="]}"#;
    let jwt = signed_request_object_with_header_bytes(&request, header);

    let err = verify_signed_request_object(
        &verifier(key_resolver(&TEST_P256_SECRET)),
        &jwt,
        &dc_api_invocation(),
        11,
    )
    .expect_err("duplicate security header is rejected");
    assert_eq!(err.reason(), WalletErrorReason::InvalidRequestObject);
}

#[test]
fn rejects_trust_result_bound_to_a_different_leaf_key_or_chain() {
    let request = x509_hash_request();
    let jwt = signed_request_object_with_x5c_header(&request);

    let mut wrong_key = key_resolver(&TEST_P256_SECRET);
    wrong_key.x509_dns_sans = Some(Vec::new());
    wrong_key.x509_leaf_public_key = Some(b"different leaf key".to_vec());
    let err = verify_signed_request_object(&verifier(wrong_key), &jwt, &dc_api_invocation(), 11)
        .expect_err("trust evidence for a different leaf key is rejected");
    assert_eq!(err.reason(), WalletErrorReason::X509LeafKeyMismatch);

    let mut wrong_chain = key_resolver(&TEST_P256_SECRET);
    wrong_chain.x509_dns_sans = Some(Vec::new());
    wrong_chain.x509_chain_override = Some(
        BoundedX509CertificateChain::new(vec![b"other leaf".to_vec()])
            .expect("bounded alternate chain"),
    );
    let err = verify_signed_request_object(&verifier(wrong_chain), &jwt, &dc_api_invocation(), 11)
        .expect_err("trust evidence for a different x5c chain is rejected");
    assert_eq!(err.reason(), WalletErrorReason::X509LeafKeyMismatch);
}

#[test]
fn accepts_verifier_attestation_evidence_from_jose_resolver() {
    let jwt = signed_request_object_for(&verifier_attestation_request());
    let attestation = VerifiedVerifierAttestation::new(
        "verifier.example".to_owned(),
        Some(vec!["https://verifier.example/cb".to_owned()]),
        test_public_key(),
        100,
    )
    .expect("test attestation evidence is valid");
    let verifier = verifier(key_resolver_with_attestation(Ok(attestation)));

    let verified = verify_signed_request_object(
        &verifier,
        &jwt,
        &WalletInvocationContext::ProtocolTransport,
        11,
    )
    .expect("host-verified attestation evidence is accepted");

    assert_eq!(
        verified
            .request()
            .client_id
            .as_ref()
            .map(ClientIdentifier::prefix),
        Some(ClientIdentifierPrefix::VerifierAttestation)
    );
}

#[test]
fn rejects_verifier_attestation_jws_failure_from_jose_resolver() {
    let jwt = signed_request_object_for(&verifier_attestation_request());
    let verifier = verifier(key_resolver_with_attestation(Err(
        WalletErrorReason::InvalidVerifierAttestation,
    )));

    let err = verify_signed_request_object(
        &verifier,
        &jwt,
        &WalletInvocationContext::ProtocolTransport,
        11,
    )
    .expect_err("attestation JWS validation failure is rejected");

    assert_eq!(err.reason(), WalletErrorReason::InvalidVerifierAttestation);
}

#[test]
fn rejects_verifier_attestation_subject_from_jose_resolver() {
    let jwt = signed_request_object_for(&verifier_attestation_request());
    let attestation =
        VerifiedVerifierAttestation::new("other.example".to_owned(), None, test_public_key(), 100)
            .expect("test attestation evidence is valid");
    let verifier = verifier(key_resolver_with_attestation(Ok(attestation)));

    let err = verify_signed_request_object(
        &verifier,
        &jwt,
        &WalletInvocationContext::ProtocolTransport,
        11,
    )
    .expect_err("attestation subject binding is rejected");

    assert_eq!(err.reason(), WalletErrorReason::InvalidVerifierAttestation);
}
