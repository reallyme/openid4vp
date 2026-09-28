// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_types::{
    AuthorizationRequestObject, ClientIdentifier, ClientMetadata, ResponseMode, ResponseType,
};
use serde_json::Map as JsonMap;
use sha2::{Digest, Sha256};

use crate::{
    verify_signed_request_object, BoundedX509CertificateChain, JoseNestedRequestObjectVerifier,
    JoseRequestObjectVerification, JoseRequestObjectVerificationResolver,
    JoseSignedRequestObjectVerifier, TrustedX509RequestObjectSigner,
    VerifiedClientIdentifierBinding, VerifiedClientMetadataReference, VerifiedPlatformOrigin,
    VerifiedVerifierAttestation, WalletAuthorizationRequest, WalletError, WalletErrorReason,
    WalletInvocationContext, X509RequestObjectTrustDecision, X509TrustDecisionContext,
};

static TEST_JWE_KEY: [u8; 16] = [9u8; 16];
const TEST_LEAF_CERTIFICATE_DER: &[u8] = b"test nested leaf certificate DER";

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

struct FixtureKeyResolver {
    jwk: reallyme_crypto::jwk::Jwk,
    public_key: Vec<u8>,
    verifier_attestation: Option<VerifiedVerifierAttestation>,
    client_metadata_reference: Option<VerifiedClientMetadataReference>,
    x509_dns_sans: Option<Vec<String>>,
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
                reallyme_openid4vp_types::ClientIdentifierPrefix::DecentralizedIdentifier
                    | reallyme_openid4vp_types::ClientIdentifierPrefix::OpenIdFederation
            )
        }) {
            verification = verification.with_client_identifier_binding(
                VerifiedClientIdentifierBinding::new(client_id.clone(), &self.public_key)?,
            );
        }
        if let Some(attestation) = self.verifier_attestation.as_ref() {
            verification = verification.with_verifier_attestation(attestation.clone());
        }
        if let Some(metadata) = self.client_metadata_reference.as_ref() {
            verification = verification.with_client_metadata_reference(metadata.clone());
        }
        if let Some(dns_sans) = self.x509_dns_sans.as_ref() {
            let chain = x509_chain
                .cloned()
                .ok_or_else(|| WalletError::new(WalletErrorReason::MissingX509CertificateChain))?;
            let context = X509TrustDecisionContext::new(1, [1_u8; 32], [2_u8; 32], 10, 20)?;
            let signer = TrustedX509RequestObjectSigner::new(
                chain,
                self.public_key.clone(),
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

fn key_resolver() -> FixtureKeyResolver {
    let (public_key, _secret_key) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&TEST_P256_SECRET)
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
        client_metadata_reference: None,
        x509_dns_sans: None,
    }
}

fn signed_request_object() -> String {
    signed_request_object_for(&request(20, 10))
}

fn signed_request_object_for(request: &AuthorizationRequestObject) -> String {
    let resolver = key_resolver();
    reallyme_jose::jwt::encode_signed_jwt_with_header_options(
        request,
        &resolver.jwk,
        &TEST_P256_SECRET,
        &reallyme_jose::jwt::JwtHeaderEncodeOptions::new(Some("oauth-authz-req+jwt".to_owned())),
    )
    .expect("test request object signs")
}

fn signed_x509_request_object(request: &AuthorizationRequestObject) -> String {
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "oauth-authz-req+jwt",
        "kid": "verifier-key-1",
        "x5c": ["dGVzdCBuZXN0ZWQgbGVhZiBjZXJ0aWZpY2F0ZSBERVI="],
    });
    let protected = reallyme_codec::base64url::bytes_to_base64url(
        &serde_json::to_vec(&header).expect("test JOSE header serializes"),
    );
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

fn nested_verifier(
    resolver: FixtureKeyResolver,
) -> JoseNestedRequestObjectVerifier<
    reallyme_jose::jwe::DirectJweKeyResolver<'static>,
    JoseSignedRequestObjectVerifier<FixtureKeyResolver>,
> {
    let inner = JoseSignedRequestObjectVerifier::new(resolver, "wallet".to_owned());
    JoseNestedRequestObjectVerifier::new(
        reallyme_jose::jwe::DirectJweKeyResolver::new(&TEST_JWE_KEY),
        inner,
    )
}

fn compact_jwe_dir_a128gcm(payload: &[u8]) -> String {
    let protected = reallyme_codec::base64url::bytes_to_base64url(
        &serde_json::to_vec(&serde_json::json!({"alg":"dir","enc":"A128GCM"}))
            .expect("test header serializes"),
    );
    let key =
        reallyme_crypto::aes::Aes128GcmKey::from_slice(&TEST_JWE_KEY).expect("test key is valid");
    let nonce =
        reallyme_crypto::aes::Aes128GcmNonce::from_slice(&[7u8; 12]).expect("test nonce is valid");
    let ciphertext_with_tag =
        reallyme_crypto::aes::encrypt_aes128_gcm(&reallyme_crypto::aes::Aes128GcmEncryptRequest {
            key: &key,
            nonce,
            aad: protected.as_bytes(),
            plaintext: payload,
        })
        .expect("test payload encrypts");
    let ciphertext_and_tag = ciphertext_with_tag.as_bytes();
    let split_at = ciphertext_and_tag
        .len()
        .checked_sub(reallyme_jose::jwe::JweContentEncryptionAlgorithm::A128Gcm.tag_len())
        .expect("test ciphertext includes tag");
    let ciphertext = reallyme_codec::base64url::bytes_to_base64url(&ciphertext_and_tag[..split_at]);
    let tag = reallyme_codec::base64url::bytes_to_base64url(&ciphertext_and_tag[split_at..]);
    let iv = reallyme_codec::base64url::bytes_to_base64url(&[7u8; 12]);
    format!("{protected}..{iv}.{ciphertext}.{tag}")
}

#[test]
fn verifies_nested_signed_then_encrypted_request_object_with_jose() {
    let signed = signed_request_object();
    let encrypted = compact_jwe_dir_a128gcm(signed.as_bytes());
    let inner = JoseSignedRequestObjectVerifier::new(key_resolver(), "wallet".to_owned());
    let verifier = JoseNestedRequestObjectVerifier::new(
        reallyme_jose::jwe::DirectJweKeyResolver::new(&TEST_JWE_KEY),
        inner,
    );

    let verified = verify_signed_request_object(&verifier, &encrypted, &dc_api_invocation(), 11)
        .expect("nested Request Object verifies");

    assert_eq!(verified.request().nonce, "0123456789abcdef");
}

#[test]
fn rejects_nested_request_object_with_unsigned_plaintext() {
    let encrypted = compact_jwe_dir_a128gcm(br#"{"nonce":"0123456789abcdef"}"#);
    let inner = JoseSignedRequestObjectVerifier::new(key_resolver(), "wallet".to_owned());
    let verifier = JoseNestedRequestObjectVerifier::new(
        reallyme_jose::jwe::DirectJweKeyResolver::new(&TEST_JWE_KEY),
        inner,
    );

    let err = verify_signed_request_object(&verifier, &encrypted, &dc_api_invocation(), 11)
        .expect_err("encrypted plaintext must be an inner signed JWT");

    assert_eq!(err.reason(), WalletErrorReason::InvalidRequestObject);
}

#[test]
fn rejects_oversized_outer_jwe_with_typed_size_error() {
    let oversized = "a".repeat(reallyme_jose::jwe::MAX_COMPACT_JWE_BYTES + 1);
    let verifier = nested_verifier(key_resolver());

    let err = verify_signed_request_object(&verifier, &oversized, &dc_api_invocation(), 11)
        .expect_err("oversized compact JWE is rejected before decryption");

    assert_eq!(err.reason(), WalletErrorReason::RequestObjectTooLarge);
}

#[test]
fn preserves_verifier_attestation_evidence_from_inner_signed_request() {
    let mut request = request(20, 10);
    request.client_id = Some(
        ClientIdentifier::parse("verifier_attestation:verifier.example")
            .expect("test client id is valid"),
    );
    request.iss = Some("verifier_attestation:verifier.example".to_owned());
    let signed = signed_request_object_for(&request);
    let encrypted = compact_jwe_dir_a128gcm(signed.as_bytes());
    let mut resolver = key_resolver();
    resolver.verifier_attestation = Some(
        VerifiedVerifierAttestation::new(
            "verifier.example".to_owned(),
            None,
            resolver.public_key.clone(),
            100,
        )
        .expect("test verifier attestation is valid"),
    );

    let verified = verify_signed_request_object(
        &nested_verifier(resolver),
        &encrypted,
        &dc_api_invocation(),
        11,
    )
    .expect("nested verifier attestation evidence is retained");

    assert_eq!(verified.request().nonce, "0123456789abcdef");
}

#[test]
fn preserves_metadata_evidence_from_inner_signed_request() {
    let mut request = request(20, 10);
    let metadata_uri = "https://verifier.example/metadata.json";
    request.client_metadata_uri = Some(metadata_uri.to_owned());
    let signed = signed_request_object_for(&request);
    let encrypted = compact_jwe_dir_a128gcm(signed.as_bytes());
    let mut resolver = key_resolver();
    resolver.client_metadata_reference = Some(
        VerifiedClientMetadataReference::new(
            metadata_uri.to_owned(),
            ClientMetadata {
                raw: serde_json::Value::Object(JsonMap::new()),
            },
            20,
        )
        .expect("test metadata evidence is valid"),
    );

    let verified = verify_signed_request_object(
        &nested_verifier(resolver),
        &encrypted,
        &dc_api_invocation(),
        11,
    )
    .expect("nested metadata trust evidence is retained");

    assert_eq!(verified.request().nonce, "0123456789abcdef");
}

#[test]
fn preserves_x509_evidence_from_inner_signed_request() {
    let digest = Sha256::digest(TEST_LEAF_CERTIFICATE_DER);
    let encoded_hash = reallyme_codec::base64url::bytes_to_base64url(&digest);
    let mut client_id = "x509_hash:".to_owned();
    client_id.push_str(&encoded_hash);
    let mut request = request(20, 10);
    request.client_id = Some(ClientIdentifier::parse(&client_id).expect("test client id is valid"));
    request.iss = Some(client_id);
    let signed = signed_x509_request_object(&request);
    let encrypted = compact_jwe_dir_a128gcm(signed.as_bytes());
    let mut resolver = key_resolver();
    resolver.x509_dns_sans = Some(Vec::new());

    let verified = verify_signed_request_object(
        &nested_verifier(resolver),
        &encrypted,
        &dc_api_invocation(),
        11,
    )
    .expect("nested X.509 trust evidence is retained");

    assert_eq!(verified.request().nonce, "0123456789abcdef");
}
