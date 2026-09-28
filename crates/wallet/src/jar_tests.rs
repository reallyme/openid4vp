// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_types::{
    AuthorizationRequestObject, ClientIdentifier, ResponseMode, ResponseType, TransactionData,
};
use serde_json::{json, Map as JsonMap};
use sha2::{Digest, Sha256};

use crate::jar::{
    validate_wallet_request_object, validate_wallet_request_object_with_evidence,
    validate_wallet_request_object_with_transaction_data_policy,
    validate_wallet_request_object_with_trust, verify_request_transport,
    RequestObjectSignatureVerifier, WalletRequestTrustEvidence,
};
use crate::{
    AuthorizationRequestTransport, VerifiedPlatformOrigin, VerifiedWalletRequest, WalletError,
    WalletErrorReason, WalletInvocationContext, WalletTransactionDataPolicy,
};
use crate::{
    VerifiedClientMetadataReference, VerifiedRequestObject, VerifiedVerifierAttestation,
    VerifiedX509CertificateBinding,
};

const TEST_LEAF_CERTIFICATE_DER: &[u8] = b"test leaf certificate DER";

impl VerifiedWalletRequest {
    pub(crate) const fn for_test(request: AuthorizationRequestObject) -> Self {
        Self { request }
    }

    pub(crate) fn request_mut_for_test(&mut self) -> &mut AuthorizationRequestObject {
        &mut self.request
    }
}

fn dc_api_invocation() -> WalletInvocationContext {
    WalletInvocationContext::DigitalCredentialsApi(
        VerifiedPlatformOrigin::from_browser_security_context("https://rp.example".to_owned())
            .expect("test origin is valid"),
    )
}

fn signed_dc_api_request() -> AuthorizationRequestObject {
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
        iss: Some("client".to_owned()),
        aud: Some(vec!["wallet".to_owned()]),
        iat: Some(10),
        exp: Some(20),
    }
}

struct FixtureVerifier {
    request: AuthorizationRequestObject,
}

impl RequestObjectSignatureVerifier for FixtureVerifier {
    fn verify_request_object(
        &self,
        _jwt: &str,
        _invocation: &crate::WalletInvocationContext,
        _now_unix: u64,
    ) -> Result<VerifiedRequestObject, WalletError> {
        let client_id =
            self.request.client_id.clone().ok_or_else(|| {
                WalletError::new(WalletErrorReason::InvalidClientIdentifierPrefix)
            })?;
        Ok(VerifiedRequestObject::new(
            self.request.clone(),
            crate::WalletRequestTrustEvidence {
                client_identifier_binding: Some(crate::VerifiedClientIdentifierBinding::new(
                    client_id,
                    b"test-key",
                )?),
                verifier_attestation: None,
                client_metadata_reference: None,
                x509_certificate_binding: None,
            },
        ))
    }
}

#[test]
fn rejects_unbound_origin() {
    let err = validate_wallet_request_object(
        &signed_dc_api_request(),
        Some("https://attacker.example"),
        11,
    )
    .expect_err("origin mismatch is rejected");

    assert_eq!(err.reason(), WalletErrorReason::ExpectedOriginMismatch);
}

#[test]
fn rejects_transport_client_id_mismatch() {
    let err = verify_request_transport(
        &FixtureVerifier {
            request: signed_dc_api_request(),
        },
        AuthorizationRequestTransport::RequestJwt {
            jwt: "header.payload.signature".to_owned(),
            expected_client_id: Some("decentralized_identifier:did:example:other".to_owned()),
            expected_wallet_nonce: None,
        },
        &dc_api_invocation(),
        11,
    )
    .expect_err("transport client_id mismatch is rejected");

    assert_eq!(
        err.reason(),
        WalletErrorReason::TransportClientIdentifierMismatch
    );
}

#[test]
fn accepts_post_wallet_nonce_echo() {
    let mut request = signed_dc_api_request();
    request.wallet_nonce = Some("wallet-nonce".to_owned());

    verify_request_transport(
        &FixtureVerifier { request },
        AuthorizationRequestTransport::RequestJwt {
            jwt: "header.payload.signature".to_owned(),
            expected_client_id: Some("decentralized_identifier:did:example:verifier".to_owned()),
            expected_wallet_nonce: Some("wallet-nonce".to_owned()),
        },
        &dc_api_invocation(),
        11,
    )
    .expect("wallet_nonce echo is accepted");
}

#[test]
fn rejects_post_wallet_nonce_mismatch() {
    let mut request = signed_dc_api_request();
    request.wallet_nonce = Some("other".to_owned());

    let err = verify_request_transport(
        &FixtureVerifier { request },
        AuthorizationRequestTransport::RequestJwt {
            jwt: "header.payload.signature".to_owned(),
            expected_client_id: Some("decentralized_identifier:did:example:verifier".to_owned()),
            expected_wallet_nonce: Some("wallet-nonce".to_owned()),
        },
        &dc_api_invocation(),
        11,
    )
    .expect_err("wallet_nonce mismatch is rejected");

    assert_eq!(
        err.reason(),
        WalletErrorReason::TransportWalletNonceMismatch
    );
}

#[test]
fn rejects_unexpected_request_object_wallet_nonce() {
    let mut request = signed_dc_api_request();
    request.wallet_nonce = Some("unexpected".to_owned());

    let err = verify_request_transport(
        &FixtureVerifier { request },
        AuthorizationRequestTransport::RequestJwt {
            jwt: "header.payload.signature".to_owned(),
            expected_client_id: Some("decentralized_identifier:did:example:verifier".to_owned()),
            expected_wallet_nonce: None,
        },
        &dc_api_invocation(),
        11,
    )
    .expect_err("wallet_nonce without POST binding is rejected");

    assert_eq!(err.reason(), WalletErrorReason::UnexpectedWalletNonce);
}

#[test]
fn rejects_expired_request_object() {
    let mut request = signed_dc_api_request();
    request.exp = Some(10);

    let err = validate_wallet_request_object(&request, Some("https://rp.example"), 11)
        .expect_err("expired request object is rejected");

    assert_eq!(err.reason(), WalletErrorReason::RequestObjectExpired);
}

#[test]
fn accepts_request_object_without_optional_temporal_claims() {
    let mut request = signed_dc_api_request();
    request.exp = None;
    request.iat = None;

    validate_wallet_request_object(&request, Some("https://rp.example"), 11)
        .expect("optional temporal claims may be absent");
}

#[test]
fn accepts_request_object_at_future_iat_skew_boundary() {
    let mut request = signed_dc_api_request();
    request.iat = Some(71);

    validate_wallet_request_object(&request, Some("https://rp.example"), 11)
        .expect("iat at the configured future-skew boundary is accepted");
}

#[test]
fn rejects_request_object_beyond_future_iat_skew_boundary() {
    let mut request = signed_dc_api_request();
    request.iat = Some(72);

    let err = validate_wallet_request_object(&request, Some("https://rp.example"), 11)
        .expect_err("iat beyond the configured future-skew boundary is rejected");

    assert_eq!(err.reason(), WalletErrorReason::RequestObjectIssuedInFuture);
}

#[test]
fn rejects_request_object_without_nonce() {
    let mut request = signed_dc_api_request();
    request.nonce.clear();

    let err = validate_wallet_request_object(&request, Some("https://rp.example"), 11)
        .expect_err("nonce is required for holder binding");

    assert_eq!(err.reason(), WalletErrorReason::InvalidRequestObject);
}

fn payment_transaction_data() -> TransactionData {
    TransactionData::new(
        "payment".to_owned(),
        vec!["pid".to_owned()],
        json!({"payment_data": {"currency": "CHF"}}),
    )
    .expect("test transaction data is valid")
}

#[test]
fn rejects_unknown_transaction_data_type_without_explicit_policy() {
    let mut request = signed_dc_api_request();
    request.transaction_data = Some(vec![payment_transaction_data()]);

    let error = validate_wallet_request_object(&request, Some("https://rp.example"), 11)
        .expect_err("transaction data must fail closed without an application policy");

    assert_eq!(error.reason(), WalletErrorReason::InvalidTransactionData);
}

#[test]
fn accepts_explicitly_supported_transaction_data_type() {
    let mut request = signed_dc_api_request();
    request.transaction_data = Some(vec![payment_transaction_data()]);
    let supported_types = ["payment"];
    let policy = WalletTransactionDataPolicy::new(&supported_types)
        .expect("test policy contains a unique, non-empty type");

    validate_wallet_request_object_with_transaction_data_policy(
        &request,
        Some("https://rp.example"),
        11,
        policy,
    )
    .expect("an explicitly supported transaction type is accepted");
}

#[test]
fn rejects_transaction_data_type_absent_from_explicit_policy() {
    let mut request = signed_dc_api_request();
    request.transaction_data = Some(vec![payment_transaction_data()]);
    let supported_types = ["document-signing"];
    let policy = WalletTransactionDataPolicy::new(&supported_types)
        .expect("test policy contains a unique, non-empty type");

    let error = validate_wallet_request_object_with_transaction_data_policy(
        &request,
        Some("https://rp.example"),
        11,
        policy,
    )
    .expect_err("an unlisted transaction type is rejected");

    assert_eq!(error.reason(), WalletErrorReason::InvalidTransactionData);
}

#[test]
fn rejects_ambiguous_transaction_data_policy_configuration() {
    let empty = [""];
    let duplicate = ["payment", "payment"];

    let empty_error = WalletTransactionDataPolicy::new(&empty)
        .expect_err("empty transaction type policy entries are rejected");
    let duplicate_error = WalletTransactionDataPolicy::new(&duplicate)
        .expect_err("duplicate transaction type policy entries are rejected");

    assert_eq!(
        empty_error.reason(),
        WalletErrorReason::InvalidTransactionData
    );
    assert_eq!(
        duplicate_error.reason(),
        WalletErrorReason::InvalidTransactionData
    );
}

#[test]
fn rejects_redirect_uri_with_direct_post_response_mode() {
    let mut request = signed_dc_api_request();
    request.response_mode = Some(ResponseMode::DirectPost);
    request.response_uri = Some("https://verifier.example/response".to_owned());
    request.redirect_uri = Some("https://verifier.example/callback".to_owned());

    let error = validate_wallet_request_object(&request, None, 11)
        .expect_err("direct_post must not carry redirect_uri");

    assert_eq!(error.reason(), WalletErrorReason::InvalidRequestObject);
}

#[test]
fn accepts_response_endpoint_cardinality_for_each_transport_family() {
    let mut direct_post = signed_dc_api_request();
    direct_post.response_mode = Some(ResponseMode::DirectPostJwt);
    direct_post.response_uri = Some("https://verifier.example/response".to_owned());
    validate_wallet_request_object(&direct_post, None, 11)
        .expect("direct_post.jwt uses response_uri only");

    let mut front_channel = signed_dc_api_request();
    front_channel.response_mode = Some(ResponseMode::FormPost);
    front_channel.redirect_uri = Some("https://verifier.example/callback".to_owned());
    validate_wallet_request_object(&front_channel, None, 11)
        .expect("front-channel response uses redirect_uri only");

    validate_wallet_request_object(&signed_dc_api_request(), Some("https://rp.example"), 11)
        .expect("DC API response has no redirect or response endpoint");
}

#[test]
fn rejects_unsigned_client_identifier_prefix() {
    let mut request = signed_dc_api_request();
    request.client_id =
        Some(ClientIdentifier::parse("verifier.example").expect("test client id is valid"));

    let err = validate_wallet_request_object(&request, Some("https://rp.example"), 11)
        .expect_err("unprefixed signed client id is rejected");

    assert_eq!(
        err.reason(),
        WalletErrorReason::UnsupportedClientIdentifierMode
    );
}

#[test]
fn structurally_validates_subject_key_prefixes_without_authorizing_them() {
    let prefixes = [
        "openid_federation:https://verifier.example",
        "decentralized_identifier:did:example:verifier",
    ];

    for client_id in prefixes {
        let mut request = signed_dc_api_request();
        request.client_id =
            Some(ClientIdentifier::parse(client_id).expect("test client id is valid"));

        validate_wallet_request_object(&request, Some("https://rp.example"), 11)
            .expect("the raw validator is diagnostic and does not issue a receipt");
    }
}

#[test]
fn accepts_x509_san_dns_response_uri_host_binding() {
    let mut request = signed_dc_api_request();
    request.response_mode = Some(ResponseMode::DirectPostJwt);
    request.client_id = Some(
        ClientIdentifier::parse("x509_san_dns:verifier.example").expect("test client id is valid"),
    );
    request.response_uri = Some("https://verifier.example:8443/response".to_owned());
    let evidence = x509_evidence(vec!["verifier.example".to_owned()]);

    validate_wallet_request_object_with_evidence(&request, None, 11, &evidence)
        .expect("x509_san_dns endpoint host binding is accepted");
}

#[test]
fn rejects_x509_san_dns_response_uri_host_mismatch() {
    let mut request = signed_dc_api_request();
    request.response_mode = Some(ResponseMode::DirectPostJwt);
    request.client_id = Some(
        ClientIdentifier::parse("x509_san_dns:verifier.example").expect("test client id is valid"),
    );
    request.response_uri = Some("https://attacker.example/response".to_owned());
    let evidence = x509_evidence(vec!["verifier.example".to_owned()]);

    let err = validate_wallet_request_object_with_evidence(
        &request,
        Some("https://rp.example"),
        11,
        &evidence,
    )
    .expect_err("wallet rejects response endpoint not bound to client_id DNS name");

    assert_eq!(
        err.reason(),
        WalletErrorReason::ResponseEndpointClientIdentifierMismatch
    );
}

#[test]
fn rejects_x509_san_dns_without_certificate_binding() {
    let mut request = signed_dc_api_request();
    request.client_id = Some(
        ClientIdentifier::parse("x509_san_dns:verifier.example").expect("test client id is valid"),
    );

    let err = validate_wallet_request_object(&request, Some("https://rp.example"), 11)
        .expect_err("x509_san_dns requires leaf certificate SAN evidence");

    assert_eq!(err.reason(), WalletErrorReason::MissingX509CertificateChain);
}

#[test]
fn rejects_x509_san_dns_client_identifier_missing_from_leaf_certificate() {
    let mut request = signed_dc_api_request();
    request.client_id = Some(
        ClientIdentifier::parse("x509_san_dns:verifier.example").expect("test client id is valid"),
    );
    let evidence = x509_evidence(vec!["other.example".to_owned()]);

    let err = validate_wallet_request_object_with_evidence(
        &request,
        Some("https://rp.example"),
        11,
        &evidence,
    )
    .expect_err("client identifier must occur in the leaf certificate DNS SAN");

    assert_eq!(err.reason(), WalletErrorReason::X509CertificateSanMismatch);
}

#[test]
fn rejects_x509_hash_without_certificate_binding() {
    let mut request = signed_dc_api_request();
    request.client_id = Some(
        ClientIdentifier::parse(&x509_hash_client_id(TEST_LEAF_CERTIFICATE_DER))
            .expect("test client id is valid"),
    );

    let err = validate_wallet_request_object(&request, Some("https://rp.example"), 11)
        .expect_err("x509_hash requires leaf certificate digest evidence");

    assert_eq!(err.reason(), WalletErrorReason::MissingX509CertificateChain);
}

#[test]
fn rejects_x509_hash_that_does_not_match_leaf_certificate() {
    let mut request = signed_dc_api_request();
    request.client_id = Some(
        ClientIdentifier::parse(&x509_hash_client_id(b"different certificate"))
            .expect("test client id is valid"),
    );
    let evidence = x509_evidence(vec!["verifier.example".to_owned()]);

    let err = validate_wallet_request_object_with_evidence(
        &request,
        Some("https://rp.example"),
        11,
        &evidence,
    )
    .expect_err("x509_hash must equal the leaf certificate DER SHA-256 digest");

    assert_eq!(err.reason(), WalletErrorReason::X509CertificateHashMismatch);
}

#[test]
fn accepts_x509_hash_matching_leaf_certificate() {
    let mut request = signed_dc_api_request();
    request.response_mode = Some(ResponseMode::DirectPostJwt);
    request.client_id = Some(
        ClientIdentifier::parse(&x509_hash_client_id(TEST_LEAF_CERTIFICATE_DER))
            .expect("test client id is valid"),
    );
    request.response_uri = Some("https://verifier.example/response".to_owned());
    let evidence = x509_evidence(vec!["verifier.example".to_owned()]);

    validate_wallet_request_object_with_evidence(&request, None, 11, &evidence)
        .expect("x509_hash matches the verified leaf certificate and endpoint SAN");
}

fn x509_evidence(dns_names: Vec<String>) -> WalletRequestTrustEvidence {
    WalletRequestTrustEvidence {
        client_identifier_binding: None,
        verifier_attestation: None,
        client_metadata_reference: None,
        x509_certificate_binding: Some(
            VerifiedX509CertificateBinding::from_leaf_certificate_der(
                dns_names,
                TEST_LEAF_CERTIFICATE_DER,
            )
            .expect("test certificate binding is valid"),
        ),
    }
}

fn x509_hash_client_id(leaf_certificate_der: &[u8]) -> String {
    let digest = Sha256::digest(leaf_certificate_der);
    let encoded = reallyme_codec::base64url::bytes_to_base64url(&digest);
    let mut client_id = "x509_hash:".to_owned();
    client_id.push_str(&encoded);
    client_id
}

#[test]
fn rejects_redirect_uri_prefix_for_signed_request_object() {
    let mut request = signed_dc_api_request();
    request.client_id = Some(
        ClientIdentifier::parse("redirect_uri:https://verifier.example/cb")
            .expect("test client id is valid"),
    );

    let err = validate_wallet_request_object(&request, Some("https://rp.example"), 11)
        .expect_err("redirect_uri prefix is not valid for signed request objects");

    assert_eq!(
        err.reason(),
        WalletErrorReason::InvalidClientIdentifierPrefix
    );
}

#[test]
fn rejects_verifier_attestation_prefix_without_verified_attestation() {
    let mut request = signed_dc_api_request();
    request.client_id = Some(
        ClientIdentifier::parse("verifier_attestation:verifier.example")
            .expect("test client id is valid"),
    );

    let err = validate_wallet_request_object(&request, Some("https://rp.example"), 11)
        .expect_err("verifier_attestation prefix requires verified evidence");

    assert_eq!(err.reason(), WalletErrorReason::InvalidVerifierAttestation);
}

#[test]
fn accepts_verifier_attestation_prefix_with_verified_attestation() {
    let mut request = signed_dc_api_request();
    request.response_mode = Some(ResponseMode::FormPost);
    request.client_id = Some(
        ClientIdentifier::parse("verifier_attestation:verifier.example")
            .expect("test client id is valid"),
    );
    request.redirect_uri = Some("https://verifier.example/cb".to_owned());
    let attestation = VerifiedVerifierAttestation::new(
        "verifier.example".to_owned(),
        Some(vec!["https://verifier.example/cb".to_owned()]),
        vec![1_u8],
        100,
    )
    .expect("test attestation is valid");

    validate_wallet_request_object_with_trust(&request, None, 11, Some(&attestation), &[1_u8])
        .expect("verified verifier attestation is accepted");
}

#[test]
fn rejects_client_metadata_uri_without_verified_evidence() {
    let mut request = signed_dc_api_request();
    request.client_metadata_uri = Some("https://verifier.example/metadata.json".to_owned());

    let err = validate_wallet_request_object(&request, Some("https://rp.example"), 11)
        .expect_err("metadata reference requires verified evidence");

    assert_eq!(err.reason(), WalletErrorReason::InvalidMetadataReference);
}

#[test]
fn accepts_client_metadata_uri_with_fresh_verified_evidence() {
    let mut request = signed_dc_api_request();
    request.client_metadata_uri = Some("https://verifier.example/metadata.json".to_owned());
    let metadata = reallyme_openid4vp_types::ClientMetadata {
        raw: serde_json::Value::Object(JsonMap::new()),
    };
    let evidence = WalletRequestTrustEvidence {
        client_identifier_binding: None,
        verifier_attestation: None,
        client_metadata_reference: Some(
            VerifiedClientMetadataReference::new(
                "https://verifier.example/metadata.json".to_owned(),
                metadata,
                20,
            )
            .expect("test metadata evidence is valid"),
        ),
        x509_certificate_binding: None,
    };

    validate_wallet_request_object_with_evidence(
        &request,
        Some("https://rp.example"),
        11,
        &evidence,
    )
    .expect("fresh metadata evidence is accepted");
}

#[test]
fn rejects_origin_client_identifier_prefix_for_signed_request_object() {
    let mut request = signed_dc_api_request();
    request.client_id = Some(
        ClientIdentifier::parse("origin:https://rp.example").expect("test client id is valid"),
    );

    let err = validate_wallet_request_object(&request, Some("https://rp.example"), 11)
        .expect_err("origin prefix is reserved for unsigned DC API processing");

    assert_eq!(
        err.reason(),
        WalletErrorReason::UnsupportedClientIdentifierMode
    );
}

#[test]
fn rejects_missing_expected_origin_binding() {
    let mut request = signed_dc_api_request();
    request.expected_origins = None;

    let err = validate_wallet_request_object(&request, Some("https://rp.example"), 11)
        .expect_err("expected_origins is required for origin-bound requests");

    assert_eq!(err.reason(), WalletErrorReason::ExpectedOriginMismatch);
}
