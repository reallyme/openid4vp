// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wallet-side OpenID4VP request verification and response construction boundary.

mod build_authorization_response;
mod client_identifier_binding;
#[cfg(feature = "jose")]
mod encrypt_authorization_response_with_jose;
mod endpoint_binding_policy;
mod error;
mod jar;
mod metadata_reference;
mod multisigned_request_object;
mod platform_origin;
mod prepare_consent_data;
mod prepare_zk_presentation;
mod transaction_data_policy;
mod transport;
mod unsigned_dc_api_request;
mod validate_endpoint_binding;
mod validate_response_selection;
mod verifier_attestation;
#[cfg(feature = "jose")]
mod verify_nested_request_object_with_jose;
#[cfg(feature = "jose")]
mod verify_signed_request_object_with_jose;

pub use build_authorization_response::{
    build_authorization_response, TransactionDataPresentationVerificationContext,
    TransactionDataPresentationVerifier, WalletSelectedPresentation, WalletSelectedPresentationSet,
};
pub use client_identifier_binding::VerifiedClientIdentifierBinding;
#[cfg(feature = "jose")]
pub use encrypt_authorization_response_with_jose::{
    encrypt_authorization_response_with_jose, response_encryption_key_thumbprint_sha256,
};
pub use endpoint_binding_policy::validate_response_endpoint_binding;
pub use error::{WalletError, WalletErrorReason};
pub use jar::{
    validate_transport_client_id_binding, validate_wallet_request_object,
    validate_wallet_request_object_with_evidence,
    validate_wallet_request_object_with_evidence_and_transaction_data_policy,
    validate_wallet_request_object_with_transaction_data_policy,
    validate_wallet_request_object_with_trust, verify_request_transport,
    verify_request_transport_with_transaction_data_policy, verify_signed_request_object,
    verify_signed_request_object_with_transaction_data_policy, RequestObjectSignatureVerifier,
    VerifiedRequestObject, VerifiedWalletRequest, WalletAuthorizationRequest,
    WalletClientIdentifierPolicy, WalletRequestTrustEvidence,
};
pub use metadata_reference::{
    validate_client_metadata_reference_binding, VerifiedClientMetadataReference,
};
pub use multisigned_request_object::{
    verify_multisigned_request_object,
    verify_multisigned_request_object_with_transaction_data_policy,
    MultiSignedRequestObjectSignatureVerifier, MAX_MULTISIGNED_REQUEST_OBJECT_BYTES,
    MAX_MULTISIGNED_REQUEST_OBJECT_SIGNATURES,
};
pub use platform_origin::{VerifiedPlatformOrigin, WalletInvocationContext};
pub use prepare_consent_data::prepare_consent_data;
pub use prepare_zk_presentation::prepare_zk_presentation;
pub use transaction_data_policy::WalletTransactionDataPolicy;
pub use transport::{
    parse_authorization_request_transport, AuthorizationRequestTransport, RequestTransportPolicy,
};
pub use unsigned_dc_api_request::{
    validate_unsigned_dc_api_request,
    validate_unsigned_dc_api_request_with_transaction_data_policy, VerifiedUnsignedDcApiRequest,
};
pub use validate_endpoint_binding::{
    BoundedX509CertificateChain, TrustedX509RequestObjectSigner, VerifiedX509CertificateBinding,
    X509RequestObjectTrustDecision, X509RequestObjectTrustPurpose, X509TrustDecisionContext,
    X509TrustIndeterminateReason, X509TrustRejectionReason, MAX_X509_CERTIFICATE_DER_BYTES,
    MAX_X509_CHAIN_CERTIFICATES, MAX_X509_CHAIN_DER_BYTES, MAX_X509_DNS_SAN_BYTES,
    MAX_X509_DNS_SAN_NAMES,
};
pub use verifier_attestation::{
    validate_verifier_attestation_binding, VerifiedVerifierAttestation,
};
#[cfg(feature = "jose")]
pub use verify_nested_request_object_with_jose::JoseNestedRequestObjectVerifier;
#[cfg(feature = "jose")]
pub use verify_signed_request_object_with_jose::{
    JoseRequestObjectVerification, JoseRequestObjectVerificationResolver,
    JoseSignedRequestObjectVerifier,
};
