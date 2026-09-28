// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::MessageField;
use reallyme_openid4vp_dcql::{DcqlQuery, QueryId};
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_types::TransactionDataHashAlgorithm;
use reallyme_openid4vp_verifier::{
    BrowserSessionBinding, FollowBackRequirement, HolderBindingClaims, PostResponseRedirectUri,
    RequestBinding, RetainedMdocSessionTranscript, SessionRecord as VerifierSessionRecord,
    TransactionDataBinding, BROWSER_SESSION_BINDING_BYTES, MAX_TRANSACTION_DATA_BINDINGS,
};

use crate::map_client_identifier::{client_identifier_to_proto, proto_to_client_identifier};
use crate::report_proto_error::OpenId4VpProtoError;
use crate::sensitive_json::{
    deserialize_sensitive_json, serialize_sensitive_json, MAX_DCQL_JSON_BYTES,
};
use crate::{convert::proto_to_response_mode, convert::response_mode_to_proto};

/// Map verifier request binding into the generated protobuf message.
pub fn request_binding_to_proto(binding: &RequestBinding) -> pb::RequestBinding {
    pb::RequestBinding {
        client_id: MessageField::some(client_identifier_to_proto(&binding.client_id)),
        nonce: binding.nonce.clone(),
        response_uri: binding.response_uri.clone(),
        redirect_uri: binding.redirect_uri.clone(),
        dc_api_origin: binding.dc_api_origin.clone(),
        expiry_unix: binding.expiry_unix,
        transaction_data_bindings: binding
            .transaction_data_bindings
            .iter()
            .map(|binding| pb::TransactionDataBinding {
                query_id: binding.query_id.as_str().to_owned(),
                algorithm: transaction_data_hash_algorithm_to_proto(binding.algorithm),
                digest: binding.digest.to_vec(),
                __buffa_unknown_fields: Default::default(),
            })
            .collect(),
        __buffa_unknown_fields: Default::default(),
    }
}

/// Map a generated protobuf request binding into verifier session binding.
pub fn proto_to_request_binding(
    binding: &pb::RequestBinding,
) -> Result<RequestBinding, OpenId4VpProtoError> {
    let Some(client_id) = binding.client_id.as_option() else {
        return Err(OpenId4VpProtoError::MissingField);
    };
    if binding.transaction_data_bindings.len() > MAX_TRANSACTION_DATA_BINDINGS {
        return Err(OpenId4VpProtoError::InvalidField);
    }
    let transaction_data_bindings = binding
        .transaction_data_bindings
        .iter()
        .map(proto_to_transaction_data_binding)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RequestBinding {
        client_id: proto_to_client_identifier(client_id)?,
        nonce: binding.nonce.clone(),
        response_uri: binding.response_uri.clone(),
        redirect_uri: binding.redirect_uri.clone(),
        dc_api_origin: binding.dc_api_origin.clone(),
        expiry_unix: binding.expiry_unix,
        transaction_data_bindings,
    })
}

fn proto_to_transaction_data_binding(
    binding: &pb::TransactionDataBinding,
) -> Result<TransactionDataBinding, OpenId4VpProtoError> {
    let algorithm = match binding.algorithm.as_str() {
        "sha-256" => TransactionDataHashAlgorithm::Sha256,
        _ => return Err(OpenId4VpProtoError::InvalidField),
    };
    let digest = <[u8; 32]>::try_from(binding.digest.as_slice())
        .map_err(|_| OpenId4VpProtoError::InvalidField)?;
    Ok(TransactionDataBinding {
        query_id: QueryId::parse(&binding.query_id)
            .map_err(|_| OpenId4VpProtoError::InvalidField)?,
        algorithm,
        digest,
    })
}

/// Map decoded holder-binding claims into the generated protobuf message.
pub fn holder_binding_claims_to_proto(claims: &HolderBindingClaims) -> pb::HolderBindingClaims {
    pb::HolderBindingClaims {
        audience: claims.audience.clone(),
        nonce: claims.nonce.clone(),
        expiration_unix: claims.expiration_unix,
        issued_at_unix: claims.issued_at_unix,
        sd_hash: claims.sd_hash.clone(),
        transaction_data_hashes: claims
            .transaction_data_hashes
            .iter()
            .map(|hash| hash.to_vec())
            .collect(),
        transaction_data_hashes_alg: claims
            .transaction_data_hashes_alg
            .map(transaction_data_hash_algorithm_to_proto),
        __buffa_unknown_fields: Default::default(),
    }
}

/// Map generated holder-binding claims into the verifier model.
pub fn proto_to_holder_binding_claims(
    claims: &pb::HolderBindingClaims,
) -> Result<HolderBindingClaims, OpenId4VpProtoError> {
    let transaction_data_hashes = claims
        .transaction_data_hashes
        .iter()
        .cloned()
        .map(|hash| <[u8; 32]>::try_from(hash).map_err(|_| OpenId4VpProtoError::InvalidField))
        .collect::<Result<Vec<_>, _>>()?;
    let transaction_data_hashes_alg = match claims.transaction_data_hashes_alg.as_deref() {
        None => None,
        Some("sha-256") => Some(TransactionDataHashAlgorithm::Sha256),
        Some(_) => return Err(OpenId4VpProtoError::InvalidField),
    };
    if transaction_data_hashes.is_empty() && transaction_data_hashes_alg.is_some() {
        return Err(OpenId4VpProtoError::InvalidField);
    }
    Ok(HolderBindingClaims {
        audience: claims.audience.clone(),
        nonce: claims.nonce.clone(),
        expiration_unix: claims.expiration_unix,
        issued_at_unix: claims.issued_at_unix,
        sd_hash: claims.sd_hash.clone(),
        transaction_data_hashes,
        transaction_data_hashes_alg,
    })
}

fn transaction_data_hash_algorithm_to_proto(algorithm: TransactionDataHashAlgorithm) -> String {
    match algorithm {
        TransactionDataHashAlgorithm::Sha256 => "sha-256".to_owned(),
    }
}

/// Map a verifier session record into the generated protobuf message.
pub fn session_record_to_proto(
    record: &VerifierSessionRecord,
) -> Result<pb::SessionRecord, OpenId4VpProtoError> {
    validate_follow_back_pair(
        record.post_response_redirect_uri.as_ref(),
        record.follow_back_requirement.as_ref(),
        record.binding.expiry_unix,
    )?;
    let dcql_query_json = serialize_sensitive_json(&record.dcql_query, MAX_DCQL_JSON_BYTES)?;
    Ok(pb::SessionRecord {
        binding: MessageField::some(request_binding_to_proto(&record.binding)),
        state: record.state.clone(),
        dcql_query_json,
        mdoc_session_transcript_cbor: record
            .mdoc_session_transcript
            .as_ref()
            .map(|transcript| transcript.as_bytes().to_vec()),
        mdoc_response_key_thumbprint_sha256: record
            .mdoc_session_transcript
            .as_ref()
            .and_then(|transcript| transcript.response_key_thumbprint_sha256())
            .map(|thumbprint| thumbprint.to_vec()),
        post_response_redirect_uri: record
            .post_response_redirect_uri
            .as_ref()
            .map(|uri| uri.as_str().to_owned()),
        response_mode: response_mode_to_proto(record.response_mode).into(),
        follow_back_requirement: record
            .follow_back_requirement
            .as_ref()
            .map(|requirement| {
                MessageField::some(pb::FollowBackRequirement {
                    browser_session_binding: requirement.browser_session().as_bytes().to_vec(),
                    expires_unix: requirement.expires_unix(),
                    __buffa_unknown_fields: Default::default(),
                })
            })
            .unwrap_or_default(),
        __buffa_unknown_fields: Default::default(),
    })
}

/// Map a generated protobuf session record into the verifier model.
pub fn proto_to_session_record(
    record: &pb::SessionRecord,
) -> Result<VerifierSessionRecord, OpenId4VpProtoError> {
    let Some(binding) = record.binding.as_option() else {
        return Err(OpenId4VpProtoError::MissingField);
    };
    let dcql_query: DcqlQuery =
        deserialize_sensitive_json(&record.dcql_query_json, MAX_DCQL_JSON_BYTES)?;
    reallyme_openid4vp_dcql::validate_query(&dcql_query)
        .map_err(|_| OpenId4VpProtoError::InvalidField)?;
    let response_key_thumbprint_sha256 = record
        .mdoc_response_key_thumbprint_sha256
        .as_ref()
        .map(|value| {
            <[u8; 32]>::try_from(value.as_slice()).map_err(|_| OpenId4VpProtoError::InvalidField)
        })
        .transpose()?;
    let mdoc_session_transcript = match (
        record.mdoc_session_transcript_cbor.clone(),
        response_key_thumbprint_sha256,
    ) {
        (Some(transcript), thumbprint) => Some(
            RetainedMdocSessionTranscript::new_with_response_key_thumbprint(transcript, thumbprint)
                .map_err(|_| OpenId4VpProtoError::InvalidField)?,
        ),
        (None, None) => None,
        (None, Some(_)) => return Err(OpenId4VpProtoError::InvalidField),
    };
    let post_response_redirect_uri = record
        .post_response_redirect_uri
        .clone()
        .map(PostResponseRedirectUri::parse)
        .transpose()
        .map_err(|_| OpenId4VpProtoError::InvalidField)?;
    let follow_back_requirement = record
        .follow_back_requirement
        .as_option()
        .map(|requirement| {
            let binding = <[u8; BROWSER_SESSION_BINDING_BYTES]>::try_from(
                requirement.browser_session_binding.as_slice(),
            )
            .map_err(|_| OpenId4VpProtoError::InvalidField)?;
            FollowBackRequirement::new(
                BrowserSessionBinding::new(binding),
                requirement.expires_unix,
            )
            .map_err(|_| OpenId4VpProtoError::InvalidField)
        })
        .transpose()?;
    validate_follow_back_pair(
        post_response_redirect_uri.as_ref(),
        follow_back_requirement.as_ref(),
        binding.expiry_unix,
    )?;
    Ok(VerifierSessionRecord {
        binding: proto_to_request_binding(binding)?,
        state: record.state.clone(),
        dcql_query,
        response_mode: proto_to_response_mode(&record.response_mode)?,
        mdoc_session_transcript,
        post_response_redirect_uri,
        follow_back_requirement,
    })
}

fn validate_follow_back_pair(
    redirect: Option<&PostResponseRedirectUri>,
    requirement: Option<&FollowBackRequirement>,
    request_expiry_unix: u64,
) -> Result<(), OpenId4VpProtoError> {
    match (redirect, requirement) {
        (Some(_), Some(requirement)) if requirement.expires_unix() <= request_expiry_unix => Ok(()),
        (None, None) => Ok(()),
        (Some(_), Some(_)) | (Some(_), None) | (None, Some(_)) => {
            Err(OpenId4VpProtoError::InvalidField)
        }
    }
}
