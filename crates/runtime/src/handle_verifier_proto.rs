// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::MessageField;
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_proto_codec::{
    authorization_request_to_proto, proto_to_authorization_request, request_binding_to_proto,
};
use reallyme_openid4vp_verifier::{
    validate_jar_claims_for_signing, JarPolicy, RequestBinding, TransactionDataBinding,
    MAX_TRANSACTION_DATA_BINDINGS,
};

use crate::map_runtime_problem::runtime_error_to_problem_proto;
use crate::{RuntimeError, RuntimeErrorReason, VerifierRuntimeService};

impl VerifierRuntimeService {
    /// Build an authorization request through the generated protobuf boundary.
    pub fn build_authorization_request_proto(
        &self,
        request: &pb::BuildAuthorizationRequestRequest,
    ) -> pb::BuildAuthorizationRequestResponse {
        match self.try_build_authorization_request_response(request) {
            Ok(response) => response,
            Err(error) => {
                let mut response = pb::BuildAuthorizationRequestResponse::default();
                response.problem = MessageField::some(runtime_error_to_problem_proto(error));
                response
            }
        }
    }

    /// Reject the legacy stateless validation operation.
    ///
    /// Authorization requires a server-owned clock, atomic session consumption,
    /// durable result storage, and response-code issuance. A caller-supplied
    /// session and timestamp cannot provide those guarantees; hosts must use
    /// [`crate::VerifierHttpRuntime`] instead.
    pub fn validate_authorization_response_proto(
        &self,
        _request: &pb::ValidateAuthorizationResponseRequest,
    ) -> pb::ValidateAuthorizationResponseResponse {
        pb::ValidateAuthorizationResponseResponse {
            valid: false,
            problem: MessageField::some(runtime_error_to_problem_proto(RuntimeError::new(
                RuntimeErrorReason::UnsupportedFeature,
            ))),
            ..Default::default()
        }
    }

    fn try_build_authorization_request_response(
        &self,
        request: &pb::BuildAuthorizationRequestRequest,
    ) -> Result<pb::BuildAuthorizationRequestResponse, RuntimeError> {
        let Some(proto_request) = request.request.as_option() else {
            return Err(RuntimeError::new(RuntimeErrorReason::MissingField));
        };
        let domain_request = proto_to_authorization_request(proto_request)
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidProto))?;
        let binding = request_binding_from_authorization_request(&domain_request)?;

        let mut response = pb::BuildAuthorizationRequestResponse::default();
        response.binding = MessageField::some(request_binding_to_proto(&binding));

        if request.sign_request_object {
            let Some(signer) = self.signer() else {
                return Err(RuntimeError::new(RuntimeErrorReason::MissingSigner));
            };
            validate_jar_claims_for_signing(
                &domain_request,
                request.now_unix,
                JarPolicy::default(),
            )
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::SigningFailed))?;
            let jwt = signer
                .sign_request_object(&domain_request)
                .map_err(|_| RuntimeError::new(RuntimeErrorReason::SigningFailed))?;
            response.request_jwt = Some(jwt.as_str().to_owned());
        } else {
            response.request = MessageField::some(
                authorization_request_to_proto(&domain_request)
                    .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidProto))?,
            );
        }

        Ok(response)
    }
}

pub(crate) fn request_binding_from_authorization_request(
    request: &reallyme_openid4vp_types::AuthorizationRequestObject,
) -> Result<RequestBinding, RuntimeError> {
    let Some(client_id) = request.client_id.clone() else {
        return Err(RuntimeError::new(RuntimeErrorReason::MissingField));
    };
    let Some(expiry_unix) = request.exp else {
        return Err(RuntimeError::new(RuntimeErrorReason::MissingField));
    };
    if request.nonce.is_empty() {
        return Err(RuntimeError::new(RuntimeErrorReason::MissingField));
    }
    let dc_api_origin = match request.response_mode {
        Some(
            reallyme_openid4vp_types::ResponseMode::DcApi
            | reallyme_openid4vp_types::ResponseMode::DcApiJwt,
        ) => {
            let origins = request
                .expected_origins
                .as_ref()
                .ok_or_else(|| RuntimeError::new(RuntimeErrorReason::MissingField))?;
            if origins.len() != 1 {
                return Err(RuntimeError::new(RuntimeErrorReason::InvalidProto));
            }
            origins.first().cloned()
        }
        _ => None,
    };
    Ok(RequestBinding {
        client_id,
        nonce: request.nonce.clone(),
        response_uri: request.response_uri.clone(),
        redirect_uri: request.redirect_uri.clone(),
        dc_api_origin,
        expiry_unix,
        transaction_data_bindings: transaction_data_bindings_from_request(request)?,
    })
}

fn transaction_data_bindings_from_request(
    request: &reallyme_openid4vp_types::AuthorizationRequestObject,
) -> Result<Vec<TransactionDataBinding>, RuntimeError> {
    let Some(transaction_data) = request.transaction_data.as_ref() else {
        return Ok(Vec::new());
    };
    let mut bindings = Vec::new();
    for transaction in transaction_data {
        let hash =
            reallyme_openid4vp_types::TransactionDataHash::sha256_transaction_data(transaction)
                .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidProto))?;
        let required_capacity = bindings
            .len()
            .checked_add(transaction.credential_ids().len())
            .ok_or_else(|| RuntimeError::new(RuntimeErrorReason::InvalidProto))?;
        if required_capacity > MAX_TRANSACTION_DATA_BINDINGS {
            return Err(RuntimeError::new(RuntimeErrorReason::InvalidProto));
        }
        bindings.reserve(transaction.credential_ids().len());
        for credential_id in transaction.credential_ids() {
            let query_id = request
                .dcql_query
                .credentials
                .iter()
                .find(|query| query.id.as_str() == credential_id)
                .map(|query| query.id.clone())
                .ok_or_else(|| RuntimeError::new(RuntimeErrorReason::InvalidProto))?;
            bindings.push(TransactionDataBinding {
                query_id,
                algorithm: hash.algorithm,
                digest: hash.digest,
            });
        }
    }
    Ok(bindings)
}
