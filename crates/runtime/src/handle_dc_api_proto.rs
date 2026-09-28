// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::MessageField;
use reallyme_openid4vp_dc_api::DigitalCredentialRequestOptions;
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_proto_codec::{
    digital_credential_request_options_to_proto, problem_details_to_proto,
    proto_to_digital_credential_get_request,
};
use reallyme_openid4vp_types::{ProblemDetails, ProblemKind};

use crate::map_runtime_problem::runtime_error_to_problem_proto;
use crate::{RuntimeError, RuntimeErrorReason, VerifierRuntimeService};

impl VerifierRuntimeService {
    /// Build Digital Credentials API options through the generated protobuf boundary.
    pub fn build_digital_credential_request_options_proto(
        &self,
        request: &pb::BuildDigitalCredentialRequestOptionsRequest,
    ) -> pb::BuildDigitalCredentialRequestOptionsResponse {
        match self.try_build_digital_credential_request_options_body(request) {
            Ok(options) => pb::BuildDigitalCredentialRequestOptionsResponse {
                options: MessageField::some(options),
                ..Default::default()
            },
            Err(problem) => pb::BuildDigitalCredentialRequestOptionsResponse {
                problem: MessageField::some(problem),
                ..Default::default()
            },
        }
    }

    /// Decode a Digital Credentials API response through the generated protobuf boundary.
    pub fn decode_dc_api_authorization_response_proto(
        &self,
        request: &pb::DecodeDcApiAuthorizationResponseRequest,
    ) -> pb::DecodeDcApiAuthorizationResponseResponse {
        match self.try_decode_dc_api_authorization_response_body(request) {
            Ok(response) => pb::DecodeDcApiAuthorizationResponseResponse {
                response: MessageField::some(response),
                ..Default::default()
            },
            Err(problem) => pb::DecodeDcApiAuthorizationResponseResponse {
                problem: MessageField::some(problem),
                ..Default::default()
            },
        }
    }

    fn try_build_digital_credential_request_options_body(
        &self,
        request: &pb::BuildDigitalCredentialRequestOptionsRequest,
    ) -> Result<pb::DigitalCredentialRequestOptions, pb::ProblemDetails> {
        let requests = request
            .requests
            .iter()
            .map(proto_to_digital_credential_get_request)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid_request_problem())?;
        let options = DigitalCredentialRequestOptions::new(requests)
            .map_err(|_| invalid_request_problem())?;
        digital_credential_request_options_to_proto(&options).map_err(|_| invalid_request_problem())
    }

    fn try_decode_dc_api_authorization_response_body(
        &self,
        request: &pb::DecodeDcApiAuthorizationResponseRequest,
    ) -> Result<pb::AuthorizationResponse, pb::ProblemDetails> {
        let Some(_response) = request.response.as_ref() else {
            return Err(runtime_error_to_problem_proto(RuntimeError::new(
                RuntimeErrorReason::MissingField,
            )));
        };
        // This legacy decode-only operation has no server-owned session,
        // authenticated browser origin, negotiated response mode, or one-time
        // consumption boundary. Returning decrypted presentation data here
        // would invite callers to treat normalization as authorization. Both
        // plaintext and encrypted variants therefore fail closed until the
        // operation is replaced by a session-owned DC API endpoint.
        Err(runtime_error_to_problem_proto(RuntimeError::new(
            RuntimeErrorReason::UnsupportedFeature,
        )))
    }
}

fn invalid_request_problem() -> pb::ProblemDetails {
    problem_details_to_proto(&ProblemDetails::from_kind(ProblemKind::InvalidRequest))
}
