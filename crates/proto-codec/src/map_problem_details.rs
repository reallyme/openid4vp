// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_types::{ProblemDetails, ProblemInstance, ProblemKind};

use crate::report_proto_error::OpenId4VpProtoError;

/// Map RFC 9457 problem details into generated protobuf.
pub fn problem_details_to_proto(problem: &ProblemDetails) -> pb::ProblemDetails {
    pb::ProblemDetails {
        r#type: problem.problem_type.as_str().to_owned(),
        title: problem.title.as_str().to_owned(),
        status: u32::from(problem.status.as_u16()),
        instance: problem
            .instance
            .as_ref()
            .map(|value| value.as_str().to_owned()),
        kind: buffa::EnumValue::from(problem_kind_to_proto(problem.extensions.kind)),
        __buffa_unknown_fields: Default::default(),
    }
}

/// Map generated protobuf problem details into the Rust RFC 9457 model.
pub fn proto_to_problem_details(
    problem: &pb::ProblemDetails,
) -> Result<ProblemDetails, OpenId4VpProtoError> {
    let kind = proto_to_problem_kind(&problem.kind)?;
    let out = ProblemDetails::from_kind(kind);
    Ok(match problem.instance.as_ref() {
        Some(instance) => out.with_instance(ProblemInstance::new(instance.clone())),
        None => out,
    })
}

fn problem_kind_to_proto(kind: ProblemKind) -> pb::ProblemKind {
    match kind {
        ProblemKind::InvalidRequest => pb::ProblemKind::InvalidRequest,
        ProblemKind::InvalidRequestObject => pb::ProblemKind::InvalidRequestObject,
        ProblemKind::InvalidClientIdentifier => pb::ProblemKind::InvalidClientIdentifier,
        ProblemKind::InvalidDcqlQuery => pb::ProblemKind::InvalidDcqlQuery,
        ProblemKind::UnsatisfiedDcqlQuery => pb::ProblemKind::UnsatisfiedDcqlQuery,
        ProblemKind::BindingExpired => pb::ProblemKind::BindingExpired,
        ProblemKind::SessionNotFound => pb::ProblemKind::SessionNotFound,
        ProblemKind::SessionMismatch => pb::ProblemKind::SessionMismatch,
        ProblemKind::UnsupportedFeature => pb::ProblemKind::UnsupportedFeature,
        ProblemKind::WalletUnavailable => pb::ProblemKind::WalletUnavailable,
        ProblemKind::Internal => pb::ProblemKind::Internal,
    }
}

fn proto_to_problem_kind(
    kind: &buffa::EnumValue<pb::ProblemKind>,
) -> Result<ProblemKind, OpenId4VpProtoError> {
    match kind.as_known() {
        Some(pb::ProblemKind::InvalidRequest) => Ok(ProblemKind::InvalidRequest),
        Some(pb::ProblemKind::InvalidRequestObject) => Ok(ProblemKind::InvalidRequestObject),
        Some(pb::ProblemKind::InvalidClientIdentifier) => Ok(ProblemKind::InvalidClientIdentifier),
        Some(pb::ProblemKind::InvalidDcqlQuery) => Ok(ProblemKind::InvalidDcqlQuery),
        Some(pb::ProblemKind::UnsatisfiedDcqlQuery) => Ok(ProblemKind::UnsatisfiedDcqlQuery),
        Some(pb::ProblemKind::BindingExpired) => Ok(ProblemKind::BindingExpired),
        Some(pb::ProblemKind::SessionNotFound) => Ok(ProblemKind::SessionNotFound),
        Some(pb::ProblemKind::SessionMismatch) => Ok(ProblemKind::SessionMismatch),
        Some(pb::ProblemKind::UnsupportedFeature) => Ok(ProblemKind::UnsupportedFeature),
        Some(pb::ProblemKind::WalletUnavailable) => Ok(ProblemKind::WalletUnavailable),
        Some(pb::ProblemKind::Internal) => Ok(ProblemKind::Internal),
        Some(pb::ProblemKind::Unspecified) | None => Err(OpenId4VpProtoError::InvalidEnumValue),
    }
}
