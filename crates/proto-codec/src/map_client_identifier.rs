// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_types::{ClientIdentifier, ClientIdentifierPrefix};

use crate::report_proto_error::OpenId4VpProtoError;

/// Map a Rust client identifier into the generated protobuf message.
pub fn client_identifier_to_proto(client_id: &ClientIdentifier) -> pb::ClientIdentifier {
    pb::ClientIdentifier {
        prefix: buffa::EnumValue::from(client_identifier_prefix_to_proto(client_id.prefix())),
        identifier: client_id.identifier().to_owned(),
        wire_value: client_id.to_wire_value(),
        __buffa_unknown_fields: Default::default(),
    }
}

/// Map a generated protobuf client identifier into the Rust model.
pub fn proto_to_client_identifier(
    client_id: &pb::ClientIdentifier,
) -> Result<ClientIdentifier, OpenId4VpProtoError> {
    let parsed =
        ClientIdentifier::parse(&client_id.wire_value).map_err(OpenId4VpProtoError::from)?;
    let prefix = proto_to_client_identifier_prefix(&client_id.prefix)?;
    if parsed.prefix() != prefix || parsed.identifier() != client_id.identifier {
        return Err(OpenId4VpProtoError::InvalidField);
    }
    Ok(parsed)
}

pub(crate) fn client_identifier_prefix_to_proto(
    prefix: ClientIdentifierPrefix,
) -> pb::ClientIdentifierPrefix {
    match prefix {
        ClientIdentifierPrefix::None => pb::ClientIdentifierPrefix::None,
        ClientIdentifierPrefix::RedirectUri => pb::ClientIdentifierPrefix::RedirectUri,
        ClientIdentifierPrefix::OpenIdFederation => pb::ClientIdentifierPrefix::OpenidFederation,
        ClientIdentifierPrefix::DecentralizedIdentifier => {
            pb::ClientIdentifierPrefix::DecentralizedIdentifier
        }
        ClientIdentifierPrefix::VerifierAttestation => {
            pb::ClientIdentifierPrefix::VerifierAttestation
        }
        ClientIdentifierPrefix::X509SanDns => pb::ClientIdentifierPrefix::X509SanDns,
        ClientIdentifierPrefix::X509Hash => pb::ClientIdentifierPrefix::X509Hash,
        ClientIdentifierPrefix::Origin => pb::ClientIdentifierPrefix::Origin,
    }
}

pub(crate) fn proto_to_client_identifier_prefix(
    prefix: &buffa::EnumValue<pb::ClientIdentifierPrefix>,
) -> Result<ClientIdentifierPrefix, OpenId4VpProtoError> {
    match prefix.as_known() {
        Some(pb::ClientIdentifierPrefix::None) => Ok(ClientIdentifierPrefix::None),
        Some(pb::ClientIdentifierPrefix::RedirectUri) => Ok(ClientIdentifierPrefix::RedirectUri),
        Some(pb::ClientIdentifierPrefix::OpenidFederation) => {
            Ok(ClientIdentifierPrefix::OpenIdFederation)
        }
        Some(pb::ClientIdentifierPrefix::DecentralizedIdentifier) => {
            Ok(ClientIdentifierPrefix::DecentralizedIdentifier)
        }
        Some(pb::ClientIdentifierPrefix::VerifierAttestation) => {
            Ok(ClientIdentifierPrefix::VerifierAttestation)
        }
        Some(pb::ClientIdentifierPrefix::X509SanDns) => Ok(ClientIdentifierPrefix::X509SanDns),
        Some(pb::ClientIdentifierPrefix::X509Hash) => Ok(ClientIdentifierPrefix::X509Hash),
        Some(pb::ClientIdentifierPrefix::Origin) => Ok(ClientIdentifierPrefix::Origin),
        Some(pb::ClientIdentifierPrefix::Unspecified) | None => {
            Err(OpenId4VpProtoError::InvalidEnumValue)
        }
    }
}
