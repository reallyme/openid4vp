// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// OpenID4VP final SD-JWT VC format identifier.
pub const FORMAT_DC_SD_JWT: &str = reallyme_openid4vp_dcql::CredentialFormat::DC_SD_JWT;

/// OpenID4VP final ISO mdoc format identifier.
pub const FORMAT_MSO_MDOC: &str = reallyme_openid4vp_dcql::CredentialFormat::MSO_MDOC;

/// ReallyMe ZK presentation format marker.
pub const FORMAT_REALLYME_ZK: &str = super::zk_presentation::ZK_PRESENTATION_TYPE;
