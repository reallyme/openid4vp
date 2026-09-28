// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_types::ResponseMode;

use crate::describe_haip::{haip_presentation_profile, HaipCredentialFormat, HaipPresentationFlow};

#[test]
fn haip_shares_cross_protocol_identity() {
    use crate::describe_haip::{haip_profile_identity, PROFILE_HAIP_VERSION};

    assert_eq!(
        PROFILE_HAIP_VERSION,
        reallyme_openid4vc_profiles::HAIP_VERSION
    );
    assert!(haip_profile_identity().is_eidas_relevant());
    assert_eq!(
        reallyme_openid4vc_profiles::Profile::Haip.short_name(),
        reallyme_openid4vc_profiles::HAIP_SHORT_NAME
    );
}

#[test]
fn haip_profile_includes_dc_api_and_mdoc() {
    let profile = haip_presentation_profile();

    assert!(profile
        .flows
        .contains(&HaipPresentationFlow::DigitalCredentialsApi));
    assert!(profile
        .credential_formats
        .contains(&HaipCredentialFormat::Mdoc));
    assert_eq!(
        profile.response_modes,
        &[ResponseMode::DirectPostJwt, ResponseMode::DcApiJwt]
    );
}

#[test]
fn haip_profile_rejects_plaintext_response_modes() {
    let profile = haip_presentation_profile();

    assert!(!profile.response_modes.contains(&ResponseMode::DirectPost));
    assert!(!profile.response_modes.contains(&ResponseMode::DcApi));
}
