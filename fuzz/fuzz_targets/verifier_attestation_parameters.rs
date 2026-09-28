// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_types::{
    AuthorizationRequestObject, ClientIdentifier, ResponseMode, ResponseType,
};
use reallyme_openid4vp_wallet::{
    validate_verifier_attestation_binding, VerifiedVerifierAttestation,
};
use serde_json::Map as JsonMap;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = core::str::from_utf8(data) else {
        return;
    };
    let mut parts = input.split('|');
    let subject = next_part(&mut parts).to_owned();
    let client_id_value = next_part(&mut parts);
    let request_redirect = next_part(&mut parts);
    let allowed_redirect = next_part(&mut parts);
    let redirect_uris = (!allowed_redirect.is_empty()).then(|| vec![allowed_redirect.to_owned()]);
    let Ok(attestation) = VerifiedVerifierAttestation::new(subject, redirect_uris, vec![1_u8], 100)
    else {
        return;
    };
    let request = authorization_request(client_id_value, request_redirect);
    let _ = validate_verifier_attestation_binding(&request, &attestation, &[1_u8], 99);
});

fn next_part<'a>(parts: &mut core::str::Split<'a, char>) -> &'a str {
    parts.next().map_or("", core::convert::identity)
}

fn authorization_request(client_id_value: &str, redirect_uri: &str) -> AuthorizationRequestObject {
    AuthorizationRequestObject {
        client_id: ClientIdentifier::parse(client_id_value).ok(),
        response_type: ResponseType::VpToken,
        response_mode: Some(ResponseMode::DirectPost),
        response_uri: Some("https://verifier.example/response".to_owned()),
        redirect_uri: (!redirect_uri.is_empty()).then(|| redirect_uri.to_owned()),
        nonce: "0123456789abcdef".to_owned(),
        wallet_nonce: None,
        state: None,
        dcql_query: dcql_query(),
        transaction_data: None,
        client_metadata: None,
        client_metadata_uri: None,
        expected_origins: None,
        iss: None,
        aud: None,
        iat: Some(10),
        exp: Some(20),
    }
}

fn dcql_query() -> DcqlQuery {
    let id = QueryId::parse("pid").ok();
    let format = CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned()).ok();
    match (id, format) {
        (Some(id), Some(format)) => DcqlQuery {
            credentials: vec![CredentialQuery {
                id,
                format,
                multiple: false,
                meta: JsonMap::new(),
                trusted_authorities: None,
                require_cryptographic_holder_binding: true,
                claims: None,
                claim_sets: None,
            }],
            credential_sets: None,
        },
        _ => DcqlQuery {
            credentials: Vec::new(),
            credential_sets: None,
        },
    }
}
