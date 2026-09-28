// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

mod runtime_support;

use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_runtime::{
    JoseAuthorizationResponseJwtDecryptor, RuntimeHttpMethod, RuntimeHttpRequest,
    SessionBoundDirectJweKeyResolver, VerifierHttpEndpoint, VerifierHttpRuntime,
    VerifierRuntimeConfig, VerifierRuntimeService,
};
use reallyme_openid4vp_types::ClientIdentifier;
use reallyme_openid4vp_verifier::{RequestBinding, SessionRecord};
use runtime_support::{FixedRuntimeClock, FuzzSessionStore, RejectingRequestObjectStore};
use serde_json::{json, Map as JsonMap};

const FUZZ_MAX_DIRECT_POST_JWT_BODY_BYTES: usize = 512;
const FUZZ_DIRECT_JWE_KEY: [u8; 16] = [9u8; 16];
const FUZZ_SESSION_KEY: &str = "fuzz-session";

fuzz_target!(|data: &[u8]| {
    let Some(session) = session() else {
        return;
    };
    let decryptor = JoseAuthorizationResponseJwtDecryptor::new(
        SessionBoundDirectJweKeyResolver::platform(&FUZZ_DIRECT_JWE_KEY),
    );
    let runtime = VerifierHttpRuntime::new(
        Arc::new(VerifierRuntimeService::new(
            VerifierRuntimeConfig::new().with_response_jwt_decryptor(Arc::new(decryptor)),
        )),
        Arc::new(FuzzSessionStore::new(session)),
        Arc::new(RejectingRequestObjectStore),
        Arc::new(FixedRuntimeClock::new(10)),
    )
    .with_max_direct_post_body_bytes(FUZZ_MAX_DIRECT_POST_JWT_BODY_BYTES);
    let selector = data.first().copied().map_or(0, core::convert::identity);
    let body = data.get(1..).map_or_else(Vec::new, <[u8]>::to_vec);
    let request = RuntimeHttpRequest {
        method: if selector & 1 == 0 {
            RuntimeHttpMethod::Post
        } else {
            RuntimeHttpMethod::Get
        },
        accept: None,
        content_type: (selector & 2 == 0).then(|| "application/x-www-form-urlencoded".to_owned()),
        body,
    };
    let _ = runtime.handle(
        VerifierHttpEndpoint::DirectPostJwt {
            session_key: FUZZ_SESSION_KEY,
        },
        &request,
    );
});

fn session() -> Option<SessionRecord> {
    let client_id = ClientIdentifier::parse("x509_san_dns:verifier.example").ok()?;
    Some(SessionRecord {
        binding: RequestBinding {
            client_id,
            nonce: "0123456789abcdef".to_owned(),
            response_uri: Some("https://verifier.example/response".to_owned()),
            redirect_uri: None,
            dc_api_origin: None,
            expiry_unix: 100,
            transaction_data_bindings: Vec::new(),
        },
        state: Some("fedcba9876543210".to_owned()),
        dcql_query: dcql_query()?,
        response_mode: reallyme_openid4vp_types::ResponseMode::DirectPostJwt,
        mdoc_session_transcript: None,
        post_response_redirect_uri: None,
        follow_back_requirement: None,
    })
}

fn dcql_query() -> Option<DcqlQuery> {
    Some(DcqlQuery {
        credentials: vec![CredentialQuery {
            id: QueryId::parse("pid").ok()?,
            format: CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned()).ok()?,
            multiple: false,
            meta: JsonMap::from_iter([(
                "vct_values".to_owned(),
                json!(["https://credentials.example.com/identity_credential"]),
            )]),
            trusted_authorities: None,
            require_cryptographic_holder_binding: true,
            claims: None,
            claim_sets: None,
        }],
        credential_sets: None,
    })
}
