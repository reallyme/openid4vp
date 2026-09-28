// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_crypto::jwk::{ed25519_public_key_to_jwk, Jwk, JwkOptions};
use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, QueryId};
use reallyme_openid4vp_formats::sd_jwt::{
    verify_sd_jwt_presentation, SdJwtFormatError, SdJwtFormatErrorReason, SdJwtIssuerKeySource,
    SdJwtIssuerIdentity, SdJwtPresentationVerificationInput, SdJwtTrustProvider,
    SdJwtVerificationKeyMaterial,
};
use serde_json::{json, Map as JsonMap, Value as JsonValue};

const FIXED_PUBLIC_KEY: [u8; 32] = [7; 32];

struct FixedTrustProvider;

impl SdJwtTrustProvider for FixedTrustProvider {
    fn resolve_verification_keys(
        &self,
        _compact: &str,
        _credential_query: &CredentialQuery,
        _now_unix: u64,
    ) -> Result<SdJwtVerificationKeyMaterial, SdJwtFormatError> {
        let public_jwk = fixed_public_jwk()?;
        Ok(SdJwtVerificationKeyMaterial::new(
            public_jwk.clone(),
            FIXED_PUBLIC_KEY.to_vec(),
            public_jwk,
            FIXED_PUBLIC_KEY.to_vec(),
            SdJwtIssuerKeySource::Resolved,
            SdJwtIssuerIdentity::new("https://issuer.example".to_owned())?,
        ))
    }

    fn verify_credential_status(
        &self,
        _issuer_payload: &JsonValue,
        _resolved_payload: &JsonValue,
    ) -> Result<(), SdJwtFormatError> {
        Ok(())
    }
}

fn fixed_public_jwk() -> Result<Jwk, SdJwtFormatError> {
    let public_jwk = ed25519_public_key_to_jwk(
        &FIXED_PUBLIC_KEY,
        JwkOptions {
            alg: true,
            use_sig: true,
            ..JwkOptions::default()
        },
    )
    .map_err(|_| SdJwtFormatError::new(SdJwtFormatErrorReason::KeyResolutionFailed))?;
    Ok(Jwk::Okp(public_jwk.into()))
}

fn credential_query() -> Option<CredentialQuery> {
    let id = QueryId::parse("pid").ok()?;
    let format = CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned()).ok()?;
    let mut meta = JsonMap::new();
    meta.insert(
        "vct_values".to_owned(),
        json!(["https://credentials.example/pid"]),
    );
    Some(CredentialQuery {
        id,
        format,
        multiple: false,
        meta,
        trusted_authorities: None,
        require_cryptographic_holder_binding: true,
        claims: None,
        claim_sets: None,
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(compact) = core::str::from_utf8(data) else {
        return;
    };
    let Some(query) = credential_query() else {
        return;
    };
    let _ = verify_sd_jwt_presentation(
        SdJwtPresentationVerificationInput {
            compact,
            expected_audience: "x509_hash:verifier.example",
            expected_nonce: "nonce",
            now_unix: 1_700_000_000,
            credential_query: &query,
        },
        &FixedTrustProvider,
    );
});
