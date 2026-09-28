// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_openid4vp_dcql::{
    evaluate_query, CredentialCandidate, CredentialFormat, DcqlQuery, EvaluationCredential,
};
use serde_json::{json, Map as JsonMap};

fuzz_target!(|data: &[u8]| {
    let Ok(query) = serde_json::from_slice::<DcqlQuery>(data) else {
        return;
    };
    let Some(candidate) = candidate_from_bytes(data) else {
        return;
    };
    let _ = evaluate_query(&query, &[candidate]);
});

fn candidate_from_bytes(data: &[u8]) -> Option<CredentialCandidate> {
    let first = data.first().copied().map_or(0, core::convert::identity);
    let format_name = if first & 1 == 0 {
        CredentialFormat::DC_SD_JWT
    } else {
        CredentialFormat::MSO_MDOC
    };
    let format = CredentialFormat::new(format_name.to_owned()).ok()?;
    let id = EvaluationCredential::new("fuzz-credential".to_owned()).ok()?;
    let claims = if first & 2 == 0 {
        json!({
            "given_name": "Ada",
            "age_over_18": true,
            "names": [{"given_name": "Ada"}]
        })
    } else {
        json!({
            "family_name": "Lovelace",
            "age_over_18": false,
            "names": []
        })
    };
    Some(CredentialCandidate {
        id,
        format,
        meta: JsonMap::new(),
        claims,
        cryptographic_holder_binding: first & 4 == 0,
    })
}
