// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Emit compiled OpenID4VP-to-mdoc transport evidence.

use std::io::{self, Write};

use reallyme_openid4vp_dc_api::{
    OpenId4VpDcApiHandover, OpenId4VpRedirectHandover, SHA256_DIGEST_BYTES,
};
use reallyme_openid4vp_types::ClientIdentifier;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
enum EvidenceError {
    #[error("ISO transport evidence fixture is invalid")]
    InvalidFixture,
    #[error("ISO transport evidence serialization failed")]
    Serialize,
    #[error("ISO transport evidence output failed")]
    Output,
}

#[derive(Serialize)]
struct Evidence {
    schema: &'static str,
    producer: Producer,
    transports: Vec<TransportEvidence>,
}

#[derive(Serialize)]
struct Producer {
    repository: &'static str,
    artifact: &'static str,
}

#[derive(Serialize)]
struct TransportEvidence {
    iso_profile: &'static str,
    flow: &'static str,
    rust_type: &'static str,
    fields: Vec<FieldEvidence>,
    payload_semantics: &'static str,
}

#[derive(Serialize)]
struct FieldEvidence {
    name: &'static str,
    encoding: &'static str,
    cardinality: &'static str,
}

fn build_evidence() -> Result<Evidence, EvidenceError> {
    // Destructuring both production structs binds this generator to their
    // compiled field names and prevents a refactor from leaving stale output.
    let redirect = OpenId4VpRedirectHandover {
        client_id: ClientIdentifier::parse("evidence.example")
            .map_err(|_| EvidenceError::InvalidFixture)?,
        nonce: String::new(),
        jwk_thumbprint_sha256: Some([0_u8; SHA256_DIGEST_BYTES]),
        response_uri: String::new(),
    };
    let dc_api = OpenId4VpDcApiHandover {
        origin: String::new(),
        nonce: String::new(),
        jwk_thumbprint_sha256: None,
    };
    let _compiled_fields = (
        &redirect.client_id,
        &redirect.nonce,
        &redirect.jwk_thumbprint_sha256,
        &redirect.response_uri,
        &dc_api.origin,
        &dc_api.nonce,
        &dc_api.jwk_thumbprint_sha256,
    );

    Ok(Evidence {
        schema: "reallyme.identity.iso_transport_evidence.v1",
        producer: Producer {
            repository: "reallyme/openid4vp",
            artifact: "compiled-rust-transport-models",
        },
        transports: vec![
            TransportEvidence {
                iso_profile: "iso_conformance_18013_7_2025",
                flow: "openid4vp_redirect",
                rust_type: "OpenId4VpRedirectHandover",
                fields: vec![
                    FieldEvidence {
                        name: "client_id",
                        encoding: "openid4vp_client_identifier",
                        cardinality: "one",
                    },
                    FieldEvidence {
                        name: "nonce",
                        encoding: "tstr",
                        cardinality: "one",
                    },
                    FieldEvidence {
                        name: "jwk_thumbprint_sha256",
                        encoding: "32_byte_digest",
                        cardinality: "zero_or_one",
                    },
                    FieldEvidence {
                        name: "response_uri",
                        encoding: "uri_tstr",
                        cardinality: "one",
                    },
                ],
                payload_semantics: "handover_input_only_device_response_remains_opaque",
            },
            TransportEvidence {
                iso_profile: "iso_conformance_18013_7_2025",
                flow: "digital_credentials_api",
                rust_type: "OpenId4VpDcApiHandover",
                fields: vec![
                    FieldEvidence {
                        name: "origin",
                        encoding: "origin_tstr",
                        cardinality: "one",
                    },
                    FieldEvidence {
                        name: "nonce",
                        encoding: "tstr",
                        cardinality: "one",
                    },
                    FieldEvidence {
                        name: "jwk_thumbprint_sha256",
                        encoding: "32_byte_digest",
                        cardinality: "zero_or_one",
                    },
                ],
                payload_semantics: "handover_input_only_device_response_remains_opaque",
            },
        ],
    })
}

fn main() -> Result<(), EvidenceError> {
    let evidence = build_evidence()?;
    let encoded = serde_json::to_vec_pretty(&evidence).map_err(|_| EvidenceError::Serialize)?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    output
        .write_all(&encoded)
        .and_then(|()| output.write_all(b"\n"))
        .map_err(|_| EvidenceError::Output)
}
