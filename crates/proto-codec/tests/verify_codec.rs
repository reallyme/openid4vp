// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests for OpenID4VP protobuf codec mappings.

#![allow(clippy::expect_used)]

use buffa::{Message, MessageField};
use reallyme_openid4vp_dc_api::{
    DcApiProtocol, DcApiRequestKind, DigitalCredentialGetRequest, DigitalCredentialRequestOptions,
    JwsJsonGeneral, JwsJsonSignature,
};
use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_formats::{
    DerivedClaimStatement, ZkPresentation, ZkPresentationBinding, ZkPresentationCircuitRef,
    ZkPresentationProfile, ZkPresentationProofSuite, ZkPresentationStage, ZkPresentationStageKind,
    ZK_PRESENTATION_TYPE,
};
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_proto_codec::{
    authorization_request_json_to_proto, authorization_request_proto_to_json,
    authorization_request_transport_to_proto, authorization_response_to_proto,
    client_identifier_to_proto, decode_authorization_request, decode_authorization_request_proto,
    decode_authorization_response, decode_session_record,
    digital_credential_request_options_to_proto, encode_authorization_request,
    encode_authorization_request_proto, encode_authorization_response, encode_session_record,
    holder_binding_claims_to_proto, problem_details_to_proto, proto_to_authorization_request,
    proto_to_authorization_request_transport, proto_to_authorization_response,
    proto_to_digital_credential_request_options, proto_to_holder_binding_claims,
    proto_to_problem_details, OpenId4VpProtoError, MAX_DCQL_JSON_BYTES,
    MAX_OPENID4VP_PROTO_JSON_BYTES, MAX_OPENID4VP_PROTO_MESSAGE_BYTES,
    MAX_SENSITIVE_JSON_NESTING_DEPTH,
};
use reallyme_openid4vp_types::{
    decode_transaction_data_string, AuthorizationRequestObject, AuthorizationResponse,
    ClientIdentifier, ClientMetadata, PresentationValue, ProblemDetails, ProblemInstance,
    ProblemKind, RequestUriMethod, ResponseMode, ResponseType, TransactionDataHashAlgorithm,
};
use reallyme_openid4vp_verifier::{
    BrowserSessionBinding, FollowBackRequirement, HolderBindingClaims, PostResponseRedirectUri,
    RequestBinding, RetainedMdocSessionTranscript, SessionRecord, TransactionDataBinding,
    MAX_RETAINED_MDOC_SESSION_TRANSCRIPT_BYTES,
};
use reallyme_openid4vp_wallet::AuthorizationRequestTransport;
use serde_json::{json, Map as JsonMap};

fn dcql_query() -> DcqlQuery {
    DcqlQuery {
        credentials: vec![CredentialQuery {
            id: QueryId::parse("pid").expect("test query id is valid"),
            format: CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned())
                .expect("test credential format is valid"),
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
    }
}

fn verifier_session() -> SessionRecord {
    SessionRecord {
        binding: RequestBinding {
            client_id: ClientIdentifier::parse("x509_hash:certificate-thumbprint")
                .expect("test client identifier is valid"),
            nonce: "request-nonce".to_owned(),
            response_uri: Some("https://verifier.example/direct-post".to_owned()),
            redirect_uri: None,
            dc_api_origin: None,
            expiry_unix: 1_900_000_000,
            transaction_data_bindings: vec![TransactionDataBinding {
                query_id: QueryId::parse("pid").expect("test query id is valid"),
                algorithm: TransactionDataHashAlgorithm::Sha256,
                digest: [7_u8; 32],
            }],
        },
        state: Some("opaque-state".to_owned()),
        dcql_query: dcql_query(),
        response_mode: ResponseMode::DirectPost,
        mdoc_session_transcript: Some(
            RetainedMdocSessionTranscript::new_with_response_key_thumbprint(
                vec![0x83, 0xf6, 0xf6, 0x80],
                Some([9_u8; 32]),
            )
            .expect("test transcript is bounded"),
        ),
        post_response_redirect_uri: Some(
            PostResponseRedirectUri::parse("https://verifier.example/result".to_owned())
                .expect("test redirect is valid"),
        ),
        follow_back_requirement: Some(
            FollowBackRequirement::new(BrowserSessionBinding::new([11_u8; 32]), 1_899_999_999)
                .expect("test follow-back requirement is valid"),
        ),
    }
}

#[test]
fn encodes_and_decodes_authorization_response_proto() {
    let response = AuthorizationResponse::single(
        QueryId::parse("pid").expect("test query id is valid"),
        vec![
            PresentationValue::Compact("header.payload.signature".to_owned()),
            PresentationValue::Json(json!({"proof": true})),
        ],
        Some("fedcba9876543210".to_owned()),
    )
    .expect("test response is valid");

    let encoded = encode_authorization_response(&response).expect("response encodes");
    let decoded = decode_authorization_response(&encoded).expect("response decodes");

    assert_eq!(decoded, response);
}

#[test]
fn encodes_and_decodes_verifier_session_proto() {
    let session = verifier_session();

    let encoded = encode_session_record(&session).expect("session encodes");
    let decoded = decode_session_record(&encoded).expect("session decodes");

    assert_eq!(decoded, session);
}

#[test]
fn verifier_session_decode_rejects_invalid_follow_back_persistence() {
    let mut proto = reallyme_openid4vp_proto_codec::session_record_to_proto(&verifier_session())
        .expect("test session maps to proto");
    proto.follow_back_requirement = MessageField::some(pb::FollowBackRequirement {
        browser_session_binding: vec![7_u8; 31],
        expires_unix: 1_899_999_999,
        __buffa_unknown_fields: Default::default(),
    });
    let encoded = proto.encode_to_vec();

    let error = decode_session_record(&encoded)
        .expect_err("non-fixed browser-session binding must fail closed");

    assert_eq!(error, OpenId4VpProtoError::InvalidField);
}

#[test]
fn verifier_session_decode_rejects_oversized_and_unknown_input() {
    let oversized = vec![0_u8; MAX_OPENID4VP_PROTO_MESSAGE_BYTES + 1];
    let oversized_error =
        decode_session_record(&oversized).expect_err("oversized session must fail before decode");
    assert_eq!(oversized_error, OpenId4VpProtoError::Decode);

    let unknown_length_delimited_field = [0xfa, 0x07, 0x01, 0x00];
    let unknown_error = decode_session_record(&unknown_length_delimited_field)
        .expect_err("unknown session fields must fail closed");
    assert_eq!(unknown_error, OpenId4VpProtoError::Decode);
}

#[test]
fn verifier_session_decode_revalidates_embedded_dcql() {
    let session = verifier_session();
    let mut proto = reallyme_openid4vp_proto_codec::session_record_to_proto(&session)
        .expect("test session maps to proto");
    proto.dcql_query_json = br#"{"credentials":[],"credentials":[]}"#.to_vec();
    let encoded = buffa::Message::encode_to_vec(&proto);

    let error =
        decode_session_record(&encoded).expect_err("duplicate embedded DCQL keys must fail closed");

    assert_eq!(error, OpenId4VpProtoError::JsonDuplicateKey);
}

#[test]
fn verifier_session_decode_rejects_invalid_retained_mdoc_transcript_sizes() {
    let session = verifier_session();
    let mut proto = reallyme_openid4vp_proto_codec::session_record_to_proto(&session)
        .expect("test session maps to proto");
    proto.mdoc_session_transcript_cbor = Some(Vec::new());
    let empty = buffa::Message::encode_to_vec(&proto);
    let empty_error =
        decode_session_record(&empty).expect_err("empty retained transcript must fail closed");
    assert_eq!(empty_error, OpenId4VpProtoError::InvalidField);

    proto.mdoc_session_transcript_cbor =
        Some(vec![0_u8; MAX_RETAINED_MDOC_SESSION_TRANSCRIPT_BYTES + 1]);
    let oversized = buffa::Message::encode_to_vec(&proto);
    let oversized_error = decode_session_record(&oversized)
        .expect_err("oversized retained transcript must fail closed");
    assert_eq!(oversized_error, OpenId4VpProtoError::InvalidField);

    proto.mdoc_session_transcript_cbor = Some(vec![0x83, 0xf6, 0xf6, 0x80]);
    proto.mdoc_response_key_thumbprint_sha256 = Some(vec![0_u8; 31]);
    let short_thumbprint = buffa::Message::encode_to_vec(&proto);
    let short_thumbprint_error = decode_session_record(&short_thumbprint)
        .expect_err("a short mdoc response-key thumbprint must fail closed");
    assert_eq!(short_thumbprint_error, OpenId4VpProtoError::InvalidField);

    proto.mdoc_session_transcript_cbor = None;
    proto.mdoc_response_key_thumbprint_sha256 = Some(vec![0_u8; 32]);
    let orphaned_thumbprint = buffa::Message::encode_to_vec(&proto);
    let orphaned_thumbprint_error = decode_session_record(&orphaned_thumbprint)
        .expect_err("a thumbprint without its transcript must fail closed");
    assert_eq!(orphaned_thumbprint_error, OpenId4VpProtoError::InvalidField);
}

#[test]
fn generated_proto_decode_rejects_oversized_input() {
    let oversized = vec![0_u8; MAX_OPENID4VP_PROTO_MESSAGE_BYTES + 1];
    let err = decode_authorization_request_proto(&oversized)
        .expect_err("oversized protobuf input must fail before decode");

    assert_eq!(err, OpenId4VpProtoError::Decode);
}

#[test]
fn generated_proto_decode_rejects_unknown_fields() {
    // Field 127, wire type 2, with one byte of payload. Retaining unknown
    // length-delimited data would create an untyped allocation and bypass the
    // schema-owned zeroization policy.
    let unknown_length_delimited_field = [0xfa, 0x07, 0x01, 0x00];
    let err = decode_authorization_request_proto(&unknown_length_delimited_field)
        .expect_err("unknown protobuf fields must fail closed");

    assert_eq!(err, OpenId4VpProtoError::Decode);
}

#[test]
fn generated_proto_json_rejects_oversized_input() {
    let oversized = " ".repeat(MAX_OPENID4VP_PROTO_JSON_BYTES + 1);
    let err = authorization_request_json_to_proto(&oversized)
        .expect_err("oversized JSON input must fail before parse");

    assert_eq!(err, OpenId4VpProtoError::JsonDeserialize);
}

#[test]
fn generated_proto_json_rejects_message_over_protobuf_budget() {
    let oversized_len = MAX_OPENID4VP_PROTO_MESSAGE_BYTES
        .checked_add(1)
        .expect("test size remains representable");
    let mut request = pb::AuthorizationRequest::default();
    request.nonce = "n".repeat(oversized_len);

    let err = authorization_request_proto_to_json(&request)
        .expect_err("ProtoJSON output must retain the protobuf message budget");

    assert_eq!(err, OpenId4VpProtoError::JsonSerialize);
}

#[test]
fn generated_proto_json_output_uses_zeroizing_owner() {
    let mut request = pb::AuthorizationRequest::default();
    request.nonce = "0123456789abcdef".to_owned();
    request.dcql_query_json = br#"{"credentials":[]}"#.to_vec();

    let json = authorization_request_proto_to_json(&request).expect("request JSON serializes");
    assert!(json.contains("dcqlQueryJson"));

    let bytes = encode_authorization_request_proto(&request).expect("request protobuf serializes");
    assert!(!bytes.is_empty());
}

fn inline_params_transport(parameters: &[(&str, &str)]) -> pb::AuthorizationRequestTransport {
    pb::AuthorizationRequestTransport {
        transport: Some(
            pb::authorization_request_transport::Transport::InlineParams(Box::new(
                pb::InlineParamsTransport {
                    params: parameters
                        .iter()
                        .map(|(name, value)| pb::InlineParam {
                            name: (*name).to_owned(),
                            value: (*value).to_owned(),
                            __buffa_unknown_fields: Default::default(),
                        })
                        .collect(),
                    __buffa_unknown_fields: Default::default(),
                },
            )),
        ),
        __buffa_unknown_fields: Default::default(),
    }
}

#[test]
fn proto_mapping_rejects_duplicate_inline_parameter_names() {
    let transport = inline_params_transport(&[("client_id", "first"), ("client_id", "second")]);

    let err = proto_to_authorization_request_transport(&transport)
        .expect_err("duplicate inline parameter names must fail closed");

    assert_eq!(err, OpenId4VpProtoError::InvalidField);
}

#[test]
fn proto_mapping_rejects_empty_inline_parameter_names() {
    let transport = inline_params_transport(&[("", "value")]);

    let err = proto_to_authorization_request_transport(&transport)
        .expect_err("empty inline parameter names must fail closed");

    assert_eq!(err, OpenId4VpProtoError::InvalidField);
}

fn authorization_request_with_dcql_json(dcql_query_json: Vec<u8>) -> pb::AuthorizationRequest {
    let mut request = pb::AuthorizationRequest::default();
    request.response_type = buffa::EnumValue::from(pb::ResponseType::VpToken);
    request.dcql_query_json = dcql_query_json;
    request
}

#[test]
fn proto_mapping_rejects_oversized_embedded_dcql_json() {
    let request = authorization_request_with_dcql_json(vec![b' '; MAX_DCQL_JSON_BYTES + 1]);

    let err = proto_to_authorization_request(&request)
        .expect_err("oversized embedded DCQL must fail before parse");

    assert_eq!(err, OpenId4VpProtoError::JsonTooLarge);
}

#[test]
fn proto_mapping_rejects_duplicate_embedded_json_keys() {
    let request =
        authorization_request_with_dcql_json(br#"{"credentials":[],"credentials":[]}"#.to_vec());

    let err = proto_to_authorization_request(&request)
        .expect_err("duplicate DCQL object keys must fail closed");

    assert_eq!(err, OpenId4VpProtoError::JsonDuplicateKey);
}

#[test]
fn proto_mapping_rejects_excessive_embedded_json_nesting() {
    let mut nested = "null".to_owned();
    for _ in 0..=MAX_SENSITIVE_JSON_NESTING_DEPTH {
        nested = format!("[{nested}]");
    }
    let request = authorization_request_with_dcql_json(nested.into_bytes());

    let err = proto_to_authorization_request(&request)
        .expect_err("deeply nested DCQL must fail before domain mapping");

    assert_eq!(err, OpenId4VpProtoError::JsonNestingTooDeep);
}

#[test]
fn encodes_zk_presentation_as_typed_proto_oneof() {
    let presentation = ZkPresentation {
        type_: ZK_PRESENTATION_TYPE.to_owned(),
        profile: ZkPresentationProfile::PrivateClaimV1,
        proof_suite: ZkPresentationProofSuite::BarretenbergUltraHonkKeccakZkNoIpa,
        stages: zk_presentation_stages(),
        derived_claims: vec![DerivedClaimStatement {
            statement_id: "age".to_owned(),
            statement: "age_over_18".to_owned(),
        }],
        binding: ZkPresentationBinding {
            nonce_hash: [7; 32],
            audience_hash: [8; 32],
            transaction_data_hash: Some([9; 32]),
        },
    };
    let response = AuthorizationResponse::single(
        QueryId::parse("pid").expect("test query id is valid"),
        vec![PresentationValue::Json(
            serde_json::to_value(presentation).expect("test presentation serializes"),
        )],
        None,
    )
    .expect("test response is valid");

    let proto = authorization_response_to_proto(&response).expect("response maps to proto");
    let typed_zk = proto
        .vp_token
        .first()
        .and_then(|entry| entry.presentations.first())
        .and_then(|value| value.kind.as_ref())
        .and_then(|kind| match kind {
            pb::presentation_value::Kind::Zk(zk) => Some(zk.as_ref()),
            _ => None,
        });

    assert_eq!(
        typed_zk.and_then(|zk| zk.profile.as_known()),
        Some(pb::ZkPresentationProfile::PrivateClaimV1)
    );
    assert_eq!(
        typed_zk.and_then(|zk| zk.proof_suite.as_known()),
        Some(pb::ZkPresentationProofSuite::BarretenbergUltraHonkKeccakZkNoIpa)
    );
    assert_eq!(
        typed_zk.and_then(|zk| {
            zk.stages
                .first()
                .map(|stage| stage.artifact_manifest_sha256.as_slice())
        }),
        Some([10_u8; 32].as_slice())
    );
    let decoded = proto_to_authorization_response(&proto).expect("typed zk proto decodes");
    assert_eq!(decoded, response);

    let mut malformed_manifest = proto.clone();
    if let Some(pb::presentation_value::Kind::Zk(zk)) = malformed_manifest
        .vp_token
        .first_mut()
        .and_then(|entry| entry.presentations.first_mut())
        .and_then(|value| value.kind.as_mut())
    {
        if let Some(stage) = zk.stages.first_mut() {
            stage.artifact_manifest_sha256.truncate(31);
        }
    }
    let error = proto_to_authorization_response(&malformed_manifest)
        .expect_err("a malformed artifact manifest digest must fail closed");
    assert_eq!(error, OpenId4VpProtoError::InvalidField);

    let mut reordered_stages = proto.clone();
    if let Some(pb::presentation_value::Kind::Zk(zk)) = reordered_stages
        .vp_token
        .first_mut()
        .and_then(|entry| entry.presentations.first_mut())
        .and_then(|value| value.kind.as_mut())
    {
        zk.stages.swap(0, 1);
    }
    let error = proto_to_authorization_response(&reordered_stages)
        .expect_err("noncanonical ZK stages must fail at the protobuf boundary");
    assert_eq!(error, OpenId4VpProtoError::InvalidField);

    let mut unspecified_suite = proto;
    if let Some(pb::presentation_value::Kind::Zk(zk)) = unspecified_suite
        .vp_token
        .first_mut()
        .and_then(|entry| entry.presentations.first_mut())
        .and_then(|value| value.kind.as_mut())
    {
        zk.proof_suite = pb::ZkPresentationProofSuite::Unspecified.into();
    }
    let error = proto_to_authorization_response(&unspecified_suite)
        .expect_err("an unspecified ZK proof suite must fail closed");
    assert_eq!(error, OpenId4VpProtoError::InvalidEnumValue);

    let mut unknown_suite = malformed_manifest;
    if let Some(pb::presentation_value::Kind::Zk(zk)) = unknown_suite
        .vp_token
        .first_mut()
        .and_then(|entry| entry.presentations.first_mut())
        .and_then(|value| value.kind.as_mut())
    {
        if let Some(stage) = zk.stages.first_mut() {
            stage.artifact_manifest_sha256 = vec![10_u8; 32];
        }
        zk.proof_suite = buffa::EnumValue::from(2);
    }
    let error = proto_to_authorization_response(&unknown_suite)
        .expect_err("an unknown ZK proof suite must fail closed");
    assert_eq!(error, OpenId4VpProtoError::InvalidEnumValue);
}

fn zk_presentation_stages() -> Vec<ZkPresentationStage> {
    [
        (ZkPresentationStageKind::Session, "session"),
        (
            ZkPresentationStageKind::CredentialEnvelope,
            "credential_envelope",
        ),
        (ZkPresentationStageKind::CredentialRoot, "credential_root"),
        (ZkPresentationStageKind::Claim, "claim"),
    ]
    .into_iter()
    .map(|(stage, stage_name)| ZkPresentationStage {
        stage,
        circuit_ref: ZkPresentationCircuitRef {
            hash_strategy: "sha256".to_owned(),
            family: "private_claim_v1".to_owned(),
            stage: stage_name.to_owned(),
            version: 1,
        },
        artifact_manifest_sha256: [10_u8; 32],
        proof: vec![1, 2, 3],
        public_inputs: vec![4, 5, 6],
    })
    .collect()
}

#[test]
fn rejects_empty_authorization_response_proto() {
    let proto = pb::AuthorizationResponse {
        vp_token: Vec::new(),
        state: None,
        __buffa_unknown_fields: Default::default(),
    };

    let err = proto_to_authorization_response(&proto)
        .expect_err("empty final vp_token object is rejected");

    assert_eq!(err, OpenId4VpProtoError::MissingField);
}

#[test]
fn rejects_invalid_vp_token_query_id() {
    let proto = pb::AuthorizationResponse {
        vp_token: vec![pb::VpTokenEntry {
            query_id: "not a valid id".to_owned(),
            presentations: vec![pb::PresentationValue {
                kind: Some(pb::presentation_value::Kind::Compact(
                    "header.payload.signature".to_owned(),
                )),
                __buffa_unknown_fields: Default::default(),
            }],
            __buffa_unknown_fields: Default::default(),
        }],
        state: None,
        __buffa_unknown_fields: Default::default(),
    };

    let err =
        proto_to_authorization_response(&proto).expect_err("invalid DCQL query id is rejected");

    assert_eq!(err, OpenId4VpProtoError::InvalidField);
}

#[test]
fn rejects_empty_presentation_list_in_response_proto() {
    let proto = pb::AuthorizationResponse {
        vp_token: vec![pb::VpTokenEntry {
            query_id: "pid".to_owned(),
            presentations: Vec::new(),
            __buffa_unknown_fields: Default::default(),
        }],
        state: None,
        __buffa_unknown_fields: Default::default(),
    };

    let err = proto_to_authorization_response(&proto)
        .expect_err("empty per-query presentation list is rejected");

    assert_eq!(err, OpenId4VpProtoError::MissingField);
}

#[test]
fn maps_client_identifier_to_generated_proto() {
    let client_id =
        ClientIdentifier::parse("x509_san_dns:verifier.example").expect("test client id is valid");
    let proto = client_identifier_to_proto(&client_id);

    assert_eq!(proto.wire_value, "x509_san_dns:verifier.example");
    assert_eq!(proto.identifier, "verifier.example");
}

#[test]
fn encodes_and_decodes_authorization_request_proto() {
    let encoded_transaction_data = "ewogICAgICAgICAgImN1cnJlbmN5IjogIkVVUiIsCiAgICAgICAgICAiY3JlZGVudGlhbF9pZHMiOiBbInBpZCJdLAogICAgICAgICAgInR5cGUiOiAicGF5bWVudCIsCiAgICAgICAgICAiYW1vdW50IjogIjEwLjAwIgogICAgICAgIH0".to_owned();
    let request = AuthorizationRequestObject {
        client_id: Some(
            ClientIdentifier::parse("x509_san_dns:verifier.example")
                .expect("test client id is valid"),
        ),
        response_type: ResponseType::VpToken,
        response_mode: Some(ResponseMode::DirectPostJwt),
        response_uri: Some("https://verifier.example/response".to_owned()),
        redirect_uri: None,
        nonce: "0123456789abcdef".to_owned(),
        wallet_nonce: None,
        state: Some("fedcba9876543210".to_owned()),
        dcql_query: dcql_query(),
        transaction_data: Some(vec![decode_transaction_data_string(
            &encoded_transaction_data,
        )
        .expect("test transaction data is valid")]),
        client_metadata: Some(ClientMetadata {
            raw: json!({"jwks_uri": "https://verifier.example/jwks.json"}),
        }),
        client_metadata_uri: Some("https://verifier.example/metadata.json".to_owned()),
        expected_origins: Some(vec!["https://verifier.example".to_owned()]),
        iss: Some("x509_san_dns:verifier.example".to_owned()),
        aud: Some(vec!["wallet".to_owned()]),
        iat: Some(10),
        exp: Some(70),
    };

    let encoded = encode_authorization_request(&request).expect("request encodes");
    let decoded = decode_authorization_request(&encoded).expect("request decodes");

    assert_eq!(decoded, request);
    assert_eq!(
        decoded
            .transaction_data
            .as_ref()
            .and_then(|values| values.first())
            .map(|value| value.encoded_value()),
        Some(encoded_transaction_data.as_str())
    );
}

#[test]
fn maps_verified_transaction_data_holder_claims() {
    let claims = HolderBindingClaims {
        audience: vec!["x509_san_dns:verifier.example".to_owned()],
        nonce: "0123456789abcdef".to_owned(),
        expiration_unix: 100,
        issued_at_unix: 10,
        sd_hash: Some("sd-hash".to_owned()),
        transaction_data_hashes: vec![[23; 32]],
        transaction_data_hashes_alg: Some(TransactionDataHashAlgorithm::Sha256),
    };

    let proto = holder_binding_claims_to_proto(&claims);
    let decoded = proto_to_holder_binding_claims(&proto).expect("holder claims decode");
    assert_eq!(decoded, claims);

    let mut malformed = proto;
    malformed.transaction_data_hashes = vec![vec![1; 31]];
    let error = proto_to_holder_binding_claims(&malformed)
        .expect_err("non-SHA-256 digest lengths must fail closed");
    assert_eq!(error, OpenId4VpProtoError::InvalidField);
}

#[test]
fn maps_wallet_request_transport_oneof() {
    let transport = AuthorizationRequestTransport::RequestUri {
        uri: "https://verifier.example/request.jwt".to_owned(),
        method: RequestUriMethod::Post,
        wallet_nonce: Some("wallet-nonce".to_owned()),
        expected_client_id: Some("x509_san_dns:verifier.example".to_owned()),
    };

    let proto = authorization_request_transport_to_proto(&transport);
    let mapped = proto_to_authorization_request_transport(&proto).expect("transport maps");

    assert_eq!(mapped, transport);
}

#[test]
fn maps_problem_details_without_detail_text() {
    let problem = ProblemDetails::from_kind(ProblemKind::InvalidRequestObject)
        .with_instance(ProblemInstance::new("urn:trace:test".to_owned()));

    let proto = problem_details_to_proto(&problem);
    let mapped = proto_to_problem_details(&proto).expect("problem details map");

    assert_eq!(mapped.extensions.kind, ProblemKind::InvalidRequestObject);
    assert_eq!(
        mapped.instance.as_ref().map(ProblemInstance::as_str),
        Some("urn:trace:test")
    );
}

#[test]
fn maps_dc_api_request_options() {
    let request = AuthorizationRequestObject {
        client_id: None,
        response_type: ResponseType::VpToken,
        response_mode: Some(ResponseMode::DcApi),
        response_uri: None,
        redirect_uri: None,
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
        iat: None,
        exp: None,
    };
    let entry =
        DigitalCredentialGetRequest::new(DcApiProtocol::v1(DcApiRequestKind::Unsigned), request)
            .expect("test DC API request is valid");
    let options = DigitalCredentialRequestOptions::new(vec![entry])
        .expect("test DC API request options are valid");

    let proto = digital_credential_request_options_to_proto(&options).expect("DC API options map");
    let mapped =
        proto_to_digital_credential_request_options(&proto).expect("DC API options map back");

    assert_eq!(mapped, options);
}

#[test]
fn rejects_dc_api_protocol_data_mismatch_in_proto() {
    let request = AuthorizationRequestObject {
        client_id: None,
        response_type: ResponseType::VpToken,
        response_mode: Some(ResponseMode::DcApi),
        response_uri: None,
        redirect_uri: None,
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
        iat: None,
        exp: None,
    };
    let entry =
        DigitalCredentialGetRequest::new(DcApiProtocol::v1(DcApiRequestKind::Unsigned), request)
            .expect("test DC API request is valid");
    let options = DigitalCredentialRequestOptions::new(vec![entry])
        .expect("test DC API request options are valid");
    let mut proto =
        digital_credential_request_options_to_proto(&options).expect("DC API options map");
    proto.requests[0].protocol = "openid4vp-v1-signed".to_owned();

    proto_to_digital_credential_request_options(&proto)
        .expect_err("the protocol identifier must agree with the protobuf oneof");
}

#[test]
fn maps_multisigned_dc_api_request_options() {
    let signature = JwsJsonSignature::new("cHJvdGVjdGVk".to_owned(), "c2lnbmF0dXJl".to_owned())
        .expect("test signature is valid");
    let request = JwsJsonGeneral::new("cGF5bG9hZA".to_owned(), vec![signature])
        .expect("test JWS JSON is valid");
    let entry = DigitalCredentialGetRequest::new_multisigned_request_object(
        DcApiProtocol::v1(DcApiRequestKind::Multisigned),
        request,
    )
    .expect("test multi-signed DC API request is valid");
    let options = DigitalCredentialRequestOptions::new(vec![entry])
        .expect("test DC API request options are valid");

    let proto = digital_credential_request_options_to_proto(&options).expect("DC API options map");
    let mapped =
        proto_to_digital_credential_request_options(&proto).expect("DC API options map back");

    assert_eq!(mapped, options);
}
