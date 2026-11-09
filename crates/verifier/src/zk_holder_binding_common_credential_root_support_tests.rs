// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

struct CommonCredentialRootEvidenceVerifier {
    calls: AtomicUsize,
    accept: bool,
    expected_request_time_unix: u64,
}
struct AdvancingRootEvidenceVerifier<'a> {
    floor: &'a TestRootStatusFloor,
    feed_id: [u8; 32],
    calls: AtomicUsize,
}
impl ZkCommonCredentialRootVerifier for AdvancingRootEvidenceVerifier<'_> {
    fn verify_common_credential_root_evidence(
        &self,
        _request: &ZkCommonCredentialRootVerifyRequest<'_>,
    ) -> Result<(), ZkError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.floor
            .admit_verified(self.feed_id, 3, [9_u8; 32])
            .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))
    }
}
impl ZkCommonCredentialRootVerifier for CommonCredentialRootEvidenceVerifier {
    fn verify_common_credential_root_evidence(
        &self,
        request: &ZkCommonCredentialRootVerifyRequest<'_>,
    ) -> Result<(), ZkError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if request.join_policy().request_time_unix != self.expected_request_time_unix {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        if self.accept {
            Ok(())
        } else {
            Err(ZkError::new(ZkErrorReason::InvalidProof))
        }
    }
}
const COMMON_CREDENTIAL_ROOT_NOW: u64 = 10;
const COMMON_CREDENTIAL_ROOT_EXPIRY: u64 = 190;
const FIELD_BYTES: usize = 32;
const ATTESTATION_FIELDS: usize = 258;
const STATUS_FIELDS: usize = 192;
const LINEAGE_FIELDS: usize = 257;
const PRIVATE_CLAIM_FIELDS: usize = 354;
const PRIVATE_SESSION_FIELDS: usize = 129;
const COMMON_CREDENTIAL_ROOT_POLICY_ID: [u8; 32] = [0x77; 32];
const COMMON_CREDENTIAL_ROOT_STATUS_ROOT: [u8; 32] = [0x66; 32];
const COMMON_CREDENTIAL_ROOT_ROOT_JOIN: [u8; 32] = [0x44; 32];
const COMMON_CREDENTIAL_ROOT_ATTESTATION_JOIN: [u8; 32] = [0x55; 32];
const COMMON_CREDENTIAL_ROOT_SESSION_BINDING: [u8; 32] = [0x88; 32];
const COMMON_CREDENTIAL_ROOT_FIRST_NAME: [u8; 32] = [0x91; 32];
const COMMON_CREDENTIAL_ROOT_SECOND_NAME: [u8; 32] = [0x92; 32];
const COMMON_CREDENTIAL_ROOT_FIRST_VALUE: &[u8] = b"degree";
const COMMON_CREDENTIAL_ROOT_SECOND_VALUE: &[u8] = b"employed";

struct JoinPolicyRootFloor;

impl ZkRootStatusRollbackFloor for JoinPolicyRootFloor {
    fn admit_verified(
        &self,
        _feed_id: [u8; 32],
        _sequence: u64,
        _signing_digest: [u8; 32],
    ) -> Result<(), VerifierError> {
        Ok(())
    }
}

struct JoinPolicyIssuerFloor;

impl ZkIssuerStatusRollbackFloor for JoinPolicyIssuerFloor {
    fn admit_verified(
        &self,
        _list_key: [u8; 32],
        _issued_at: u64,
        _payload_sha256: [u8; 32],
    ) -> Result<(), VerifierError> {
        Ok(())
    }
}

// These stateless floors keep the raw-proof fixtures on the production
// validation path. Stateful rollback and equivocation behavior is covered by
// the signed-status tests below.
static JOIN_POLICY_ROOT_FLOOR: JoinPolicyRootFloor = JoinPolicyRootFloor;
static JOIN_POLICY_ISSUER_FLOOR: JoinPolicyIssuerFloor = JoinPolicyIssuerFloor;

fn common_credential_root_meta() -> JsonMap<String, JsonValue> {
    json!({
        "profile": "common_credential_root_v1_private_persona",
        "hash_strategy": "sha256",
        "claim_0_name_hash": "9191919191919191919191919191919191919191919191919191919191919191",
        "claim_0_value_b64u": "ZGVncmVl",
        "claim_1_name_hash": "9292929292929292929292929292929292929292929292929292929292929292",
        "claim_1_value_b64u": "ZW1wbG95ZWQ"
    })
    .as_object()
    .expect("fixture is a JSON object")
    .clone()
}

fn common_credential_root_session() -> SessionRecord {
    let mut session = session();
    session.binding.expiry_unix = 1_000;
    session.dcql_query.credentials[0].meta = common_credential_root_meta();
    session
}

fn common_credential_root_policy(status_root: [u8; 32]) -> ZkCommonCredentialRootVerificationPolicy<'static> {
    common_credential_root_policy_for_window(
        status_root,
        COMMON_CREDENTIAL_ROOT_NOW - 1,
        COMMON_CREDENTIAL_ROOT_NOW + 1,
        COMMON_CREDENTIAL_ROOT_NOW,
    )
}

fn common_credential_root_policy_for_window(
    status_root: [u8; 32],
    issued_unix: u64,
    expires_unix: u64,
    constructed_at_unix: u64,
) -> ZkCommonCredentialRootVerificationPolicy<'static> {
    let (snapshot, status_signer) = signed_status_snapshot(status_root, issued_unix, expires_unix);
    let mut policy = ZkCommonCredentialRootVerificationPolicy::try_from_signed_snapshot(
        ZkCommonCredentialRootTrustPolicy {
            attestation_signer: issuer_key(0xa0),
            assurance_policy_id: COMMON_CREDENTIAL_ROOT_POLICY_ID,
            credential_issuers: [issuer_key(0xc0), issuer_key(0xc2)],
            status_feed_id: [0x5a; 32],
            status: ZkRootStatusTrustPolicy {
                authority: status_signer,
                minimum_sequence: 2,
                maximum_age_seconds: 300,
            },
        },
        snapshot,
        constructed_at_unix,
    )
    .expect("test status snapshot verifies");
    // The synthetic raw-proof fixtures exercise the join policy. Separate
    // signed-list tests exercise admission of real SSI status material.
    let status = ZkVerifiedIssuerStatus {
        expectation: ZkCommonCredentialRootIssuerStatusExpectation {
            root: [0xa1; 32],
            length: 256,
            list_id: [0xa2; 32],
            url_hash: [0xa3; 32],
            purpose: ZkCommonCredentialRootIssuerStatusPurpose::Revocation,
        },
        list_key: [0_u8; 32],
        payload_sha256: [0_u8; 32],
        issued_at: COMMON_CREDENTIAL_ROOT_NOW - 1,
        next_update: COMMON_CREDENTIAL_ROOT_EXPIRY + 100,
        max_age_secs: 1_000,
    };
    policy.issuer_status = Some([status; 2]);
    policy.root_floor = Some(&JOIN_POLICY_ROOT_FLOOR);
    policy.issuer_floors = Some([&JOIN_POLICY_ISSUER_FLOOR; 2]);
    policy
}

fn signed_status_snapshot(
    status_root: [u8; 32],
    issued_unix: u64,
    expires_unix: u64,
) -> (ZkRootStatusSnapshot, ZkIssuerPublicKey) {
    signed_status_snapshot_at_sequence(status_root, issued_unix, expires_unix, 2)
}

fn signed_status_snapshot_at_sequence(
    status_root: [u8; 32],
    issued_unix: u64,
    expires_unix: u64,
    sequence: u64,
) -> (ZkRootStatusSnapshot, ZkIssuerPublicKey) {
    signed_status_snapshot_at_sequence_with_signer(
        status_root,
        issued_unix,
        expires_unix,
        sequence,
        37,
    )
}

fn signed_status_snapshot_at_sequence_with_signer(
    status_root: [u8; 32],
    issued_unix: u64,
    expires_unix: u64,
    sequence: u64,
    signer_secret_byte: u8,
) -> (ZkRootStatusSnapshot, ZkIssuerPublicKey) {
    let mut secret = zeroize::Zeroizing::new([0_u8; 32]);
    secret[31] = signer_secret_byte;
    let (compressed, _owned_secret) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&secret)
            .expect("test status authority key is valid");
    let uncompressed = reallyme_crypto::p256::decompress_public_key(&compressed)
        .expect("test status authority key decompresses");
    let mut x = [0_u8; 32];
    let mut y = [0_u8; 32];
    x.copy_from_slice(&uncompressed[1..33]);
    y.copy_from_slice(&uncompressed[33..65]);
    let status_signer = ZkIssuerPublicKey { x, y };
    let digest = ZkRootStatusSnapshot::signing_digest_for_fields(
        status_root,
        issued_unix,
        expires_unix,
        sequence,
    );
    let digest = crypto_p256::P256Sha256Digest::new(digest);
    let signature_der =
        crypto_p256::sign_p256_sha256_digest_low_s_der(secret.as_ref(), &digest)
            .expect("test status snapshot signs");
    let signature = reallyme_crypto::p256::p256_ecdsa_der_to_jose_signature(&signature_der)
        .expect("test status signature transcodes");
    let snapshot = ZkRootStatusSnapshot::try_from_parts(
        status_root,
        issued_unix,
        expires_unix,
        sequence,
        status_signer,
        signature,
    )
    .expect("test status snapshot fields are valid");
    (snapshot, status_signer)
}

struct TestIssuerStatusVerifier {
    issuer: &'static str,
    public_key: Vec<u8>,
}

impl StatusListVerifier for TestIssuerStatusVerifier {
    fn verify_status_list(
        &self,
        issuer: &str,
        alg: StatusListAlgorithm,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), CredentialStatusError> {
        if issuer != self.issuer || alg != StatusListAlgorithm::P256 {
            return Err(CredentialStatusError::InvalidSignature);
        }
        let digest = Sha256::digest(payload);
        let digest = crypto_p256::P256Sha256Digest::try_from_slice(digest.as_ref())
            .expect("SHA-256 produces a fixed-width digest");
        crypto_p256::verify_p256_sha256_digest_low_s_der(
            signature,
            &digest,
            &self.public_key,
        )
        .map_err(|_| CredentialStatusError::InvalidSignature)
    }
}

#[derive(Default)]
struct TestIssuerStatusFloor {
    seen: Mutex<TestIssuerStatusEntries>,
}

type TestIssuerStatusEntries = BTreeMap<[u8; 32], (u64, [u8; 32])>;

impl ZkIssuerStatusRollbackFloor for TestIssuerStatusFloor {
    fn admit_verified(
        &self,
        list_key: [u8; 32],
        issued_at: u64,
        payload_sha256: [u8; 32],
    ) -> Result<(), VerifierError> {
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidCredentialStatus))?;
        if let Some((previous_time, previous_digest)) = seen.get(&list_key) {
            if issued_at < *previous_time
                || (issued_at == *previous_time && payload_sha256 != *previous_digest)
            {
                return Err(VerifierError::new(
                    VerifierErrorReason::InvalidCredentialStatus,
                ));
            }
        }
        seen.insert(list_key, (issued_at, payload_sha256));
        Ok(())
    }
}

#[derive(Default)]
struct TestRootStatusFloor {
    seen: Mutex<Option<RootStatusObservation>>,
}

type RootStatusObservation = ([u8; 32], u64, [u8; 32]);

impl ZkRootStatusRollbackFloor for TestRootStatusFloor {
    fn admit_verified(
        &self,
        feed_id: [u8; 32],
        sequence: u64,
        signing_digest: [u8; 32],
    ) -> Result<(), VerifierError> {
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidRootAssuranceStatus))?;
        if let Some((previous_feed_id, previous_sequence, previous_digest)) = *seen {
            if feed_id != previous_feed_id
                || sequence < previous_sequence
                || (sequence == previous_sequence && signing_digest != previous_digest)
            {
                return Err(VerifierError::new(
                    VerifierErrorReason::InvalidRootAssuranceStatus,
                ));
            }
        }
        *seen = Some((feed_id, sequence, signing_digest));
        Ok(())
    }
}

fn signed_issuer_status_list(secret: &[u8; 32], list_id: [u8; 32], issued_at: u64) -> StatusList {
    let mut list = StatusList {
        issuer: "did:example:issuer".to_owned(),
        purpose: StatusPurpose::Revocation,
        issued_at,
        next_update: 200,
        encoded_list: vec![0_u8],
        length: 8,
        list_id: Some(list_id),
        signature: StatusListSignature {
            alg: StatusListAlgorithm::P256,
            sig_bytes: Vec::new(),
        },
    };
    let payload = status_list_signing_payload(&list).expect("valid test list payload");
    let digest = Sha256::digest(payload.as_slice());
    let digest = crypto_p256::P256Sha256Digest::try_from_slice(digest.as_ref())
        .expect("SHA-256 produces a fixed-width digest");
    list.signature.sig_bytes = crypto_p256::sign_p256_sha256_digest_low_s_der(
        secret, &digest,
    )
    .expect("test signer signs list");
    list
}

fn test_status_trust<'a>(
    list: &'a StatusList,
    url: &'a str,
    verifier: &'a TestIssuerStatusVerifier,
    floor: &'a TestIssuerStatusFloor,
) -> ZkIssuerStatusTrust<'a, 'a> {
    ZkIssuerStatusTrust {
        list,
        issuer: "did:example:issuer",
        url,
        purpose: StatusPurpose::Revocation,
        verifier,
        freshness: StatusListFreshnessPolicy { max_age_secs: 100 },
        floor,
    }
}

fn issuer_key(marker: u8) -> ZkIssuerPublicKey {
    ZkIssuerPublicKey {
        x: [marker; 32],
        y: [marker + 1; 32],
    }
}

fn common_credential_root_presentation(tamper_second_session: bool) -> PresentationValue {
    let binding =
        build_zk_presentation_binding("0123456789abcdef", "x509_san_dns:verifier.example", None);
    common_credential_root_presentation_for_binding(binding, tamper_second_session)
}

fn common_credential_root_presentation_for_binding(
    binding: reallyme_openid4vp_formats::ZkPresentationBinding,
    tamper_second_session: bool,
) -> PresentationValue {
    let stages = common_credential_root_stages(binding.clone(), tamper_second_session);
    encode_zk_presentation_value(ZkPresentation {
        type_: ZK_PRESENTATION_TYPE.to_owned(),
        profile: ZkPresentationProfile::CommonCredentialRootPrivatePersonaV1,
        proof_suite: ZkPresentationProofSuite::BarretenbergUltraHonkKeccakZkNoIpa,
        stages,
        derived_claims: Vec::new(),
        binding,
    })
    .expect("common-credential-root fixture has valid shape")
}

fn common_credential_root_stages(
    binding: reallyme_openid4vp_formats::ZkPresentationBinding,
    tamper_second_session: bool,
) -> Vec<ZkPresentationStage> {
    ZkCommonCredentialRootProofSlot::ALL
        .iter()
        .map(|slot| {
            let circuit_ref =
                ZkCommonCredentialRootV1Profile::PrivatePersona.source_ref(ZkHashStrategy::Sha256, *slot);
            ZkPresentationStage {
                stage: common_credential_root_stage_kind(*slot),
                circuit_ref: ZkPresentationCircuitRef {
                    hash_strategy: circuit_ref.hash_strategy.as_str().to_owned(),
                    family: circuit_ref.family.as_str().to_owned(),
                    stage: circuit_ref.stage.as_str().to_owned(),
                    version: circuit_ref.version,
                },
                artifact_manifest_sha256: [7_u8; 32],
                proof: vec![slot.index() + 1],
                public_inputs: common_credential_root_public_inputs(
                    *slot,
                    binding.clone(),
                    tamper_second_session,
                ),
            }
        })
        .collect()
}

#[allow(clippy::panic)]
fn common_credential_root_stage_kind(slot: ZkCommonCredentialRootProofSlot) -> ZkPresentationStageKind {
    match slot {
        ZkCommonCredentialRootProofSlot::RootAttestation => ZkPresentationStageKind::RootAttestation,
        ZkCommonCredentialRootProofSlot::RootStatus => ZkPresentationStageKind::RootStatus,
        ZkCommonCredentialRootProofSlot::Lineage0 => ZkPresentationStageKind::Lineage0,
        ZkCommonCredentialRootProofSlot::Lineage1 => ZkPresentationStageKind::Lineage1,
        ZkCommonCredentialRootProofSlot::SelectedClaim0 => ZkPresentationStageKind::SelectedClaim0,
        ZkCommonCredentialRootProofSlot::SelectedClaim1 => ZkPresentationStageKind::SelectedClaim1,
        ZkCommonCredentialRootProofSlot::Session => ZkPresentationStageKind::Session,
        ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0 => {
            ZkPresentationStageKind::IssuerCredentialStatus0
        }
        ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1 => {
            ZkPresentationStageKind::IssuerCredentialStatus1
        }
        _ => panic!("test fixture covers all current common-credential-root slots"),
    }
}

fn common_credential_root_public_inputs(
    slot: ZkCommonCredentialRootProofSlot,
    binding: reallyme_openid4vp_formats::ZkPresentationBinding,
    tamper_second_session: bool,
) -> Vec<u8> {
    match slot {
        ZkCommonCredentialRootProofSlot::RootAttestation => root_attestation_inputs(binding),
        ZkCommonCredentialRootProofSlot::RootStatus => root_status_inputs(binding),
        ZkCommonCredentialRootProofSlot::Lineage0 => lineage_inputs(binding, 0),
        ZkCommonCredentialRootProofSlot::Lineage1 => lineage_inputs(binding, 1),
        ZkCommonCredentialRootProofSlot::SelectedClaim0 => claim_inputs(binding, 0, false),
        ZkCommonCredentialRootProofSlot::SelectedClaim1 => claim_inputs(binding, 1, tamper_second_session),
        ZkCommonCredentialRootProofSlot::Session => session_inputs(binding),
        ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0 => issuer_status_inputs(binding, 0),
        ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1 => issuer_status_inputs(binding, 1),
        _ => Vec::new(),
    }
}

fn root_attestation_inputs(binding: reallyme_openid4vp_formats::ZkPresentationBinding) -> Vec<u8> {
    let mut fields = vec![0_u8; ATTESTATION_FIELDS * FIELD_BYTES];
    set_key(&mut fields, 0, issuer_key(0xa0));
    set_bytes(&mut fields, 64, &COMMON_CREDENTIAL_ROOT_POLICY_ID);
    set_u64(&mut fields, 96, COMMON_CREDENTIAL_ROOT_NOW);
    set_u64(&mut fields, 97, COMMON_CREDENTIAL_ROOT_EXPIRY);
    set_request(&mut fields, 98, binding);
    set_bytes(&mut fields, 194, &COMMON_CREDENTIAL_ROOT_ROOT_JOIN);
    set_bytes(&mut fields, 226, &COMMON_CREDENTIAL_ROOT_ATTESTATION_JOIN);
    fields
}

fn root_status_inputs(binding: reallyme_openid4vp_formats::ZkPresentationBinding) -> Vec<u8> {
    let mut fields = vec![0_u8; STATUS_FIELDS * FIELD_BYTES];
    set_request(&mut fields, 0, binding);
    set_bytes(&mut fields, 96, &COMMON_CREDENTIAL_ROOT_STATUS_ROOT);
    set_bytes(&mut fields, 128, &COMMON_CREDENTIAL_ROOT_ROOT_JOIN);
    set_bytes(&mut fields, 160, &COMMON_CREDENTIAL_ROOT_ATTESTATION_JOIN);
    fields
}

fn lineage_inputs(
    binding: reallyme_openid4vp_formats::ZkPresentationBinding,
    slot: usize,
) -> Vec<u8> {
    let mut fields = vec![0_u8; LINEAGE_FIELDS * FIELD_BYTES];
    let issuer = if slot == 0 {
        issuer_key(0xc0)
    } else {
        issuer_key(0xc2)
    };
    let credential = if slot == 0 { [0xd1; 32] } else { [0xd2; 32] };
    let subject = if slot == 0 { [0xe1; 32] } else { [0xe2; 32] };
    set_request(&mut fields, 0, binding);
    set_bytes(&mut fields, 96, &COMMON_CREDENTIAL_ROOT_ROOT_JOIN);
    set_key(&mut fields, 128, issuer);
    set_u64(&mut fields, 192, COMMON_CREDENTIAL_ROOT_EXPIRY);
    set_bytes(&mut fields, 193, &credential);
    set_bytes(&mut fields, 225, &subject);
    fields
}

fn claim_inputs(
    binding: reallyme_openid4vp_formats::ZkPresentationBinding,
    slot: usize,
    tamper_session: bool,
) -> Vec<u8> {
    let mut fields = vec![0_u8; PRIVATE_CLAIM_FIELDS * FIELD_BYTES];
    let (issuer, credential, subject, name, value) = if slot == 0 {
        (
            issuer_key(0xc0),
            [0xd1; 32],
            [0xe1; 32],
            COMMON_CREDENTIAL_ROOT_FIRST_NAME,
            COMMON_CREDENTIAL_ROOT_FIRST_VALUE,
        )
    } else {
        (
            issuer_key(0xc2),
            [0xd2; 32],
            [0xe2; 32],
            COMMON_CREDENTIAL_ROOT_SECOND_NAME,
            COMMON_CREDENTIAL_ROOT_SECOND_VALUE,
        )
    };
    set_key(&mut fields, 0, issuer);
    set_request(&mut fields, 64, binding);
    set_u64(&mut fields, 160, COMMON_CREDENTIAL_ROOT_EXPIRY);
    set_bytes(
        &mut fields,
        161,
        if tamper_session {
            &[0x99; 32]
        } else {
            &COMMON_CREDENTIAL_ROOT_SESSION_BINDING
        },
    );
    set_bytes(&mut fields, 193, &credential);
    set_bytes(&mut fields, 225, &subject);
    set_u32(
        &mut fields,
        257,
        u32::try_from(value.len()).unwrap_or_default(),
    );
    set_bytes(&mut fields, 258, value);
    set_bytes(&mut fields, 322, &name);
    fields
}

fn session_inputs(binding: reallyme_openid4vp_formats::ZkPresentationBinding) -> Vec<u8> {
    let mut fields = vec![0_u8; PRIVATE_SESSION_FIELDS * FIELD_BYTES];
    set_request(&mut fields, 0, binding);
    set_u64(&mut fields, 96, COMMON_CREDENTIAL_ROOT_EXPIRY);
    set_bytes(&mut fields, 97, &COMMON_CREDENTIAL_ROOT_SESSION_BINDING);
    fields
}

fn issuer_status_inputs(
    binding: reallyme_openid4vp_formats::ZkPresentationBinding,
    slot: usize,
) -> Vec<u8> {
    const ISSUER_STATUS_FIELDS: usize = 292;
    let mut fields = vec![0_u8; ISSUER_STATUS_FIELDS * FIELD_BYTES];
    let issuer = if slot == 0 {
        issuer_key(0xc0)
    } else {
        issuer_key(0xc2)
    };
    let credential = if slot == 0 { [0xd1; 32] } else { [0xd2; 32] };
    set_request(&mut fields, 0, binding);
    set_key(&mut fields, 96, issuer);
    set_u64(&mut fields, 160, COMMON_CREDENTIAL_ROOT_EXPIRY);
    set_bytes(&mut fields, 161, &credential);
    set_bytes(&mut fields, 193, &[0xa1; 32]);
    set_u64(&mut fields, 225, 256);
    set_bytes(&mut fields, 226, &[0xa2; 32]);
    set_bytes(&mut fields, 258, &[0xa3; 32]);
    set_bytes(&mut fields, 290, &[1]);
    set_u64(&mut fields, 291, COMMON_CREDENTIAL_ROOT_NOW);
    fields
}

fn set_request(
    fields: &mut [u8],
    first: usize,
    binding: reallyme_openid4vp_formats::ZkPresentationBinding,
) {
    set_bytes(fields, first, &binding.nonce_hash);
    set_bytes(fields, first + 32, &binding.audience_hash);
    set_bytes(
        fields,
        first + 64,
        binding
            .transaction_data_hash
            .as_ref()
            .unwrap_or(&reallyme_zk_api::ABSENT_TRANSACTION_DATA_HASH),
    );
}

fn set_key(fields: &mut [u8], first: usize, key: ZkIssuerPublicKey) {
    set_bytes(fields, first, &key.x);
    set_bytes(fields, first + 32, &key.y);
}

fn set_bytes(fields: &mut [u8], first: usize, value: &[u8]) {
    for (offset, byte) in value.iter().enumerate() {
        let index = (first + offset) * FIELD_BYTES + FIELD_BYTES - 1;
        fields[index] = *byte;
    }
}

fn set_u64(fields: &mut [u8], index: usize, value: u64) {
    let start = index * FIELD_BYTES + FIELD_BYTES - 8;
    fields[start..start + 8].copy_from_slice(&value.to_be_bytes());
}

fn set_u32(fields: &mut [u8], index: usize, value: u32) {
    let start = index * FIELD_BYTES + FIELD_BYTES - 4;
    fields[start..start + 4].copy_from_slice(&value.to_be_bytes());
}
