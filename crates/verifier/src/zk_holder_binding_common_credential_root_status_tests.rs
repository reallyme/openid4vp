// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn common_credential_root_admits_only_signed_fresh_issuer_status_with_rollback_floor() {
    let mut secret = zeroize::Zeroizing::new([0_u8; 32]);
    secret[31] = 41;
    let (public_key, _) = reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&secret)
        .expect("test issuer key is valid");
    let verifier = TestIssuerStatusVerifier {
        issuer: "did:example:issuer",
        public_key: public_key.to_vec(),
    };
    let floor = TestIssuerStatusFloor::default();
    let root_floor = TestRootStatusFloor::default();
    let first = signed_issuer_status_list(&secret, [1; 32], 9);
    let second = signed_issuer_status_list(&secret, [2; 32], 9);
    let (snapshot, status_signer) = signed_status_snapshot(COMMON_CREDENTIAL_ROOT_STATUS_ROOT, 9, 200);
    let trust = ZkCommonCredentialRootTrustPolicy {
        attestation_signer: attestation_key(0xa0),
        assurance_policy_id: COMMON_CREDENTIAL_ROOT_POLICY_ID,
        credential_issuers: [issuer_key(0xc0), issuer_key(0xc2)],
        status_feed_id: [0x5a; 32],
        status: ZkRootStatusTrustPolicy {
            authority: status_signer,
            minimum_sequence: 2,
            maximum_age_seconds: 300,
        },
    };
    let policy = ZkCommonCredentialRootVerificationPolicy::try_from_signed_snapshot_with_issuer_status(
        trust,
        snapshot,
        &root_floor,
        [
            test_status_trust(&first, "https://issuer.example/first", &verifier, &floor),
            test_status_trust(&second, "https://issuer.example/second", &verifier, &floor),
        ],
        COMMON_CREDENTIAL_ROOT_NOW,
    )
    .expect("both issuer signatures and freshness windows verify");
    let admitted = policy.issuer_status.expect("two admitted status lists");
    assert_eq!(admitted[0].expectation.length, 8);
    assert_ne!(
        admitted[0].expectation.url_hash,
        admitted[1].expectation.url_hash
    );
    let rollback = root_floor.admit_verified([0x5a; 32], 1, [0_u8; 32]);
    assert_eq!(
        rollback.err().map(VerifierError::reason),
        Some(VerifierErrorReason::InvalidRootAssuranceStatus)
    );
    let equivocation = root_floor.admit_verified([0x5a; 32], 2, [0_u8; 32]);
    assert_eq!(
        equivocation.err().map(VerifierError::reason),
        Some(VerifierErrorReason::InvalidRootAssuranceStatus)
    );
    let (older_snapshot, _) =
        signed_status_snapshot_at_sequence(COMMON_CREDENTIAL_ROOT_STATUS_ROOT, 9, 200, 1);
    let older_trust = ZkCommonCredentialRootTrustPolicy {
        status: ZkRootStatusTrustPolicy {
            minimum_sequence: 0,
            ..trust.status
        },
        ..trust
    };
    let older_policy = ZkCommonCredentialRootVerificationPolicy::try_from_signed_snapshot_with_issuer_status(
        older_trust,
        older_snapshot,
        &root_floor,
        [
            test_status_trust(&first, "https://issuer.example/first", &verifier, &floor),
            test_status_trust(&second, "https://issuer.example/second", &verifier, &floor),
        ],
        COMMON_CREDENTIAL_ROOT_NOW,
    );
    assert_eq!(
        older_policy.err().map(VerifierError::reason),
        Some(VerifierErrorReason::InvalidRootAssuranceStatus)
    );

    let older = signed_issuer_status_list(&secret, [1; 32], 8);
    let error = super::status::verify_issuer_status(
        test_status_trust(&older, "https://issuer.example/first", &verifier, &floor),
        COMMON_CREDENTIAL_ROOT_NOW,
    )
    .err()
    .expect("older signed status list is rejected by the floor");
    assert_eq!(error.reason(), VerifierErrorReason::InvalidCredentialStatus);

    let mut forged = signed_issuer_status_list(&secret, [1; 32], 11);
    forged.encoded_list[0] ^= 1;
    let error = super::status::verify_issuer_status(
        test_status_trust(&forged, "https://issuer.example/first", &verifier, &floor),
        11,
    )
    .err()
    .expect("changed bitstring invalidates the issuer signature");
    assert_eq!(error.reason(), VerifierErrorReason::InvalidCredentialStatus);
}

#[test]
fn signed_but_noncanonical_status_bits_do_not_advance_issuer_floor() {
    let mut secret = zeroize::Zeroizing::new([0_u8; 32]);
    secret[31] = 41;
    let (public_key, _) = reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&secret)
        .expect("test issuer key is valid");
    let verifier = TestIssuerStatusVerifier {
        issuer: "did:example:issuer",
        public_key: public_key.to_vec(),
    };
    let floor = TestIssuerStatusFloor::default();
    let mut malformed = signed_issuer_status_list(&secret, [1; 32], 11);
    malformed.length = 9;
    malformed.encoded_list.push(0x80);
    let payload = status_list_signing_payload(&malformed).expect("SSI accepts the byte length");
    let digest = Sha256::digest(payload.as_slice());
    let digest = crypto_p256::P256Sha256Digest::try_from_slice(digest.as_ref())
        .expect("SHA-256 produces a fixed-width digest");
    malformed.signature.sig_bytes = crypto_p256::sign_p256_sha256_digest_low_s_der(
        secret.as_slice(),
        &digest,
    )
    .expect("issuer signs structurally valid but noncanonical tail bits");
    assert_eq!(
        super::status::verify_issuer_status(
            test_status_trust(&malformed, "https://issuer.example/first", &verifier, &floor),
            11,
        )
        .err()
        .map(VerifierError::reason),
        Some(VerifierErrorReason::InvalidCredentialStatus)
    );

    let valid = signed_issuer_status_list(&secret, [1; 32], 10);
    super::status::verify_issuer_status(
        test_status_trust(&valid, "https://issuer.example/first", &verifier, &floor),
        11,
    )
    .expect("a rejected malformed list cannot poison the durable floor");
}

#[test]
fn common_credential_root_signer_rotation_keeps_the_feed_floor() {
    let mut issuer_secret = zeroize::Zeroizing::new([0_u8; 32]);
    issuer_secret[31] = 41;
    let (issuer_key_bytes, _) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&issuer_secret)
            .expect("test issuer key is valid");
    let verifier = TestIssuerStatusVerifier {
        issuer: "did:example:issuer",
        public_key: issuer_key_bytes.to_vec(),
    };
    let issuer_floor = TestIssuerStatusFloor::default();
    let root_floor = TestRootStatusFloor::default();
    let first = signed_issuer_status_list(&issuer_secret, [1; 32], 9);
    let second = signed_issuer_status_list(&issuer_secret, [2; 32], 9);
    let admit = |sequence, signer_secret_byte| {
        let (snapshot, signer) = signed_status_snapshot_at_sequence_with_signer(
            COMMON_CREDENTIAL_ROOT_STATUS_ROOT,
            9,
            200,
            sequence,
            signer_secret_byte,
        );
        ZkCommonCredentialRootVerificationPolicy::try_from_signed_snapshot_with_issuer_status(
            ZkCommonCredentialRootTrustPolicy {
                attestation_signer: attestation_key(0xa0),
                assurance_policy_id: COMMON_CREDENTIAL_ROOT_POLICY_ID,
                credential_issuers: [issuer_key(0xc0), issuer_key(0xc2)],
                status_feed_id: [0x5a; 32],
                status: ZkRootStatusTrustPolicy {
                    authority: signer,
                    minimum_sequence: 0,
                    maximum_age_seconds: 300,
                },
            },
            snapshot,
            &root_floor,
            [
                test_status_trust(
                    &first,
                    "https://issuer.example/first",
                    &verifier,
                    &issuer_floor,
                ),
                test_status_trust(
                    &second,
                    "https://issuer.example/second",
                    &verifier,
                    &issuer_floor,
                ),
            ],
            COMMON_CREDENTIAL_ROOT_NOW,
        )
    };
    assert!(admit(2, 37).is_ok());
    assert_eq!(
        admit(1, 38).err().map(VerifierError::reason),
        Some(VerifierErrorReason::InvalidRootAssuranceStatus)
    );
    assert!(admit(3, 38).is_ok());
}

#[test]
fn retained_common_credential_root_policy_rejects_newer_status_observations() {
    let mut secret = zeroize::Zeroizing::new([0_u8; 32]);
    secret[31] = 41;
    let (public_key, _) = reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&secret)
        .expect("test issuer key is valid");
    let verifier = TestIssuerStatusVerifier {
        issuer: "did:example:issuer",
        public_key: public_key.to_vec(),
    };
    let issuer_floor = TestIssuerStatusFloor::default();
    let root_floor = TestRootStatusFloor::default();
    let first = signed_issuer_status_list(&secret, [1; 32], 9);
    let second = signed_issuer_status_list(&secret, [2; 32], 9);
    let (snapshot, status_signer) = signed_status_snapshot(COMMON_CREDENTIAL_ROOT_STATUS_ROOT, 9, 200);
    let trust = ZkCommonCredentialRootTrustPolicy {
        attestation_signer: attestation_key(0xa0),
        assurance_policy_id: COMMON_CREDENTIAL_ROOT_POLICY_ID,
        credential_issuers: [issuer_key(0xc0), issuer_key(0xc2)],
        status_feed_id: [0x5a; 32],
        status: ZkRootStatusTrustPolicy {
            authority: status_signer,
            minimum_sequence: 2,
            maximum_age_seconds: 300,
        },
    };
    let old_policy = ZkCommonCredentialRootVerificationPolicy::try_from_signed_snapshot_with_issuer_status(
        trust,
        snapshot,
        &root_floor,
        [
            test_status_trust(
                &first,
                "https://issuer.example/first",
                &verifier,
                &issuer_floor,
            ),
            test_status_trust(
                &second,
                "https://issuer.example/second",
                &verifier,
                &issuer_floor,
            ),
        ],
        COMMON_CREDENTIAL_ROOT_NOW,
    )
    .expect("old policy initially admits authenticated status");
    assert!(old_policy
        .issuer_status_expectations(COMMON_CREDENTIAL_ROOT_NOW)
        .is_ok());

    let newer_first = signed_issuer_status_list(&secret, [1; 32], 11);
    super::status::verify_issuer_status(
        test_status_trust(
            &newer_first,
            "https://issuer.example/first",
            &verifier,
            &issuer_floor,
        ),
        11,
    )
    .expect("newer signed issuer list advances the durable floor");
    let rollback = old_policy.issuer_status_expectations(11);
    assert_eq!(
        rollback.err().map(VerifierError::reason),
        Some(VerifierErrorReason::InvalidCredentialStatus)
    );

    root_floor
        .admit_verified([0x5a; 32], 3, [9_u8; 32])
        .expect("newer authenticated root advances the durable floor");
    let rollback = old_policy.issuer_status_expectations(11);
    assert_eq!(
        rollback.err().map(VerifierError::reason),
        Some(VerifierErrorReason::InvalidRootAssuranceStatus)
    );
}

#[test]
fn common_credential_root_status_snapshot_rejects_tampering_wrong_authority_and_rollback() {
    let (snapshot, signer) = signed_status_snapshot(COMMON_CREDENTIAL_ROOT_STATUS_ROOT, 9, 20);
    let policy = |snapshot, pinned_signer, floor, now| {
        ZkCommonCredentialRootVerificationPolicy::try_from_signed_snapshot(
            ZkCommonCredentialRootTrustPolicy {
                attestation_signer: attestation_key(0xa0),
                assurance_policy_id: COMMON_CREDENTIAL_ROOT_POLICY_ID,
                credential_issuers: [issuer_key(0xc0), issuer_key(0xc2)],
                status_feed_id: [0x5a; 32],
                status: ZkRootStatusTrustPolicy {
                    authority: pinned_signer,
                    minimum_sequence: floor,
                    maximum_age_seconds: 10,
                },
            },
            snapshot,
            now,
        )
    };
    let mut tampered_signature = *snapshot.signature();
    tampered_signature[0] ^= 1;
    let tampered = ZkRootStatusSnapshot::try_from_parts(
        snapshot.status_root(),
        snapshot.issued_unix(),
        snapshot.expires_unix(),
        snapshot.sequence(),
        snapshot.signer(),
        tampered_signature,
    )
    .expect("tampered signature retains valid shape");
    for outcome in [
        policy(tampered, signer, 2, 10),
        policy(snapshot, status_authority_key(0xc0), 2, 10),
        policy(snapshot, signer, 3, 10),
        policy(snapshot, signer, 2, 20),
        policy(snapshot, signer, 2, 8),
    ] {
        assert_eq!(
            outcome
                .expect_err("untrusted root status must fail")
                .reason(),
            VerifierErrorReason::InvalidRootAssuranceStatus
        );
    }
}
