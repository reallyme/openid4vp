# Changelog

## 0.3.1 (unreleased)

- Upgrade the registry ZK API dependency to 0.3.2.
- Upgrade the lockstep SSI dependency cohort to 0.6.2 and refresh the main and
  fuzz lockfiles, dependency-policy checks, and release package versions.

## 0.3.0

- Enforce final-spec nonce and state syntax, transaction-data query binding,
  verifier key-ID uniqueness, and complete encryption-capability validation.
- Validate DCQL format advertisements and the final-spec algorithm capability
  shapes before accepting or signing Request Objects.
- Add the `verifier_info` request field with strict empty-array handling and
  per-signature binding for multi-signed requests. Retain authenticated X.509
  signer provenance and ignore unauthenticated requester identity fields in
  unsigned Digital Credentials API requests.
- Add structural ETSI TS 119 472-2 registration checks. Signature, registration
  status, requester association, and disclosure authorization remain host
  responsibilities.
- Add ZK bundle and common-credential-root presentation adapters with request
  binding, issuer-validity policy, authenticated status, and rollback-floor
  interfaces. The adapters use ZK API 0.3.0.
- Retain verifier-owned request timestamps and apply endpoint-specific form
  limits to presentation responses.
- Update the credential and cryptographic dependency baseline, including SSI
  0.6.1 and COSE 0.2.10. Raise the minimum supported Rust version to 1.99.
- Update OIDF compatibility coverage to the pinned `release-v5.3.4` suite and
  strengthen executable EUDI coverage and claims-path regression cases.

The 0.3 release updates the Rust ZK adapter APIs and the JSON presentation
format. Each proof stage identifies its artifact digest by construction,
using the `artifact_identity` member in the JSON presentation. Protobuf
retains the original manifest digest, proof, and public input tags and adds a
separate artifact-set digest field. Regenerate platform bindings from the 0.3
schema before using artifact-set presentations.
