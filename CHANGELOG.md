# Changelog

## 0.2.1 (unreleased)

- Update COSE to 0.2.10 in the workspace and fuzz dependency locks.
- Enforce final-spec ASCII URL-safe nonce and state syntax at wallet and
  verifier boundaries while continuing to ignore state in unsigned DC API requests.
- Reject transaction data that references unknown credential queries or targets
  an SD-JWT query with cryptographic holder binding disabled, for both signed
  requests and unsigned Digital Credentials API requests.
- Reject ambiguous verifier key IDs across the complete response-encryption
  JWKS and validate every advertised content-encryption algorithm member before
  selecting the preferred supported algorithm.
- Repair EUDI coverage evidence links and require locally covered fixtures and
  upstream scenarios to resolve to executable tests. Add independent claims-path
  cases for wildcard pruning, mixed container types, and empty selections.
- Refresh the ReallyMe codec, cryptography, JOSE, and COSE dependency baseline
  and update the locked dependency graph to current security-patched releases.
- Update the release-readiness runner to the immutable commit published as
  release v0.6.9.
- Advance the reviewed OIDF conformance-suite baseline to `release-v5.3.4`,
  including the new DCQL claim-path, Request Object `typ`, credential-status,
  credential-type, and age-over-18 module coverage.
- Validate that every DCQL credential format is advertised by verifier
  `vp_formats_supported` metadata and enforce the final OpenID4VP algorithm
  capability shapes before accepting or signing a Request Object.

- Add the OpenID4VP `verifier_info` request field to the canonical protobuf,
  Rust request model, and bounded protobuf codec. Presence of an empty array
  is preserved and rejected.
- Bind multi-signed DC API `verifier_info` to the accepted signature's protected
  header, and reject the field in the shared JWS payload.
- Retain authenticated X.509 request-signer provenance for downstream
  relying-party authorization decisions.
- Ignore requester identity and attestation fields supplied by unsigned DC API
  requests.
- Add structural validation for the ETSI TS 119 472-2 registrar dataset and
  optional encoded registration certificate. Trust and current registration
  status remain separate decisions for the wallet host.
- Add production ZK bundle and common-credential-root presentation adapters, including
  request-time session binding, issuer-validity policy, authenticated status
  inputs, and durable rollback-floor interfaces.
- Retain the verifier-owned request timestamp in the session contract and
  apply endpoint-specific form-value limits to large presentation responses.
- Update the security dependency baseline and raise the public crate MSRV to
  Rust 1.99. Consume the lockstep SSI 0.5.1 release, whose `reallyme-mdoc`
  package owns the codec feature required by its data-element projection
  instead of relying on downstream feature unification, and consume the
  published `reallyme-zk-api` 0.2.1 release and its canonical
  `ZkPersonaCredentialEvidence*` Rust API without changing the established
  protobuf schema or encoded proof values.

The added `AuthorizationRequestObject` field and signer receipt API change the
Rust source API. The renamed ZK profile enum member also changes generated Rust
and ProtoJSON names. The new protobuf fields are binary-wire additive, while
their typed SDK projection requires regenerated platform bindings. These
changes therefore require the pre-1.0 compatibility boundary to advance from
`0.1` to `0.2`; they cannot be released as `0.1.2`.
