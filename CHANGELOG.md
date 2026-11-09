# Changelog

## 0.2.0 (unreleased)

- Refresh the ReallyMe codec, cryptography, JOSE, and COSE dependency baseline
  and update the locked dependency graph to current security-patched releases.
- Update the release-readiness runner to the immutable commit published as
  release v0.6.9.

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
