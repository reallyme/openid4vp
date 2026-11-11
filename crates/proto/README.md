# reallyme-openid4vp-proto

Generated message-only Buffa protobuf bindings for ReallyMe OpenID4VP.

Generated code is committed so downstream SDKs can consume stable proto-first
interfaces without running code generation during normal builds.

The canonical message schema lives under `proto/reallyme/openid4vp/v1` so the
published crate owns its protobuf contract. Generated Rust includes ProtoJSON
support; JSON callers use the generated protobuf JSON mapping rather than a
parallel hand-written JSON DTO model.

The repository-root `vectors/` directory contains the reviewable cross-platform
contract corpus: generated ProtoJSON, malicious JSON inputs, and exact protobuf
bytes encoded as hexadecimal text. Keeping that corpus outside this crate makes
its ownership explicit and allows Rust, Swift, Kotlin, and TypeScript consumers
to share the same vectors without treating them as Rust package internals.

Transport-neutral service declarations live in `openid4vp_service.proto`.
This message-only crate provides no Connect runtime, dependency, or feature.

Regenerate bindings from the repository root with:

```sh
buf generate
node scripts/harden-generated-openid4vp-proto.mjs
cargo fmt --package reallyme-openid4vp-proto
```

## ZK artifact identities

The codec maps each `ZkPresentationStage` to either a canonical manifest digest
or a derived artifact-set identity. Protobuf keeps the manifest digest on field
3 and carries the artifact-set identity on field 6. The codec rejects missing
or conflicting identities, invalid digest lengths, and all-zero digests.
The issuer-status proof in a status-qualified claim bundle requires the
artifact-set construction.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
