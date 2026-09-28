# Platform Binding Contract

This repository owns the versioned `reallyme.openid4vp.v1` protobuf schema and
the language-neutral fixtures used to verify generated platform bindings. The
schema under `crates/proto/proto` is the only SDK DTO contract.
Swift, Kotlin/Android, and TypeScript/WASM packages must generate from that
schema and must not maintain parallel hand-written request or response models.

The repository packages the language-neutral contract corpus under the root
`vectors/` directory:

- `vectors/protojson` contains generated ProtoJSON examples and
  fail-closed malicious inputs.
- `vectors/protobuf` contains exact protobuf bytes represented as
  reviewable lowercase hexadecimal text.

Rust tests decode each ProtoJSON fixture into a generated message, assert its
exact protobuf encoding, decode those wire bytes with bounded Buffa options,
and compare the generated messages. Platform package tests in
`reallyme/identity` must consume the same pairs and prove equivalent
binary/ProtoJSON behavior before release.

Service declarations remain alongside the messages in
`openid4vp_service.proto`. They define transport operations, not a second DTO
model. Connect client generation and SDK facades may wrap the generated
messages, but cannot redefine their fields or JSON representation.
