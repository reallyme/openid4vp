# reallyme-openid4vp-proto-codec

Mappings between generated OpenID4VP protobuf messages and Rust domain types.

The codec is strict at the boundary: missing fields, invalid enum values, and
malformed JSON payloads return typed errors.

Generated protobuf messages and the sealed `OpenId4VpProtoJson` API are the
stable SDK DTO boundary. Domain Serde models are internal protocol parsers and
must not be exposed as cross-language JSON contracts.
