# reallyme-openid4vp-types

Native Rust validation models for OpenID4VP requests, responses, metadata,
client identifiers, problem details, and transaction data.

Serde implementations support bounded parsing of OpenID4VP's JSON-native
protocol fields. They are not the stable SDK DTO contract. SDK and
cross-language callers use the generated `reallyme-openid4vp-proto` messages
and their generated ProtoJSON mapping, with explicit validation through
`reallyme-openid4vp-proto-codec`.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
