<div align="center">

# ReallyMe OpenID4VP

**Feature-gated Rust facade for OpenID4VP verifier and wallet infrastructure**

[![OpenID4VP 1.0 Final](https://img.shields.io/badge/OpenID4VP-1.0%20Final-0f766e)](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html)
[![HAIP 1.0 Final](https://img.shields.io/badge/HAIP-1.0%20Final-0f766e)](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)
[![MSRV](https://img.shields.io/badge/MSRV-1.96-475569)](https://github.com/reallyme/openid4vp/blob/main/Cargo.toml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/reallyme/openid4vp#license)

Identity · [SSI](https://github.com/reallyme/ssi) · [OpenID4VCI](https://github.com/reallyme/openid4vci) · **OpenID4VP** · Wallet · [ZK](https://github.com/reallyme/zk)

</div>

`reallyme-openid4vp` is the coherent Rust entry point for the focused
ReallyMe OpenID4VP crates. It re-exports verifier, wallet, DCQL, and protocol
type APIs by default, with optional features for profiles, formats, HTTP
framing, Digital Credentials API support, protobuf codecs, and runtime
operations.

The facade is deliberately thin: protocol behavior remains owned by the
focused crates, which can also be used directly. This avoids a second
implementation layer while giving applications one versioned dependency and
one place to select a complete protocol surface.

## Installation

Use the default native verifier and wallet surface:

```toml
[dependencies]
reallyme-openid4vp = "0.1"
```

Enable only the additional boundaries the application owns:

```toml
[dependencies]
reallyme-openid4vp = { version = "0.1", features = [
  "codec",
  "formats",
  "http",
  "profiles",
  "runtime",
] }
```

For WebAssembly composition, disable the default native feature explicitly:

```toml
[dependencies]
reallyme-openid4vp = { version = "0.1", default-features = false, features = [
  "wasm",
  "codec",
  "formats",
  "profiles",
  "runtime",
] }
```

## Features

| Feature | Purpose |
| --- | --- |
| `native` | Native-platform behavior; enabled by default. |
| `wasm` | `wasm32-unknown-unknown` composition without native defaults. |
| `dc-api` | Digital Credentials API and ISO/IEC 18013-7 handover support. |
| `formats` | SD-JWT VC, mdoc, and ZK presentation-format adapters. |
| `http` | Framework-neutral HTTP request and response framing. |
| `profiles` | HAIP and eIDAS-aligned presentation profiles. |
| `codec` | Canonical protobuf and ProtoJSON SDK contract plus strict domain mappings. |
| `runtime` | Transport-neutral protobuf operations and runtime adapters. |
| `jose` | JOSE-backed wallet and runtime operations; also enables `runtime`. |

The verifier, wallet, DCQL, and validated protocol types are always available
as `verifier`, `wallet`, `dcql`, and `types`. Optional crates are re-exported
under module names matching their feature.

## Boundaries

This crate composes protocol APIs; it does not own application storage,
network access, key management, trust-evidence acquisition, consent UI, or
durable wallet and verifier lifecycle. Hosts inject those capabilities through
the focused crates' typed interfaces.

Generated protobuf messages and ProtoJSON are the cross-language SDK contract.
Serde representations of Rust domain types are not a cross-language
compatibility surface. Platform packaging and combined Wasm artifacts are
owned by ReallyMe Identity rather than this crate.

Use a focused `reallyme-openid4vp-*` crate when an integration needs only one
boundary. Use this facade when a Rust application needs coordinated verifier,
wallet, profile, codec, and runtime features under one release version.

## Documentation and security

The [repository README](https://github.com/reallyme/openid4vp) describes the
architecture, crate inventory, security properties, and conformance scope.
See the [repository contract](https://github.com/reallyme/openid4vp/blob/main/contracts/repository-contract.md),
[threat model](https://github.com/reallyme/openid4vp/blob/main/docs/threat-model.md),
and [security policy](https://github.com/reallyme/openid4vp/blob/main/SECURITY.md)
before integrating security-sensitive flows.

## License

Licensed under either the
[MIT License](https://github.com/reallyme/openid4vp/blob/main/LICENSE-MIT) or the
[Apache License, Version 2.0](https://github.com/reallyme/openid4vp/blob/main/LICENSE-APACHE),
at your option.
