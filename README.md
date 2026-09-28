<div align="center">

# ReallyMe OpenID4VP

**OpenID4VP infrastructure for verifiers, wallets, and EUDI ecosystems**

[![OpenID4VP 1.0 Final](https://img.shields.io/badge/OpenID4VP-1.0%20Final-0f766e)](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html)
[![HAIP 1.0 Final](https://img.shields.io/badge/HAIP-1.0%20Final-0f766e)](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)
[![MSRV](https://img.shields.io/badge/MSRV-1.96-475569)](Cargo.toml)
[![Security Policy](https://img.shields.io/badge/security-policy-0f766e)](SECURITY.md)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

Identity · [SSI](https://github.com/reallyme/ssi) · [OpenID4VCI](https://github.com/reallyme/openid4vci) · **OpenID4VP** · Wallet · [ZK](https://github.com/reallyme/zk)

</div>

`reallyme-openid4vp` provides the protocol infrastructure for presenting digital
credentials using **OpenID for Verifiable Presentations 1.0 (OpenID4VP)** and
the **OpenID4VC High Assurance Interoperability Profile (HAIP) 1.0**.

It supports both sides of the presentation exchange: verifiers that construct
presentation requests and validate presentation responses, and wallets that
validate requests, evaluate DCQL queries, select credentials, and prepare
presentations.

The protocol core is independent of HTTP frameworks, persistence, key
management, network access, and platform SDKs. Those capabilities are supplied
through explicit interfaces, keeping the protocol core portable across server,
native, and WebAssembly environments.

> **Looking for the ReallyMe SDK?** Start with ReallyMe Identity, the
> application-facing SDK for building verifiers,
> wallets, and identity-enabled applications. This repository provides the
> underlying OpenID4VP protocol implementation.

## Quick start

Application developers should normally use ReallyMe Identity. For direct DCQL
validation and wallet-side evaluation, add the standalone public crate:

```toml
[dependencies]
reallyme-openid4vp-dcql = "0.1"
serde_json = "1"
```

The parser treats the query as untrusted input and the evaluator operates over
an application-supplied credential inventory:

```rust
use reallyme_openid4vp_dcql::{
    evaluate_query, CredentialCandidate, CredentialFormat, DcqlError, DcqlQuery,
    EvaluationCredential,
};
use serde_json::{json, Map};

fn main() -> Result<(), DcqlError> {
    let query = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": {"vct_values": ["https://credentials.example/pid"]}
          }]
        }"#,
    )?;
    let candidate = CredentialCandidate {
        id: EvaluationCredential::new("wallet-credential".to_owned())?,
        format: CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned())?,
        meta: Map::from_iter([(
            "vct_values".to_owned(),
            json!(["https://credentials.example/pid"]),
        )]),
        claims: json!({"age_over_18": true}),
        cryptographic_holder_binding: true,
    };
    let _evaluation = evaluate_query(&query, &[candidate])?;
    Ok(())
}
```

## Capabilities

| Area | Support |
| --- | --- |
| Protocol | OpenID4VP 1.0 Final |
| Security profile | HAIP 1.0 Final |
| Roles | Verifier and wallet |
| Query language | DCQL |
| Response modes | `direct_post` and `direct_post.jwt` |
| Credential formats | SD-JWT VC and mdoc through ReallyMe SSI |
| Request security | JAR, `request_uri`, transaction data, client identifier prefixes, and verifier attestation |
| Digital Credentials API | Browser API and ISO/IEC 18013-7 handover |
| Platforms | Native Rust and `wasm32-unknown-unknown` |
| Interfaces | Rust APIs, protobuf operations, ProtoJSON, and optional HTTP framing |

## Architecture

This is a conceptual ownership and composition view, not a Cargo dependency
graph.

```text
                                 ReallyMe Identity
                              application-facing SDKs
                                         │
                                         ▼
┌──────────────────────┐  ┌──────────────────────────────┐
│ Host capabilities    │  │ ReallyMe OpenID4VP           │
│ network/HTTP runtime ├─►│ verifier · wallet · profiles │
│ storage · keys · UI  │  │ HTTP framing · protobuf      │
│ trust evidence       │  └──────────────┬───────────────┘
└──────────────────────┘                 │
                                         ▼
                                   ReallyMe SSI
                      credentials · status · trust primitives
```

OpenID4VP implements both the verifier and wallet sides of credential
presentation. ReallyMe Identity composes those protocol capabilities into the
application-facing SDK.

Credential-format primitives, identity envelopes, claims, status, and trust
primitives are provided by [`reallyme/ssi`](https://github.com/reallyme/ssi).
COSE and JOSE structures are provided by
[`reallyme/cose`](https://github.com/reallyme/cose) and
[`reallyme/jose`](https://github.com/reallyme/jose), while cryptographic
operations are provided by
[`reallyme/crypto`](https://github.com/reallyme/crypto). Wallet inventory,
consent, lifecycle, persistence policy, durable presentation state, and audit
policy are owned by ReallyMe Wallet.

The protocol core is transport-agnostic. Optional HTTP adapters own OpenID4VP
routing and framing; the host owns the network and HTTP runtime and injects
storage, key-use, external trust-evidence acquisition, and user-interaction
capabilities.

Generated protobuf messages and generated ProtoJSON form the stable transport
contract consumed by ReallyMe Identity. JSON-native protocol values such as
DCQL and presentation payloads remain canonical JSON bytes inside those
messages. HTTP compression and final Connect transport packaging stay outside
the message crate.

Platform packaging is provided by ReallyMe Identity. Swift, Kotlin, TypeScript,
native, and Wasm packages compose the lower-level Rust components into
application-facing artifacts rather than loading independent protocol binaries.

### Security properties

Request Object verification is network-free. Hosts resolve external metadata
and inject trusted keys, verifier-attestation evidence, and metadata-reference
evidence. Service hosts also own key resolution for encrypted responses; the
protocol engine does not acquire ambient network or keystore access.

Successful HTTP verification crosses a typed durable-store boundary and
returns only a single-use `response_code`; the legacy caller-owned proto
validation operation is retained for wire compatibility but rejects
authorization. The Digital Credentials API request boundary is available,
but response authorization is not enabled without the server-owned session
lifecycle required for authorization. Constrained mdoc queries and responses
without proven `SessionTranscript` inputs also fail closed.

ZK-enabled products compose their prover and verifier outside this repository.
The wallet passes the resulting typed envelope through
`prepare_zk_presentation`; the verifier injects a `HolderBindingVerifier`
security boundary whose implementation must verify the envelope's proof
stages, issuer trust, credential status, DCQL projection, and session binding.
Without that adapter, ZK presentations fail closed.

## Which layer should I use?

| Goal | Start here |
| --- | --- |
| Build an application with ReallyMe | Use the application-facing ReallyMe Identity SDK. |
| Own wallet state, consent, lifecycle, persistence policy, and audit policy | Use ReallyMe Wallet. |
| Evaluate DCQL in a Rust service | Use `reallyme-openid4vp-dcql`. |
| Validate or generate OpenID4VP wire documents | Use `reallyme-openid4vp-types`. |
| Integrate the canonical protobuf contract | Use `reallyme-openid4vp-proto`. |
| Integrate wallet-side request verification and response construction | Use `reallyme-openid4vp-wallet`. |
| Compose the complete Rust protocol surface | Use the feature-gated `reallyme-openid4vp` facade. |
| Integrate one focused verifier, profile, transport, codec, or runtime boundary | Use its corresponding `reallyme-openid4vp-*` crate. |

Released dependencies resolve from crates.io; a sibling checkout is not
required. Released SSI dependencies are exact-version pinned by the workspace
and release gate; the current assurance baseline is crates.io version `0.3.4`.

## Repository structure

| Path | Purpose |
| --- | --- |
| `crates/openid4vp` | Feature-gated Rust facade and SDK-facing policy surface. |
| `crates/dcql` | Standalone DCQL model, validation, and evaluation engine. |
| `crates/types` | Final request, response, metadata, transaction, and problem types. |
| `crates/verifier` | Verifier request, session, response, and injected format-verification boundary. |
| `crates/wallet` | Wallet request parsing, trust evidence, and validation boundaries. |
| `crates/dc-api` | Digital Credentials API and ISO/IEC 18013-7 handover support. |
| `crates/formats` | Presentation-format adapters for SD-JWT VC, mdoc, and ZK entries. |
| `crates/profiles` | HAIP and eIDAS-aligned presentation profiles. |
| `crates/proto`, `crates/proto-codec` | Canonical generated contracts and bounded domain mappings. |
| `crates/runtime`, `crates/http` | Transport-neutral operations and optional HTTP framing. |
| `conformance`, `formal`, `vectors` | Executable evidence, symbolic session models, and portable fixtures. |

Concrete zero-knowledge provers and verifiers are intentionally outside this
repository. Where ZK presentation integration is enabled, the workspace owns
only backend-neutral OpenID4VP envelope types; protocol services remain
independent of concrete ZK implementations.

### Package availability

The crates.io publication surface contains exactly these packages:

| Package | Purpose |
| --- | --- |
| [`reallyme-openid4vp-dcql`](https://crates.io/crates/reallyme-openid4vp-dcql) | Bounded DCQL model, validation, and wallet-side evaluation. |
| [`reallyme-openid4vp-types`](https://crates.io/crates/reallyme-openid4vp-types) | Validated OpenID4VP 1.0 wire types and protocol errors. |
| [`reallyme-openid4vp-proto`](https://crates.io/crates/reallyme-openid4vp-proto) | Canonical generated protobuf and ProtoJSON contract. |
| [`reallyme-openid4vp-dc-api`](https://crates.io/crates/reallyme-openid4vp-dc-api) | Digital Credentials API and ISO/IEC 18013-7 handover types. |
| [`reallyme-openid4vp-formats`](https://crates.io/crates/reallyme-openid4vp-formats) | Wallet presentation-format adapters and validation boundaries. |
| [`reallyme-openid4vp-wallet`](https://crates.io/crates/reallyme-openid4vp-wallet) | Wallet-side request verification and response construction. |
| [`reallyme-openid4vp-profiles`](https://crates.io/crates/reallyme-openid4vp-profiles) | Shared presentation profiles. |
| [`reallyme-openid4vp-verifier`](https://crates.io/crates/reallyme-openid4vp-verifier) | Verifier request and response validation boundary. |
| [`reallyme-openid4vp-http`](https://crates.io/crates/reallyme-openid4vp-http) | Framework-neutral HTTP transport adapter traits. |
| [`reallyme-openid4vp-proto-codec`](https://crates.io/crates/reallyme-openid4vp-proto-codec) | Strict protobuf/domain conversion boundary. |
| [`reallyme-openid4vp-runtime`](https://crates.io/crates/reallyme-openid4vp-runtime) | Runtime protobuf operations and transport adapters. |
| [`reallyme-openid4vp`](https://crates.io/crates/reallyme-openid4vp) | Feature-gated facade for coherent protocol composition. |

The conformance and fuzz packages remain repository tooling and are not
published. The
[publishing guide](docs/rust-publishing.md) documents the release process and
package policy.

## Conformance

The repository targets the OpenID4VP 1.0 final specification and the HAIP 1.0
Final Specification.
Conformance coverage includes verifier and wallet profiles across SD-JWT VC,
ISO mDL, `direct_post.jwt`, and `dc_api.jwt`.

Testing includes OIDF role adapters, reusable vectors and requirement maps,
EUDI/EWC fixtures, negative cases, property tests, coverage-instrumented fuzz
targets, and symbolic session models. This is engineering coverage, not a
claim of an OpenID Foundation certification.

The [conformance runbook](conformance/README.md) documents live-suite execution,
the pinned OIDF suite revision, and downstream orchestration boundaries. The
[formal model](formal/README.md) covers exact session binding, response replay
prevention, and repeatable Request Object retrieval.

## Documentation

| Topic | Reference |
| --- | --- |
| Stable repository and protocol commitments | [Repository contract](contracts/repository-contract.md) |
| Specification coverage and evidence | [Specification map](contracts/spec-map.md) and [compliance map](contracts/compliance-map.md) |
| Security and privacy analysis | [Threat model](docs/threat-model.md) |
| Rust publication surface | [Publishing guide](docs/rust-publishing.md) |
| Binary and Wasm composition | [Packaging policy](docs/packaging.md) |
| Platform DTO and fixture contract | [Platform binding contract](docs/platform-binding-contract.md) |

## Development

Development, release packaging, and primary CI use the pinned Rust 1.98.1
toolchain in `rust-toolchain.toml`. The twelve public crates retain an MSRV of
Rust 1.96, which is checked separately and must not be raised merely to match
the maintainer toolchain.

Run the repository gate and core workspace checks before submitting changes:

```sh
scripts/check-openid4vp-format.sh
npm exec --yes --package=github:reallyme/release-readiness#bdedc88f3f25fcc14242730d4dec6ce6a0c75531 -- \
  reallyme-release-readiness
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo check --target wasm32-unknown-unknown --no-default-features --features wasm \
  -p reallyme-openid4vp-types \
  -p reallyme-openid4vp-dc-api \
  -p reallyme-openid4vp-formats \
  -p reallyme-openid4vp-verifier \
  -p reallyme-openid4vp-wallet \
  -p reallyme-openid4vp-proto-codec \
  -p reallyme-openid4vp-runtime \
  -p reallyme-openid4vp
cargo deny check
```

These crates are Rust inputs to ReallyMe Identity's combined Wasm build. This
repository does not publish a `wasm-bindgen` API, `cdylib`, standalone Wasm
binary, or npm package.

Protobuf changes also require the generated-freshness gate. Formal model
changes require Tamarin 1.12.0 and `scripts/check-formal-models.sh`.

## Security

Follow the [security policy](SECURITY.md) when reporting a vulnerability. Do
not include credentials, presentation payloads, private keys, access tokens, or
production wallet and verifier data in reports.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

Third-party components retain their own licenses and notices.

## Copyright and Trademarks

Copyright © 2026 by ReallyMe LLC.

ReallyMe® is a registered trademark of ReallyMe LLC.
