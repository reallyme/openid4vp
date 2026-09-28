# OpenID4VP Specification Map

The machine-readable normative-source inventory is locked in
`conformance/specifications.lock`. This map records where each source is owned
and how changes are verified.

| Specification | Repository ownership | Primary implementation | Verification evidence |
| --- | --- | --- | --- |
| OpenID for Verifiable Presentations 1.0 Final | Authorization request and response models, client identifiers, response modes, transaction data, request transport, holder binding, and verifier/wallet policy | `crates/types`, `crates/verifier`, `crates/wallet`, `crates/runtime`, `crates/http` | Crate tests, `vectors/`, `conformance/requirements/openid4vp.json`, and OIDF plans |
| OpenID4VP 1.0 errata-incorporating text | Regression-review input; changes require explicit compatibility review before implementation | Same OpenID4VP ownership boundaries | `conformance/specifications.lock`, requirements, reports, and release review |
| OpenID4VC High Assurance Interoperability Profile 1.0 Final | Presentation capability profile and high-assurance policy composition | `crates/profiles`, `crates/formats`, `crates/verifier`, `crates/wallet` | Profile tests and `conformance/requirements/haip-presentation.json` |
| RFC 9101 | OpenID4VP-specific JAR claim and binding policy; cryptographic verification is delegated | `crates/verifier`, `crates/wallet` | Request Object and injected-verifier tests |
| RFC 9457 | Typed protocol problem representation and stable error mapping | `crates/types`, `crates/proto`, `crates/proto-codec`, `crates/runtime` | Serialization, mapping, and ProtoJSON tests |
| W3C Digital Credentials API Editor's Draft | Draft-scoped request and response projections, including mdoc handover integration | `crates/dc-api`, `crates/runtime` | DC API tests, `vectors/dc-api`, and conformance fixtures |
| ISO/IEC 18013-7 Annex B | OpenID4VP mdoc handover inputs | `crates/dc-api` | Handover digest tests and `vectors/mdoc` |
| ISO/IEC 18013-5 | Consumed mdoc structures; encoding and cryptographic validation are delegated to `reallyme/ssi` | `crates/formats`, `crates/dc-api` adapters | Local boundary tests plus sibling mdoc verification |

The W3C draft is intentionally tracked as volatile. Draft changes do not alter
the stable OpenID4VP protobuf or domain contract without an explicit review and
corresponding updates to the compliance map, vectors, and conformance evidence.
