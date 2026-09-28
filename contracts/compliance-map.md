# OpenID4VP Compliance Map

This map ties normative requirements to repository modules, tests, and
conformance assets. All active protocol surfaces target OpenID4VP 1.0 final
wire shapes.

| Standard or profile | Scope in this repo | Primary modules | Verification assets |
| --- | --- | --- | --- |
| OpenID4VP 1.0 final | Authorization Request/Response objects, DCQL, final `vp_token` object keyed by DCQL query id, client identifier prefixes, and deny-by-default application transaction-data types | `crates/types`, `crates/dcql`, `crates/verifier`, `crates/wallet` | Unit tests in each crate; conformance harness in `conformance/`, including unknown transaction-data rejection |
| RFC 9101 JAR | Request Object signing and verifier/wallet validation policy | `crates/verifier::jar`, `crates/wallet::jar` | Claim validation tests; injected signer/verifier traits for reallyme crypto adapters |
| OpenID4VP Request Object transport | Pure wallet parsing plus HTTP `request_uri` resolution | `crates/wallet::transport`, `crates/http` | Transport classification, POST with optional `wallet_nonce`, HTTPS, and resolver tests |
| OpenID4VP holder binding | OID4VP-specific comparison of decoded proof claims to request binding | `crates/verifier::holder_binding` | Audience, nonce, and expiration tests; crypto/JWT parsing remains in `reallyme/ssi` |
| OpenID4VP Authorization Response validation | Verifier session binding and final `vp_token` shape acceptance checks | `crates/verifier::response` | State mismatch and non-empty `vp_token` tests |
| OpenID4VP Authorization Error Response | Response URI processing for wallet error callbacks and `direct_post.jwt` plain-error fallback | `crates/runtime::handle_direct_post`, `crates/runtime::handle_direct_post_jwt` | Runtime tests for accepted error responses, state mismatch, and mixed success/error rejection |
| OpenID4VP encrypted Authorization Response | `direct_post.jwt` compact JWE decryption through `reallyme-jose` and `reallyme-crypto` | `crates/runtime::JoseAuthorizationResponseJwtDecryptor` | A128GCM and ECDH-ES compact JWE runtime tests with injected host key resolvers |
| W3C Digital Credentials API response boundary | Request construction and encrypted envelope parsing are implemented; authorization through the legacy sessionless proto decode operation fails closed until a server-owned session and authenticated browser origin are supplied | `crates/dc-api`, `crates/verifier::RequestBinding`, `VerifierRuntimeService::decode_dc_api_authorization_response_proto` | Origin-binding tests and runtime negative tests for plaintext and encrypted sessionless responses |
| Protobuf-first transport | Stable Buffa-generated OpenID4VP contract with JSON only as protobuf JSON or canonical bytes for JSON-native spec fields. Compression is an outer host/package concern that composes the shared identity Brotli primitive. | `crates/proto/proto/reallyme/openid4vp/v1/openid4vp.proto`, `crates/proto`, `crates/proto-codec` | Root `vectors/`, `buf lint`, `buf generate`, generated hardening checks, and response codec tests |
| RFC 9457 Problem Details | Typed problem details mapping for verifier and wallet errors | `crates/types::problem_details` | Serialization tests; crate-level `From<...>` mappings |
| W3C Digital Credentials API Editor's Draft | `dc_api` and `dc_api.jwt` request/response modes, including Appendix A.2 unsigned origin-bound normalization and bounded JWS JSON General multi-signed Request Objects with at-least-one-valid verification | `crates/dc-api`, `crates/wallet::unsigned_dc_api_request`, `crates/wallet::multisigned_request_object` | Unsigned ignored-member tests, DC API model/protobuf round trips, mixed-validity X.509 JOSE tests, `vectors/dc-api`, and OIDF conformance harness target |
| ISO/IEC 18013-7 Annex B | OID4VP mdoc SessionTranscript handover inputs | `crates/dc-api::mdoc` | Handover digest tests and `vectors/mdoc` with delegated CBOR encoding |
| ISO/IEC 18013-5 mdoc | DeviceResponse and issuer-signed mdoc structures | `reallyme/ssi` dependency `reallyme-mdoc` | SSI mdoc tests; this repo does not reimplement CBOR structures |
| HAIP 1.0 | High Assurance Interoperability Profile presentation capabilities | `crates/profiles` | HAIP profile unit tests |
| eIDAS ARF and CIR 2024/2977-2982 | Presentation profile alignment and EUDI interoperability | `crates/profiles`, `conformance/fixtures/eudi` | EUDI reference verifier/wallet fixtures |
| OIDF conformance suite | Six supported HAIP protocol profiles for verifier and wallet roles, with exact production and stricter demo-rehearsal inventories | `.github/workflows/conformance.yml`, `conformance/oidf/profile-matrix.json`, `conformance/oidf/demo-rehearsal-overlay.json`, `conformance/scripts/run_oidf_verifier_plan.sh`, `conformance/scripts/run_oidf_wallet_plan.sh`, `crates/runtime` | Public selected-profile execution, source-drift gates, and module-result validation; composed profile selection, immutable deployment binding, retained evidence, and final pre-submission acceptance belong to `identity-conformance` |
| EWC eudi-wallet-rfcs | Interop flows for EUDI wallet community profiles | `conformance/fixtures/ewc` | Machine-readable Digital Credentials API and EUDI Wallet RFC presentation fixtures |

## Notes

- The W3C Digital Credentials API is draft-volatility-sensitive. Public doc
  comments in `crates/dc-api` call this out so downstream users do not treat
  those strings as immutable platform law.
- RFC 9101 cryptographic operations are trait boundaries here. Concrete JOSE
  signing, encryption, and signature validation should live in adapters backed
  by `reallyme-crypto`.
- mdoc CBOR and DeviceResponse structures remain in `reallyme/ssi`
  `reallyme-mdoc`; this repo only constructs the OID4VP handover inputs and
  delegates encoding.
- The active OpenID4VP proto intentionally owns only protocol DTOs. Sibling
  consumers must follow their reviewed source-lock and generation policies;
  they must not independently edit a second OpenID4VP schema.
