# OpenID4VP Threat Model

Scope: OpenID4VP verifier and wallet protocol code in this repository, including
DCQL, Request Object transport, response-mode handling, DC API helpers, ZK
presentation envelopes, protobuf contracts, and framework-neutral HTTP
runtime adapters.

Out of scope: credential-format cryptography owned by `reallyme/ssi`,
primitive cryptography owned by `reallyme/crypto`, concrete service storage,
network ingress, TLS termination, and platform package signing.

## Trust Boundaries

| Boundary | Trusted side | Untrusted side | Controls |
| --- | --- | --- | --- |
| Authorization Request input | Wallet parser and verifier adapters | Browser URL, QR content, app link, request URI contents | `crates/wallet/src/transport.rs`, request size limits, signed Request Object policy |
| Request URI retrieval | Wallet HTTP adapter | Verifier-controlled URL and HTTP body | HTTPS-only policy, media-type checks, max JWT size, `wallet_nonce` rules |
| Verifier response endpoint | Runtime verifier host | Wallet POST body and user agent | Method/content-type checks, body limits, form duplicate rejection, state/session binding |
| Encrypted response decryptor | Injected JOSE adapter | Compact JWE string | Compact JWE preflight, fail-closed missing decryptor, upstream `reallyme-jose` header policy |
| Presentation validation | Verifier protocol core | VP Token entries and presentations | DCQL-keyed response model, non-empty checks, holder-binding validation, typed ZK envelope and session-binding validation |
| ZK verifier adapter | Injected `HolderBindingVerifier` implementation | Typed ZK presentation envelope | Exact circuit and artifact policy, stage-specific proof verification, issuer trust, status, DCQL projection, and authenticated nonce/audience/transaction binding |
| Protobuf operation boundary | Generated Buffa messages | SDK or transport adapters | Bounded protobuf/ProtoJSON decode, strict embedded JSON, typed mappings, problem-details fields for protocol failures |

## Primary Threats

| Threat | Impact | Mitigation |
| --- | --- | --- |
| Presentation replay to a different verifier | Credential replay, account takeover | Holder-binding audience and nonce checks in `crates/verifier/src/holder_binding.rs`; ZK envelope binding checks in `crates/formats/src/zk_presentation.rs` |
| Session fixation through `direct_post` | Attacker completes a verifier session started elsewhere | State and response validation before atomic session consumption; typed durable result storage; CSPRNG, single-use response-code continuation |
| Mixed success and error response body | Parser confusion or forged callback state | `crates/runtime/src/handle_authorization_error_response.rs` rejects bodies carrying both `error` and `vp_token` or `response` |
| Duplicate form or JSON fields | Ambiguous parser interpretation | Form parsing rejects duplicate sensitive fields; the proto codec rejects duplicate object keys in embedded JSON |
| Oversized callback body or Request Object | Memory pressure and parser DoS | Runtime direct-post body limit; wallet/http Request Object size limits |
| Request URI downgrade or exfiltration | Wallet retrieves unsigned or attacker-controlled request | HTTPS default in `crates/http`; signed-request policy in `crates/wallet`; final client-id prefix binding |
| Unsupported or ABI-ambiguous ZK presentation accepted | Invalid derived-claim proof | Core validates the canonical four-stage envelope and active-session binding; the injected verifier must enforce exact circuit artifacts, issuer trust, status, and DCQL statement projection before returning claims |
| Host-supplied mdoc transcript is unrelated to the request | Device authentication binds attacker-chosen bytes | mdoc verification requires a provider to canonically rebuild and validate the session transcript; the retained-bytes adapter cannot authorize a presentation |
| Missing encrypted-response decryptor | Unencrypted or unchecked sensitive callback | `direct_post.jwt` maps missing decryptor to unsupported feature; encrypted payload is never skipped |
| PII leakage through error strings | Logs or telemetry expose credentials or claims | Error enums carry stable reasons only; RFC 9457 problems omit raw request/credential data |
| Multiple Rust binaries in one app | Handle/state mismatch across FFI/wasm layers | `docs/packaging.md` Russian-doll rule; root facade intended for `reallyme/identity` aggregation |

## Privacy Review

OpenID4VP responses can contain highly sensitive presentations. Runtime code
therefore treats raw bodies, `vp_token`, compact JWE values, and decrypted
payloads as untrusted sensitive material. The repository does not log or format
these values into errors. Problem Details expose only stable problem kinds and
transport-owned instance IDs.

The DCQL engine supports data minimization by selecting credentials and claims
against the verifier query. ZK presentation envelopes add a derivation path so
wallets can prove statements without disclosing underlying claims, while keeping
circuit semantics and proof backends in the composed verifier instead of this crate.

Digital Credentials API support is intentionally isolated in `crates/dc-api`
because the W3C draft is volatile. Public comments warn consumers not to treat
draft string constants as permanent platform law.

## Operational Requirements

- Terminate TLS before exposing any verifier response endpoint.
- Store verifier sessions server-side with short expirations, non-consuming
  lookup, and atomic take semantics; invalid responses must leave them usable.
- Use high-entropy `state`, `nonce`, `wallet_nonce`, and any response-code
  continuation secret.
- Never log request bodies, VP Tokens, compact JWEs, decrypted response
  payloads, transaction data, or holder-binding claims.
- Inject production JOSE and holder-binding backends explicitly; ZK
  presentations and sessionless DC API responses fail closed when their
  required adapter or authorization context is absent.
- Run OIDF conformance and interop fixture suites before launch and preserve
  machine-readable result artifacts.

## Host-owned controls

This protocol library does not provide a deployable verifier process or a
durable replay store. Production hosts must supply those components, bind JWE
key selection to the exact session, implement atomic session consumption and
verified-result/response-code storage, and test single-use redemption.
The repository's parser and protocol tests do not replace deployment-specific
abuse, storage, network, and recovery testing.
