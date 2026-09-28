# reallyme-openid4vp-runtime

Framework-neutral OpenID4VP HTTP handlers and protobuf operation handlers.

Hosts inject signing, decryption, storage, clocks, and holder-binding
verification. The runtime routes protocol endpoints without owning app state
or network policy. Successful direct-post processing validates before atomic
session consumption, persists the typed verified response through
`VerifiedAuthorizationResponseStore`, generates a 256-bit response code with
the operating-system CSPRNG, and embeds that single-use code in the returned
`redirect_uri` fragment as required by OpenID4VP.

Validation intentionally happens before the atomic consume step so malformed
or unauthenticated traffic cannot burn a legitimate session. Hosts MUST apply
per-session and per-source request-rate limits at the HTTP edge: an attacker
who knows a response URI can otherwise submit unlimited bounded but
computationally expensive invalid presentations. Authorization error responses
are acknowledged without consuming or redirecting the session because `state`
is correlation data present in the retrievable Request Object, not an
authentication secret.

`VerifierRuntimeService` accepts generated protobuf operation requests and
returns generated protobuf responses. Operations that cannot supply a
server-owned session, trusted clock, authenticated browser origin, and durable
result store fail closed. In particular, the legacy stateless authorization
validation and DC API response-decoding operations cannot authorize a result.

The reviewed HTTP ingress exceptions are protocol transports, not SDK DTOs:
`direct_post` and `direct_post.jwt` use bounded form decoding, compact JWE is
validated before injected JOSE decryption, hosted Request Objects use their
registered media type, and the OIDF launch endpoint uses a bounded,
deny-unknown-fields JSON model only for conformance-driver integration.

Certification hosts attach a `VerifierEvidenceContext` to each planned OIDF
launch. The launch store receives that profile/module identity in the same
atomic record as the single-use verifier session and repeatable hosted Request
Object. Runtime observations use the resulting private lookup keys, so a host
cannot accidentally detach a verifier decision from the exact suite module
that exercised it.
