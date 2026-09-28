# reallyme-openid4vp-verifier

Verifier-side OpenID4VP request construction and authorization-response
validation.

The crate is network-free. Signing, holder-binding verification, clock access,
and session storage are injected through explicit traits. A composed ZK
adapter uses the same `HolderBindingVerifier` boundary and must enforce proof
verification, issuer trust, credential status, DCQL statement projection, and
binding to the active request before returning claims. Without such an adapter,
ZK presentations fail closed. mdoc verification additionally requires a
transcript provider that canonically rebuilds and proves the active request
binding; retained bytes alone are rejected.
