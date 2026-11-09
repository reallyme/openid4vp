# reallyme-openid4vp-profiles

OpenID4VP presentation profile descriptors.

The crate exposes HAIP presentation capabilities for OpenID4VP while using the
cross-protocol profile identity owned by `reallyme-openid4vc-profiles`.

`validate_etsi_registration_request` checks the ETSI TS 119 472-2 request-body
profile, including the required registrar dataset and optional encoded WRPRC.
It does not authenticate either artifact. A wallet must separately establish
the request-signing WRPAC path, registrar or WRPRC signer trust, current
registration status, requester association, and permitted disclosure scope
before presenting a credential.
