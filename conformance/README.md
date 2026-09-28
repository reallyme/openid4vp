# Conformance Harness

This directory contains the OpenID Foundation conformance-suite harness and
interop fixtures for OpenID4VP 1.0 final.

## Structure

- `specifications.lock`: normative and tracked draft source inventory.
- `requirements/`: machine-readable requirement-to-code/test mappings.
- `oidf/`: implementation-independent OIDF runner configuration and exclusions.
  `oidf/profile-matrix.json` is the fail-closed public inventory of protocol
  profiles supported by this repository for the exact suite checkout. Product
  certification selection, deployment identity, retained evidence, and final
  submission gates belong to downstream `identity-conformance` orchestration.
- `eudi/`: EUDI reference-source pins, upstream test map, test cases, and
  exclusions.
- `fixtures/`: suite-specific deterministic interoperability fixtures, split by
  protocol area.
- `src/`, `tests/`: the workspace conformance crate. It executes the reusable
  protocol vectors in the repository-root `vectors/` directory against the real
  parsers and validates that requirement manifests keep implementation and test
  anchors current.

Generated runner output is transient and defaults to the ignored
`target/conformance-results/` directory. Reviewed result summaries,
cross-repository provenance, release-readiness conclusions, and retained
interoperability evidence belong to downstream `identity-conformance`, not to
this protocol implementation repository.

The independently dispatched **OIDF Conformance** GitHub Actions workflow checks out
`https://gitlab.com/openid/conformance-suite` and prepares both OID4VP verifier
and wallet test-plan execution. Transport-neutral generated operations are
available through `crates/runtime`; browser-facing request-object and
`direct_post` endpoints are exposed by the framework-neutral HTTP facade so
service hosts can mount them without duplicating protocol checks.

The harness writes one machine-readable JSON result for the selected protocol profile
under `target/conformance-results/`. The reviewed matrix covers both verifier formats
with `direct_post.jwt` and both wallet formats with `direct_post.jwt` and
`dc_api.jwt` (six supported profiles total). Set `OIDF_PROFILE_ID` to exactly
one profile from `oidf/profile-matrix.json`. By default local execution records
a pending result for that profile. Set
`OIDF_RUNNER_MODE=execute` only when both the OIDF conformance-suite server and
the ReallyMe verifier flow driver are running; configuration failures are
emitted as `failed` results with stable non-PII reason codes.

Execute mode is a certification evidence boundary. Unless
`CONFORMANCE_DEV_MODE=true` is explicitly selected for a local rehearsal, both
OIDF bearer tokens are required, TLS verification must remain enabled, and the
suite, mTLS, product, launch, evidence, and harness endpoints must use HTTPS.
All configured endpoints are parsed as bounded canonical URLs and reject
userinfo, fragments, query-bearing base URLs, ambiguous authorities, and
invalid ports. Suite-provided authorization and Browser API submission URLs
also reject HTTP unless development mode was explicitly selected.
Development-mode outputs are never formal certification evidence.

The verifier plan needs an active flow driver because the OIDF suite plays the
wallet role. `conformance/scripts/drive_oidf_verifier_flow.py` polls
`CONFORMANCE_SERVER` for WAITING verifier modules, reads only the exposed
`authorization_endpoint`, and triggers one of two paths:

- Preferred launch path: set `OIDF_VERIFIER_LAUNCH_ENDPOINT` to a
  conformance-only endpoint on the ReallyMe verifier host. The driver POSTs the
  authorization endpoint and module id so the host can create a fresh verifier
  session and host a fresh Request Object. The endpoint may return `204 No
  Content` after starting the flow itself, but the preferred adapter shape is a
  JSON object with `authorization_endpoint`, optional `method`, and
  `parameters: [{ "name": "client_id", "value": "..." }, ...]`; the driver
  then submits those parameters to the OIDF mock wallet.
- Direct smoke path: set `OIDF_CLIENT_ID` plus `OIDF_REQUEST_URI`, or set
  `OIDF_REQUEST_OBJECT_JWT`, and the driver calls the OIDF authorization
  endpoint itself. This is useful for local checks but is not enough for a full
  multi-module certification run because sessions should be unique per module.

Set `OIDF_VERIFIER_FLOW_DRIVER_MODE=execute` to have
`run_oidf_verifier_plan.sh` start the sidecar alongside the OIDF runner. A live
verifier-role run needs these environment variables:

```sh
export CONFORMANCE_SUITE_DIR=/path/to/conformance-suite
export CONFORMANCE_SERVER=https://suite.example.test
export CONFORMANCE_SERVER_MTLS=https://mtls.suite.example.test
export CONFORMANCE_TOKEN=replace-with-suite-access-token
export CONFORMANCE_API_TOKEN="${CONFORMANCE_TOKEN}"
export EXAMPLE_VERIFIER_BASE_URL=https://verifier.example.test
export OIDF_VERIFIER_LAUNCH_ENDPOINT=https://verifier.example.test/oidf/launch
export OIDF_VERIFIER_EVIDENCE_ENDPOINT=https://verifier.example.test/oidf/evidence
# Optional only when /healthz cannot be derived from the launch endpoint.
export OIDF_VERIFIER_HEALTH_ENDPOINT=https://verifier.example.test/healthz
export OIDF_VERIFIER_LAUNCH_TOKEN=replace-with-dedicated-launch-token
export OIDF_VERIFIER_EVIDENCE_TOKEN=replace-with-dedicated-evidence-token
export OIDF_RUNNER_MODE=execute
export OIDF_VERIFIER_FLOW_DRIVER_MODE=execute
conformance/scripts/run_oidf_verifier_plan.sh
```

The health endpoint must return JSON containing
`"composed_flow_driver_enabled": true`. Execute mode refuses a verifier host
that cannot prove its product-composed flow is active, and it fails if the
sidecar exits before any profile result is accepted.
The production Identity verifier host requires separate launch and evidence
bearer tokens of at least 32 non-whitespace bytes. Keep the matching secrets in
its owner-only configuration file; do not reuse the OIDF suite API token.
The runner replaces the suite's shared example alias with a fresh,
collision-resistant alias for every execute-mode run. Set
`OIDF_VERIFIER_ALIAS` only when an operator needs a stable deployment-specific
alias; the shared `oidf-vp-test-wallet` example is deliberately rejected. The
rendered private runtime configuration is retained with the run results. The
runner starts a profile-bound sidecar for each matrix entry. The sidecar
considers only newly created instances of that exact plan and alias, sends the
immutable plan, profile, module id, and module name with every launch request,
and exits only after its trigger count exactly matches that profile's module
inventory.
This binding is required because suite module names such as `happy-flow` occur
in both the SD-JWT and mdoc profiles and are not sufficient to select DCQL
policy on their own.

After the suite validates a profile, the runner asks the deployed verifier's
evidence endpoint for one bounded JSON record per exact module instance. The
record is accepted only when its plan, profile, module id, module name,
accepted/rejected decision, and stable non-PII observations match the reviewed
matrix. The fetch-twice module requires two Request Object retrieval
observations; negative response modules require a rejected authorization
response observation. Records and a SHA-256 index are written owner-only under
`target/conformance-results/implementation-evidence/`. Missing, stale, foreign,
oversized, duplicate-key, or free-text records fail the profile. The index
retains the suite's exact plan-instance identifier, and every result in the
profile export must carry that same identifier.

The driver writes its own machine-readable status to
`target/conformance-results/oidf-verifier-flow-driver.json` and intentionally avoids
printing Request Objects, request URIs, bearer tokens, or wallet response data.

The wallet certification profiles use `conformance/scripts/run_oidf_wallet_plan.sh`. Set
`OIDF_WALLET_RUNNER_MODE=execute` only when a conformance wallet harness is
available through `OIDF_WALLET_HARNESS_ENDPOINT`. `reallyme/wallet` provides
`conformance/scripts/serve_oidf_wallet_harness.sh`, which serves
`/oidf/wallet/authorize` and validates launch transport through
`reallyme-openid4vp-wallet`. A passing OIDF wallet-role run needs a composed
ReallyMe Identity or an application harness for the same endpoint shape, because the
flow must resolve `request_uri`, verify compact and JWS JSON General Request
Objects, accept a multisigned request when at least one signature is valid,
select credentials, build a DCQL-keyed `vp_token`, encrypt `direct_post.jwt` or
`dc_api.jwt`, and return the response to the suite. This repository owns the
OpenID4VP request/response/proto/DCQL validation boundary, not wallet storage,
consent UI, credential inventory, or the composed presentation driver.

Set `OIDF_WALLET_FLOW_DRIVER_MODE=execute` to have
`run_oidf_wallet_plan.sh` start `conformance/scripts/drive_oidf_wallet_flow.py`
beside the OIDF runner. The driver polls `CONFORMANCE_SERVER` for WAITING
wallet modules. For redirect flows it forwards the suite-published authorization
request parameters. For Digital Credentials API flows it forwards the exact
structured `browser_api_request` and the suite `submit_url` as JSON. The wallet
harness method defaults to `POST`; a `GET` harness is rejected for Browser API
flows because it cannot preserve the structured request. Set
`OIDF_WALLET_HARNESS_TOKEN` to a dedicated bearer token containing 32 to 4096
ASCII graphic bytes. Keep the matching secret in the composed host's owner-only
configuration and do not reuse the OIDF suite API token. The
default wallet-plan configs are repo-owned, format-specific DCQL/HAIP templates
under `conformance/oidf/configs/`. The runner binds every matrix profile to
either the SD-JWT VC or mdoc mDL template and rejects a template whose DCQL
format or credential type does not match that profile. Both templates keep
Presentation Exchange out of OpenID4VP 1.0 final runs and supply the HAIP
credential and status-list trust anchors required by the pinned suite. The
SD-JWT template uses the VCI issuer root; the mdoc template uses the IACA root.
Those credential roots are deliberately independent of the VP signing CA used
to authenticate Request Objects at the composed wallet host.
Before either pending or execute mode starts, the harness expands those templates
with only the reviewed key files from the exact suite checkout, rejects
duplicate JSON keys and unsafe or unresolved placeholders, and verifies that
the primary signer, independent secondary signer, credential signer, and both
trust anchors exactly match the pinned suite material.
Expanded runtime configurations are created in an owner-only temporary
directory, removed when the runner exits, and excluded from uploaded evidence;
private test signing material must never be retained in certification exports.

A live wallet-role run needs these environment variables:

```sh
export CONFORMANCE_SUITE_DIR=/path/to/conformance-suite
export CONFORMANCE_SERVER=https://suite.example.test
export CONFORMANCE_SERVER_MTLS=https://mtls.suite.example.test
export CONFORMANCE_TOKEN=replace-with-suite-access-token
export CONFORMANCE_API_TOKEN="${CONFORMANCE_TOKEN}"
export OIDF_WALLET_HARNESS_ENDPOINT=https://wallet.example.test/oidf/wallet/authorize
# Optional only when /healthz cannot be derived from the launch endpoint.
export OIDF_WALLET_HARNESS_HEALTH_ENDPOINT=https://wallet.example.test/healthz
# Optional only when /oidf/wallet/error cannot be derived from the launch endpoint.
export OIDF_WALLET_ERROR_SCREEN_ENDPOINT=https://wallet.example.test/oidf/wallet/error
export OIDF_WALLET_HARNESS_TOKEN=replace-with-dedicated-wallet-harness-token
export OIDF_WALLET_HARNESS_METHOD=POST
# Absolute path to the audited Chromium-family browser used for evidence capture.
export OIDF_WALLET_SCREENSHOT_BROWSER=/path/to/chrome
export OIDF_WALLET_RUNNER_MODE=execute
export OIDF_WALLET_FLOW_DRIVER_MODE=execute
conformance/scripts/run_oidf_wallet_plan.sh
```

The wallet health endpoint must return JSON containing
`"composed_flow_driver_enabled": true`. This is a hard boundary between the
transport-only Wallet example and the Identity-composed product harness.
Negative modules additionally use the authenticated wallet error-screen endpoint.
The sidecar captures that actual, non-sensitive error view with the configured
browser and uploads it to the exact screenshot placeholder opened by the suite.
For Digital Credentials API negatives, the sidecar first submits the browser
promise rejection produced by the wallet failure, so the suite—not the sidecar—
decides that screenshot evidence is required. A missing typed wallet rejection,
error view, browser, placeholder, or upload fails the run.
Execute mode starts a separate, profile-bound sidecar for every plan and
accepts only its terminal `passed` record with the exact matrix module count.
Each record is retained as
`target/conformance-results/oidf-wallet-flow-driver-<profile-id>.json`; its exact
suite plan-instance identifier must also match every result in that profile
export.
The runner replaces the shared wallet-plan example alias with a fresh,
collision-resistant value. `OIDF_WALLET_ALIAS` may supply a stable
deployment-specific alias, but the shared `oidf-vp-test-verifier` example is
rejected so concurrent certification runs cannot select each other's plan.
Negative-test modules may return the harness's bounded
HTTP 400 rejection, while positive modules must complete the harness call; all
modules remain bound to the newly created plan instance and counted before an
export is accepted.

The authoritative composed-product OIDF selection and certification evidence
live in downstream `identity-conformance` orchestration. This repository retains
its generic adapter configuration, a reviewed public profile matrix for suite commit
`440eec8bac7b12b7389d7ca9cbc459b53507a443` (the official
`release-v5.3.1` tag), and transient execute-mode outputs.
CI builds the exact pinned checkout, discovers its OpenID4VP sources, and runs
`verify_oidf_certification_target.py`; any module drift blocks execution. The
official release tag and the public profile matrix are the protocol-profile
contract. CI does not mix unreleased demo-branch modules into release evidence.
The result validator requires the complete expected module multiset, exact
matrix variant binding, and `FINISHED` status for every profile. It accepts `REVIEW` only for
modules explicitly classified by the matrix from the pinned suite source:
positive verifier flows that require a verification screenshot, and wallet
negative flows whose specification-defined outcome may require an error-screen
screenshot. All other modules must be `PASSED`; the validator never promotes or
rewrites a suite result. A product release may claim external conformance only
after downstream orchestration has selected and executed its complete profile
set and every OIDF review item has been resolved through the official
publication process.
For formal certification, each passing plan must then be published with the
suite UI's **Publish for certification** action and retained as a separate OIDF
ZIP. Verifier profiles also require per-test implementation evidence showing
the behavior detected by the deployed verifier, particularly for negative
tests. The immutable deployment name/version and protocol endpoint must stay
bound to those artifacts; a different endpoint is a different certification
deployment.
The complete two-verifier/four-wallet self-assessment, immutable deployment
binding, evidence index, and final pre-submission gate are run by
`identity-conformance`. The public workflow intentionally runs only one selected
protocol profile and does not claim product certification evidence.
It remains a separately dispatched protocol-evidence workflow and is not a
prerequisite of crates.io package publication.

OIDF's available formal route is called self-certification and culminates in a
legally binding Declaration of Conformance. It is distinct from a local
self-test. OIDF currently describes independent certification by authorized
auditors/testing service providers as a developing route. Payment or
fee-waiver requests, submission, and signature are human-controlled actions
and are never performed by CI. Follow the OpenID Foundation's published
certification instructions for the current submission process.

The composed pre-submission sequence, including exact profile selection and
execution counts, is owned by
`identity-conformance`. Local exports are deliberately not interchangeable with
the ZIP files issued by **Publish for certification**.
The suite build and source tests run in the same digest-pinned Maven container
used by OpenID4VCI CI. A reachable local Docker daemon is required for that
reproducible build even when `CONFORMANCE_SERVER` points to an already-running
suite.

Downstream orchestration owns the composed OpenID4VCI and OpenID4VP
certification plans. Results from one protocol or role must never be counted as
coverage for another.

Interop fixture targets:

- EUDI reference verifier and wallet:
  `https://github.com/eu-digital-identity-wallet`
- EWC EUDI wallet RFC flows:
  `https://github.com/EWC-consortium/eudi-wallet-rfcs`

Hardening targets:

- `tests/property_tests.rs` covers parser and generated-message invariants with
  bounded `proptest` cases.
- `../fuzz/` contains `cargo-fuzz` targets for DCQL JSON and evaluation,
  request transport, Request Object JWT shape, Client Identifier parsing,
  Authorization Response JSON/protobuf, metadata JSON, transaction data JSON,
  Direct Post/direct_post.jwt forms, DC API request/response JSON, and
  verifier-attestation parameters.
- `../scripts/run-fuzz-smoke.sh` runs a short bounded fuzz smoke pass suitable
  for CI and local pre-release validation.

Fixtures must use final OpenID4VP wire shapes: DCQL queries, `vp_token` objects
keyed by DCQL query id, and client identifier prefixes.
