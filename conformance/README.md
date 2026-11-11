# Conformance Harness

This directory contains executable protocol vectors, interoperability fixtures,
and OpenID Foundation conformance-suite runners for OpenID4VP 1.0 final.

## Scope and layout

- `specifications.lock` pins normative and tracked draft sources.
- `requirements/` maps requirements to implementation and executable tests.
- `oidf/profile-matrix.json` pins the suite revision and the complete supported
  inventory: two verifier profiles and four wallet profiles across SD-JWT VC,
  ISO mDL, `direct_post.jwt`, and `dc_api.jwt`.
- `oidf/` contains format-specific runner templates and explicit exclusions.
- `eudi/` contains pinned reference sources, upstream test mappings, and exclusions.
- `fixtures/` contains deterministic EUDI and EWC interoperability fixtures.
- `src/` and `tests/` execute the shared corpus in `../vectors/` and validate
  requirement-to-test mappings.

The **OIDF Protocol Compatibility** workflow builds the exact pinned suite,
checks its OpenID4VP source and complete profile inventory, and tests the
repository-owned Rust and Python boundaries. It needs no product endpoint or
secret. Its result records `oidf_plan_execution: false` and
`certification_evidence: false`: passing compatibility CI is not an executed
OIDF plan or a certification claim.

Live plan execution requires a host-supplied verifier or wallet. Product
storage, consent, credential inventory, deployment identity, certification
submission, and retained product evidence are host responsibilities.
Generated results default to the ignored `target/conformance-results/`
directory. Credentials, private signing material, and bearer tokens must not
be committed or included in exported evidence.

## Runner modes and prerequisites

Set `OIDF_PROFILE_ID` to one exact entry in `oidf/profile-matrix.json`.
`OIDF_RUNNER_MODE=execute` or `OIDF_WALLET_RUNNER_MODE=execute` requires a running
suite and a composed product driver. Pending mode performs configuration
preflight only; it provides no conformance or certification evidence.

The runners build the pinned suite in a digest-pinned Maven container. A
reachable local Docker daemon is required even when the configured suite
server is remote. The suite checkout must match the matrix commit and remain
clean. `verify_oidf_certification_target.py` rejects module or variant drift.

Execute mode requires both OIDF bearer-token variables, verified TLS, and HTTPS
for suite, mTLS, product, launch, evidence, and harness endpoints. Endpoint
validation rejects userinfo, fragments, query-bearing base URLs, ambiguous
authorities, and invalid ports. `CONFORMANCE_DEV_MODE=true` permits isolated
local testing; its output is not certification evidence.

Dedicated product launch, evidence, and wallet-harness tokens must not reuse
the suite API token. The wallet harness token must contain 32–4096 ASCII graphic
bytes. Store product credentials in owner-only host configuration.

## Verifier execution

The suite acts as a wallet. `drive_oidf_verifier_flow.py` polls waiting modules
and submits their authorization endpoint to the verifier launch endpoint.
The host creates a fresh session and hosted Request Object for each module.
It may start the flow and return HTTP 204, or return an object containing
`authorization_endpoint`, optional `method`, and
`parameters: [{ "name": "client_id", "value": "..." }, ...]` for the driver to
submit to the suite.

```sh
export CONFORMANCE_SUITE_DIR=/path/to/conformance-suite
export CONFORMANCE_SERVER=https://suite.example.test
export CONFORMANCE_SERVER_MTLS=https://mtls.suite.example.test
export CONFORMANCE_TOKEN=replace-with-suite-access-token
export CONFORMANCE_API_TOKEN="${CONFORMANCE_TOKEN}"
export EXAMPLE_VERIFIER_BASE_URL=https://verifier.example.test
export OIDF_VERIFIER_LAUNCH_ENDPOINT=https://verifier.example.test/oidf/launch
export OIDF_VERIFIER_EVIDENCE_ENDPOINT=https://verifier.example.test/oidf/evidence
export OIDF_VERIFIER_LAUNCH_TOKEN=replace-with-dedicated-launch-token
export OIDF_VERIFIER_EVIDENCE_TOKEN=replace-with-dedicated-evidence-token
export OIDF_PROFILE_ID=verifier-sd-jwt-vc-direct-post-jwt
export OIDF_RUNNER_MODE=execute
export OIDF_VERIFIER_FLOW_DRIVER_MODE=execute
conformance/scripts/run_oidf_verifier_plan.sh
```

The health endpoint must return JSON containing
`"composed_flow_driver_enabled": true`. Set `OIDF_VERIFIER_HEALTH_ENDPOINT`
when `/healthz` cannot be derived from the launch endpoint. The runner fails
if the driver exits before a profile result can be accepted.

The runner generates a collision-resistant alias. An explicit
`OIDF_VERIFIER_ALIAS` must be deployment-specific; the shared
`oidf-vp-test-wallet` example alias is rejected. Each driver is bound to a
newly created exact plan, profile, and alias. Every launch carries the immutable
plan, profile, module id, and module name. Module names alone are insufficient:
the SD-JWT and mdoc profiles share names such as `happy-flow`.

The evidence endpoint returns one bounded record per exact module instance.
Its identity, accepted/rejected decision, and non-PII observations must match
the matrix. The fetch-twice case needs two Request Object retrieval observations;
negative-response cases need a rejected authorization-response observation.
Missing, stale, foreign, oversized, duplicate-key, and free-text records fail
the profile. Owner-only records and their SHA-256 index are written beneath
`target/conformance-results/implementation-evidence/`.

For isolated smoke tests, `OIDF_CLIENT_ID` plus `OIDF_REQUEST_URI`, or
`OIDF_REQUEST_OBJECT_JWT`, can supply the authorization parameters directly.
This path does not provide the fresh per-module sessions needed for a complete
multi-module run.

## Wallet execution

The suite acts as a verifier. The host-supplied wallet harness must resolve
`request_uri`, authenticate signed Request Objects, select credentials, build
the DCQL-keyed `vp_token`, encrypt the negotiated response, and return it to
the suite. Transport parsing alone does not implement this flow.

`drive_oidf_wallet_flow.py` forwards redirect parameters or the exact structured
`browser_api_request` and suite `submit_url`. Browser API flows require a POST
harness because GET cannot preserve the structured request.

```sh
export CONFORMANCE_SUITE_DIR=/path/to/conformance-suite
export CONFORMANCE_SERVER=https://suite.example.test
export CONFORMANCE_SERVER_MTLS=https://mtls.suite.example.test
export CONFORMANCE_TOKEN=replace-with-suite-access-token
export CONFORMANCE_API_TOKEN="${CONFORMANCE_TOKEN}"
export OIDF_WALLET_HARNESS_ENDPOINT=https://wallet.example.test/oidf/wallet/authorize
export OIDF_WALLET_HARNESS_TOKEN=replace-with-dedicated-wallet-harness-token
export OIDF_WALLET_HARNESS_METHOD=POST
export OIDF_WALLET_SCREENSHOT_BROWSER=/path/to/chrome
export OIDF_PROFILE_ID=wallet-sd-jwt-vc-direct-post-jwt
export OIDF_WALLET_RUNNER_MODE=execute
export OIDF_WALLET_FLOW_DRIVER_MODE=execute
conformance/scripts/run_oidf_wallet_plan.sh
```

The health endpoint must return `"composed_flow_driver_enabled": true`.
Set `OIDF_WALLET_HARNESS_HEALTH_ENDPOINT` or `OIDF_WALLET_ERROR_SCREEN_ENDPOINT`
when `/healthz` or `/oidf/wallet/error` cannot be derived from the harness URL.
Negative tests require the authenticated error-screen endpoint and the
configured Chromium-family browser. The driver captures the actual
non-sensitive error view and uploads it to the suite's exact screenshot
placeholder. For Browser API negatives, the wallet's typed promise rejection
is submitted first; the suite decides whether screenshot evidence is required.
Missing rejection, error view, browser, placeholder, or upload fails the run.

The format-specific DCQL/HAIP templates under `oidf/configs/` must match the
selected profile. The harness expands only reviewed key files from the exact
suite checkout. It rejects duplicate JSON keys, unknown or unresolved
placeholders, inconsistent signer material, and incorrect trust anchors.
The credential/status roots and Request Object signing CA have separate trust
purposes. Expanded configurations contain private test keys: they are created
in an owner-only temporary directory, removed on exit, and excluded from exports.

The runner generates a fresh alias; `OIDF_WALLET_ALIAS` may supply a unique
stable deployment alias, but the shared `oidf-vp-test-verifier` example is
rejected. Each sidecar must report `passed` with the exact matrix module count
and newly created suite plan-instance id. Negative modules may return the
harness's bounded HTTP 400 rejection; positive modules must complete the call.

## Results and certification limits

Each selected profile produces a machine-readable result beneath
`target/conformance-results/`. Driver records and profile exports must agree
on the exact suite plan-instance id. Configuration failures produce `failed`
results with stable non-PII reason codes. Drivers must not print Request
Objects, request URIs, bearer tokens, or wallet presentation data.

The result validator requires the complete expected module multiset, exact
variants, and `FINISHED` status. It accepts `REVIEW` only for matrix-classified
screenshot cases in the pinned suite; every other module must be `PASSED`.
It never promotes or rewrites a suite result.

Product certification requires execution of the product's complete applicable
profile set, resolution of official review items, and evidence bound to the
immutable deployed product identity and endpoint. Local exports are not the
suite's **Publish for certification** ZIP files. Compatibility CI and local
self-tests do not establish an OpenID Foundation certification.

## Other verification assets

EUDI and EWC fixtures target the pinned reference implementations and scenarios
listed in `eudi/sources.lock` and the fixture manifests. Fixture inputs must
use final-spec wire shapes: DCQL queries, `vp_token` objects keyed by credential
query id, and Client Identifier Prefixes.

`tests/property_tests.rs` exercises bounded parser and generated-message
invariants. `../fuzz/` contains coverage-instrumented parser and protocol-boundary
fuzz targets; `../scripts/run-fuzz-smoke.sh` runs the bounded CI smoke suite.
Formal security models and their limits are documented in `../formal/README.md`.
