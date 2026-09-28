# Security Policy

## Supported Versions

The `0.1.x` release line is supported. Security fixes are developed against
`main` and released as versioned crates after coordinated review. Older
snapshots, unpublished development branches, and locally modified package
archives are not supported releases.

## Reporting A Vulnerability

Report suspected vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/reallyme/openid4vp/security/advisories/new).
Do not open a public issue, discussion, or pull request containing exploit
details, credentials, private identity data, presentation material, keys, or
conformance access tokens.

Include the affected version or commit, the smallest safe reproduction, the
expected security property, and the observed behavior. Redact all personal and
cryptographic material. If a reproduction requires sensitive artifacts,
describe how to reproduce the issue without attaching those artifacts until a
secure exchange method has been agreed.

ReallyMe will acknowledge a report, assess its scope, and coordinate remediation
and disclosure with the reporter. Please allow a reasonable remediation window
before public disclosure, especially where a fix must be coordinated across the
OpenID4VP, SSI, JOSE/COSE, cryptography, wallet, or platform SDK boundaries.

## Scope

Reports are especially useful when they concern parser differentials, request or
session binding, replay, trust-anchor or certificate validation, signature or
encryption verification, credential status, selective disclosure, sensitive
memory handling, provider routing, protobuf/JSON boundary validation, or
conformance-driver secret handling.

OIDF certification status and interoperability failures without a security
impact should be reported separately from vulnerabilities. Passing local or
hosted conformance tests is evidence of protocol interoperability; it is not a
security warranty.
