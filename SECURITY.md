# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities in the SwornMail protocol design or any
reference implementation to **security@swornmail.dev**. Do not open public
issues for security reports.

You will receive an acknowledgment within 72 hours. We follow coordinated
disclosure with a default 90-day window, negotiable for complex issues.

## Scope

- Protocol design flaws (spoofing, replay, downgrade, verification bypass)
- Reference implementations: swornmail-go, the swornmail Rust crate, plugins
- Test vectors that mask a defect

Out of scope: issues in third-party MTAs integrating these libraries, and
volumetric abuse of DNS that the spec's lookup budgets already document.

## Supported versions

Pre-release (0.x): only the latest published version of each component
receives fixes. The protocol wire format is not yet frozen; breaking
security fixes may change it prior to v1.

## No bounty program yet

We currently offer acknowledgment in release notes and the spec's
acknowledgments section. A bounty program is planned once the protocol
reaches operational deployment.
