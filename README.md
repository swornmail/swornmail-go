# swornmail-go

Go reference implementation of the [SwornMail
protocol](https://github.com/swornmail/spec): cryptographic IPv6 prefix
attestation for email senders.

## Implemented

- **Mode-2 connection tokens** (`sworn`): tagged COSE_Sign1 (Ed25519) over
  deterministic CBOR — sign and verify per `draft-kafedzhy-swornmail-01`,
  with protected `kid`/content-type binding, canonical/range-bounded
  prefixes, source-eligibility rules, fixed 300s skew, and operator-domain
  validation. `ParseUnverified` exposes the pre-DNS syntax checks.
- **`_sworn` records** (`sworn`): key records (`ParseRecord`) and policy
  records (`ParsePolicyRecord`), with duplicate-tag rejection.
- **Mode-1 discovery** (`sworn/discover`): DNS-only discovery — reverse-tree
  pointer then forward-confirmed PTR candidates, bounded by a 10-query
  budget, with an injectable resolver for tests.
- **CLI** (`cmd/sworn`): `verify` a token, `record` lint a domain, `discover`
  a source address.
- **Postfix milter** (`cmd/sworn-milter`): runs Mode-1 discovery per
  connection and stamps `Authentication-Results: sworn=…`, stripping inbound
  results at the trust boundary. Strictly fail-open — never rejects mail.
  (Uses `github.com/emersion/go-milter`.)
- **Cross-implementation test vectors** (`cmd/genvectors` → `spec/test-vectors/v1.json`):
  expectations authored from the draft; generation self-checks the reference
  and fails on any disagreement. The [Rust verifier](https://github.com/swornmail/swornmail)
  passes the same file.

A complete Ed25519 token is 174 bytes. Verification is stateless; replay
outside the attested prefix is impossible by construction, so no
anti-replay state exists.

## Planned

rspamd module (first receiver-side integration) · token signing helpers.
Further items in the issues and `spec` #2.

## Use

```
go test ./...
go run ./cmd/genvectors               # regenerate the deterministic vectors
go run ./cmd/sworn verify <token> --ip <addr> --key <b64>
go run ./cmd/sworn record example.com --selector 2026a
go run ./cmd/sworn discover --ip <addr>
go run ./cmd/sworn-milter --listen unix:/var/spool/postfix/sworn.sock
```

Requires Go 1.22+. The `-01` wire format is frozen (v1 vectors); pin exact
versions until v1.0.

## Security

See `SECURITY.md`. Report privately to security@swornmail.dev.

## License

Apache-2.0 (see `LICENSE`).

Maintained by [PlatOps Security, LLC](https://platops.com). Copyright:
see `NOTICE`.
