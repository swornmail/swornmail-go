# swornmail-go

Go reference implementation of the [SwornMail
protocol](https://github.com/swornmail/spec): cryptographic IPv6 prefix
attestation for email senders.

## Implemented

- Mode-2 connection tokens: COSE_Sign1 (Ed25519) over deterministic CBOR —
  sign and verify, with the five-step verification order from the draft
  (parse, key, signature, validity window, source-prefix membership)
- `_sworn` operator record parsing
- Cross-implementation test vectors (`spec/test-vectors/v0.json`)

A complete Ed25519 token is 135 bytes. Verification is stateless; replay
outside the attested prefix is impossible by construction, so no
anti-replay state exists.

## Planned

Postfix milter · verification CLI · Mode-1 (DNS-only) discovery ·
hardening items tracked in issues.

## Use

```
go test ./...
go run ./cmd/genvectors   # regenerates the deterministic test vectors
```

Requires Go 1.22+. **The protocol wire format is not yet frozen** —
expect breaking changes before v1; pin exact versions.

## Security

See `SECURITY.md`. Report privately to security@swornmail.dev.

## License

Apache-2.0 (see `LICENSE`).
