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
- **CLI** (`cmd/sworn`): sender side — `keygen` a signing key, `genrecord` the
  DNS records (validating every `-01` constraint and round-tripping the output
  through the protocol's own parsers), `sign` a Mode-2 token; receiver side —
  `verify` a token, `record` lint a domain, `discover` a source address.
- **Postfix milter** (`cmd/sworn-milter`): runs Mode-1 discovery per
  connection and stamps `Authentication-Results: sworn=…`, stripping inbound
  results at the trust boundary. Honors `t=y` — a testing operator is
  reported `sworn=none policy.testing=y policy.wouldbe=pass`, never `pass`,
  so no reputation is staked on a deployment that has not opted in. Strictly
  fail-open — never rejects mail. (Uses `github.com/emersion/go-milter`.)
- **Record differential** (`cmd/recorddiff`): drives an external implementation
  through an adversarial corpus of record, prefix, and eligibility cases and
  fails on any disagreement with this one. The rspamd module is checked
  against it.
- **Cross-implementation test vectors** (`cmd/genvectors` → `spec/test-vectors/v1.json`):
  expectations authored from the draft; generation self-checks the reference
  and fails on any disagreement. The [Rust verifier](https://github.com/swornmail/swornmail)
  passes the same file.

A complete Ed25519 token is 174 bytes. Verification is stateless; replay
outside the attested prefix is impossible by construction, so no
anti-replay state exists.

## Planned

rspamd module (first receiver-side integration). Further items in the issues
and `spec` #2.

## Deploy SwornMail in 5 minutes

You need a domain, the IPv6 prefix your mail leaves from, and the ability to
add two TXT records.

```
go build -o sworn ./cmd/sworn

# 1. Generate a signing key. Writes 2026a.key (mode 0600) — back it up.
./sworn keygen

# 2. Generate the records for your domain and prefix.
./sworn genrecord --domain mailer.example.com --selector 2026a \
                  --key 2026a.key --prefix 2001:db8:f00::/48

# 3. Publish the two TXT records it prints (zone-file and DNS-panel forms
#    are both shown), then check them:
./sworn record mailer.example.com --selector 2026a
./sworn discover --ip <one of your MTA's IPv6 addresses>
# → sworn=none testing=y wouldbe=pass mode=dns op=mailer.example.com …
```

`wouldbe=pass` is success: your records are correct and discovery found you.

Step 2 defaults to `t=y`, testing mode, so receivers verify exactly as they
otherwise would but report `sworn=none policy.testing=y policy.wouldbe=pass`
and stake no reputation on you — neither credit nor blame. Watch your traffic,
then re-run `genrecord` with `--testing=false` and republish when you are
ready to be accountable for the prefix; discovery then reports `sworn=pass`.

That is the whole Mode-1 deployment. Mode 2 additionally signs a token per
connection; `sworn sign` issues one so you can prove the key works:

```
TOKEN=$(./sworn sign --key 2026a.key --selector 2026a \
                     --domain mailer.example.com --prefix 2001:db8:f00::/48)
./sworn verify "$TOKEN" --ip 2001:db8:f00::25       # fetches your key record
```

## Use

```
go test ./...
go run ./cmd/genvectors               # regenerate the deterministic vectors
go run ./cmd/sworn keygen --selector 2026a
go run ./cmd/sworn genrecord --domain example.com --selector 2026a --key 2026a.key --prefix <p>
go run ./cmd/sworn genrecord ... --json    # feed a DNS provider's API
go run ./cmd/sworn sign --key 2026a.key --selector 2026a --domain example.com --prefix <p>
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
