# swornmail-go

Go reference implementation of the [SwornMail
protocol](https://github.com/swornmail/spec): cryptographic IPv6 prefix
attestation for email senders.

## Implemented

- **Mode-2 connection tokens** (`sworn`): tagged COSE_Sign1 (Ed25519) over
  deterministic CBOR — sign and verify per `draft-kafedzhy-swornmail-01`,
  with protected `kid`/content-type binding, canonical/range-bounded
  prefixes, source-eligibility rules, fixed 300s skew, and operator-domain
  validation. `PrepareVerification` completes every local check before DNS;
  its staged `Authorize` flow requires the policy to cover the signed prefix
  before a receiver fetches the key.
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

A complete Ed25519 token is 174 bytes. Verification is stateless. Replay is
limited to the signed prefix and remains attributable to its operator. A broad
signed claim alone is not proof that a shared-hosting tenant controls the
provider aggregate, so reputation attaches to the *observed unit* — the source
`/64`, computed from the connection rather than from anything the claimant
wrote — unless the receiver has independent evidence of a wider control
boundary. It is reported as `policy.observed` in Authentication-Results.

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
./sworn verify "$TOKEN" --ip 2001:db8:f00::25       # policy first, then key
```

## Use

```
go test ./...
go run ./cmd/genvectors               # regenerate the deterministic vectors
go run ./cmd/sworn keygen --selector 2026a
go run ./cmd/sworn genrecord --domain example.com --selector 2026a --key 2026a.key --prefix <p>
go run ./cmd/sworn genrecord ... --json    # feed a DNS provider's API
go run ./cmd/sworn sign --key 2026a.key --selector 2026a --domain example.com --prefix <p>
go run ./cmd/sworn verify <token> --ip <addr>
go run ./cmd/sworn verify <token> --ip <addr> --policy '<policy TXT>' --key <b64> # fully offline
go run ./cmd/sworn record example.com --selector 2026a
go run ./cmd/sworn discover --ip <addr>
go run ./cmd/sworn-milter --listen unix:/var/spool/postfix/sworn.sock
```

For library integrations, the safe live-DNS order is:

```go
pending, err := sworn.PrepareVerification(token, source, now) // no DNS
// fetch and parse _prefixes._sworn.<pending.Operator()>
authorized, err := pending.Authorize(policy)                  // no key query yet
// fetch and parse <pending.Selector()>._sworn.<pending.Operator()>
result, err := authorized.VerifySignature(key)

switch {
case errors.Is(err, sworn.ErrTestingMode):
    // t=y: report sworn=none policy.wouldbe=pass. `result` is populated,
    // but nothing is staked. This is an error, not a flag on a nil-error
    // result, so `err == nil` can never mean pass for a testing operator.
case err != nil:
    // sworn.AuthResult(err) / sworn.Reason(err); attribute nothing to anyone.
default:
    // Key reputation on result.ObservedUnit, NOT result.Unit.
}
```

`result.Unit` is the aggregation the operator *asked for*. `result.ObservedUnit`
is the source `/64` this connection actually corroborated, and is the reputation
key unless you hold independent evidence that the operator controls the whole
attested prefix. They are equal at the default `u=64`.

When both records are already available, `sworn.Verify` is the complete
no-I/O helper and requires the policy argument. Only conformance tooling
should use the deliberately named `sworn.VerifySignatureOnly` primitive,
which does not apply DNS policy and must never be reported as a protocol pass.

Requires Go 1.24+. The `-01` wire format is frozen (v1 vectors); pin exact
versions until v1.0.

Record *acceptance* was tightened within `-01`: a policy `u=` coarser than
any prefix in the same record, a `rua=` outside a conservative ASCII
`mailto:<dot-atom>@<domain>`, and any octet outside printable US-ASCII in a
record are now malformed. Token bytes are unchanged and every pre-existing
vector still passes byte-identically. `sworn genrecord` never emitted any of
those shapes; an operator who hand-wrote one must fix the record.

## Security

See `SECURITY.md`. Report privately to security@swornmail.dev.

## License

Apache-2.0 (see `LICENSE`).

Maintained by Val Kafedzhy. Copyright:
see `NOTICE`.
