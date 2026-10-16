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
go build -o bin/sworn ./cmd/sworn

# 1. Generate a signing key. Writes 2026a.key (mode 0600) — back it up.
./bin/sworn keygen

# 2. Generate the records for your domain and prefix.
./bin/sworn genrecord --domain mailer.example.com --selector 2026a \
                  --key 2026a.key --prefix 2001:db8:f00::/48

# 3. Publish the two TXT records it prints (zone-file and DNS-panel forms
#    are both shown), then check them:
./bin/sworn record mailer.example.com --selector 2026a
./bin/sworn discover --ip <one of your MTA's IPv6 addresses>
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
TOKEN=$(./bin/sworn sign --key 2026a.key --selector 2026a \
                     --domain mailer.example.com --prefix 2001:db8:f00::/48)
./bin/sworn verify "$TOKEN" --ip 2001:db8:f00::25       # policy first, then key
```

## Use

```
go test ./...
sh test/postfix/run.sh                 # the milter through a real Postfix (needs Docker)
go run ./cmd/genvectors               # regenerate the deterministic vectors
go run ./cmd/sworn keygen --selector 2026a
go run ./cmd/sworn genrecord --domain example.com --selector 2026a --key 2026a.key --prefix <p>
go run ./cmd/sworn genrecord ... --json    # feed a DNS provider's API
go run ./cmd/sworn sign --key 2026a.key --selector 2026a --domain example.com --prefix <p>
go run ./cmd/sworn verify <token> --ip <addr>
go run ./cmd/sworn verify <token> --ip <addr> --policy '<policy TXT>' --key <b64> # fully offline
go run ./cmd/sworn record example.com --selector 2026a
go run ./cmd/sworn discover --ip <addr>
go run ./cmd/sworn-milter --authserv-id mx.example.com  # listens on tcp:127.0.0.1:10025
```

### Running the milter under Postfix

The full walkthrough is at [swornmail.dev/milter](https://swornmail.dev/milter/).

```
# main.cf (Postfix 3.0 or later)
smtpd_milters = { inet:127.0.0.1:10025, default_action=accept }
```

- **`default_action=accept` is what keeps the deployment fail-open.** The
  milter itself never rejects. Without that setting, a stopped or timed-out
  milter gets the global `milter_default_action`: `tempfail`, or `shutdown`
  since Postfix 3.11, and either one refuses mail. Set inside the braces, it
  covers this milter only. Don't set the global `milter_default_action =
  accept` instead: it would also let mail through unscanned whenever a virus
  or spam milter is down.
- **Check that port 10025 is free.** Content-filter setups, amavis among
  them, often have Postfix listen on 127.0.0.1:10025 to take filtered mail
  back. `postconf -M | grep 10025` shows whether Postfix has a service there,
  and `ss -ltn` (or `lsof -iTCP -sTCP:LISTEN`) shows anything else. If it's
  taken, run `sworn-milter --listen tcp:127.0.0.1:<free port>` and use the
  same port in `smtpd_milters`.
- **If `smtpd_milters` is already set, edit that line** rather than adding a
  second one, which would replace it. Put this entry first:
  `smtpd_milters = { inet:127.0.0.1:10025, default_action=accept }, <your existing milters>`.
  OpenDKIM or OpenDMARC may use the same authserv-id; running ahead of them,
  sworn-milter never sees their results, so it can't remove them.
- **TCP on loopback works the same everywhere.** A `unix:` socket works too,
  but a chrooted smtpd reads an absolute socket path inside the queue
  directory, so `unix:/var/spool/postfix/sworn.sock` would point at the wrong
  place, and with `default_action=accept` Postfix would just log a warning and
  skip the milter.
- **Run it on the border MTA**, the one that accepts connections from the
  Internet. It evaluates the connecting address and deletes inbound
  `Authentication-Results` fields that claim its authserv-id, so it must sit
  where mail enters your ADMD. Behind a load balancer or proxy, Postfix must
  see the real client address (for example `smtpd_upstream_proxy_protocol =
  haproxy`); otherwise every connection is evaluated as the balancer's address.
  Only do that on a listener nothing but the proxy can reach, or anyone can
  claim an attested address.
- **`--ineligible-prefix`** lists IPv6 prefixes the milter must never match
  to an operator: comma-separated, and the flag may repeat. **If this host
  reaches IPv4 clients through NAT64 or SIIT, list the translation prefix
  here.** Every translated client appears inside that one prefix, so a
  record covering it would otherwise be attributed for all of them. The same
  goes for any of your own relays that carry outside traffic. A source in a
  listed prefix gets `sworn=none` with no DNS lookup. A malformed prefix
  stops the milter at startup. `sworn verify` and `sworn discover` take the
  same flag.
- **`--authserv-id`** defaults to the hostname. Set it to the authserv-id your
  downstream filters trust; inbound results claiming that id are removed. The
  match is deliberately loose (case, a trailing dot, odd whitespace,
  comments), and any field containing a MIME encoded-word is removed outright,
  so oddly spelled forgeries go too.
- **Removing forged results fails open too.** While the milter is down, mail is
  accepted without our result *and* without inbound `Authentication-Results`
  fields claiming your id being removed. A downstream filter that trusts that
  id will see whatever the sender wrote until the milter is back.

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

Look record names up with a trailing dot (`_prefixes._sworn.example.com.`).
Without it, the resolver also tries each search domain in `resolv.conf` and
returns the error from the last attempt, so a SERVFAIL comes back as NXDOMAIN
and you'd report `none` instead of `temperror`. `discover.Discover` already
does this, which means a custom `discover.Resolver` receives names ending in a
dot and should match them that way.

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

A token longer than `sworn.MaxTokenSize` (3072 octets) is malformed and is
rejected before any CBOR decoding. The longest SWORN command line carries at
most 3066 octets of token, so nothing a client can send over SMTP is
affected; the bound protects library callers that take tokens from
elsewhere.

## Security

See `SECURITY.md`. Report privately to security@swornmail.dev.

## License

Apache-2.0 (see `LICENSE`).

Maintained by Val Kafedzhy. Copyright:
see `NOTICE`.
