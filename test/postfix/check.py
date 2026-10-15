"""Compares each delivered message's Authentication-Results with what the
milter should have left, and checks discovery never used the search domain."""
import mailbox
import sys

PASS = ('mx.example.com; sworn=pass policy.mode=dns policy.op=mailer.example.com '
        'policy.unit="2001:db8:f00:1234::/64" policy.observed="2001:db8:f00:1234::/64"')
NONE = "mx.example.com; sworn=none"

EXPECTED = {
    # Our result on top, forgeries gone, other domains' results kept in order.
    "A1": [PASS, "other.example; spf=pass", "other.example; dkim=pass"],
    "A2": [PASS],
    "A3": [PASS, "other.example; spf=pass"],
    "A5": [PASS],
    "B1": [NONE],
    "C1": [NONE],
    # DNS failed (SERVFAIL): temperror, never none, so breaking a sender's DNS
    # can't erase their attestation.
    "E1": ["mx.example.com; sworn=temperror"],
    # The milter was down: Postfix accepted the message without it, so the
    # forged field is still there. That is the documented fail-open cost.
    "D1": ["mx.example.com; sworn=pass policy.op=victim.example"],
}

delivered = {}
for msg in mailbox.mbox("/var/mail/rcpt"):
    delivered[msg["Subject"]] = [" ".join(v.split()) for v in msg.get_all("Authentication-Results", [])]

fails = 0
for subject, want in EXPECTED.items():
    got = delivered.pop(subject, None)
    if got == want:
        print(f"ok   {subject}: {got[0]}")
    else:
        print(f"FAIL {subject}: want {want}, got {got}")
        fails += 1
for subject in delivered:  # A4 was rejected; nothing else should arrive
    print(f"FAIL {subject}: delivered but not expected")
    fails += 1

with open("/tmp/dnsmasq.log") as log:
    leaked = [line.strip() for line in log if "query[" in line and "test.example" in line]
if leaked:
    print(f"FAIL lookups went into the search domain: {leaked}")
    fails += 1
else:
    print("ok   no lookup went into the resolv.conf search domain")

sys.exit(1 if fails else 0)
