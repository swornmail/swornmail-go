"""Sends one scenario's messages over a single SMTP connection."""
import smtplib
import sys

FORGED = "Authentication-Results: mx.example.com; sworn=pass policy.op=victim.example"

SCENARIOS = {
    # Messages 2, 3 and 5 forge our result in ways a naive match misses, and
    # header positions have to restart for each message for them to go.
    # Message 4 is rejected by Postfix part-way through.
    "attested": [
        ("A1", ["Authentication-Results: other.example; spf=pass",
                "Authentication-Results: other.example; dkim=pass"]),
        ("A2", ["Authentication-Results: mx.example.com 1; sworn=pass policy.op=victim.example"]),
        ("A3", ["Authentication-Results: =?utf-8?q?mx.example.com?=; sworn=pass",
                "Authentication-Results: other.example; spf=pass"]),
        ("A4", ["Authentication-Results: other.example; spf=pass",
                "Authentication-Results: other.example; dkim=pass", "X-Lab-Reject: yes"]),
        ("A5", ["Authentication-Results: MX.EXAMPLE.COM.; sworn=pass"]),
    ],
    "unattested": [("B1", [FORGED])],
    "ipv4": [("C1", ["Authentication-Results: (c) mx.example.com; sworn=pass"])],
    "servfail": [("E1", [FORGED])],
    "milter-down": [("D1", [FORGED])],
}


def message(subject, headers):
    lines = headers + [f"Subject: {subject}", "From: a@mailer.example.com",
                       "To: rcpt@mx.example.com", "", "body"]
    return "\r\n".join(lines) + "\r\n"


host, scenario = sys.argv[1], sys.argv[2]
smtp = smtplib.SMTP(host, 25, timeout=30)
smtp.ehlo("client.mailer.example.com")
for subject, headers in SCENARIOS[scenario]:
    try:
        smtp.sendmail("a@mailer.example.com", ["rcpt@mx.example.com"], message(subject, headers))
        print(f"{subject} accepted")
    except smtplib.SMTPException as err:
        print(f"{subject} refused: {err}")
smtp.quit()
