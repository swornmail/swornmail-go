# Postfix with sworn-milter configured the way swornmail.dev/milter documents,
# plus dnsmasq serving the test records. Build from the repository root:
#   docker build -f test/postfix/Dockerfile .
# Base images pinned by digest. The apt packages are not: Debian removes
# superseded versions from its archive, so pinning them would break the build
# at the next point release. run.sh prints the Postfix version it tested.
FROM golang:1.24-trixie@sha256:5835f052b784aa39f2fe9070def3568605c8bc3fcd810f10402066348b61e716 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /sworn-milter ./cmd/sworn-milter

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections \
 && echo "postfix postfix/mailname string mx.example.com" | debconf-set-selections \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postfix dnsmasq python3 procps iproute2 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /sworn-milter /usr/local/bin/sworn-milter
COPY test/postfix/dnsmasq.conf /etc/sworn-dnsmasq.conf
COPY test/postfix/entrypoint.sh test/postfix/send.py test/postfix/check.py test/postfix/servfail.py /lab/
# Debian's default master.cf runs smtpd chrooted, which is the case the
# documentation's choice of an inet: milter address is about.
RUN useradd -m rcpt \
 && touch /var/mail/rcpt && chown rcpt:mail /var/mail/rcpt && chmod 0660 /var/mail/rcpt \
 && printf '/^X-Lab-Reject:/ REJECT rejected by the test\n' > /etc/postfix/header_checks \
 && postconf -e 'myhostname = mx.example.com' 'mydestination = mx.example.com, localhost' \
      'inet_protocols = all' 'maillog_file = /var/log/postfix.log' \
      'header_checks = regexp:/etc/postfix/header_checks' \
      'smtpd_milters = { inet:127.0.0.1:10025, default_action=accept }'
ENTRYPOINT ["/bin/sh", "/lab/entrypoint.sh"]
