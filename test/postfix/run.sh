#!/bin/sh
# End-to-end check through a real Postfix: the milter configured as
# swornmail.dev/milter documents, a chrooted smtpd, an IPv6 network, and
# planted SwornMail records. Run from anywhere; needs Docker.
set -e
cd "$(dirname "$0")/../.."
# Per-run names, so cleanup can only ever remove what this run created.
NET=sworn-postfix-net-$$
MX=sworn-postfix-mx-$$
IMAGE=sworn-postfix-test

cleanup() {
  docker rm -f "$MX" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

docker build -q -f test/postfix/Dockerfile -t "$IMAGE" . >/dev/null
docker network create --ipv6 --subnet 2001:db8:f00::/48 --subnet 172.30.99.0/24 "$NET" >/dev/null
docker run -d --name "$MX" --hostname mx.example.com --network "$NET" \
  --ip6 2001:db8:f00:1234::10 --ip 172.30.99.10 "$IMAGE" >/dev/null

listening() { docker exec "$MX" sh -c "ss -ltn | grep -q ':$1 '"; }
i=0
until listening 25 && listening 10025; do
  i=$((i + 1)); [ "$i" -lt 60 ] || { echo "FAIL: Postfix or the milter never started"; docker logs "$MX"; exit 1; }
  sleep 1
done

# The documentation's choice of an inet: milter address is about chrooted
# smtpd, so make sure that's what is being tested.
chroot=$(docker exec "$MX" postconf -F smtp/inet/chroot | awk '{print $NF}')
[ "$chroot" = y ] || { echo "FAIL: smtpd is not chrooted ($chroot)"; exit 1; }
echo "Postfix $(docker exec "$MX" postconf -h mail_version), smtpd chrooted"

send() { # send <client ipv6> <client ipv4> <server address> <scenario>
  docker run --rm --network "$NET" --ip6 "$1" --ip "$2" \
    --entrypoint python3 "$IMAGE" /lab/send.py "$3" "$4"
}
send 2001:db8:f00:1234::25 172.30.99.21 2001:db8:f00:1234::10 attested
send 2001:db8:f00:9999::25 172.30.99.22 2001:db8:f00:1234::10 unattested
send 2001:db8:f00:1234::23 172.30.99.23 172.30.99.10 ipv4
send 2001:db8:f00:dead::25 172.30.99.25 2001:db8:f00:1234::10 servfail

# With the milter stopped, default_action=accept must keep mail flowing.
docker exec "$MX" pkill -x sworn-milter
while listening 10025; do sleep 1; done
send 2001:db8:f00:1234::26 172.30.99.24 2001:db8:f00:1234::10 milter-down

i=0
until docker exec "$MX" sh -c 'test -z "$(postqueue -j)"'; do
  i=$((i + 1)); [ "$i" -lt 30 ] || { echo "FAIL: mail still queued"; docker exec "$MX" postqueue -p; exit 1; }
  sleep 1
done

echo
if docker exec "$MX" python3 /lab/check.py; then
  echo "postfix integration: ok"
else
  echo "postfix integration: failed"; docker exec "$MX" tail -40 /var/log/postfix.log; exit 1
fi
