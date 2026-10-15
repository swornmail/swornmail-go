# A search domain on purpose: discovery must never send a lookup into it.
printf 'nameserver 127.0.0.1\nsearch test.example\n' > /etc/resolv.conf
python3 /lab/servfail.py &
dnsmasq --conf-file=/etc/sworn-dnsmasq.conf
su -s /bin/sh nobody -c 'sworn-milter --authserv-id mx.example.com >/tmp/sworn-milter.log 2>&1 &'
exec postfix start-fg
