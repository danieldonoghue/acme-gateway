FROM alpine:latest

RUN apk add --no-cache \
    bind \
    bind-tools \
    && rm -rf /var/cache/apk/*

COPY named.conf /etc/bind/named.conf
COPY zones /etc/bind/zones

RUN chown -R named:named /etc/bind && \
    mkdir -p /var/cache/bind /var/lib/bind && \
    chown -R named:named /var/cache/bind /var/lib/bind && \
    chmod 755 /var/cache/bind /var/lib/bind && \
    cp /etc/bind/zones/pebble-test.local.zone /var/lib/bind/pebble-test.local.zone && \
    chown named:named /var/lib/bind/pebble-test.local.zone && \
    chmod 644 /var/lib/bind/pebble-test.local.zone

EXPOSE 53/tcp 53/udp

CMD ["/usr/sbin/named", "-g", "-u", "named"]
