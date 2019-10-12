FROM certbot/certbot

RUN apk update && \
    apk add build-base \
    rm -rf /var/cache/apk/* && \
    rm -rf /tmp/*

COPY . src/certbot-dns-w4dns

RUN pip install --no-cache-dir --editable src/certbot-dns-w4dns
