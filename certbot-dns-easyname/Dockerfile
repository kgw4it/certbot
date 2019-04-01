FROM certbot/certbot

RUN apk update && \
    apk add build-base \
            libxml2-dev \
            libxslt-dev && \
    rm -rf /var/cache/apk/* && \
    rm -rf /tmp/*

COPY . src/certbot-dns-easyname

RUN pip install --no-cache-dir --editable src/certbot-dns-easyname
