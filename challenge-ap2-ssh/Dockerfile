FROM python:3.11-alpine

WORKDIR /app

COPY requirements.txt ./

RUN apk add --no-cache libffi openssl \
    && apk add --no-cache --virtual .build-deps build-base cargo libffi-dev openssl-dev rust \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-deps \
    && addgroup -S -g 10002 ap2ssh \
    && adduser -S -D -H -u 10002 -G ap2ssh -s /sbin/nologin ap2ssh

COPY requirements.txt server.py credential.py probe.py selftest.py ./

USER 10002:10002

EXPOSE 2222

ENTRYPOINT ["python", "server.py", "serve"]
