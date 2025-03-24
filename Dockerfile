FROM alpine:3.21.3

LABEL maintainer="Michael Oberdorf IT-Consulting <info@oberdorf-itc.de>"
LABEL site.local.program.version="1.1.0"

ENV TZ=Europe/Berlin \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    CONFIG_FILE=/app/etc/snmp2mqtt.json

RUN apk upgrade --available --no-cache --update \
    && apk add --no-cache --update \
       python3=3.12.9-r0 \
       py3-pip=24.3.1-r0 \
       ca-certificates=20241121-r1 \
       tzdata=2025a-r0 \
    # Cleanup APK
    && rm -rf /var/cache/apk/* /tmp/* /var/tmp/* \
    # Using PIP to install Python pacakges
    && pip3 install --no-cache-dir -r /requirements.txt --break-system-packages \
    # Set Timezone
    && cp /usr/share/zoneinfo/${TZ} /etc/localtime \
    && echo "${TC}" > /etc/timezone

COPY --chown=root:root /src /

USER 3917:3917

WORKDIR /app/bin

# Start Process
ENTRYPOINT ["python"]
CMD ["-u", "/app/bin/snmp2mqtt.py"]
