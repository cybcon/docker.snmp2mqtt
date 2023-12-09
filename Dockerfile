FROM alpine:3.19.0

LABEL maintainer="Michael Oberdorf IT-Consulting <info@oberdorf-itc.de>"
LABEL site.local.program.version="1.0.3"

ENV TZ=Europe/Berlin \
    CONFIG_FILE=/app/etc/snmp2mqtt.json

RUN apk upgrade --available --no-cache --update \
    && apk add --no-cache --update \
       python3=3.11.6-r1 \
       py3-paho-mqtt=1.6.1-r2 \
       py3-ply=3.11-r10 \
       py3-asn1=0.5.1-r0 \
       py3-pycryptodomex=3.19.0-r0 \
       py3-snmp=4.4.12-r4 \
       tzdata=2023c-r1 \
    # Cleanup APK
    && rm -rf /var/cache/apk/* /tmp/* /var/tmp/* \
    # Set Timezone
    && cp /usr/share/zoneinfo/${TZ} /etc/localtime \
    && echo "${TC}" > /etc/timezone

COPY --chown=root:root /src /

USER 3917:3917

WORKDIR /app/bin

# Start Process
ENTRYPOINT ["python"]
CMD ["-u", "/app/bin/snmp2mqtt.py"]
