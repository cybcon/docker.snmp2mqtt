FROM alpine:3.18.4

LABEL maintainer="Michael Oberdorf IT-Consulting <info@oberdorf-itc.de>"
LABEL site.local.program.version="1.0.1"

ENV TZ=Europe/Berlin \
    CONFIG_FILE=/app/etc/snmp2mqtt.json

RUN apk upgrade --available --no-cache --update \
    && apk add --no-cache --update \
       python3=3.11.6-r0 \
       py3-pip=23.1.2-r0 \
       tzdata=2023c-r1 \
    # Cleanup APK
    && rm -rf /var/cache/apk/* /tmp/* /var/tmp/* \
    # Set Timezone
    && cp /usr/share/zoneinfo/${TZ} /etc/localtime \
    && echo "${TC}" > /etc/timezone

COPY --chown=root:root /src /

RUN pip3 install --no-cache-dir -r /requirements.txt

USER 3917:3917

WORKDIR /app/bin

# Start Process
ENTRYPOINT ["python"]
CMD ["-u", "/app/bin/snmp2mqtt.py"]
