ARG BUILD_FROM=alpine:3.19
FROM $BUILD_FROM

RUN apk add --no-cache \
    python3 \
    py3-pillow \
    py3-requests \
    py3-urllib3 \
    tzdata \
    bash

WORKDIR /app

COPY gateway.py panel_layout.json config.json config.json.example run.sh app-debug.apk* /app/
RUN chmod +x /app/run.sh /app/gateway.py

EXPOSE 8090

CMD ["/app/run.sh"]
