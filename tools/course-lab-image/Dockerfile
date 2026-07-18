FROM node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3

RUN apt-get update \
    && apt-get install --no-install-recommends --yes binutils-mingw-w64-x86-64 unzip \
    && rm -rf /var/lib/apt/lists/*

COPY --chown=65532:65532 analyze-static.mjs /opt/templar/analyze-static.mjs

USER 65532:65532
WORKDIR /drone
ENTRYPOINT ["/usr/local/bin/node", "/opt/templar/analyze-static.mjs"]
