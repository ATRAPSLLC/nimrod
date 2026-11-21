# Runtime oracle for the type-recovery tests: gdb stops a fixture after its
# DatInit000 functions ran and dumps the writable memory they filled.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends gdb \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /work
