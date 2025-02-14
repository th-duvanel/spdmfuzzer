FROM debian:bullseye-slim AS builder

RUN apt update && apt install -y \
    gcc \
    git \
    make \
    g++ \
    wget \
    tar \
    gawk \
    cmake \
    moreutils \
    xz-utils \
    psmisc

RUN git clone https://github.com/th-duvanel/spdmfuzzer.git /home/spdmfuzzer
WORKDIR /home/spdmfuzzer
RUN git checkout containerized-fuzzer

RUN chmod +x compile.sh
RUN ./compile.sh

RUN ./spdmfuzzer -f 1 > /home/spdmfuzzer/output.txt 2>&1