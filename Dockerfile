FROM ubuntu:22.04

COPY . /home/spdmfuzzer
WORKDIR /home/spdmfuzzer

# Install dependencies
RUN apt-get update && apt-get install -y \
apt-utils \
g++ \
gawk \
tar \
gcc \
git \
wget \
make \
cmake \
moreutils \
xz-utils

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y tshark

RUN chmod +x compile.sh start-fuzzing.sh

RUN ./compile.sh

ENTRYPOINT ["./start-fuzzing.sh"]

