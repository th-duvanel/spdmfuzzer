#!/bin/bash

# Sniffer in background
tshark -i lo -f "tcp port 2323" -w /home/spdmfuzzer/spdmfuzzer.pcapng > /dev/null &
tshark_pid=$!

./spdmfuzzer

kill -9 $!

exit 0