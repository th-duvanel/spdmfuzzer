# spdmfuzzer: a grammar-based fuzzer for SPDM

The `spdmfuzzer` is an object-oriented grammar-based fuzzer that takes on the role of a `Responder` in SPDM protocol communications. Its objective is to send semi-random messages to the `Requester` in order to explore unexpected responses for analysis.

The binary automatically starts the `Requester` as communication may terminate if the `Requester` does not find the received message favorable to continue the exchange. To ensure functionality, all folders and files must be maintained as organized within the repository.

If the fuzzer receives an unexpected response, it saves the message used and continues using it until a successful connection is established.

You can check a version of this document in Portuguese-Brazilian. It's available in the ``doc`` folder.

## Compilation and Execution

**Assuming you have an up-to-date Linux system. Preferably, a distribution with apt package manager.**

We strongly recommend using `spdm-wid` listed in the Related Projects section below, which is a dissector for understanding packets in tcpdump or Wireshark.

It's worth noting that the fuzzer sends messages individually (header, command, buffer, size), so there might be differences in transmission depending on how the TCP protocol aggregates sent packets into one, making it difficult for `spdm-wid` to parse as bytes may not be formatted exactly as in real communication due to emulation errors such as missing size, etc. If this occurs, simply rerun it or wait for another well-formed packet to appear.

Set the packet filter as follows:
```
tcp.port == 2323 && tcp.flags.push == 1
```

Here, you can follow two paths:
1. Compile on your own machine
2. Automatically compile in a Docker container

Regardless of the process, you need to clone the repository:
```console
foo@current-folder:~$ git clone https://github.com/th-duvanel/spdmfuzzer.git
foo@current-folder:~$ cd spdmfuzzer
```

Now you can choose one of the paths described above.

### Compile on your own machine

If installing libraries and dependencies is not an issue for you, feel free to install locally on your machine. There is no need to execute anything with elevated privileges; simply grant execution permission to the bash script.

It will run and check some dependencies on your system (not many), list them, and prompt for installation. To avoid the need to run sudo with a script, it does not install automatically. For double-check, below are the dependencies used in the program.

You do not need to follow the specific version used. Preferably, use the latest version available in your system's package manager or use the automated tutorial in a container.

```
g++ 11.4.0
gawk 5.1.0
tar 1.34
gcc 11.4.0
git 2.34.1
wget 1.21.2
make 4.3
cmake 3.22.1
moreutils 0.66-1 # sponge
xz-utils 5.2.5
psmisc
```

To do this, simply execute in the current folder:
```console
foo@spdmfuzzer:~$ chmod +x compile.sh

foo@spdmfuzzer:~$ ./compile.sh
```

If you want to monitor message exchange, start your preferred sniffer now (preferably with spdm-wid).

To execute with the default configuration, simply:
```console
foo@spdmfuzzer:~$ ./spdmfuzzer
```
To change configurations, try:
```console
foo@spdmfuzzer:~$ ./spdmfuzzer -h
```
All necessary information for understanding will be displayed in your terminal. If you want to understand better the "fuzzing levels",
please, check spdmfuzzer/doc/FUZZING.md.

### Automatically compile in Docker container

The most important dependency in this case is having docker installed on your system.

This method is more automated, with fewer steps and more visual feedback. In addition to being installed and executed in a virtual environment, it will generate a .pcapng for automatic packet study exchange, unlike the previous step, which requires manually running the sniffer.

```console
foo@spdmfuzzer:~$ docker build -t spdmfuzzer .      # build

foo@spdmfuzzer:~$ docker run -ti spdmfuzzer         # execution
```

By default, the fuzzer will run in a screen session, called spdmfuzzer_session. It will run in the fuzzing mode 3, which can be found explanation in the /doc/FUZZING.md file. If you want to change the fuzzing mode, first you find the docker container id with

```console
foo@spdmfuzzer:~$ docker ps -a   # to capture the container id
container ID        IMAGE        NAMES      ...
<container-id>      spdmfuzzer   <name>     ...
```

```console
foo@spdmfuzzer:~$ docker exec -it <container-id> /bin/bash
```
This way, will you have access to the container's terminal, which you can run any command you want. This way, you can follow the steps below, like you're running on your local machine.

Besides all this, you can copy the .pcapng file after you end the container execution, which will end the fuzzer execution too.

```console
foo@spdmfuzzer:~$ docker cp <container-id>:/home/spdmfuzzer/spdmfuzzer.pcapng .     # copies the .pcapng in the actual folder
```

By applying this .pcapng in Wireshark, you will have a complete view of the packet exchange. It is recommended again to use spdm-wid and the packet filter listed above for better visualization.

## Execution (help)



```console
# [*] => Fuzzer started the round.
# [+] => Requester started in the background.
# [IO/TCP] => Requester connected. Unexpected requests:
# [3] => GET_VERSION: 05 10 84 00 00
# [3] => VERSION: 05 75 04 6b 67 96 02 12 59 e0 ee
# [3] => GET_CAPABILITIES: 05 10 e1 00 00
# [3] => CAPABILITIES: 05 cb 61 30 20 2e 0c 42 e6 2c ee 00 80
# [3] => NEGOTIATE_ALGORITHMS: 05 10 e3 00 00 20 00 01 00 10 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
# [IO/TCP] => Requester disconnected.
# [-] => Fuzzer finished the round.
```

## Environment Specifications Used
```console
OS: Ubuntu 22.04.4 LTS x86_64
Kernel: 6.5.0-41-generic
Shell: zsh 5.8.1
CPU: AMD Ryzen 7 5800H with Radeon Graphics (16) @ 4.463GHz
GPU: AMD ATI 05:00.0 Cezanne
GPU: NVIDIA GeForce RTX 3060 Mobile / Max-Q
Memory: 15328MiB
```

## Related Projects

* **SPDM-WID** - [GitHub](https://github.com/th-duvanel/spdm-wid)
* **RISCV-SPDM** - [GitHub](https://github.com/th-duvanel/riscv-spdm)
* **TLS fuzzers for SPDM** - [GitHub](https://github.com/th-duvanel/fuzzer-tests)


## Author

Thiago Duvanel Ferreira - LinkedIn - GitHub
