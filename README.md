# spdmfuzzer: a grammar fuzzer for the Security Protocol Data Model

This repo is part of an Undergraduate Research by FAPESP, that aims to develop and test older implementations of SPDM,
with an objective of searching for vulnerabilities that were already discovered, with the addition of a fuzzer, to claim that
if the fuzzer was developed before, the results would be more satisfactory.

## The fuzzer

The fuzzer is made in C++. In the ``Fuzzer`` folder you chan check that are two different folder: ``local`` and ``x86``.

The ``local`` folder is the one that we are now working on. The "local" means that we are testing te implementation in a
local environment, without having to emulate it all over again, like in other project I've made, that you can check in the
links below. There is a script to compile the older version of SPDM and a newer version, that is not appliable to this moment.

The ``x86`` folder has an implementation of a SPDM emulation, on a x86 system in a Hard Drive. We have the objective to
implement the fuzzer in this environment, making it more close to reality as possible.

## How to

To run the fuzzers and the environment made for the test, you can check the documentation inside each folder. If there isn't a
doc yet, please, be patient. I'm working the best I can to deliver both docs and good coding.

## Other projects related to SPDM
* **SPDM-WID** - [GitHub](https://github.com/th-duvanel/spdm-wid)
* **RISCV-SPDM** - [GitHub](https://github.com/th-duvanel/riscv-spdm)

## Author

* **Thiago Duvanel Ferreira** - [Linkedin](https://www.linkedin.com/in/thiago-duvanel-ferreira-142028244/) - [GitHub](https://github.com/th-duvanel)



