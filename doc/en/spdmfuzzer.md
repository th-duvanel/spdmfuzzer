# spdmfuzzer

In this document, you can find more technical details about ``spdmfuzzer``.

## Fuzzing Campaign
It is possible to easily change the fuzzer campaign by modifying the program's main and the fuzzing.cpp, which is the kernel of the fuzzer. In the future, new functionalities will be implemented to facilitate this modification. The ultimate goal is to make the fuzzer fully modular by only changing function arguments in the main or perhaps terminal inputs.

More details about fuzzer campaign change will be applied to this doc in the future.

## Architecture
The fuzzer was made in C++ because it is an object-oriented language. Additionally, since the standard SPDM libraries are written in C, it is possible to configure them to be combined in some way in the future, maybe when the fuzzer is placed in an emulated environment, meaning it will no longer be a binary but will become a library.

Each packet and each functionality is a different object; this was used to facilitate and construct the fuzzer's grammar.

## Grammar
The grammar, as previously mentioned, was created from objects. The innermost part of the packets, such as specific bytes that can only assume specific values, was made using dictionaries (map in C++), inspired by Luis Rodriguez's fuzzer, which can be found [here](https://gitfront.io/r/luisgar1990/aZXKzGjT1Wzj/mqttgram-h-repo/).

## Random Number Generation
A C++ standard library was used, which utilizes the Marsenne Twister Engine (std::mt19937) to generate random numbers, an important part of the fuzzing process.
