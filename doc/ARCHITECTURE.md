# Class description

## Fuzz Strategy
Uses the Strategy pattern to assign a strategy to the Fuzz class. The strategy is used to determine the behavior of the Fuzz class, and depending on the input (request message) it returns a fuzzed response message.

## Packet Factory
Uses the Factory pattern to create packets. The Packet Factory class is responsible for creating packets of different types from the SPDM architecture, using packet arguments as input to determine different fields.

## Observer
Uses the Observer pattern to observe and log any message from the Fuzzer or the Requester. The Observer class is responsible for logging the messages and the time they were sent.

## IO
Uses the Adapter pattern to adapt the IO class to the Fuzzer and Requester classes. The IO class is responsible for reading and writing messages to the network, and the Fuzzer and Requester classes are responsible for sending and receiving messages to and from the network.