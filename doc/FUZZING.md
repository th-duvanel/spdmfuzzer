# Fuzzing Strategies

## 0 - Random Options
It chooses randomly each round a option from below.

## 1 - Totally Random Fuzzing with fixed length
The fuzzer will generate random messages with fixed lengths, for example, it will generate a message with 10 bytes, then another with 10 bytes, and so on. The message will be totally random, with no constraints.

## 2 - Totally Random Fuzzing with random added length
The fuzzer will generate random messages with random lengths, for example, it will generate a message with 10 bytes, then 20 bytes, then 30 bytes, and so on. The message will be totally random, with no constraints.

## 3 - Random Fuzzing with acceptable values
The fuzzer will generate random messages with acceptable values, for example,
it will follow the available algorithms by the Requester, and not random ones. Besides that, message sizes will be kept.

## 4 - Backtrack
The fuzzer will try to create messages from the beginning. When a message is responded by the requester with a new request, the message will be stored and used in every round to reach the same point that the before round, until it finds another accepted message and the process starts all over again, until all the types of messages are sent.

## 5 - Checkpoint
The user choices a point to begin the message sending. For example, if he
chooses to start in the CAPABILITIES message, the fuzzer will reach CAPABILITIES with mocked messages, and then start to fuzzing.


