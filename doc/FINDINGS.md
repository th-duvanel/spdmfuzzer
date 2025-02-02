# Unexpected responses

This document describes which messages and types were found during the fuzzing process. The fuzzer sends messages to the requester, and the requester responds with unexpected messages.

## VERSION
- Any messages with the 02 in the version quantity field were accepted.
- Messages much longer than that causes Segmentation Fault in the Requester, which causes to closing the connection.

## CAPABILITIES
- Basically, any message with a determined size is accepted. This is not 
a very uncommon practice, since this Message is all defined by the Responder, our fuzzer, so the Requester "trusts" the fuzzer.
- Messages much longer than that causes Segmentation Fault in the Requester, which causes to closing the connection.

## ALGORITHMS

## DIGESTS

## CERTIFICATE

## CHALLENGE_AUTH

## MEASUREMENTS