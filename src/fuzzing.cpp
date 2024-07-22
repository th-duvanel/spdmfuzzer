#include "../include/fuzzing.hpp"

#include <cstdlib>


std::vector<fuzzFunctions> responseFuzzing = { &Fuzzer::fuzzVersion, 
                                               &Fuzzer::fuzzCapabilities,
                                               &Fuzzer::fuzzAlgorithms, 
                                               &Fuzzer::fuzzDigests, 
                                               &Fuzzer::fuzzCertificate1, 
                                               &Fuzzer::fuzzCertificate2, 
                                               &Fuzzer::fuzzChallenge };

Fuzzer::Fuzzer(int port, int timer, size_t max_length)
{
    this->buffer = new u8[max_length];
    this->socket = new TCP(port);

    this->i_request = 0;
    this->i_response = -1;

    this->timer = timer;
}

void Fuzzer::startRequester()
{
    system("cd openspdm/build/bin/ && ./SpdmRequesterTest > /dev/null &");
    i_request = 0;
    i_response = -1;
    fuzzerConsole("Requester (client) started in the background");
    socket->acceptRequester();
}

bool Fuzzer::assertRequest()
{
    if (!socket->checkConnection()) startRequester();
    if (!socket->responderRead(&command, &ttype, &size, buffer)) return false;

    ttype = ntohl(ttype);

    if (i_request > 0) {
        fuzzerConsole("wow! this is not expected.");
        // Add the spdm accepted message to the list of accepted messages.
        sleep(timer);
    }
    return true;
}

bool Fuzzer::fuzzerLoop()
{
    // ToDo: checks if last fuzzed packet was accepted. If it was,
    // continue using it in all next connections, until finding the next
    // fuzzed packet that continues the connection.
    while (true)
    {
        if (!assertRequest())
        {
            fuzzerConsole("Requester (client) failed. Trying to restart.", '!');
            continue;
        }
        i_request++; // Iterates to next request packet to check.
        i_response++;

        break;
    }
    return true;
}

size_t Fuzzer::getIResponse()
{
    return i_response;
}

void Fuzzer::fuzzVersion(bool fuzz, size_t max) 
{ 
    buffer = mockedVersion;
    size = SIZE_VERSION;

    if (fuzz) {
        if (packet) delete packet;  // Clears last packet
        packet = new Version();
        buffer = packet->serialize(max);
        size   = packet->getSize();
    }

    // ToDo: try to remove the line below, since it is repeated in each function.
    // problem: i can't put the line in fuzzerLoop, since the packet will be generated before
    // receiving anything from the requester, and in future packets i need the received packet.

    // solution (maybe?): create a generic function for all the packets. Instead of using the
    // function pointer, use a switch case to call the correct function.
    socket->responderWrite(command, ttype, size, buffer);
}

void Fuzzer::fuzzCapabilities(bool fuzz, size_t max)
{
    buffer = mockedCapabilities;
    size = SIZE_CAPABILITIES;

    if (fuzz) {
        if (packet) delete packet;  // Clears last packet
        packet = new Capabilities();
        buffer = packet->serialize(max);
        size   = packet->getSize();
    }

    socket->responderWrite(command, ttype, size, buffer);
}

void Fuzzer::fuzzAlgorithms(bool fuzz, size_t max)
{
    buffer = mockedAlgorithms;
    size = SIZE_ALGORITHMS;

    if (fuzz) {
        if (packet) delete packet;  // Clears last packet
        packet = new Algorithms();
        buffer = packet->serialize(max);
        size   = packet->getSize();
    }

    socket->responderWrite(command, ttype, size, buffer);
}

void Fuzzer::fuzzDigests(bool fuzz, size_t max)
{
    socket->responderWrite(command, ttype, SIZE_DIGESTS, mockedDigests);
}

void Fuzzer::fuzzCertificate1(bool fuzz, size_t max)
{
    socket->responderWrite(command, ttype, SIZE_CERTIFICATE1, mockedCertificate1);
}

void Fuzzer::fuzzCertificate2(bool fuzz, size_t max)
{
    socket->responderWrite(command, ttype, SIZE_CERTIFICATE2, mockedCertificate2);
}

void Fuzzer::fuzzChallenge(bool fuzz, size_t max)
{
    socket->responderWrite(command, ttype, SIZE_CHALLENGEAUTH, mockedChallengeAuth);
}