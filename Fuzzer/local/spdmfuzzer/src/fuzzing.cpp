#include "../include/fuzzing.hpp"

#include <cstdlib>  // For requester start

std::vector<u8*> RequestPackets = { mockedGetVersion, 
                                    mockedGetCapabilities, 
                                    mockedNegAlgorithms, 
                                    mockedGetDigests, 
                                    mockedGetCertificate,
                                    mockedChallange};

std::vector<fuzzFunctions> ResponsePackets = { &Fuzzer::fuzzVersion, 
                                               &Fuzzer::fuzzCapabilities,
                                               &Fuzzer::fuzzNegAlgorithms, 
                                               &Fuzzer::fuzzDigets, 
                                               &Fuzzer::fuzzCertificate1, 
                                               &Fuzzer::fuzzCertificate2, 
                                               &Fuzzer::fuzzChallange };

// TODO: could construct with member init? (ugly)
Fuzzer::Fuzzer(int port, size_t max_length)
{
    this->buffer = new u8[max_length];
    this->i_request = 0;
    this->i_response = -1;
    this->socket = new TCP(port);
}

void Fuzzer::startRequester()
{
    // If not, start the binary in the background
    system("../openspdm/build/bin/SpdmRequesterTest > /dev/null &");
    i_request = 0;
    i_response = -1;
    fuzzerConsole("Requester (client) started in the background");
    socket->acceptRequester();
}

bool Fuzzer::assertRequest()
{
    u8* castedBuffer = static_cast<u8*>(buffer);

    if (!socket->checkConnection()) startRequester();
    if (!socket->responderRead(&command, &ttype, &size, buffer)) return false;

    for (size_t i = 0 ; i < ntohl(size) ; i++) {
        if (castedBuffer[i] != RequestPackets[i_request][i]) {
            fuzzerConsole("Request packet does not match");
            return false;
        }
    }
    return true;
}

bool Fuzzer::fuzzerLoop()
{
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



void Fuzzer::fuzzVersion(bool fuzz) 
{ 
    if (fuzz) buffer = (new Version())->serialize();
    else      buffer = mockedVersion;

    socket->responderWrite(command, headerMCTP, SIZE_VERSION, buffer);
}

void Fuzzer::fuzzCapabilities(bool fuzz)
{
    socket->responderWrite(command, headerMCTP, SIZE_CAPABILITIES, mockedCapabilities);
}

void Fuzzer::fuzzNegAlgorithms(bool fuzz)
{
    socket->responderWrite(command, headerMCTP, SIZE_NEGALGORITHMS, mockedNegAlgorithms);
}

void Fuzzer::fuzzDigets(bool fuzz)
{
    socket->responderWrite(command, headerMCTP, SIZE_DIGESTS, mockedDigests);
}

void Fuzzer::fuzzCertificate1(bool fuzz)
{
    socket->responderWrite(command, headerMCTP, SIZE_CERTIFICATE1, mockedCertificate1);
}

void Fuzzer::fuzzCertificate2(bool fuzz)
{
    socket->responderWrite(command, headerMCTP, SIZE_CERTIFICATE2, mockedCertificate2);
}

void Fuzzer::fuzzChallange(bool fuzz)
{
    socket->responderWrite(command, headerMCTP, SIZE_CHALLENGEAUTH, mockedChallengeAuth);
}