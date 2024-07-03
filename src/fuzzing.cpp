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
                                               &Fuzzer::fuzzAlgorithms, 
                                               &Fuzzer::fuzzDigets, 
                                               &Fuzzer::fuzzCertificate1, 
                                               &Fuzzer::fuzzCertificate2, 
                                               &Fuzzer::fuzzChallange };

// TODO: could construct with member init? (ugly)
Fuzzer::Fuzzer(int port, int timer, size_t max_length)
{
    this->buffer = new u8[max_length];
    this->i_request = 0;
    this->i_response = -1;
    this->socket = new TCP(port);
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

    if (i_request > 0) {
        fuzzerConsole("wow! this is not expected.");
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

void Fuzzer::fuzzVersion(bool fuzz, bool random_size) 
{ 
    u32 size = SIZE_VERSION;
    Version* version = nullptr; // Inicializa version como nullptr

    if (fuzz) { 
        version = new Version(random_size);
        buffer = version->serialize();
        size   = version->getSize();
    }
    else buffer = mockedVersion;

    socket->responderWrite(command, headerMCTP, size, buffer);
    if (version) delete version;
}

void Fuzzer::fuzzCapabilities(bool fuzz, bool random_size)
{
    socket->responderWrite(command, headerMCTP, SIZE_CAPABILITIES, mockedCapabilities);
}

void Fuzzer::fuzzAlgorithms(bool fuzz, bool random_size)
{
    socket->responderWrite(command, headerMCTP, SIZE_ALGORITHMS, mockedAlgorithms);
}

void Fuzzer::fuzzDigets(bool fuzz, bool random_size)
{
    socket->responderWrite(command, headerMCTP, SIZE_DIGESTS, mockedDigests);
}

void Fuzzer::fuzzCertificate1(bool fuzz, bool random_size)
{
    socket->responderWrite(command, headerMCTP, SIZE_CERTIFICATE1, mockedCertificate1);
}

void Fuzzer::fuzzCertificate2(bool fuzz, bool random_size)
{
    socket->responderWrite(command, headerMCTP, SIZE_CERTIFICATE2, mockedCertificate2);
}

void Fuzzer::fuzzChallange(bool fuzz, bool random_size)
{
    socket->responderWrite(command, headerMCTP, SIZE_CHALLENGEAUTH, mockedChallengeAuth);
}