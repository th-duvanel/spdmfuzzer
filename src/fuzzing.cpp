#include "../include/fuzzing.hpp"

std::vector<std::function<responsePacket*(int)>> 
Responses = { [](int fuzz_level) -> responsePacket* { return new Version(fuzz_level); },
              [](int fuzz_level) -> responsePacket* { return new Capabilities(fuzz_level); },
              [](int fuzz_level) -> responsePacket* { return new Algorithms(fuzz_level); }, };

Fuzzer::Fuzzer(int port, int timer, size_t max_length)
{
    this->buffer = new u8[max_length];
    this->socket = new TCP(port);
    this->i_request = 0;
    this->i_response = -1;
    this->timer = timer;
    this->packet = nullptr;
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

void Fuzzer::deletePacket()
{
    if (this->packet) {
        delete packet;
        packet = nullptr;
    }
}

void Fuzzer::fuzz(int fuzz_level)
{
    deletePacket();

    packet = Responses[i_response](fuzz_level);
    packet->serialize(buffer);

    socket->responderWrite(command, ttype, packet->getSize(), buffer);
}