#include "../include/fuzzing.hpp"

std::vector<std::function<responsePacket*(int)>> 
Responses = { [](int fuzz_level) -> responsePacket* { return new Version(fuzz_level); },
              [](int fuzz_level) -> responsePacket* { return new Capabilities(fuzz_level); },
              [](int fuzz_level) -> responsePacket* { return new Algorithms(fuzz_level); },
              [](int fuzz_level) -> responsePacket* { return new Digests(fuzz_level); },
              [](int fuzz_level) -> responsePacket* { return new Certificate(fuzz_level); },
              [](int fuzz_level) -> responsePacket* { return new ChallengeAuth(fuzz_level); } };

std::vector<std::string> ResponseNames = { "VERSION", "CAPABILITIES", "ALGORITHMS", "DIGESTS", "CERTIFICATE", "CHALLENGE_AUTH" };
std::vector<std::string> RequestNames = { "GET_VERSION", "GET_CAPABILITIES", "NEGOTIATE_ALGORITHMS", "GET_DIGESTS", "GET_CERTIFICATE", "CHALLENGE" };

Fuzzer::Fuzzer(int port, int timer, size_t max_length, bool verbose, int fuzz_level)
{
    this->buffer = new u8[max_length];
    this->socket = new TCP(port, verbose);

    this->i_request = 0;
    this->i_response = -1;
    this->old_response_size = 0;

    this->timer = timer;
    this->verbose = verbose;
    this->fuzz_level = fuzz_level;
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

void Fuzzer::printStoredPackets()
{
    fuzzerConsole("wow! You have unexpected response(s):", !verbose, '!');

    for (size_t i = 0; i < storedResponses.size(); ++i) {
        if (i < ResponseNames.size() && i < RequestNames.size()) {
            socketConsole((ResponseNames[i] + ": ").c_str(), storedResponses[i].first.data(), storedResponses[i].second, !verbose);
            socketConsole((RequestNames[i + 1] + ": ").c_str(), storedRequests[i].first.data(), storedRequests[i].second, !verbose);
        }
    }
}

void Fuzzer::cleanStoredPackets()
{
    storedResponses.clear();
    storedRequests.clear();
}

bool Fuzzer::assertRequest()
{
    if (!socket->checkConnection()) startRequester();
    if (!socket->responderRead(&command, &ttype, &size, buffer)) return false;

    ttype = ntohl(ttype);

    if (i_request > 0 && i_response >= storedResponses.size()) {
        fuzzerConsole("wow! The last response wasn't expected.", verbose, '!');

        size = ntohl(size);

        std::vector<u8> reqPacket(buffer, buffer + size);
        std::vector<u8> resPacket(packet->getSize());

        packet->serialize(resPacket.data());

        storedRequests.emplace_back(std::move(reqPacket), size);
        storedResponses.emplace_back(std::move(resPacket), packet->getSize());
        
        sleep(timer);
    }
    return true;
}

bool Fuzzer::fuzzerLoop()
{
    while (true) {
        if (!assertRequest()) {
            if (fuzz_level == 3) backtrackFuzzing();
            else linearFuzzing();
            
            continue;
        }
        i_request++; 
        i_response++;
        break;
    }
    return true;
}

void Fuzzer::linearFuzzing()
{
    if (!storedResponses.empty()) {
        printStoredPackets();
        cleanStoredPackets();
    }
    fuzzerConsole("Requester (client) failed. Trying to restart.", verbose, '!');
}

void Fuzzer::backtrackFuzzing()
{
    if (old_response_size != storedResponses.size()) {
        printStoredPackets();
        fuzzerConsole("Trying to fuzz the next response...", !verbose, '+');

        if (storedResponses.size() == ResponseNames.size()) {
            fuzzerConsole("nice! All supported responses were unexpected. Fuzzing round finished, starting another one...", verbose, '!');
            cleanStoredPackets();
            system("killall SpdmRequesterTest > /dev/null");
        }
        old_response_size = storedResponses.size();
    }
}

void Fuzzer::deletePacket()
{
    if (packet) {
        delete packet;
        packet = nullptr;
    }
}

void Fuzzer::fuzz()
{
    deletePacket();

    // Backtrack fuzzing
    if (fuzz_level == 3 && i_response < storedResponses.size()) {
        size = storedResponses[i_response].second;
        memcpy(buffer, storedResponses[i_response].first.data(), size);
    }
    // Linear fuzzing or backtrack without sufficient
    else {
        if (fuzz_level == -1) 
            packet = Responses[i_response](randomize(0, 2));
        else packet = Responses[i_response](fuzz_level);
        
        packet->serialize(buffer);
        size = packet->getSize();
    }
    socket->responderWrite(command, ttype, size, buffer);
}