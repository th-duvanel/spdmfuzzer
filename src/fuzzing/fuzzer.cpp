#include "../../include/fuzzing/fuzzer.hpp"

Fuzzer::Fuzzer(int port, int fuzzStrategy, size_t bufferSize, bool verbose)
{
    Logger = new ConsoleLogger(verbose);
    Socket = new SocketTCP(Logger, port, verbose);

    switch (fuzzStrategy) {
        case 0:
            Strategy = new MockedStrategy();
            break;
        case 1:
            Strategy = new RandomStrategy();
            break;
        case 2:
            Strategy = new LinearStrategy();
            break;
        case 3:
            Strategy = new BacktrackStrategy();
            break;
        case 4:
            Strategy = new CheckpointStrategy();
            break;
        default:
            Strategy = new RandomStrategy();
            break;
    }
}

void Fuzzer::StartRequester()
{
    system("killall SpdmRequesterTest > /dev/null");
    system("cd openspdm/build/bin/ && ./SpdmRequesterTest > /dev/null &");

    Logger->onEvent("+", "Requester started in the background.");
    Socket->AcceptRequester();
}

void Fuzzer::Round()
{
    StartRequester();

    while (Socket->ReadResponder(Request)) {
        Response = Strategy->InterpretRequest(Request);

        if (!Socket->WriteResponder(Response)) {
            break;
        }
    }
}

void Fuzzer::Run()
{
    while (1) {
        Logger->ShowStart();
        Round();
        Logger->ShowEnd();
    }
}