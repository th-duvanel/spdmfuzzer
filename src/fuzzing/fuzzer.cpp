#include "../../include/fuzzing/fuzzer.hpp"

Fuzzer::Fuzzer(int port, int fuzzStrategy, size_t bufferSize, bool verbose, int extra)
{
    Logger = new ConsoleLogger(verbose);
    Socket = new SocketTCP(Logger, port, verbose);

    Response = new MessageSPDM(bufferSize);
    Request = new MessageSPDM(bufferSize);

    switch (fuzzStrategy) {
        case 0:
            Strategy = new MockedStrategy(Logger);
            break;
        case 1:
            Strategy = new RandomStrategy(Logger);
            break;
        case 2:
            Strategy = new SizedStrategy(Logger);
            break;
        case 3:
            Strategy = new GrammaticalStrategy(Logger);
            break;
        case 4:
            Strategy = new BacktrackStrategy(Logger);
            break;
        case 5:
            Strategy = new CheckpointStrategy(Logger, extra);
            break;
        default:
            Strategy = new GrammaticalStrategy(Logger);
            break;
    }
}

void Fuzzer::StartRequester()
{
    system("killall SpdmRequesterTest > /dev/null 2>&1");
    system("cd openspdm/build/bin/ && ./SpdmRequesterTest > /dev/null &");

    Logger->onEvent("+", "Requester started in the background.");
    Socket->AcceptRequester();
}

void Fuzzer::Round()
{
    StartRequester();

    while (Socket->ReadResponder(Request)) {
        if (!Strategy->InterpretRequest(Request, Response)) {
            break;
        }
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