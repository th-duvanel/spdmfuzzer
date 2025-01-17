#include "../../include/fuzzing/fuzz_strategy.hpp"

FuzzStrategy::FuzzStrategy(Observer *Logger) : Logger(Logger) {}
MockedStrategy::MockedStrategy(Observer *Logger) : FuzzStrategy(Logger) {}
RandomStrategy::RandomStrategy(Observer *Logger) : FuzzStrategy(Logger) {}
GrammaticalStrategy::GrammaticalStrategy(Observer *Logger) : FuzzStrategy(Logger) {}
LinearStrategy::LinearStrategy(Observer *Logger) : GrammaticalStrategy(Logger) {}
BacktrackStrategy::BacktrackStrategy(Observer *Logger) : GrammaticalStrategy(Logger) {}
CheckpointStrategy::CheckpointStrategy(Observer *Logger) : GrammaticalStrategy(Logger) {}

bool MockedStrategy::InterpretRequest(MessageSPDM *request, MessageSPDM *response)
{
    if (RequestToResponseCode.find(request->getCode()) == RequestToResponseCode.end()) {
        response->Buffer = MockedPackets[0].data();
        response->Size = MockedPackets[0].size();

        Logger->onEvent("!", "Unexpected request code: " + std::to_string(request->getCode()));
        return response;
    }
    u8 response_code = RequestToResponseCode[request->getCode()];

    Logger->onResponse(*request);

    response->Command = ntohl(request->Command);
    response->TransportType = ntohl(request->TransportType);
    response->Buffer = MockedPackets[response_code].data();
    response->Size = MockedPackets[response_code].size();

    return response;
}

bool RandomStrategy::InterpretRequest(MessageSPDM *request, MessageSPDM *response)
{

}

bool GrammaticalStrategy::InterpretRequest(MessageSPDM *request, MessageSPDM *response)
{
 
}

bool LinearStrategy::InterpretRequest(MessageSPDM *request, MessageSPDM *response)
{
 
}

bool BacktrackStrategy::InterpretRequest(MessageSPDM *request, MessageSPDM *response)
{
 
}

bool CheckpointStrategy::InterpretRequest(MessageSPDM *request, MessageSPDM *response)
{
 
}