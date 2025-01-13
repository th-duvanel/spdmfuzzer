#include "../../include/fuzzing/fuzz_strategy.hpp"

MessageSPDM MockedStrategy::InterpretRequest(MessageSPDM &request)
{
    MessageSPDM response;
    u8 response_code = RequestToResponseCode[request.getCode()];

    response.Buffer = MockedPackets[response_code].data();
    response.Size = MockedPackets[response_code].size();

    return response;
}

MessageSPDM RandomStrategy::InterpretRequest(MessageSPDM &request)
{
 
}

MessageSPDM GrammaticalStrategy::InterpretRequest(MessageSPDM &request)
{
 
}

MessageSPDM LinearStrategy::InterpretRequest(MessageSPDM &request)
{
 
}

MessageSPDM BacktrackStrategy::InterpretRequest(MessageSPDM &request)
{
 
}

MessageSPDM CheckpointStrategy::InterpretRequest(MessageSPDM &request)
{
 
}