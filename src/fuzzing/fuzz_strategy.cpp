#include "../../include/fuzzing/fuzz_strategy.hpp"

MockedStrategy::MockedStrategy(Observer *Logger) : FuzzStrategy(Logger) {}
RandomStrategy::RandomStrategy(Observer *Logger) : FuzzStrategy(Logger) {}
GrammaticalStrategy::GrammaticalStrategy(Observer *Logger) : FuzzStrategy(Logger) {}
SizedStrategy::SizedStrategy(Observer *Logger) : GrammaticalStrategy(Logger) {}
BacktrackStrategy::BacktrackStrategy(Observer *Logger) : GrammaticalStrategy(Logger) {}
CheckpointStrategy::CheckpointStrategy(Observer *Logger, u8 Checkpoint) : GrammaticalStrategy(Logger) { this->Checkpoint = Checkpoint; }

FuzzStrategy::FuzzStrategy(Observer *Logger) : Logger(Logger) {
    Factory = new PacketFactory();
    certifiedSent = false;
}

bool FuzzStrategy::CheckRequest(MessageSPDM *request, MessageSPDM *response)
{   
    if (RequestToResponseCode.find(request->getCode()) == RequestToResponseCode.end()) {
        response->Buffer = MockedPackets[0].data();
        response->Size = MockedPackets[0].size();

        Logger->onEvent("!", "Unexpected request code: " + std::to_string(request->getCode()));
        return false;
    }
    return true;
}

bool MockedStrategy::InterpretRequest(MessageSPDM *request, MessageSPDM *response)
{
    if (!CheckRequest(request, response)) {
        return false;
    }

    u8 response_code = RequestToResponseCode[request->getCode()];
    Logger->onResponse(*response, 0);   // Older response (to other request)
    Logger->onResponse(*request, 0);    // Received request

    response->Command = ntohl(request->Command);
    response->TransportType = ntohl(request->TransportType);

    if (response_code == 0x02) {
        // Checks certificate sent
        if (certifiedSent) {
            response->Buffer = mockedCertificate2.data();
            response->Size = mockedCertificate2.size();
            certifiedSent = false;
        }
        else {
            response->Buffer = mockedCertificate1.data();
            response->Size = mockedCertificate1.size();
            certifiedSent = true;
        }
    }
    else {
        response->Buffer = MockedPackets[response_code].data();
        response->Size = MockedPackets[response_code].size();
    }

    return response;
}

bool RandomStrategy::InterpretRequest(MessageSPDM *request, MessageSPDM *response)
{
    if (!CheckRequest(request, response)) {
        return false;
    }
    response->Command = ntohl(request->Command);
    response->TransportType = ntohl(request->TransportType);

    u8 response_code = RequestToResponseCode[request->getCode()];
    Logger->onResponse(*response, 1);   // Older response (to other request)
    Logger->onResponse(*request, 1);    // Received request

    // Sends Server Hello
    if (response_code == 0x72) {
        response->Buffer = MockedPackets[response_code].data();
        response->Size = MockedPackets[response_code].size();
    }
    else if (response_code == 0x02) {
        // Checks certificate sent
        if (certifiedSent) {
            response->Buffer = mockedCertificate2.data();
            response->Size = mockedCertificate2.size();
            certifiedSent = false;
        }
        else {
            response->Buffer = mockedCertificate1.data();
            response->Size = mockedCertificate1.size();
            certifiedSent = true;
        }
    }
    else {
        Factory->CreatePacket(response_code, 1, response);
    }

    return response;    // New response
}

bool GrammaticalStrategy::InterpretRequest(MessageSPDM *request, MessageSPDM *response)
{
    if (!CheckRequest(request, response)) {
        return false;
    }
    response->Command = ntohl(request->Command);
    response->TransportType = ntohl(request->TransportType);

    u8 response_code = RequestToResponseCode[request->getCode()];
    Logger->onResponse(*response, 3);   // Older response (to other request)
    Logger->onResponse(*request, 3);    // Received request

    // Sends Server Hello
    if (response_code == 0x72) {
        response->Buffer = MockedPackets[response_code].data();
        response->Size = MockedPackets[response_code].size();
    }
    else if (response_code == 0x02) {
        // Checks certificate sent
        if (certifiedSent) {
            response->Buffer = mockedCertificate2.data();
            response->Size = mockedCertificate2.size();
            certifiedSent = false;
        }
        else {
            response->Buffer = mockedCertificate1.data();
            response->Size = mockedCertificate1.size();
            certifiedSent = true;
        }
    }
    else {
        Factory->CreatePacket(response_code, 3, response);
    }

    return response;
}

bool SizedStrategy::InterpretRequest(MessageSPDM *request, MessageSPDM *response)
{
    if (!CheckRequest(request, response)) {
        return false;
    }
    response->Command = ntohl(request->Command);
    response->TransportType = ntohl(request->TransportType);

    u8 response_code = RequestToResponseCode[request->getCode()];
    Logger->onResponse(*response, 1);   // Older response (to other request)
    Logger->onResponse(*request, 1);    // Received request

    // Sends Server Hello
    if (response_code == 0x72) {
        response->Buffer = MockedPackets[response_code].data();
        response->Size = MockedPackets[response_code].size();
    }
    else if (response_code == 0x02) {
        // Checks certificate sent
        if (certifiedSent) {
            response->Buffer = mockedCertificate2.data();
            response->Size = mockedCertificate2.size();
            certifiedSent = false;
        }
        else {
            response->Buffer = mockedCertificate1.data();
            response->Size = mockedCertificate1.size();
            certifiedSent = true;
        }
    }
    else {
        Factory->CreatePacket(response_code, 2, response);
    }

    return response;
}

bool BacktrackStrategy::InterpretRequest(MessageSPDM *request, MessageSPDM *response)
{
    MessageSPDM* foundMessage;

    if (!CheckRequest(request, response)) {
        return false;
    }

    // Searchs if the last accepted response is already on the vector
    foundMessage = findMessage(StoredResponses, response->getCode());
    if (!foundMessage) {
        // If is not, adds to the vector and warns the user.
        StoredResponses.push_back(*response);
        Logger->onResponse(*response, 1);   // Older response (to other request)
        Logger->onResponse(*request, 1);    // Received request
    }

    u8 response_code = RequestToResponseCode[request->getCode()];
    // Searchs if the next response is already on the vector
    foundMessage = findMessage(StoredResponses, response_code);
    if (!foundMessage) {
        // If is not, need to create it. We don't add it to the vector because we don't
        // know yet if it will be accepted.
        if (response_code == 0x02) {
            // Checks certificate sent
            if (certifiedSent) {
                response->Buffer = mockedCertificate2.data();
                response->Size = mockedCertificate2.size();
                certifiedSent = false;
            }
            else {
                response->Buffer = mockedCertificate1.data();
                response->Size = mockedCertificate1.size();
                certifiedSent = true;
            }
        }
        else {
            Factory->CreatePacket(response_code, 1, response);
        }
    }
    else {
        response = foundMessage;
    }

    return response;
}

bool CheckpointStrategy::InterpretRequest(MessageSPDM *request, MessageSPDM *response)
{
    if (!CheckRequest(request, response)) {
        return false;
    }
    response->Command = ntohl(request->Command);
    response->TransportType = ntohl(request->TransportType);

    u8 response_code = RequestToResponseCode[request->getCode()];

    if (response_code == 0x04) {
        // Restarts the checkpoint counter in GET_VERSION response
        CurrentCheckpoint = Checkpoint;
    }

    if (response_code == 0x72 || CurrentCheckpoint--) {
        response->Buffer = MockedPackets[response_code].data();
        response->Size = MockedPackets[response_code].size();
    }
    else if (response_code == 0x02) {
        // Checks certificate sent
        if (certifiedSent) {
            response->Buffer = mockedCertificate2.data();
            response->Size = mockedCertificate2.size();
            certifiedSent = false;
        }
        else {
            response->Buffer = mockedCertificate1.data();
            response->Size = mockedCertificate1.size();
            certifiedSent = true;
        }
    }
    else {
        Logger->onResponse(*response, 1);   // Older response (to other request)
        Logger->onResponse(*request, 1);    // Received request
        Factory->CreatePacket(response_code, 1, response);
    }

    return response;
}