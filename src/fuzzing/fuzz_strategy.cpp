#include "../../include/fuzzing/fuzz_strategy.hpp"

MockedStrategy::MockedStrategy(Observer *Logger) : FuzzStrategy(Logger) {}
RandomStrategy::RandomStrategy(Observer *Logger) : FuzzStrategy(Logger) {}
GrammaticalStrategy::GrammaticalStrategy(Observer *Logger) : FuzzStrategy(Logger) {}
SizedStrategy::SizedStrategy(Observer *Logger) : FuzzStrategy(Logger) {}
BacktrackStrategy::BacktrackStrategy(Observer *Logger) : FuzzStrategy(Logger) {}
CheckpointStrategy::CheckpointStrategy(Observer *Logger, u8 Checkpoint) : FuzzStrategy(Logger) { this->Checkpoint = Checkpoint; }

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
    response->Command = ntohl(request->Command);
    response->TransportType = ntohl(request->TransportType);
    return response;
}

bool RandomStrategy::InterpretRequest(MessageSPDM *request, MessageSPDM *response)
{
    if (!CheckRequest(request, response)) {
        return false;
    }

    u8 response_code = RequestToResponseCode[request->getCode()];
    Logger->onResponse(*response, 1);   // Older response (to other request)
    Logger->onResponse(*request, 1);    // Received request

    // Sends Server Hello
    if (response_code == 0x72) {
        memcpy(response->Buffer, MockedPackets[0x72].data(), MockedPackets[0x72].size());
        response->Size = MockedPackets[0x72].size();
    }
    else if (response_code == 0x02) {
        // Checks certificate sent
        if (certifiedSent) {
            memcpy(response->Buffer, mockedCertificate2.data(), mockedCertificate2.size());
            response->Size = mockedCertificate2.size();
            certifiedSent = false;
        }
        else {
            memcpy(response->Buffer, mockedCertificate1.data(), mockedCertificate1.size());
            response->Size = mockedCertificate1.size();
            certifiedSent = true;
        }
    }
    else {
        Factory->CreatePacket(response_code, 1, response);
    }

    response->Command = ntohl(request->Command);
    response->TransportType = ntohl(request->TransportType);
    return response;
}

bool GrammaticalStrategy::InterpretRequest(MessageSPDM *request, MessageSPDM *response)
{
    if (!CheckRequest(request, response)) {
        return false;
    }

    u8 response_code = RequestToResponseCode[request->getCode()];
    Logger->onResponse(*response, 3);   // Older response (to other request)
    Logger->onResponse(*request, 3);    // Received request

    // Sends Server Hello
    if (response_code == 0x72) {
        memcpy(response->Buffer, MockedPackets[0x72].data(), MockedPackets[0x72].size());
        response->Size = MockedPackets[0x72].size();
    }
    else if (response_code == 0x02) {
        // Checks certificate sent
        if (certifiedSent) {
            memcpy(response->Buffer, mockedCertificate2.data(), mockedCertificate2.size());
            response->Size = mockedCertificate2.size();
            certifiedSent = false;
        }
        else {
            memcpy(response->Buffer, mockedCertificate1.data(), mockedCertificate1.size());
            response->Size = mockedCertificate1.size();
            certifiedSent = true;
        }
    }
    else {
        Factory->CreatePacket(response_code, 3, response);
    }

    response->Command = ntohl(request->Command);
    response->TransportType = ntohl(request->TransportType);
    return response;
}

bool SizedStrategy::InterpretRequest(MessageSPDM *request, MessageSPDM *response)
{
    if (!CheckRequest(request, response)) {
        return false;
    }

    u8 response_code = RequestToResponseCode[request->getCode()];
    Logger->onResponse(*response, 1);   // Older response (to other request)
    Logger->onResponse(*request, 1);    // Received request

    // Sends Server Hello
    if (response_code == 0x72) {
        memcpy(response->Buffer, MockedPackets[0x72].data(), MockedPackets[0x72].size());
        response->Size = MockedPackets[0x72].size();
    }
    else if (response_code == 0x02) {
        // Checks certificate sent
        if (certifiedSent) {
            memcpy(response->Buffer, mockedCertificate2.data(), mockedCertificate2.size());
            response->Size = mockedCertificate2.size();
            certifiedSent = false;
        }
        else {
            memcpy(response->Buffer, mockedCertificate1.data(), mockedCertificate1.size());
            response->Size = mockedCertificate1.size();
            certifiedSent = true;
        }
    }
    else {
        Factory->CreatePacket(response_code, 2, response);
    }
    response->Command = ntohl(request->Command);
    response->TransportType = ntohl(request->TransportType);
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
        Logger->onResponse(*response, 4);   // Older response (to other request)
        Logger->onResponse(*request, 4);    // Received request
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
                memcpy(response->Buffer, mockedCertificate2.data(), mockedCertificate2.size());
                response->Size = mockedCertificate2.size();
                certifiedSent = false;
            }
            else {
                memcpy(response->Buffer, mockedCertificate1.data(), mockedCertificate1.size());
                response->Size = mockedCertificate1.size();
                certifiedSent = true;
            }
        }
        else {
            Factory->CreatePacket(response_code, 3, response);
        }
    }
    else {
        memcpy(response->Buffer, foundMessage->Buffer, foundMessage->Size);
        response->Size = foundMessage->Size;
    }
    response->Command = ntohl(request->Command);
    response->TransportType = ntohl(request->TransportType);
    return response;
}

bool CheckpointStrategy::InterpretRequest(MessageSPDM *request, MessageSPDM *response)
{
    if (!CheckRequest(request, response)) {
        return false;
    }

    u8 response_code = RequestToResponseCode[request->getCode()];

    if (response_code == 0x04) {
        // Restarts the checkpoint counter in GET_VERSION request
        CurrentCheckpoint = Checkpoint;
    }

    if (response_code == 0x72 || CurrentCheckpoint-- > 0) {
        memcpy(response->Buffer, MockedPackets[response_code].data(), MockedPackets[response_code].size());
        response->Size = MockedPackets[response_code].size();
    }
    else if (response_code == 0x02) {
        // Checks certificate sent
        if (certifiedSent) {
            memcpy(response->Buffer, mockedCertificate2.data(), mockedCertificate2.size());
            response->Size = mockedCertificate2.size();
            certifiedSent = false;
        }
        else {
            memcpy(response->Buffer, mockedCertificate1.data(), mockedCertificate1.size());
            response->Size = mockedCertificate1.size();
            certifiedSent = true;
        }
    }
    else {
        Logger->onResponse(*response, 5);   // Older response (to other request)
        Logger->onResponse(*request, 5);    // Received request
        Factory->CreatePacket(response_code, 3, response);
    }
    response->Command = ntohl(request->Command);
    response->TransportType = ntohl(request->TransportType);

    return response;
}