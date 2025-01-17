#include "../include/io.hpp"

SocketTCP::SocketTCP(Observer *Logger, int port, bool verbose)
{
    int OptValues = 1;

    RequesterSocket = -1;
    AddressLength = sizeof(Address);

    this->Logger = Logger;

    system("killall SpdmRequesterTest > /dev/null 2>&1");

    if ((Socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        this->Logger->onEvent("IO/TCP", "Creation failed.");
    }

    setsockopt(Socket, SOL_SOCKET, SO_REUSEADDR, &OptValues, sizeof(OptValues));

    bzero(&Address, sizeof(Address));
    Address.sin_family      = AF_INET;
    Address.sin_port        = htons(port);
    Address.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(Socket, (struct sockaddr*)&Address, sizeof(Address)) < 0) {
        this->Logger->onEvent("IO/TCP", "Bind failed.");
        exit(1);
    }
    if (listen(Socket, 1) < 0) { // LISTENQ = 1
        this->Logger->onEvent("IO/TCP", "Listen start failed");
        exit(1);
    }

    this->Logger->onEvent("IO/TCP", "Responder listening on port " + std::to_string(port));
}

SocketTCP::~SocketTCP()
{
    close(Socket);
}

bool
SocketTCP::CheckConnection()
{
    if (RequesterSocket <= 0) {
        Logger->onEvent("IO/TCP", "Connection closed.");
        return false;
    }
    return true;
}

bool
SocketTCP::AssertEnd(u32 command)
{
    if (htonl(command) == ((0x00 << 24) | (0x00 << 16) | (0xff << 8) | 0xfe)) {
        close(RequesterSocket);
        RequesterSocket = -1;
        Logger->onEvent("IO/TCP", "Requester disconnected.");
        return true;
    }
    return false;
}

void
SocketTCP::AcceptRequester()
{
    if ((RequesterSocket = accept(Socket, (struct sockaddr*)&Address, &AddressLength)) < 0) {
        Logger->onEvent("IO/TCP", "Accept failed.");
    }
    Logger->onEvent("IO/TCP", "Requester connected. Unexpected requests:");
}

bool
SocketTCP::ReadResponder(MessageSPDM *Message)
{
    // o request n eh a mesma variavel que o response
    if (read(RequesterSocket, &Message->Command, 4) <= 0) {
        Logger->onEvent("IO/TCP", "Command read failed.");
        return false;
    }
    else if (AssertEnd(Message->Command)) return false;

    if (read(RequesterSocket, &Message->TransportType, 4) <= 0) {
        Logger->onEvent("IO/TCP", "Transport type read failed.");
        return false;
    }
    if (read(RequesterSocket, &Message->Size, 4) <= 0) {
        Logger->onEvent("IO/TCP", "Size read failed.");
        return false;
    }
    Message->Size = ntohl(Message->Size);
    
    if (read(RequesterSocket, Message->Buffer, Message->Size) <= 0) {
        Logger->onEvent("IO/TCP", "Buffer read failed.");
        return false;
    }
    return true;
}

bool
SocketTCP::WriteResponder(MessageSPDM *Message)
{
    Message->Command = htonl(Message->Command);
    Message->TransportType = htonl(Message->TransportType);
    Message->Size = htonl(Message->Size);

    if (write(RequesterSocket, &Message->Command, 4) <= 0) {
        Logger->onEvent("IO/TCP", "Command write failed.");
        return false;
    }
    if (write(RequesterSocket, &Message->TransportType, 4) <= 0) {
        Logger->onEvent("IO/TCP", "Transport type write failed.");
        return false;
    }
    if (write(RequesterSocket, &Message->Size, 4) <= 0) {
        Logger->onEvent("IO/TCP", "Size write failed.");
        return false;
    }
    if (Message->Size && write(RequesterSocket, Message->Buffer, ntohl(Message->Size)) <= 0) {
        Logger->onEvent("IO/TCP", "Buffer write failed.");
        return false;
    }
    return true;
}

void
SocketTCP::DisconnectResponder()
{
    close(RequesterSocket);
    RequesterSocket = -1;
    Logger->onEvent("IO/TCP", "Requester disconnected.");
}