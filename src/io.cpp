#include "../include/io.hpp"

SocketTCP::SocketTCP(Observer *Logger, int port, bool verbose)
{
    int OptValues = 1;

    RequesterSocket = -1;
    AddressLength = sizeof(Address);

    if ((Socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        Logger->onEvent("IO/TCP", "Creation failed.");
    }

    setsockopt(Socket, SOL_SOCKET, SO_REUSEADDR, &OptValues, sizeof(OptValues));

    bzero(&Address, sizeof(Address));
    Address.sin_family      = AF_INET;
    Address.sin_port        = htons(port);
    Address.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(Socket, (struct sockaddr*)&Address, sizeof(Address)) < 0) {
        Logger->onEvent("IO/TCP", "Bind failed.");
    }
    if (listen(Socket, 1) < 0) { // LISTENQ = 1
        Logger->onEvent("IO/TCP", "Listen start failed");
    }

    Logger->onEvent("IO/TCP", "Responder listening on port " + std::to_string(port));
}

SocketTCP::~SocketTCP()
{
    close(Socket);
}

bool
SocketTCP::CheckConnection()
{
    if (RequesterSocket > 0) {
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
    Logger->onEvent("IO/TCP", "Requester connected.");
}

bool
SocketTCP::ReadResponder(MessageSPDM &Message)
{
    if (!CheckConnection()) return false;

    if (read(RequesterSocket, &Message.Command, 4) <= 0) {
        Logger->onEvent("IO/TCP", "Command read failed.");
    }
    else if (AssertEnd(Message.Command)) return false;

    if (read(RequesterSocket, &Message.TransportType, 4) <= 0) {
        Logger->onEvent("IO/TCP", "Transport type read failed.");
    }
    if (read(RequesterSocket, &Message.Size, 4) <= 0) {
        Logger->onEvent("IO/TCP", "Size read failed.");
    }

    if (Message.Size) {
        Message.Buffer = new u8[Message.Size];
        if (read(RequesterSocket, Message.Buffer, Message.Size) <= 0) {
            Logger->onEvent("IO/TCP", "Buffer read failed.");
            free(Message.Buffer);
            Message.Buffer = nullptr;
            return false;
        }
    }
    else {
        Message.Buffer = nullptr;
    }
    return true;
}

bool
SocketTCP::WriteResponder(MessageSPDM &Message)
{
    if (!CheckConnection()) return false;

    if (write(RequesterSocket, &Message.Command, 4) <= 0) {
        Logger->onEvent("IO/TCP", "Command write failed.");
    }
    if (write(RequesterSocket, &Message.TransportType, 4) <= 0) {
        Logger->onEvent("IO/TCP", "Transport type write failed.");
    }
    if (write(RequesterSocket, &Message.Size, 4) <= 0) {
        Logger->onEvent("IO/TCP", "Size write failed.");
    }
    if (Message.Size && write(RequesterSocket, Message.Buffer, Message.Size) <= 0) {
        Logger->onEvent("IO/TCP", "Buffer write failed.");
    }
    if (Message.Buffer) {
        free(Message.Buffer);
        Message.Buffer = nullptr;
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