#include "../include/socket.hpp"


TCP::TCP(int port)
{
    int optval = 1;
        req_sckt = -1;

    this->address_length = sizeof(this->address);

    if ((sckt = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fuzzerError("Socket creation failed", 1);
    }

    setsockopt(sckt, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    bzero(&address, sizeof(address));
    address.sin_family      = AF_INET;
    address.sin_port        = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sckt, (struct sockaddr*)&address, sizeof(address)) < 0) {
        fuzzerError("Socket bind failed", 1);
    }

    if (listen(sckt, LISTENQ) < 0) {
        fuzzerError("Socket listen failed", 1);
    }

    fuzzerConsole("Responder (server) listening on port " + std::to_string(port));
}

TCP::~TCP()
{
    close(sckt);
}

void
TCP::acceptRequester()
{
    if ((req_sckt = accept(sckt, (struct sockaddr*)&(this->address), &(this->address_length))) < 0) {
        fuzzerError("Socket accept failed", 1);
    }

    fuzzerConsole("Requester (client) connected");
}

void 
TCP::responderRead(u32* command, u32* ttype, u32* size, void* buffer)
{
    if (read(req_sckt, command, COMMAND) < 0) {
        fuzzerError("Socket \"Command\" read failed", 1);
    }
    if (assertEnd(*command)) return;
    
    if (read(req_sckt, ttype, TTYPE) < 0) {
        fuzzerError("Socket \"TransportType\" read failed", 1);
    }
    if (read(req_sckt, size, SIZE) < 0) {
        fuzzerError("Socket \"Size\" read failed", 1);
    }
    if (*size && read(req_sckt, buffer, *size) < 0) {
        fuzzerError("Socket \"Buffer\" read failed", 1);
    }

    std::cout << ENDL;
    fuzzerConsole("Received command: ", command, COMMAND);
    fuzzerConsole("Received transport type: ", ttype, TTYPE);
    fuzzerConsole("Received buffer size: ", size, SIZE);
    fuzzerConsole("Received buffer: ", buffer, ntohl(*size));
}

void
TCP::responderWrite(u32 command, u32 ttype, u32 size, void* buffer)
{
    size = htonl(size);

    if (write(req_sckt, &command, COMMAND) < 0) {
        fuzzerError("Socket \"Command\" write failed", 1);
    }
    if (write(req_sckt, &ttype, TTYPE) < 0) {
        fuzzerError("Socket \"TransportType\" write failed", 1);
    }
    if (write(req_sckt, &size, SIZE) < 0) {
        fuzzerError("Socket \"Size\" write failed", 1);
    }
    if (size && write(req_sckt, buffer, ntohl(size)) < 0) {
        fuzzerError("Socket \"Buffer\" write failed", 1);
    }

    std::cout << ENDL;
    fuzzerConsole("Sent command: ", &command, COMMAND);
    fuzzerConsole("Sent transport type: ", &ttype, TTYPE);
    fuzzerConsole("Sent buffer size: ", &size, SIZE);
    fuzzerConsole("Sent buffer: ", buffer, ntohl(size));
}

void
TCP::responderDisconnect()
{
    //responderWrite(finishCommand, headerMCTP, 0, nullptr);
    close(req_sckt);
    req_sckt = -1;
    fuzzerConsole("Requester (client) disconnected");
}

bool
TCP::checkConnection()
{
    return req_sckt > 0;
}

bool
TCP::assertEnd(u32 command)
{
    if (htonl(command) == finishCommand) 
    {
        responderDisconnect();
        return true;
    }
    return false;
}