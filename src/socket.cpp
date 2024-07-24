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

    fuzzerConsole(("Responder (server) listening on port " + std::to_string(port)).c_str());
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

bool
TCP::responderRead(u32* command, u32* ttype, u32* size, void* buffer)
{
    ssize_t ret;

    if ((ret = read(req_sckt, command, COMMAND)) <= 0) {
        return checkSocketErrors(ret, COMMAND, "Command");
    }
    if (assertEnd(*command)) return false;
    
    if ((ret = read(req_sckt, ttype, TTYPE)) <= 0) {
        return checkSocketErrors(ret, TTYPE, "TransportType");
    }
    if ((ret = read(req_sckt, size, SIZE)) <= 0) {
        return checkSocketErrors(ret, SIZE, "Size");
    }
    if (*size && (ret = read(req_sckt, buffer, *size)) <= 0) {
        return checkSocketErrors(ret, *size, "Buffer");
    }
    std::cout << ENDL;
    socketConsole("Received command: ", command, COMMAND);
    socketConsole("Received transport type: ", ttype, TTYPE);
    socketConsole("Received buffer size: ", size, SIZE);
    socketConsole("Received buffer: ", buffer, ntohl(*size));
    return true;
}

bool
TCP::responderWrite(u32 command, u32 ttype, u32 size, void* buffer)
{
    ssize_t ret;
    size = htonl(size);
    ttype = htonl(ttype);

    if ((ret = write(req_sckt, &command, COMMAND)) <= 0) {
        return checkSocketErrors(ret, COMMAND, "Command");
    }
    if ((ret = write(req_sckt, &ttype, TTYPE)) <= 0) {
        return checkSocketErrors(ret, TTYPE, "TransportType");
    }
    if ((ret = write(req_sckt, &size, SIZE)) <= 0) {
        return checkSocketErrors(ret, SIZE, "Size");
    }
    if (size && (ret = write(req_sckt, buffer, ntohl(size))) <= 0) {
        return checkSocketErrors(ret, ntohl(size), "Buffer");
    }
    std::cout << ENDL;
    socketConsole("Sent command: ", &command, COMMAND);
    socketConsole("Sent transport type: ", &ttype, TTYPE);
    socketConsole("Sent buffer size: ", &size, SIZE);
    socketConsole("Sent buffer: ", buffer, ntohl(size));
    return true;
}

void
TCP::responderDisconnect()
{
    close(req_sckt);
    req_sckt = -1;
    //std::cout << ENDL;
    fuzzerConsole("Requester (client) disconnected", '!');
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

bool
TCP::checkSocketErrors(ssize_t ret, size_t expected, const std::string type)
{
    if (ret == 0 || ret < 0) {
        fuzzerError(("Socket " + type + " read/write connection closed").c_str(), 1);
        return false;
    }
    return true;
}