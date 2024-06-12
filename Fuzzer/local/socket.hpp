#ifdef SPDM
#include "spdm_messages.hpp"
#endif

#include <iostream>
#include <cstring>

#include <arpa/inet.h>
#include <unistd.h>


class Socket {
public:
    virtual Socket* clientConnect() = 0;

    virtual void read(void* buffer) = 0;

    virtual void write(const void* buffer) = 0;

    virtual void clientDisconnect() = 0;
};


class TCP : public Socket {
private:
    int socket;

    struct sockaddr_in address;

    socklen_t address_length;


    Socket* acceptClient(int port);


public:
    Socket* clientConnect();

    void read(void* buffer);

    void write(const void* buffer);

    void clientDisconnect();
};