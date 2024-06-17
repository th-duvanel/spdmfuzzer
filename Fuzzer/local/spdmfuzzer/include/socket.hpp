#include "grammar.hpp"
#include <arpa/inet.h>

#define LISTENQ 1

#define COMMAND 4   // Command size
#define TTYPE 4     // Transport Type size
#define SIZE 4      // Buffer Size size

#define VERSION 11

class Socket {
public:
    virtual void responderRead(u32* command, u32* ttype, u32* size, void* buffer) = 0;

    virtual void responderWrite(u32 command, u32 ttype, u32 size, void* buffer) = 0;

    virtual void responderDisconnect() = 0;

    virtual bool checkConnection() = 0;

    virtual void acceptRequester() = 0;
};


class TCP : public Socket {
private:
    int                sckt,
                       req_sckt;
    struct sockaddr_in address;
    socklen_t          address_length;

    bool assertEnd(u32 command);

public:
    TCP(int port);

    //TCP(const char* ip, int port);

    ~TCP();

    void responderRead(u32* command, u32* ttype, u32* size, void* buffer) override;

    void responderWrite(u32 command, u32 ttype, u32 size, void* buffer) override;

    void responderDisconnect() override;

    void acceptRequester() override;

    bool checkConnection() override;
};