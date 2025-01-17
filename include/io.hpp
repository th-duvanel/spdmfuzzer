#pragma once

#include "utils.hpp"
#include "observer.hpp"

class IO {
protected:
    Observer *Logger;

    virtual bool AssertEnd(u32 command) = 0;

public:
    virtual bool ReadResponder(MessageSPDM *Message) = 0;
    virtual bool WriteResponder(MessageSPDM *Message) = 0;
    virtual void DisconnectResponder() = 0;
    virtual void AcceptRequester() = 0;
};

class SocketTCP : public IO {
private:
    int Socket;
    int RequesterSocket;

    struct sockaddr_in Address;
    socklen_t AddressLength;

    bool AssertEnd(u32 command) override;
    bool CheckConnection();

public:
    SocketTCP(Observer *Logger, int port, bool verbose);
    ~SocketTCP();

    void AcceptRequester() override;
    bool ReadResponder(MessageSPDM *Message) override;
    bool WriteResponder(MessageSPDM *Message) override;
    void DisconnectResponder() override;
};