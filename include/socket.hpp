#include "grammar.hpp"
#include <arpa/inet.h>

/** @file
 *  This file contains the socket class and its methods. It has all the necessary socket basis
 *  for creating a socket for a new transport type.
 */

#define LISTENQ 1

#define COMMAND 4   /** Command size in bytes */
#define TTYPE 4     /** TransportType (MCTP header) size in bytes */
#define SIZE 4      /** Packet Size size in bytes */
#define VERSION 11  /** Version packet size in bytes */

/**
 * @class Socket
 * @brief Class responsible for sending and receiving data through a socket in the fuzzer.
 * 
 * This class is responsible for sending and receiving data through a socket in the fuzzer, it is
 * a generic class that can be used for different types of sockets.
 */
class Socket {
public:
    /**
     * Reads the responder socket received message.
     * @param command Pointer to the command received.
     * @param ttype Pointer to the transport type received.
     * @param size Pointer to the size received.
     * @param buffer Pointer to the buffer received.
     * 
     * @return True if the read was successful (the Requester didn't disconnected), false otherwise.
     */
    virtual bool responderRead(u32* command, u32* ttype, u32* size, void* buffer) = 0;

    /**
     * Writes the responder socket message.
     * @param command Command to be sent.
     * @param ttype Transport type to be sent.
     * @param size Size to be sent.
     * @param buffer Buffer to be sent.
     * 
     * @return True if the write was successful (the Requester didn't disconnected), false otherwise.
     */
    virtual bool responderWrite(u32 command, u32 ttype, u32 size, void* buffer) = 0;

    /**
     * Disconnects the responder socket.
     */
    virtual void responderDisconnect() = 0;

    /**
     * Checks if the connection is still active.
     * @return True if the connection is active, false otherwise.
     */
    virtual bool checkConnection() = 0;

    /**
     * Accepts the requester socket.
     */
    virtual void acceptRequester() = 0;
};

/**
 * @class TCP
 * @brief Class responsible for creating a TCP socket to spdmfuzzer.
 * 
 * This class is responsible for creating a TCP socket to spdmfuzzer, it is a specific class that
 */
class TCP : public Socket {
private:
    int                sckt, //< Socket file descriptor.
                       req_sckt; //< Requester socket file descriptor.
    struct sockaddr_in address; //< Address structure.
    socklen_t          address_length; //< Address length.

    bool verbose; //< Verbose mode.

    /**
     * Asserts the end of the connection by a end command sent by Requester.
     * @param command Command to be checked.
     * 
     * @return True if the command is the end of the connection, false otherwise.
     */
    bool assertEnd(u32 command);

    /**
     * Checks if the socket has any errors and prints it.
     * @param ret Return value of the socket function.
     * @param expected Expected return value.
     * @param type Type of the socket function.
     * 
     * @return True if the socket has errors, false otherwise.
     */
    bool checkSocketErrors(ssize_t ret, size_t expected, const std::string type);

public:
    /**
     * Construct a new TCP object
     * 
     * @param port Used port for connection
     * @param verbose Verbose mode
     */
    TCP(int port, bool verbose);
    
    /**
     * Destroy the TCP object
     */
    ~TCP();

    /**
     * Reads the responder socket received message.
     * @param command Pointer to the command received.
     * @param ttype Pointer to the transport type received.
     * @param size Pointer to the size received.
     * @param buffer Pointer to the buffer received.
     * 
     * @return True if the read was successful (the Requester didn't disconnected), false otherwise.
     */
    bool responderRead(u32* command, u32* ttype, u32* size, void* buffer) override;

    /**
     * Writes the responder socket message.
     * @param command Command to be sent.
     * @param ttype Transport type to be sent.
     * @param size Size to be sent.
     * @param buffer Buffer to be sent.
     * 
     * @return True if the write was successful (the Requester didn't disconnected), false otherwise.
     */
    bool responderWrite(u32 command, u32 ttype, u32 size, void* buffer) override;

    /**
     * Disconnects the responder socket.
     */
    void responderDisconnect() override;

    /**
     * Accepts the requester socket.
     */
    void acceptRequester() override;

    /**
     * Checks if the connection is still active.
     * @return True if the connection is active, false otherwise.
     */
    bool checkConnection() override;
};