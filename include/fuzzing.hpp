#include "socket.hpp"

#include <functional>
#include <cstdlib>

/** @file
 *  This file contains the main fuzzing objects and functions.
 */

extern std::vector<std::pair<std::vector<u8>, size_t>> storedResponses; ///< Vector containing stored responses and its size.
extern std::vector<std::pair<std::vector<u8>, size_t>> storedRequests; ///< Vector containing stored requests and its size.

/**
 * @class Fuzzer
 * @brief Class responsible for performing fuzzing on different parts of network communication.
 *
 * This class implements the core of fuzzing, allowing the manipulation and sending of
 * modified packets to test the robustness and security of a communication protocol.
 */
class Fuzzer {
private:
    u32 command; ///< Current command sent to the Requester.
    u32 ttype;   ///< Current transport type sent to the Requester.
    u32 size;    ///< Size of the data buffer.
    u8* buffer; ///< Buffer containing the data to be sent.

    Socket* socket; ///< Socket used for network communication.

    size_t i_request;  ///< Iterator for request packets.
    size_t i_response; ///< Iterator for response packets.
    size_t old_response_size; ///< Last iteration size of the stored responses.

    responsePacket* packet; ///< Pointer to the current response packet.

    bool verbose; ///< Verbose mode for printing messages.
    int fuzz_level; ///< Level of fuzzing to be applied.
    int timer; ///< Timer for controlling time when receiving an unexpected response.
    
    /**
     * Checks the validity of the current request. If the requester receives an unexpected response.
     * @return True if the request is valid, false otherwise.
     */
    bool assertRequest();

    /**
     * Starts the SpdmRequesterTest process.
     */
    void startRequester();

    void printStoredPackets();

    void cleanStoredPackets();

    void linearFuzzing();

    void backtrackFuzzing();

    /**
     * Deletes packet if has something and assigns nullptr to it.
     */
    void deletePacket();

public:
    /**
     * Constructor for the Fuzzer class.
     * @param port Port for network communication.
     * @param timer Timer for controlling time when receiving an unexpected response.
     * @param max_length Maximum length of the data buffer.
     */
    Fuzzer(int port, int timer, size_t max_length, bool verbose, int fuzz_level);

    /**
     * Main loop of the fuzzer.
     * @return True if the loop can continue. False otherwise
     */
    bool fuzzerLoop();

    /**
     * Fuzzes the current packet, creating and sending it.
     */
    void fuzz();
};

/** 
 * @brief Global vector containing response pointers to constructors using lambda..
 * 
 * This vector stores functions that are called in response to the request packets sent.
 * Each function is responsible for handling a specific response during the fuzzing process.
 */
extern std::vector<std::function<responsePacket*(int)>> Responses;

extern std::vector<std::string> ResponseNames;
extern std::vector<std::string> RequestNames;