#include "socket.hpp"
#include "mocks.hpp"

/** @file
 *  This file contains the main fuzzing objects and functions.
 */

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

    int timer; ///< Timer for controlling time when receiving an unexpected response.

    responsePacket* packet; ///< Pointer to the current response packet.
    std::vector<responsePacket*> storedPackets; ///< Vector containing the request packets to be sent.
    
    /**
     * Checks the validity of the current request. If the requester receives an unexpected response.
     * @return True if the request is valid, false otherwise.
     */
    bool assertRequest();

    /**
     * Starts the SpdmRequesterTest process.
     */
    void startRequester();

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
    Fuzzer(int port, int timer, size_t max_length);

    /**
     * Main loop of the fuzzer.
     * @return True if the loop can continue. False otherwise
     */
    bool fuzzerLoop();

    /**
     * Gets the index of the response packet iterator.
     * @return The current value of the response iterator.
     */
    size_t getIResponse();

    /**
     * Fuzzes the Version response message.
     * @param fuzz If true, activates fuzzing for this response message.
     * @param random_size If true, uses a random size for the data buffer.
     */
    void fuzzVersion(bool fuzz = false, size_t max = 0);

    /**
     * Fuzzes the Capabilities response message.
     * @param fuzz If true, activates fuzzing for this response message.
     * @param random_size If true, uses a random size for the data buffer.
     */
    void fuzzCapabilities(bool fuzz = false, size_t max = 0);

    /**
     * Fuzzes the Algorithms response message.
     * @param fuzz If true, activates fuzzing for this response message.
     * @param random_size If true, uses a random size for the data buffer.
     */
    void fuzzAlgorithms(bool fuzz = false, size_t max = 0);

    /**
     * Fuzzes the Digests response message.
     * @param fuzz If true, activates fuzzing for this response message.
     * @param random_size If true, uses a random size for the data buffer.
     */
    void fuzzDigests(bool fuzz = false, size_t max = 0);

    /**
     * Fuzzes the Certificates response message.
     * @param fuzz If true, activates fuzzing for this response message.
     * @param random_size If true, uses a random size for the data buffer.
     */
    void fuzzCertificate1(bool fuzz = false, size_t max = 0);

    /**
     * Fuzzes the Certificates response message.
     * @param fuzz If true, activates fuzzing for this response message.
     * @param random_size If true, uses a random size for the data buffer.
     */
    void fuzzCertificate2(bool fuzz = false, size_t max = 0);

    /**
     * Fuzzes the Challenge response message.
     * @param fuzz If true, activates fuzzing for this response message.
     * @param random_size If true, uses a random size for the data buffer.
     */
    void fuzzChallenge(bool fuzz = false, size_t max = 0);
};

/**
 * Function pointer for the fuzzing functions.
 * @param fuzz If true, activates fuzzing for this response message.
 * @param random_size If true, uses a random size for the data buffer.
 */
typedef void (Fuzzer::*fuzzFunctions)(bool, size_t);

/** 
 * @brief Global vector containing response functions for fuzzing.
 * 
 * This vector stores functions that are called in response to the request packets sent.
 * Each function is responsible for handling a specific response during the fuzzing process.
 */
extern std::vector<fuzzFunctions> responseFuzzing;