#include "../include/socket.hpp"

class Fuzzer {
private:
    u32 command;
    u32 ttype;
    u32 size;
    void* buffer;

    Socket* socket;

    size_t i_request;  // Iterates over request packets
    size_t i_response; // Iterates over response packets

    bool assertRequest();

    void startRequester();

public:
    Fuzzer(int port, size_t max_length);

    bool fuzzerLoop();

    size_t getIResponse();

    // The fuzzing kernel:
    void fuzzVersion();
    void fuzzCapabilities();
    void fuzzNegAlgorithms();
    void fuzzDigets();
    void fuzzCertificate1();
    void fuzzCertificate2();
    void fuzzChallange();
};

typedef void (Fuzzer::*fuzzFunctions)();

extern std::vector<u8*> RequestPackets;
extern std::vector<fuzzFunctions> ResponsePackets;