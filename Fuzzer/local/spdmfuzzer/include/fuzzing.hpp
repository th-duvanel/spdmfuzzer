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
    void fuzzVersion(bool fuzz = false);
    void fuzzCapabilities(bool fuzz = false);
    void fuzzNegAlgorithms(bool fuzz = false);
    void fuzzDigets(bool fuzz = false);
    void fuzzCertificate1(bool fuzz = false);
    void fuzzCertificate2(bool fuzz = false);
    void fuzzChallange(bool fuzz = false);
};

typedef void (Fuzzer::*fuzzFunctions)(bool);

extern std::vector<u8*> RequestPackets;
extern std::vector<fuzzFunctions> ResponsePackets;