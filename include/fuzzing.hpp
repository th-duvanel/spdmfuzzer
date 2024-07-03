#include "../include/socket.hpp"
#include "../include/mocks.hpp"

class Fuzzer {
private:
    u32 command;
    u32 ttype;
    u32 size;
    void* buffer;

    Socket* socket;

    size_t i_request;  // Iterates over request packets
    size_t i_response; // Iterates over response packets

    int    timer;

    bool assertRequest();

    void startRequester();

public:
    Fuzzer(int port, int timer, size_t max_length);

    bool fuzzerLoop();

    size_t getIResponse();

    // The fuzzing kernel:
    void fuzzVersion(bool fuzz = false, bool random_size = false);
    void fuzzCapabilities(bool fuzz = false, bool random_size = false);
    void fuzzAlgorithms(bool fuzz = false, bool random_size = false);
    void fuzzDigets(bool fuzz = false, bool random_size = false);
    void fuzzCertificate1(bool fuzz = false, bool random_size = false);
    void fuzzCertificate2(bool fuzz = false, bool random_size = false);
    void fuzzChallange(bool fuzz = false, bool random_size = false);
};

typedef void (Fuzzer::*fuzzFunctions)(bool, bool);

extern std::vector<u8*> RequestPackets;
extern std::vector<fuzzFunctions> ResponsePackets;