#include "../io.hpp"
#include "fuzz_strategy.hpp"

class Fuzzer {
private:
    IO *Socket;
    Observer *Logger;
    FuzzStrategy *Strategy;

    MessageSPDM *Response;
    MessageSPDM *Request;
    
    std::vector<std::vector<u8>> StoredResponses;
    std::vector<std::vector<u8>> StoredRequests;

    void StartRequester();
public:
    Fuzzer(int port, int fuzzStrategy, size_t bufferSize, bool verbose);

    void Round();
    void Run();
};