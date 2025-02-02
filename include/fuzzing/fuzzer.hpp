#include "../io.hpp"
#include "fuzz_strategy.hpp"

class Fuzzer {
private:
    IO *Socket;
    Observer *Logger;
    FuzzStrategy *Strategy;

    MessageSPDM *Response;
    MessageSPDM *Request;

    void StartRequester();
public:
    Fuzzer(int port, int fuzzStrategy, size_t bufferSize, bool verbose, int extra = 0);

    void Round();
    void Run();
};