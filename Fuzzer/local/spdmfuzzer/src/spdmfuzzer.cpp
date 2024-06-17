#include "../include/fuzzing.hpp"

#define IP_ADDRESS "127.0.0.1"
#define PORT        2323

#define MAX_LENGTH  1024

int main()
{
    Fuzzer* fuzzer = new Fuzzer(PORT, MAX_LENGTH);

    while (fuzzer->fuzzerLoop())
    {
        (fuzzer->*ResponsePackets[fuzzer->getIResponse()])();
        sleep(1);
    }

    return 0;
}