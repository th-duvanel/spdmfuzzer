#include "../include/fuzzing.hpp"

#define IP_ADDRESS "127.0.0.1"
#define PORT        2323

#define MAX_LENGTH  1024
#define STD_TIMER   3

int timer = STD_TIMER;

void help()
{
    std::cout << "Usage: spdmfuzzer [OPTION]" << ENDL;
    std::cout << "  -h, --help\t\tDisplay this help message" << ENDL;
    std::cout << "  -t, --timeout\t\tSets a sleep timer after finding unexpected behavior" << ENDL;
    //std::cout << "  -p, --port\t\tSet the port to connect to" << ENDL;
    //std::cout << "  -l, --length\t\tSet the maximum length of the buffer" << ENDL;
    //std::cout << "  -r, --random\t\tRandomize the size of the buffer" << ENDL;
    //std::cout << "  -f, --fuzz\t\tFuzz the buffer" << ENDL;
}

bool checkArgs(int argc, char** argv)
{
    if (argc == 1)
    {
        return true;
    }
    if (argc == 2)
    {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)
        {
            help();
            return false;
        }
    }
    if (argc == 3)
    {
        if (strcmp(argv[1], "-t") == 0 || strcmp(argv[1], "--timeout") == 0)
        {
            timer = atoi(argv[2]);
            return true;
        }
    }
    return false;
}

int main(int argc, char** argv)
{
    int timer = STD_TIMER;

    Fuzzer* fuzzer = new Fuzzer(PORT, timer, MAX_LENGTH);

    while (fuzzer->fuzzerLoop())
    {
        (fuzzer->*ResponsePackets[fuzzer->getIResponse()])(true, false);
    }

    return 0;
}