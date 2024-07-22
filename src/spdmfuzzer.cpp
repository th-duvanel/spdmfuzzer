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

void checkArgs(int argc, char** argv)
{
    if (argc == 1) return;
    else if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) { help(); exit(1);}
    else if (argc == 3 && (strcmp(argv[1], "-t") == 0 || strcmp(argv[1], "--timeout") == 0)) timer = 0;

    else std::cout << "# [!] => Invalid argument" << ENDL;

    return;
}

int main(int argc, char** argv)
{
    checkArgs(argc, argv);

    Fuzzer* fuzzer = new Fuzzer(PORT, timer, MAX_LENGTH);

    while (fuzzer->fuzzerLoop())
    {
        (fuzzer->*responseFuzzing[fuzzer->getIResponse()])(true, 0);
    }

    return 0;
}