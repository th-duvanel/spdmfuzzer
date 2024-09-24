#include "../include/fuzzing.hpp"

#define IP_ADDRESS "127.0.0.1"

int TIMER = 0;
int PORT = 2323;
int FUZZ_LEVEL = 1;
int MAX = 2048;
bool VERBOSE = false;


void checkArgs(int argc, char** argv);
void help();


int main(int argc, char** argv)
{
    checkArgs(argc, argv);

    Fuzzer* fuzzer = new Fuzzer(PORT, TIMER, MAX, VERBOSE, FUZZ_LEVEL);

    while (fuzzer->fuzzerLoop())
    {
        fuzzer->fuzz();
    }

    return 0;
}

void help()
{
    std::cout << "Usage: spdmfuzzer [OPTION1] [OPTION2] ..." << ENDL;
    std::cout << "  -h, --help\t\tDisplay this help message" << ENDL;
    std::cout << "  -v, --verbose\t\tEnable verbose mode" << ENDL;
    std::cout << "  -t, --timeout\t\tSets a sleep timer in seconds after finding unexpected behavior (2)" << ENDL;
    std::cout << "  -p, --port\t\tSet the port to connect to (2323)" << ENDL;
    std::cout << "  -f, --fuzz\t\tSet the fuzzing level (1)" << ENDL;
    std::cout << "  -l, --len\t\t(USE WITH CAUTION!!!) Set the maximum length of the data buffer (2048)" << ENDL;

    exit(0);
}

void checkArgs(int argc, char** argv)
{
    if (argc > 9) fuzzerError("Too many arguments", 1);

    for (u8 i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) help(); 
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) VERBOSE = true;
        else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--timeout") == 0) {
            if (i + 1 < argc) TIMER = std::stoi(argv[++i]);
            else fuzzerError("--timeout requires a value", 1);
        } 
        else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
            if (i + 1 < argc) PORT = std::stoi(argv[++i]);
            else fuzzerError("--port requires a value", 1);
        }
        else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--fuzz") == 0) {
            if (i + 1 < argc) FUZZ_LEVEL = std::stoi(argv[++i]);
            else fuzzerError("--fuzz requires a value", 1);
        }
        else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--len") == 0) {
            if (i + 1 < argc) MAX = std::stoi(argv[++i]);
            else fuzzerError("--len requires a value", 1);
        }
        else fuzzerError("Invalid argument", 1);
    }
}