#include "../include/io.hpp"
#include "../include/generation/packet_factory.hpp"
#include "../include/fuzzing/fuzzer.hpp"

int PORT = 2323;
int FUZZ_LEVEL = 0;
int MAX = 2048;
int EXTRA = 3;
bool VERBOSE = false;

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
    if (argc > 9) FuzzerError("Too many arguments", 1);

    for (u8 i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            help(); 
        }
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            VERBOSE = true;
        }
        else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
            if (i + 1 < argc) PORT = std::stoi(argv[++i]);
            else FuzzerError("--port requires a value", 1);
        }
        else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--fuzz") == 0) {
            if (i + 1 < argc) FUZZ_LEVEL = std::stoi(argv[++i]);
            else FuzzerError("--fuzz requires a value", 1);

            if (FUZZ_LEVEL == 5) {
                if (i + 1 < argc) EXTRA = std::stoi(argv[++i]);
                else FuzzerError("--fuzz 5 requires a value", 1);
            }
        }
        else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--len") == 0) {
            if (i + 1 < argc) MAX = std::stoi(argv[++i]);
            else FuzzerError("--len requires a value", 1);
        }
        else FuzzerError("Invalid argument", 1);
    }
}

int main(int argc, char *argv[])
{
    Fuzzer *fuzzer;

    checkArgs(argc, argv);

    fuzzer = new Fuzzer(PORT, FUZZ_LEVEL, MAX, VERBOSE, EXTRA);

    fuzzer->Run();

    return 0;
}