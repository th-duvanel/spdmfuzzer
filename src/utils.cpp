#include "../include/utils.hpp"

void fuzzerError(const char* message, int code)
{
    std::cerr << "# [!] => " << message << ENDL;
    exit(code);
}

void fuzzerConsole(const char* message, bool verbose, char sign)
{
    if (!verbose) return;
    std::cout << ENDL << "# [" << sign << "] => " << message << ENDL;
}

void socketConsole(const char* message, const void* buffer, size_t size, bool verbose)
{
    if (!verbose) return;
    
    std::cout << "# [+] => " << message;
    std::stringstream ss;
    const uint8_t* buf = static_cast<const uint8_t*>(buffer);
    
    for (size_t i = 0; i < size; ++i) {
        ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(buf[i]) << " ";
    }

    std::cout << ss.str() << std::endl;
}

u64 randomize(u64 min, u64 max)
{    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<u64> dis(min, max);
    return dis(gen);
}

void assignBuffer(u8* buffer, u64 pos, u64 value, u8 size)
{
    for(u8 i = 0 ; i < size ; i++) {
        buffer[pos + size - 1 - i] = (value >> (i * 8)) & 0xFF;
    }
}