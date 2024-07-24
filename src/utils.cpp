#include "../include/utils.hpp"

void fuzzerError(const char* message, int code)
{
    std::cerr << "# [!] => " << message << ENDL;
    exit(code);
}

void fuzzerConsole(const char* message, char sign)
{
    std::cout << "# [" << sign << "] => " << message << ENDL;
}

void socketConsole(const std::string& message, void* buffer, size_t size)
{
    //std::cout << "# [+] => " << message;
    //std::stringstream ss;
    //const char* buf = static_cast<const char*>(buffer);
    //for (size_t i = 0; i < size; ++i) {
    //    ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(static_cast<unsigned char>(buf[i])) << " ";
    //}
    //std::cout << ss.str() << ENDL;
}

u64 randomize(u64 min, u64 max)
{    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<u8> dis(min, max);
    return dis(gen);
}

void assignBuffer(u8* buffer, u64 pos, u64 value, u8 size)
{
    for(u8 i = 0 ; i < size ; i++) {
        buffer[pos + i] = (value >> (i * 8)) & 0xFF;
    }
}