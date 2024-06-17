#include "../include/utils.hpp"

void fuzzerError(const char* message, int code)
{
    std::cerr << "# [!] => " << message << ENDL;
    exit(code);
}

void fuzzerConsole(const std::string message, char sign)
{
    if (sign == 0) sign = '+';
    std::cout << "# [" << sign << "] => " << message << ENDL;
}

void fuzzerConsole(const std::string message, const void* buffer, size_t size)
{
    std::stringstream ss;
    const char* buf = static_cast<const char*>(buffer);
    for (size_t i = 0; i < size; ++i) {
        ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(static_cast<unsigned char>(buf[i])) << " ";
    }
    fuzzerConsole(message + ENDL + "         " + ss.str());
}

u64 randomize(u64 min, u64 max)
{    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<u8> dis(min, max);
    return dis(gen);
}