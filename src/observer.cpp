#include "../include/observer.hpp"

ConsoleLogger::ConsoleLogger(bool verbose) : verbose(verbose) {}

void ConsoleLogger::onResponse(u8 code, MessageSPDM &Message)
{
    std::cout << "# [+] => ";
    std::stringstream ss;
    const uint8_t* buf = static_cast<const uint8_t*>(Message.Buffer);
    
    for (size_t i = 0; i < Message.Size; ++i) {
        ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(buf[i]) << " ";
    }

    std::cout << ss.str() << std::endl;
}

void ConsoleLogger::onEvent(const std::string &type, const std::string &Message)
{
    std::cout << "# [" << type << "] => " << Message << std::endl;
}

void ConsoleLogger::ShowStart()
{
    std::cout << "# [*] => Fuzzer started the round." << std::endl;
}

void ConsoleLogger::ShowEnd()
{
    std::cout << "# [-] => Fuzzer finished the round." << std::endl;
}