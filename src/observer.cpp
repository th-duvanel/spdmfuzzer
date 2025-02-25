#include "../include/observer.hpp"

inline std::map<u8, std::string> ResponseRequestCode = {
    {0x84, "GET_VERSION"},
    {0xE1, "GET_CAPABILITIES"},
    {0xE3, "NEGOTIATE_ALGORITHMS"},
    {0x81, "GET_DIGESTS"},
    {0x82, "GET_CERTIFICATE"},
    {0x83, "CHALLENGE"},
    {0x69, "GET_MEASUREMENTS"},
    {0x72, "KEY_EXCHANGE"},
    {0x73, "FINISH"},
    {0x04, "VERSION"},
    {0x61, "CAPABILITIES"},
    {0x63, "ALGORITHMS"},
    {0x01, "DIGESTS"},
    {0x02, "CERTIFICATE"},
    {0x03, "CHALLENGE_AUTH"},
    {0x60, "MEASUREMENTS"},
    {0x7E, "VENDOR_DEFINED_RESPONSE"},
    {0x64, "KEY_EXCHANGE_RSP"},
    {0x65, "FINISH_RSP"},
    {0x7F, "ERROR"}
};

ConsoleLogger::ConsoleLogger(bool verbose) : verbose(verbose) {}

void ConsoleLogger::onResponse(MessageSPDM &Message, u8 fuzzStrategy)
{
    int msgCode = Message.getCode();
    // Removes CAPABILITIES AND GET_CAPABILITIES, VERSION, GET_VERSION
    if (msgCode == 0 || msgCode == 0x84 || msgCode == 0x04 || msgCode == 0xE1 || msgCode == 0x61 || msgCode == 0xE3) return;
    if (Message.Command == 2917007360) return;
    
    std::cout << "# [" << (int)fuzzStrategy << "] => " << ResponseRequestCode[Message.getCode()];
    std::stringstream ss;

    std::cout << ": ";
    
    const uint8_t* buf = static_cast<const uint8_t*>(Message.Buffer);
    
    for (size_t i = 0; i < Message.Size; ++i) {
        ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(buf[i]) << " ";
    }
    std::cout << ss.str() << ENDL;
    return;
    
    std::cout << ENDL;
}

void ConsoleLogger::onEvent(const std::string &type, const std::string &Message)
{
    if (verbose)
        std::cout << "# [" << type << "] => " << Message << ENDL;
}

void ConsoleLogger::ShowStart()
{
    if (verbose)
        std::cout << "# [*] => Fuzzer started the round." << ENDL;
}

void ConsoleLogger::ShowEnd()
{
    if (verbose)
        std::cout << "# [-] => Fuzzer finished the round." << ENDL << ENDL;
}