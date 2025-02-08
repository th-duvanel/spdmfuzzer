#include "../include/utils.hpp"

std::map<u8, u8> RequestToResponseCode = {
    {0x84, 0x04},
    {0xE1, 0x61},
    {0xE3, 0x63},
    {0x81, 0x01},
    {0x82, 0x02},
    {0x83, 0x03},
    {0x69, 0x72}
};

MessageSPDM::MessageSPDM(u64 Size)
{
    this->Size = 0;
    Buffer = new u8[Size];
}

u8 MessageSPDM::getCode() const {
    if (Size < 3) return 0;
    return Buffer[2];
}

MessageSPDM* findMessage(std::vector<MessageSPDM>& messages, u8 code) {
    auto it = std::find_if(messages.begin(), messages.end(), [code](const MessageSPDM& msg) {
        return msg.getCode() == code;
    });

    if (it != messages.end()) {
        return &(*it);
    } else {
        return nullptr;
    }
}

u64 Randomize(u64 Min, u64 Max)
{    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<u64> dis(Min, Max);
    return dis(gen);
}

void AssignBuffer(u8* Buffer, u64 Position, u64 Value, u8 Size)
{
    for (u8 i = 0 ; i < Size ; i++) {
        Buffer[Position + i] = (Value >> (i * 8)) & 0xFF;
    }
}

void RandomizeBuffer(u8 Start, u8 Size, u8 *Buffer)
{
    for (u8 i = Start; i < Size; i++) {
        Buffer[i] = Randomize(0, UINT8_MAX);
    }
}

void FuzzerError(const std::string Message, u8 Code)
{
    std::cerr << "Error: " << Message << ENDL;
    exit(Code);
}