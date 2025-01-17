#pragma once

#include <map>
#include <iostream>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <sstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <bitset>
#include <memory>
#include <sstream>
#include <netinet/in.h>

#define u8  uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t

#define u_ptr std::unique_ptr
#define ENDL std::endl

extern std::map<u8, u8> RequestToResponseCode;

class MessageSPDM {
public:
    u32 Command;
    u32 TransportType;
    u32 Size;
    u8 *Buffer;

    MessageSPDM(u64 Size);

    u8 getCode();
};

u64 Randomize(u64 Min, u64 Max);

void AssignBuffer(u8* Buffer, u64 Position, u64 Value, u8 Size);

void RandomizeBuffer(u8 Start, u8 Size, u8 *Buffer);

void FuzzerError(const std::string Message, u8 Code);