#include "../include/grammar.hpp"

u32 finishCommand = (0x00 << 24) | (0x00 << 16) | (0xff << 8) | 0xfe;

u8  M;

// To make the code more readable, we can define the namespaace right before coding.

inline std::map<std::string, u8> RequestResponseCode = {
    {"DIGESTS", 0x01},
    {"CERTIFICATE", 0x02},
    {"CHALLENGE_AUTH", 0x03},
    {"VERSION", 0x04},
    {"MEASUREMENTS", 0x60},
    {"CAPABILITIES", 0x61},
    {"ALGORITHMS", 0x63},
    {"VENDOR_DEFINED_RESPONSE", 0x7E},
    {"KEY_EXCHANGE_RSP", 0x64},
    {"FINISH_RSP", 0x65},
    {"ERROR", 0x7F}
};

// The real packet structure is stored in each packet class.

// The idea here is to create a class that will store the structure of parts of the packet,
// until we reach a point where we can really write a random number without
// compromissing the packet structure.


responsePacket::responsePacket(u8 reqresCode, u8 param1, u8 param2)
{
    this->size = 5;

    this->SPDM = 0x05;
    this->reqresCode = reqresCode;
    this->major_and_minor = (randomize(0, 15) << 4) | randomize(0, 15);
    this->param1 = param1;
    this->param2 = param2;
}

u8* responsePacket::serializeHeader()
{
    u8* buffer = new u8[5];

    buffer[0] = this->SPDM;
    buffer[1] = this->major_and_minor;
    buffer[2] = this->reqresCode;
    buffer[3] = this->param1;
    buffer[4] = this->param2;

    return buffer;
}

u32 responsePacket::getSize()
{
    return this->size;
}


Version::Version() : responsePacket(RequestResponseCode["VERSION"], 0, 0)
{
    this->reserved   = randomize(0, 255);
    // For SpdmRequester, this must be between 0 and 2.
    this->entryCount = randomize(0, 2);
    // this->entryCount = randomize(0, 255);
    this->size      += 2 + (this->entryCount * 2);
    this->entry      = new ver_number[this->entryCount];

    for(u8 i = 0 ; i < this->entryCount ; i++) {
        this->entry[i].major_version  = randomize(0, 15);
        this->entry[i].minor_version  = randomize(0, 15);
        this->entry[i].update_version = randomize(0, 15);
        this->entry[i].alpha          = randomize(0, 15);
    }
}

Version::~Version()
{
    delete[] this->entry;
}

void* Version::serialize(size_t max)
{
    this->size += randomize(0, max);

    u8* buffer = new u8[this->size];

    u8* header = this->serializeHeader();
    std::memcpy(buffer, header, 4);

    buffer[5] = this->reserved;
    buffer[6] = this->entryCount;

    for(u8 i = 0 ; i < this->entryCount ; i++) {
        buffer[7 + (i * 2)] = this->entry[i].update_version << 4 | this->entry[i].alpha;
        buffer[8 + (i * 2)] = this->entry[i].major_version << 4 | this->entry[i].minor_version;
    }

    // Fill in with random numbers
    for(u8 i = 7 + (this->entryCount * 2) ; i < this->size ; i++) {
        buffer[i] = randomize(0, 255);
    }

    delete[] header;
    return buffer;
}



Capabilities::Capabilities() : responsePacket(RequestResponseCode["CAPABILITIES"], 0, 0)
{
    this->reserved = randomize(0, 255);
    this->ct_exponent = randomize(0, 255);
    this->reserved_2 = randomize(0, 65535);

    this->flags.cache_cap = randomize(0, 1);
    this->flags.cert_cap = randomize(0, 1);
    this->flags.chal_cap = randomize(0, 1);
    this->flags.meas_cap = randomize(0, 3);
    this->flags.meas_fresh_cap = randomize(0, 1);

    this->size += 8;
}

void* Capabilities::serialize(size_t max)
{
    this->size += randomize(0, max);

    u8* buffer = new u8[this->size];

    u8* header = this->serializeHeader();
    std::memcpy(buffer, header, 4);

    buffer[5] = this->reserved;
    buffer[6] = this->ct_exponent;
    buffer[7] = this->reserved_2 >> 8;
    buffer[8] = this->reserved_2 & 0xff;

    buffer[9] = this->flags.meas_fresh_cap << 5 | this->flags.meas_cap << 3 | this->flags.chal_cap << 2 | this->flags.cert_cap << 1 | this->flags.cache_cap;

    // Fill in with random numbers
    for(u8 i = 10 ; i < this->size ; i++) {
        buffer[i] = randomize(0, 255);
    }

    delete[] header;
    return buffer;
}