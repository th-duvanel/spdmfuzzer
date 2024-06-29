#include "../include/grammar.hpp"

u32 command = (0x00 << 24) | (0x00 << 16) | (0x00 << 8) | 0x01;
u32 finishCommand = (0x00 << 24) | (0x00 << 16) | (0xff << 8) | 0xfe;
u32 headerMCTP  = (0x00 << 24) | (0x00 << 16) | (0x00 << 8) | 0x01;

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

// The idea here is to create a map that will store the structure of parts of the packet,
// until we reach a point where we can really write a random number without
// compromissing the packet structure.

inline std::map<std::string, std::vector<std::string>> packetStructure = {
    // VERSION
    {"VersionNumberEntry", {"major-version", "minor-version", "update-version", "alpha"}},
    // CAPABILITIES
    {"Flags", {"cache_cap", "cert_cap", "meas_cap", "meas_fres_cap", "reserved", "reserved", "reserved", "reserved"}},
    // ALGORITHMS
    {"MeasurementHashAlgo", {"raw-only", "sha_256", "sha_384", "sha_512", "sha3_256", "sha3_384", "sha3_512"}}
    // TODO
};

// TODO: could construct with member init? (ugly)
responsePacket::responsePacket(u8 reqresCode, u8 majorVersion, u8 minorVersion, u8 param1, u8 param2)
{
    this->size = 5;

    this->SPDM = 0x05;
    this->reqresCode = reqresCode;
    this->major_and_minor = (majorVersion << 4) | minorVersion;
    this->param1 = param1;
    this->param2 = param2;
}

void* responsePacket::serializeHeader()
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


Version::Version(bool random_size) : responsePacket(RequestResponseCode["VERSION"], 1, 0, 0, 0)
{
    // ToDo: make random_size
    this->reserved = 0;
    this->entryCount = randomize(0, 10);
    this->size += 2 + (this->entryCount * 2);
    this->entry = new u16[this->entryCount];

    for(u8 i = 0 ; i < this->entryCount ; i++) {
        u8 VERSION_major_and_minor = (randomize(0, 15) << 4) | randomize(0, 15);
        u8 VERSION_update_and_alpha = (randomize(0, 15) << 4) | randomize(0, 15);
        this->entry[i] = (VERSION_major_and_minor << 4) | VERSION_update_and_alpha;
    }
}

void* Version::serialize()
{
    u8* buffer = new u8[7 + (this->entryCount * 2)];

    void* header = this->serializeHeader();
    std::memcpy(buffer, header, 4);

    buffer[5] = this->reserved;
    buffer[6] = this->entryCount;

    for(u8 i = 0 ; i < this->entryCount ; i++) {
        buffer[7 + (i * 2)] = this->entry[i] >> 8;
        buffer[8 + (i * 2)] = this->entry[i];
    }

    return buffer;
}