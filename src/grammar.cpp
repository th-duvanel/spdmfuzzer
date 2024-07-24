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

responsePacket::~responsePacket() {}

void responsePacket::serializeHeader(u8* buffer)
{
    buffer[0] = this->SPDM;
    buffer[1] = this->major_and_minor;
    buffer[2] = this->reqresCode;
    buffer[3] = this->param1;
    buffer[4] = this->param2;
}

u32 responsePacket::getSize()
{
    return this->size;
}


Version::Version() : responsePacket(RequestResponseCode["VERSION"], 0, 0)
{
    this->reserved = randomize(0, UINT8_MAX);
    this->entryCount = randomize(0, 2);
    // this->entryCount = randomize(0, UINT8_MAX);
    this->size += 2 + (this->entryCount * 2);
    this->entry = new ver_number[this->entryCount];

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

void Version::serialize(u8* buffer, size_t max)
{
    this->size += randomize(0, max);

    serializeHeader(buffer);

    buffer[5] = this->reserved;
    buffer[6] = this->entryCount;

    for(u8 i = 0 ; i < this->entryCount ; i++) {
        buffer[7 + (i * 2)] = this->entry[i].update_version << 4 | this->entry[i].alpha;
        buffer[8 + (i * 2)] = this->entry[i].major_version << 4 | this->entry[i].minor_version;
    }

    // Fill in with random numbers
    for(u8 i = 7 + (this->entryCount * 2) ; i < this->size ; i++) {
        buffer[i] = randomize(0, UINT8_MAX);
    }
}



Capabilities::Capabilities() : responsePacket(RequestResponseCode["CAPABILITIES"], 0, 0)
{
    this->reserved = randomize(0, UINT8_MAX);
    this->ct_exponent = randomize(0, UINT8_MAX);
    this->reserved_2 = randomize(0, UINT16_MAX);

    this->flags.cache_cap = randomize(0, 1);
    this->flags.cert_cap = randomize(0, 1);
    this->flags.chal_cap = randomize(0, 1);
    this->flags.meas_cap = randomize(0, 3);
    this->flags.meas_fresh_cap = randomize(0, 1);

    this->size += 8;
}

Capabilities::~Capabilities() {}

void Capabilities::serialize(u8* buffer, size_t max)
{
    serializeHeader(buffer);

    buffer[5] = this->reserved;
    buffer[6] = this->ct_exponent;
    assignBuffer(buffer, 7, this->reserved_2, 2);

    buffer[9] = this->flags.meas_fresh_cap << 5 | this->flags.meas_cap << 3 | this->flags.chal_cap << 2 | this->flags.cert_cap << 1 | this->flags.cache_cap;

    // Fill in with random numbers
    for(u8 i = 10 ; i < this->size ; i++) {
        buffer[i] = randomize(0, UINT8_MAX);
    }
}


Algorithms::Algorithms() : responsePacket(RequestResponseCode["ALGORITHMS"], 0, 0)
{
    //A Responder shall not select both a SPDM-enumerated asymmetric key signature algorithm and an extended
    //asymmetric key signature algorithm. A Responder shall not select both a SPDM-enumerated hashing algorithm and
    //an extended Hashing algorithm

    // ToDo: randomize all the values or follow the SPDM rules.
    this->meas_specs = 1 << randomize(0, 7);
    this->reserved = randomize(0, UINT8_MAX);

    this->meas_hash_algo = 1 << randomize(0, 31);
    this->base_asym_sel = 1 << randomize(0, 31);
    this->base_hash_sel = 1 << randomize(0, 31);

    for(u8 i = 0 ; i < 12 ; i++) {
        this->reserved_2[i] = randomize(0, UINT8_MAX);
    }

    this->ext_asym_sel_count = randomize(0, 1);
    this->ext_hash_sel_count = randomize(0, 1);
    this->reserved_3 = randomize(0, UINT16_MAX);

    if (this->ext_asym_sel_count) {
        ext_sel[0].registry_id = randomize(0, UINT8_MAX);
        ext_sel[0].reserved = randomize(0, UINT8_MAX);
        ext_sel[0].algorithm_id = randomize(0, UINT16_MAX);
    }

    if (this->ext_hash_sel_count) {
        ext_sel[1].registry_id = randomize(0, UINT8_MAX);
        ext_sel[1].reserved = randomize(0, UINT8_MAX);
        ext_sel[1].algorithm_id = randomize(0, UINT16_MAX);
    }

    this->size += 32 + (this->ext_asym_sel_count * 3) + (this->ext_hash_sel_count * 3);    
    this->length = this->size - 4;
}

Algorithms::~Algorithms() {}

void Algorithms::serialize(u8* buffer, size_t max)
{
    this->size += randomize(0, max);

    serializeHeader(buffer);

    assignBuffer(buffer, 5, this->length, 2);
    buffer[7] = this->meas_specs;
    buffer[8] = this->reserved;

    assignBuffer(buffer, 9, this->meas_hash_algo, 4);
    assignBuffer(buffer, 13, this->base_asym_sel, 4);
    assignBuffer(buffer, 17, this->base_hash_sel, 4);

    for(u8 i = 0 ; i < 12 ; i++) {
        buffer[21 + i] = this->reserved_2[i];
    }

    buffer[33] = this->ext_asym_sel_count;
    buffer[34] = this->ext_hash_sel_count;
    assignBuffer(buffer, 35, this->reserved_3, 2);

    if (this->ext_asym_sel_count) {
        buffer[37] = this->ext_sel[0].registry_id;
        buffer[38] = this->ext_sel[0].reserved;
        assignBuffer(buffer, 39, this->ext_sel[0].algorithm_id, 2);
    }

    if (this->ext_hash_sel_count) {
        buffer[41] = this->ext_sel[1].registry_id;
        buffer[42] = this->ext_sel[1].reserved;
        assignBuffer(buffer, 43, this->ext_sel[1].algorithm_id, 2);
    }

    for (u8 i = 45 ; i < this->size ; i++) {
        buffer[i] = randomize(0, UINT8_MAX);
    }
}

