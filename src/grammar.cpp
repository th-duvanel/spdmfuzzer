#include "../include/grammar.hpp"

std::vector<std::vector<u8>> storedResponses; ///< Vector containing stored responses and its size.
std::vector<std::vector<u8>> storedRequests; ///< Vector containing stored requests and its size.

u32 finishCommand = (0x00 << 24) | (0x00 << 16) | (0xff << 8) | 0xfe;

u8 M, H;
u8 CERT_SENT = 0;

// To make the code more readable, we can define the namespaace right before coding.

inline std::map<std::string, u8> RequestResponseCode = {
    {"VERSION", 0x04},
    {"CAPABILITIES", 0x61},
    {"ALGORITHMS", 0x63},
    {"DIGESTS", 0x01},
    {"CERTIFICATE", 0x02},
    {"CHALLENGE_AUTH", 0x03},
    {"MEASUREMENTS", 0x60},
    {"VENDOR_DEFINED_RESPONSE", 0x7E},
    {"KEY_EXCHANGE_RSP", 0x64},
    {"FINISH_RSP", 0x65},
    {"ERROR", 0x7F}
};

inline std::map<u8, u8> HashAlgoSizes = {
    {0, 0},     // Raw Bit Stream
    {1, 32},    // TPM_ALG_SHA_256
    {2, 48},    // TPM_ALG_SHA_384
    {3, 64},    // TPM_ALG_SHA_512
    {4, 32},    // TPM_ALG_SHA3_256
    {5, 48},    // TPM_ALG_SHA3_384
    {6, 64}     // TPM_ALG_SHA3_512
};

// The real packet structure is stored in each packet class.

// The idea here is to create a class that will store the structure of parts of the packet,
// until we reach a point where we can really write a random number without
// compromissing the packet structure.


responsePacket::responsePacket(u8 reqresCode)
{
    size = 5;
    SPDM = 0x05;

    this->reqresCode = reqresCode;
    this->major_and_minor = (randomize(0, 15) << 4) | randomize(0, 15);
}

responsePacket::~responsePacket() {}

void responsePacket::serializeHeader(u8* buffer)
{
    buffer[0] = SPDM;
    buffer[1] = major_and_minor;
    buffer[2] = reqresCode;
    buffer[3] = param1;
    buffer[4] = param2;
}

u32 responsePacket::getSize()
{
    return size;
}


Version::Version(u8 fuzz_level) : responsePacket(RequestResponseCode["VERSION"])
{
    if ((this->fuzz_level = fuzz_level) == 0) {
        entryCount = 0; 
        size = SIZE_VERSION;
        return;
    }

    reserved = randomize(0, UINT8_MAX);
    entryCount = randomize(0, 2);
    // entryCount = randomize(0, UINT8_MAX);
    size += 2 + (entryCount * 2);

    if (entryCount > 0) entry = new ver_number[entryCount];

    for(u8 i = 0 ; i < entryCount ; i++) {
        entry[i].major_version  = randomize(0, 15);
        entry[i].minor_version  = randomize(0, 15);
        entry[i].update_version = randomize(0, 15);
        entry[i].alpha          = randomize(0, 15);
    }
}

Version::~Version()
{
    if (entryCount > 0) delete[] entry;
    
}

void Version::serialize(u8* buffer)
{
    if (fuzz_level == 0) {
        memcpy(buffer, mockedVersion, size);
        return;
    }

    if (fuzz_level == 4) size += randomize(0, UINT8_MAX);

    serializeHeader(buffer);

    buffer[5] = reserved;
    buffer[6] = entryCount;

    for(u8 i = 0 ; i < entryCount ; i++) {
        buffer[7 + (i * 2)] = entry[i].update_version << 4 | entry[i].alpha;
        buffer[8 + (i * 2)] = entry[i].major_version << 4 | entry[i].minor_version;
    }

    for(u8 i = 7 + (entryCount * 2) ; i < size ; i++) {
        buffer[i] = randomize(0, UINT8_MAX);
    }
}



Capabilities::Capabilities(u8 fuzz_level) : responsePacket(RequestResponseCode["CAPABILITIES"])
{
    if ((this->fuzz_level = fuzz_level) == 0) {
        size = SIZE_CAPABILITIES;
        return;
    }
    
    reserved = randomize(0, UINT8_MAX);
    ct_exponent = randomize(0, UINT8_MAX);
    reserved_2 = randomize(0, UINT16_MAX);

    flags.cache_cap = randomize(0, 1);
    flags.cert_cap = randomize(0, 1);
    flags.chal_cap = randomize(0, 1);
    flags.meas_cap = randomize(0, 3);
    flags.meas_fresh_cap = randomize(0, 1);

    size += 8;
}

Capabilities::~Capabilities() {}

void Capabilities::serialize(u8* buffer)
{
    if (fuzz_level == 0) {
        memcpy(buffer, mockedCapabilities, size);
        return;
    }

    if (fuzz_level == 4) size += randomize(0, UINT8_MAX);

    serializeHeader(buffer);

    buffer[5] = reserved;
    buffer[6] = ct_exponent;
    assignBuffer(buffer, 7, reserved_2, 2);

    buffer[9] = flags.meas_fresh_cap << 5 | flags.meas_cap << 3 | flags.chal_cap << 2 | flags.cert_cap << 1 | flags.cache_cap;

    // Fill in with random numbers
    for(u8 i = 10 ; i < size ; i++) {
        buffer[i] = randomize(0, UINT8_MAX);
    }
}



Algorithms::Algorithms(u8 fuzz_level) : responsePacket(RequestResponseCode["ALGORITHMS"])
{
    if ((this->fuzz_level = fuzz_level) == 0) {
        size = SIZE_ALGORITHMS;
        return;
    }

    //A Responder shall not select both a SPDM-enumerated asymmetric key signature algorithm and an extended
    //asymmetric key signature algorithm. 
    //A Responder shall not select both a SPDM-enumerated hashing algorithm and
    //an extended Hashing algorithm
    if (fuzz_level == 1) {
        meas_specs = randomize(0, UINT8_MAX);
        meas_hash_algo = randomize(0, UINT16_MAX);
        base_asym_sel = randomize(0, UINT16_MAX);
        base_hash_sel = randomize(0, UINT16_MAX);
    }
    else {
        meas_specs = 1 << randomize(0, 7);

        int selected_algorithm = randomize(0, 31);
        meas_hash_algo = 1 << selected_algorithm;

        if (selected_algorithm < 7) {
            M = HashAlgoSizes[selected_algorithm];
        }
        else M = 0;

        base_asym_sel = 1 << randomize(0, 31);

        selected_algorithm = randomize(0, 31);
        base_hash_sel = 1 << selected_algorithm;
        
        if (selected_algorithm < 7) {
            H = HashAlgoSizes[selected_algorithm];
        }
        else H = 0;
    }
    reserved = randomize(0, UINT8_MAX);

    for(u8 i = 0 ; i < 12 ; i++) {
        reserved_2[i] = randomize(0, UINT8_MAX);
    }

    ext_asym_sel_count = randomize(0, 1);
    ext_hash_sel_count = randomize(0, 1);
    reserved_3 = randomize(0, UINT16_MAX);

    if (ext_asym_sel_count) {
        ext_sel[0].registry_id = randomize(0, UINT8_MAX);
        ext_sel[0].reserved = randomize(0, UINT8_MAX);
        ext_sel[0].algorithm_id = randomize(0, UINT16_MAX);
    }

    if (ext_hash_sel_count) {
        ext_sel[1].registry_id = randomize(0, UINT8_MAX);
        ext_sel[1].reserved = randomize(0, UINT8_MAX);
        ext_sel[1].algorithm_id = randomize(0, UINT16_MAX);
    }

    size += 32 + (ext_asym_sel_count * 4) + (ext_hash_sel_count * 4);
}

Algorithms::~Algorithms() {}

void Algorithms::serialize(u8* buffer)
{
    if (fuzz_level == 0) {
        memcpy(buffer, mockedAlgorithms, size);
        return;
    }

    if (fuzz_level == 4) size += randomize(0, UINT8_MAX);

    serializeHeader(buffer);

    assignBuffer(buffer, 5, size - 1, 2);
    buffer[7] = meas_specs;
    buffer[8] = reserved;

    assignBuffer(buffer, 9, meas_hash_algo, 4);
    assignBuffer(buffer, 13, base_asym_sel, 4);
    assignBuffer(buffer, 17, base_hash_sel, 4);

    for(u8 i = 0 ; i < 12 ; i++) {
        buffer[21 + i] = reserved_2[i];
    }

    buffer[33] = ext_asym_sel_count;
    buffer[34] = ext_hash_sel_count;
    assignBuffer(buffer, 35, reserved_3, 2);

    if (ext_asym_sel_count) {
        buffer[37] = ext_sel[0].registry_id;
        buffer[38] = ext_sel[0].reserved;
        assignBuffer(buffer, 39, ext_sel[0].algorithm_id, 2);
    }

    if (ext_hash_sel_count) {
        buffer[41] = ext_sel[1].registry_id;
        buffer[42] = ext_sel[1].reserved;
        assignBuffer(buffer, 43, ext_sel[1].algorithm_id, 2);
    }

    for (u8 i = 45 ; i < size ; i++) {
        buffer[i] = randomize(0, UINT8_MAX);
    } 
}


Digests::Digests(u8 fuzz_level) : responsePacket(RequestResponseCode["DIGESTS"])
{
    if (fuzz_level == 0) {
        size = SIZE_DIGESTS;
        return;
    }
    
    u8 digests_qtt = randomize(0, 8);

    if (fuzz_level == 2) { // Setar os bits da esquerda à direita
        for (u8 i = 0, param2 = 0; i < digests_qtt; i++) {
            param2 |= (1 << (7 - i));
        }
    }
    else param2 = randomize(0, UINT8_MAX);  // Setar aleatoriamente

    digests = new u8*[digests_qtt];
    for(u8 i = 0 ; i < digests_qtt ; i++) {
        digests[i] = new u8[H];
        for(u8 j = 0 ; j < H ; j++) {
            digests[i][j] = randomize(0, UINT8_MAX);
        }
    }
    size += (digests_qtt * H);
}

Digests::~Digests() {}

void Digests::serialize(u8* buffer)
{
    if (fuzz_level == 0) {
        memcpy(buffer, mockedDigests, size);
        return;
    }
    
    if (fuzz_level == 4) size += randomize(0, UINT8_MAX);

    serializeHeader(buffer);
    
    u8 digests_qtt = std::bitset<8>(param2).count();
    for (u8 i = 0; i < digests_qtt; i++) {
        for (u8 j = 0; j < H; j++) {
            buffer[5 + (i * H) + j] = digests[i][j];
        }
    }
}


Certificate::Certificate(u8 fuzz_level) : responsePacket(RequestResponseCode["CERTIFICATE"])
{
    if (fuzz_level >= 0) {
        if (!CERT_SENT) size = SIZE_CERTIFICATE1;
        else size = SIZE_CERTIFICATE2;
        
        return;
    }
}

Certificate::~Certificate() {}

void Certificate::serialize(u8* buffer)
{
    if (fuzz_level >= 0) {
        if (!CERT_SENT) {
            memcpy(buffer, mockedCertificate1, size);
            CERT_SENT++;
        }
        else {
            memcpy(buffer, mockedCertificate2, size);
            CERT_SENT = 0;
        }
        return;
    }
}

ChallengeAuth::ChallengeAuth(u8 fuzz_level) : responsePacket(RequestResponseCode["CHALLENGE_AUTH"])
{
    if (fuzz_level >= 0) {
        size = SIZE_CHALLENGEAUTH;
        return;
    }

    param1 |= 1 << randomize(0, 7);
    param2 = randomize(0, UINT8_MAX);

    cert_chain_hash = new u8[H];

    for(u8 i = 0 ; i < H ; i++) {
        cert_chain_hash[i] = randomize(0, UINT8_MAX);
    }
}

ChallengeAuth::~ChallengeAuth() {}

void ChallengeAuth::serialize(u8* buffer)
{
    if (fuzz_level >= 0) {
        memcpy(buffer, mockedChallengeAuth, size);
        return;
    }
}