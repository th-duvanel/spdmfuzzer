#include "../../include/generation/packet.hpp"

inline std::map<u8, u8> HashAlgoSizes = {
    {0, 0},     // Raw Bit Stream
    {1, 32},    // TPM_ALG_SHA_256
    {2, 48},    // TPM_ALG_SHA_384
    {3, 64},    // TPM_ALG_SHA_512
    {4, 32},    // TPM_ALG_SHA3_256
    {5, 48},    // TPM_ALG_SHA3_384
    {6, 64}     // TPM_ALG_SHA3_512
};

inline std::map<u8, u8> AsymSignSize = {
    {0, 0},     // Raw Bit Stream
    {1, 256},   // TPM_ALG_RSASSA_2048
    {2, 384},   // TPM_ALG_RSASSA_3072
    {3, 384},   // TPM_ALG_RSAPSS_3072
    {4, 256},   // TPM_ALG_ECDSA_ECC_NIST_P256
    {5, 512},   // TPM_ALG_RSASSA_4096
    {6, 512},   // TPM_ALG_RSAPSS_4096
    {7, 384},   // TPM_ALG_ECDSA_ECC_NIST_P384
    {8, 512}    // TPM_ALG_ECDSA_ECC_NIST_P521
};

SPDMPacket::SPDMPacket(u8 code, u8 fuzzStrategy)
{
    Size = 5;
    
    Version = 0x05;
    Code = code;
    MajorVersion = Randomize(0, 15);
    MinorVersion = Randomize(0, 15);
    FuzzStrategy = fuzzStrategy;
}

void SPDMPacket::SerializeHeader(u8 *Buffer)
{
    Buffer[0] = Version;
    Buffer[1] = MinorVersion << 4 | MajorVersion;
    Buffer[2] = Code;
    Buffer[3] = Param1;
    Buffer[4] = Param2;
}

Version::Version(u8 fuzzStrategy) : SPDMPacket(0x04, fuzzStrategy)
{
    Reserved = Randomize(0, UINT8_MAX);
    EntryCount = Randomize(0, 2);
    Size += 2 + (EntryCount * 2);

    if (EntryCount > 0) {
        Entry = new VersionNumber[EntryCount];
    }

    for (u8 i = 0 ; i < EntryCount ; i++) {
        Entry[i].MajorVersion = Randomize(0, 15);
        Entry[i].MinorVersion = Randomize(0, 15);
        Entry[i].UpdateVersion = Randomize(0, 15);
        Entry[i].Alpha= Randomize(0, 15);
    }
}

int Version::SerializePacket(u8 *Buffer)
{
    if (FuzzStrategy == 0) {
        Size += Randomize(0, UINT8_MAX);
    }

    SerializeHeader(Buffer);

    Buffer[5] = Reserved;
    Buffer[6] = EntryCount;

    for (u8 i = 0 ; i < EntryCount ; i++) {
        Buffer[7 + (i * 2)] = Entry[i].UpdateVersion << 4 | Entry[i].Alpha;
        Buffer[8 + (i * 2)] = Entry[i].MajorVersion << 4 | Entry[i].MinorVersion;
    }
    RandomizeBuffer(7 + (EntryCount * 2), Size, Buffer);

    return Size;
}

Capabilities::Capabilities(u8 fuzzStrategy) : SPDMPacket(0x61, fuzzStrategy)
{
    Reserved = Randomize(0, UINT8_MAX);
    CTExponent = Randomize(0, UINT8_MAX);
    Reserved2 = Randomize(0, UINT16_MAX);

    Flags.CacheCap = Randomize(0, 1);
    Flags.CertCap = Randomize(0, 1);
    Flags.ChalCap = Randomize(0, 1);
    Flags.MeasCap = Randomize(0, 3);
    Flags.MeasFreshCap = Randomize(0, 1);

    Size += 8;
}

int Capabilities::SerializePacket(u8 *Buffer)
{
    if (FuzzStrategy == 0) {
        Size += Randomize(0, UINT8_MAX);
    }

    SerializeHeader(Buffer);

    Buffer[5] = Reserved;
    Buffer[6] = CTExponent;

    Buffer[9] = Flags.MeasFreshCap << 5 | 
                Flags.MeasCap << 2 | 
                Flags.ChalCap << 2 | 
                Flags.CertCap << 1 | 
                Flags.CacheCap;

    AssignBuffer(Buffer, 7, Reserved2, 2);
    RandomizeBuffer(13, Size, Buffer);

    return Size;
}

Algorithms::Algorithms(u8 fuzzStrategy) : SPDMPacket(0x63, fuzzStrategy)
{
    Reserved = Randomize(0, UINT8_MAX);
    Reserved3 = Randomize(0, UINT16_MAX);

    for (u8 i = 0 ; i < 12 ; i++) {
        Reserved2[i] = Randomize(0, UINT8_MAX);
    }
    if (FuzzStrategy != 3) {
        MeasSpecificationSelected = Randomize(0, UINT8_MAX);
        BaseAsymmetricSelected = Randomize(0, UINT32_MAX);
        MeasHashAlgorithms = Randomize(0, UINT32_MAX);
        BaseHashSelected = Randomize(0, UINT32_MAX);

        ExtAsymCount = Randomize(0, 2);
        ExtHashCount = Randomize(0, 2);
    }
    else {
        MeasSpecificationSelected = 1 << Randomize(0, 7);
        MeasHashAlgorithms = Randomize(0, 127);
        BaseAsymmetricSelected = 1 << Randomize(0, 31);
        BaseHashSelected = 1 << Randomize(0, 31);

        ExtAsymCount = Randomize(0, 1);
        ExtHashCount = Randomize(0, 1);
    }
    if (ExtAsymCount > 0) {
        ExtAsymSel = new ExtendedAlgorithm[ExtAsymCount];
        ExtAsymSel->RegistryID = Randomize(0, UINT8_MAX);
        ExtAsymSel->Reserved = Randomize(0, UINT8_MAX);
        ExtAsymSel->AlgorithmID = Randomize(0, UINT16_MAX);
    }

    if (ExtHashCount > 0) {
        ExtHashSel = new ExtendedAlgorithm[ExtHashCount];
        ExtHashSel->RegistryID = Randomize(0, UINT8_MAX);
        ExtHashSel->Reserved = Randomize(0, UINT8_MAX);
        ExtHashSel->AlgorithmID = Randomize(0, UINT16_MAX);
    }

    Size += 32 + (ExtAsymCount * 4) + (ExtHashCount * 4);
}

int Algorithms::SerializePacket(u8 *Buffer)
{
    if (FuzzStrategy == 2) {
        Size += Randomize(0, UINT8_MAX);
    }

    SerializeHeader(Buffer);

    AssignBuffer(Buffer, 5, Size - 1, 2);
    AssignBuffer(Buffer, 9, MeasHashAlgorithms, 4);
    AssignBuffer(Buffer, 13, BaseAsymmetricSelected, 4);
    AssignBuffer(Buffer, 17, BaseHashSelected, 4);
    AssignBuffer(Buffer, 35, Reserved3, 2);

    Buffer[7] = MeasSpecificationSelected;
    Buffer[8] = Reserved;
    Buffer[33] = ExtAsymCount;
    Buffer[34] = ExtHashCount;

    for (u8 i = 0 ; i < ExtAsymCount ; i++) {
        Buffer[37 + i] = ExtAsymSel[i].RegistryID;
        Buffer[38 + i] = ExtAsymSel[i].Reserved;
        AssignBuffer(Buffer, 39 + (i * 2), ExtAsymSel[i].AlgorithmID, 2);
    }

    for (u8 i = 0 ; i < ExtHashCount ; i++) {
        Buffer[37 + (ExtAsymCount * 4) + i] = ExtHashSel[i].RegistryID;
        Buffer[38 + (ExtAsymCount * 4) + i] = ExtHashSel[i].Reserved;
        AssignBuffer(Buffer, 39 + (ExtAsymCount * 4) + (i * 2), ExtHashSel[i].AlgorithmID, 2);
    }

    for (u8 i = 0 ; i < 12 ; i++) {
        Buffer[21 + i] = Reserved2[i];
    }

    for (u8 i = 37 + (ExtAsymCount + ExtHashCount) * 4 ; i < Size ; i++) {
        Buffer[i] = Randomize(0, UINT8_MAX);
    }

    return Size;
}

int* Algorithms::GetSelectedAlgorithms()
{
    
    int *selectedAlgorithms = new int[3];
    
    u8 selected_m = std::bitset<8>(MeasSpecificationSelected).count();
    u8 selected_h = std::bitset<8>(BaseHashSelected).count();
    u8 selected_s = std::bitset<8>(BaseAsymmetricSelected).count();

    if (selected_m < 7) {
        selectedAlgorithms[0] = HashAlgoSizes[selected_m];
    }
    else {
        selectedAlgorithms[0] = 0;
    }

    if (selected_h < 7) {
        selectedAlgorithms[1] = HashAlgoSizes[selected_h];
    }
    else {
        selectedAlgorithms[1] = 0;
    }

    if (selected_s < 7) {
        selectedAlgorithms[2] = AsymSignSize[selected_s];
    }
    else {
        selectedAlgorithms[2] = 0;
    }

    return selectedAlgorithms;
}

Digests::Digests(u8 fuzzStrategy, u8 H_HashSize) : SPDMPacket(0x01, fuzzStrategy)
{
    u8 digests_quantity = Randomize(0, 8);

    for (u8 i = 0, Param2 = 0 ; i < digests_quantity ; i++) {
        Param2 |= (1 << (7 - i));
    }

    DigestsBuffer = new u8*[digests_quantity];
    for (u8 i = 0 ; i < digests_quantity ; i++) {
        DigestsBuffer[i] = new u8[H_HashSize];
        for (u8 j = 0 ; j < H_HashSize ; j++) {
            DigestsBuffer[i][j] = Randomize(0, UINT8_MAX);
        }
    }

    Size += digests_quantity * H_HashSize;
}

int Digests::SerializePacket(u8 *Buffer)
{
    u8 digests_quantity = std::bitset<8>(Param2).count();
    u8 hash_size = Size / digests_quantity;

    if (FuzzStrategy == 2) {
        Size += Randomize(0, UINT8_MAX);
    }

    SerializeHeader(Buffer);

    for (u8 i = 0 ; i < digests_quantity ; i++) {
        for (u8 j = 0 ; j < hash_size ; j++) {
            Buffer[5 + (i * hash_size) + j] = DigestsBuffer[i][j];
        }
    }

    for (u8 i = digests_quantity ; i < Size ; i++) {
        Buffer[5 + i] = Randomize(0, UINT8_MAX);
    }

    return Size;
}

Certificate::Certificate(u8 fuzzStrategy) : SPDMPacket(0x02, fuzzStrategy)
{

}

int Certificate::SerializePacket(u8 *Buffer)
{

    if (FuzzStrategy == 2) {
        Size += Randomize(0, UINT8_MAX);
    }

    SerializeHeader(Buffer);

    return Size;
}

ChallengeAuth::ChallengeAuth(u8 fuzzStrategy, u8 H_HashSize, u8 S_SignatureSize) : SPDMPacket(0x03, fuzzStrategy)
{
    Param1 |= 1 << Randomize(0, 7);
    Param2 = Randomize(0, UINT8_MAX);
    OpaqueLength = Randomize(0, UINT16_MAX);
    OpaqueData = new u8[OpaqueLength];

    CertificateChainHash = new u8[H_HashSize];

    for (u8 i = 0 ; i < H_HashSize ; i++) {
        CertificateChainHash[i] = Randomize(0, UINT8_MAX);
        MeasSummaryHash[i] = Randomize(0, UINT8_MAX);
    }

    for (u8 i = 0 ; i < 32 ; i++) {
        Nonce[i] = Randomize(0, UINT8_MAX);
    }

    for (u8 i = 0 ; i < OpaqueLength ; i++) {
        OpaqueData[i] = Randomize(0, UINT8_MAX);
    }

    Signature = new u8[S_SignatureSize];
    for (u8 i = 0 ; i < S_SignatureSize ; i++) {
        Signature[i] = Randomize(0, UINT8_MAX);
    }

    Size += 44 + 2 * H_HashSize + OpaqueLength + S_SignatureSize;
}

int ChallengeAuth::SerializePacket(u8 *Buffer)
{
    // Message has a fixed size of 44 bytes + 2 * HashSize + Signature
    u8 hash_size = (Size - 44 - S_SignatureSize) / 2;

    if (FuzzStrategy == 2) {
        Size += Randomize(0, UINT8_MAX);
    }

    SerializeHeader(Buffer);

    for (u8 i = 0 ; i < hash_size ; i++) {
        Buffer[5 + i] = CertificateChainHash[i];
        Buffer[37 + i] = MeasSummaryHash[i];
    }

    for (u8 i = 0 ; i < 32 ; i++) {
        Buffer[37 + hash_size + i] = Nonce[i];
    }

    for (u8 i = 0 ; i < OpaqueLength ; i++) {
        Buffer[69 + hash_size + i] = OpaqueData[i];
    }

    for (u8 i = 0 ; i < S_SignatureSize ; i++) {
        Buffer[69 + hash_size + OpaqueLength + i] = Signature[i];
    }

    for (u8 i = 69 + hash_size + OpaqueLength + S_SignatureSize ; i < Size ; i++) {
        Buffer[i] = Randomize(0, UINT8_MAX);
    }

    return Size;
}

Measurements::Measurements(u8 fuzzStrategy, u8 S_SignatureSize) : SPDMPacket(0x60, fuzzStrategy)
{
    if (fuzzStrategy == 3) {
        if (Param2) {
            NumOfBlocks = Randomize(0, UINT8_MAX);
            MeasRecordLength = Randomize(0, UINT32_MAX);
        }
        else {
            NumOfBlocks = 0;
            MeasRecordLength = 0;
        }        

        for (u8 i = 0 ; i < MeasRecordLength ; i++) {
            MeasRecord[i] = Randomize(0, UINT8_MAX);
        }
    }
    else {
        NumOfBlocks = Randomize(0, UINT8_MAX);
        MeasRecordLength = Randomize(0, UINT32_MAX);

        for (u8 i = 0 ; i < MeasRecordLength + Randomize(0, UINT8_MAX) ; i++) {
            MeasRecord[i] = Randomize(0, UINT8_MAX);
        }
    }

    for (u8 i = 0 ; i < 32 ; i++) {
        Nonce[i] = Randomize(0, UINT8_MAX);
    }

    OpaqueLength = Randomize(0, UINT16_MAX);
    for (u8 i = 0 ; fuzzStrategy == 3 && i < OpaqueLength ; i++) {
        OpaqueData[i] = Randomize(0, UINT8_MAX);
    }
    for (u8 i = 0 ; fuzzStrategy != 3 && i < OpaqueLength + Randomize(0, UINT8_MAX) ; i++) {
        OpaqueData[i] = Randomize(0, UINT8_MAX);
    }

    for (u8 i = 0 ; i < S_SignatureSize ; i++) {
        Signature[i] = Randomize(0, UINT8_MAX);
    }

    Size += 43 + MeasRecordLength + OpaqueLength + S_SignatureSize;
}

int Measurements::SerializePacket(u8 *Buffer)
{
    // Message has a fixed size of 43 bytes + MeasRecordLength + OpaqueLength + SignatureSize
    u8 signature_size = Size - 43 - MeasRecordLength - OpaqueLength;

    if (FuzzStrategy == 2) {
        Size += Randomize(0, UINT8_MAX);
    }

    SerializeHeader(Buffer);

    Buffer[5] = NumOfBlocks;
    Buffer[41 + MeasRecordLength] = OpaqueLength;
    AssignBuffer(Buffer, 6, MeasRecordLength, 3);

    for (u8 i = 0 ; i < MeasRecordLength ; i++) {
        Buffer[9 + i] = MeasRecord[i];
    }

    for (u8 i = 0 ; i < 32 ; i++) {
        Buffer[9 + MeasRecordLength + i] = Nonce[i];
    }

    for (u8 i = 0 ; i < OpaqueLength ; i++) {
        Buffer[43 + MeasRecordLength + i] = OpaqueData[i];
    }

    for (u8 i = 0 ; i < signature_size ; i++) {
        Buffer[43 + MeasRecordLength + OpaqueLength + i] = Signature[i];
    }
    

    return Size;
}

Error::Error(u8 fuzzStrategy) : SPDMPacket(0x7F, fuzzStrategy)
{
    Param1 = Randomize(0, UINT8_MAX);
    Param2 = Randomize(0, UINT8_MAX);

    Size += 2;
}

int Error::SerializePacket(u8 *Buffer)
{
    u8 error_size = Size - 5;

    if (FuzzStrategy == 2) {
        Size += Randomize(0, UINT8_MAX);
    }

    SerializeHeader(Buffer);

    for (u8 i = 0 ; i < error_size ; i++) {
        Buffer[5 + i] = ErrorData[i];
    }

    for (u8 i = 0 ; i < Size ; i++) {
        Buffer[5 + error_size + i] = Randomize(0, UINT8_MAX);
    }

    return Size;
}