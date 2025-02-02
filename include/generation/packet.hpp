#include "../utils.hpp"

extern std::map<u8, u8> HashAlgoSizes;
extern std::map<u8, u8> AsymSignSize;

class SPDMPacket {
protected:
    u8 FuzzStrategy;

    u64 Size;
    
    u8 Version;
    u8 MajorVersion;
    u8 MinorVersion;
    u8 Code;
    u8 Param1;
    u8 Param2;

    SPDMPacket(u8 code, u8 fuzzStrategy);

    void SerializeHeader(u8 *Buffer);

public:
    virtual ~SPDMPacket() = default;
    
    virtual int SerializePacket(u8 *Buffer) = 0;    
};

class Version : public SPDMPacket {
private:
    u8 Reserved;
    u8 EntryCount;

    struct VersionNumber {
        u8 MajorVersion;
        u8 MinorVersion;
        u8 UpdateVersion;
        u8 Alpha;
    } *Entry;

public:
    Version(u8 fuzzStrategy);

    int SerializePacket(u8 *Buffer) override; 
};

class Capabilities : public SPDMPacket {
private:
    u8 Reserved;
    u8 CTExponent;
    u16 Reserved2;

    struct Flags {
        u8 CacheCap;
        u8 CertCap;
        u8 ChalCap;
        u8 MeasCap;
        u8 MeasFreshCap;
    } Flags;	

public:
    Capabilities(u8 fuzzStrategy);

    int SerializePacket(u8 *Buffer) override; 
};

struct ExtendedAlgorithm {
    u8 RegistryID;
    u8 Reserved;
    u16 AlgorithmID;
};

class NegotiateAlgorithms {
public:
    u8 MeasSpecification;

    u32 BaseAsymAlgorithms;
    u32 BaseHashAlgorithms;

    u8 ExtAsymCount;
    u8 ExtHashCount;

    ExtendedAlgorithm *ExtAsym;
    ExtendedAlgorithm *ExtHash;

    NegotiateAlgorithms(u8 *Buffer);
};

class Algorithms : public SPDMPacket {
private:
    u8 MeasSpecificationSelected;
    u8 Reserved;
    
    u32 MeasHashAlgorithms;
    u32 BaseAsymmetricSelected;
    u32 BaseHashSelected;

    u8 Reserved2[12];
    u8 ExtAsymCount;
    u8 ExtHashCount;

    u16 Reserved3;

    ExtendedAlgorithm *ExtAsymSel;
    ExtendedAlgorithm *ExtHashSel;

public:
    Algorithms(u8 fuzzStrategy);

    int SerializePacket(u8 *Buffer) override;

    int* GetSelectedAlgorithms();
};

class Digests : public SPDMPacket {
private:
    u8 **DigestsBuffer;

public:
    Digests(u8 fuzzStrategy, u8 H_HashSize);

    int SerializePacket(u8 *Buffer) override; 
};

class Certificate : public SPDMPacket {
private:
    u16 PortionLength;
    u16 RemainderLength;

    struct CertificateChain {
        u16 Length;
        u16 Reserved;
        u8 *RootHash;
        u8 *Certificates;
    } *CertificateChain;

public:
    Certificate(u8 fuzzStrategy);

    int SerializePacket(u8 *Buffer) override; 
};

class ChallengeAuth : public SPDMPacket {
private:
    u8 S_SignatureSize;

    u8 *CertificateChainHash;
    u8 Nonce[32];
    u8 *MeasSummaryHash;
    u16 OpaqueLength;
    u8 *OpaqueData;
    u8 *Signature;

public:
    ChallengeAuth(u8 fuzzStrategy, u8 H_HashSize, u8 S_SignatureSize);

    int SerializePacket(u8 *Buffer) override; 
};

class Measurements : public SPDMPacket {
private:
    u8 NumOfBlocks;
    u32 MeasRecordLength;
    u8 *MeasRecord;

    u8 Nonce[32];
    u16 OpaqueLength;
    u8 *OpaqueData;
    u8 *Signature;

public:
    Measurements(u8 fuzzStrategy, u8 S_SignatureSize);

    int SerializePacket(u8 *Buffer) override; 
};

class Error : public SPDMPacket {
private:
    u8 *ErrorData;

public:
    Error(void *packetArgs, u8 fuzzStrategy);

    int SerializePacket(u8 *Buffer) override; 
};