#include "../../include/generation/packet.hpp"

SPDMPacket::SPDMPacket(u8 code, u8 fuzzStrategy)
{
    Size = 5;
    
    Version = 0x05;
    Code = code;
    MajorVersion = Randomize(0, 15);
    MinorVersion = Randomize(0, 15);
    FuzzStrategy = fuzzStrategy;
}

void
SPDMPacket::SerializeHeader(u8 *Buffer)
{
    Buffer = new u8[Size];

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

int
Version::SerializePacket(u8 *Buffer)
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

int
Capabilities::SerializePacket(u8 *Buffer)
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
}

Algorithms::Algorithms(NegotiateAlgorithms *packetArgs, u8 fuzzStrategy) : SPDMPacket(0x63, fuzzStrategy)
{

}

int
Algorithms::SerializePacket(u8 *Buffer)
{

}

Digests::Digests(u8 fuzzStrategy) : SPDMPacket(0x01, fuzzStrategy)
{

}

int
Digests::SerializePacket(u8 *Buffer)
{

}

Certificate::Certificate(u8 fuzzStrategy) : SPDMPacket(0x02, fuzzStrategy)
{

}

int
Certificate::SerializePacket(u8 *Buffer)
{

}

ChallengeAuth::ChallengeAuth(void *packetArgs, u8 fuzzStrategy) : SPDMPacket(0x03, fuzzStrategy)
{

}

int
ChallengeAuth::SerializePacket(u8 *Buffer)
{

}

Measurements::Measurements(void *packetArgs, u8 fuzzStrategy) : SPDMPacket(0x60, fuzzStrategy)
{

}

int
Measurements::SerializePacket(u8 *Buffer)
{

}

Error::Error(void *packetArgs, u8 fuzzStrategy) : SPDMPacket(0x7F, fuzzStrategy)
{

}

int
Error::SerializePacket(u8 *Buffer)
{

}