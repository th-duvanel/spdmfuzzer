#include "utils.hpp"

#define SIZE_GETVERSION 5
#define SIZE_VERSION 11
#define SIZE_GETCAPABILITIES 21
#define SIZE_CAPABILITIES 21
#define SIZE_NEGALGORITHMS 57
#define SIZE_ALGORITHMS 62
#define SIZE_GETDIGESTS 13
#define SIZE_DIGESTS 77
#define SIZE_GETCERTIFICATE 17
#define SIZE_CERTIFICATE1 1107
#define SIZE_CERTIFICATE2 383
#define SIZE_GETCHALLENGE 45
#define SIZE_CHALLENGEAUTH 175

extern u8 mockedGetVersion[];
extern u8 mockedVersion[];
extern u8 mockedGetCapabilities[];
extern u8 mockedCapabilities[];
extern u8 mockedNegAlgorithms[];
extern u8 mockedAlgorithms[];
extern u8 mockedGetDigests[];
extern u8 mockedDigests[];
extern u8 mockedGetCertificate[];
extern u8 mockedCertificate1[];
extern u8 mockedCertificate2[];
extern u8 mockedChallange[];
extern u8 mockedChallengeAuth[];

extern u32 command;
extern u32 finishCommand;
extern u32 headerMCTP;

extern std::map<std::string, u8> RequestResponseCode;
extern std::map<std::string, std::vector<std::string>> packetStructure;

class responsePacket {
    protected:
        u8   SPDM;
        u8   major_and_minor;
        u8   reqresCode;
        u8   param1;
        u8   param2;

        responsePacket(u8 reqresCode, u8 majorVersion, u8 minorVersion, u8 param1, u8 param2);

        void* serializeHeader();

    public:
        virtual void* serialize() = 0;
};

class Version : public responsePacket {
    private:
        u8   reserved;
        u8   entryCount;
        u16* entry;

    public:
        Version();

        void* serialize() override;
};

