#include "../utils.hpp"

#define u8  uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t

extern std::map<u8, std::vector<u8>> MockedPackets;

extern std::vector<u8> mockedVersion;
extern std::vector<u8> mockedCapabilities;
extern std::vector<u8> mockedAlgorithms;
extern std::vector<u8> mockedDigests;
extern std::vector<u8> mockedCertificate;
extern std::vector<u8> mockedCertificate1;
extern std::vector<u8> mockedCertificate2;
extern std::vector<u8> mockedChallengeAuth;