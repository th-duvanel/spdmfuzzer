#include "utils.hpp"
#include <vector>

/** @file
 *  This file contains the mocks for the fuzzing process, if they are needed.
 *  The variable names say for themselves.
 */

#define u8  uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t

extern std::vector<u8> mockedGetVersion;
extern std::vector<u8> mockedVersion;
extern std::vector<u8> mockedGetCapabilities;
extern std::vector<u8> mockedCapabilities;
extern std::vector<u8> mockedNegAlgorithms;
extern std::vector<u8> mockedAlgorithms;
extern std::vector<u8> mockedGetDigests;
extern std::vector<u8> mockedDigests;
extern std::vector<u8> mockedGetCertificate;
extern std::vector<u8> mockedCertificate1;
extern std::vector<u8> mockedCertificate2;
extern std::vector<u8> mockedChallenge;
extern std::vector<u8> mockedChallengeAuth;