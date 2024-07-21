#include "utils.hpp"

/** @file
 *  This file contains the mocks for the fuzzing process, if they are needed.
 *  The variable names says for itself.
 */

#define u8  uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t

#define SIZE_GETVERSION 5
#define SIZE_VERSION 11
#define SIZE_GETCAPABILITIES 21
#define SIZE_CAPABILITIES 13
#define SIZE_NEGALGORITHMS 49
#define SIZE_ALGORITHMS 53
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
extern u8 mockedChallenge[];
extern u8 mockedChallengeAuth[];