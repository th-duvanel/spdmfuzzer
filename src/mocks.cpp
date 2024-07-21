#include "../include/mocks.hpp"

u8 mockedGetVersion[]      = "\x05\x10\x84\x00\x00";

u8 mockedVersion[]         = "\x05\x10\x04\x00\x00\x00\x02\x00\x10\x00\x11";

u8 mockedGetCapabilities[] = "\x00\x00\x00\x01\x00\x00\x00\x0d\x05\x11\xe1\x00\x00\x00\x00\x00" \
                             "\x00\xd6\xf7\x01\x00";

u8 mockedCapabilities[]    = "\x05\x11\x61\x00\x00\x00\x00\x00" \
                             "\x00\xd6\xfb\x01\x00";

u8 mockedNegAlgorithms[]   = "\x05\x11\xe3\x04\x00\x30\x00\x01\x00\x10\x00\x00\x00\x01\x00\x00\x00" \
                             "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                             "\x02\x20\x08\x00\x03\x20\x02\x00\x04\x20\x01\x00\x05\x20\x01\x00";

u8 mockedAlgorithms[]      = "\x05\x11\x63\x04\x00\x34\x00\x01\x00\x02\x00\x00\x00\x10\x00\x00\x00" \
                             "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                             "\x00\x00\x00\x00\x02\x20\x08\x00\x03\x20\x02\x00\x04\x20\x01\x00" \
                             "\x05\x20\x01\x00";

u8 mockedGetDigests[]      = "\x00\x00\x00\x01\x00\x00\x00\x05\x05\x11\x81\x00\x00";

u8 mockedDigests[]         = "\x05\x11\x01\x00\x03\xa0\x57\x50" \
                             "\x30\x5d\x36\x9c\x58\xaf\x23\x41\xed\xed\xf5\xf4\xc7\x7b\x91\x52" \
                             "\x89\xe0\x3b\x1e\x96\x3f\xe5\x6e\x9d\x75\x3b\x73\x71\xa0\x57\x50" \
                             "\x30\x5d\x36\x9c\x58\xaf\x23\x41\xed\xed\xf5\xf4\xc7\x7b\x91\x52" \
                             "\x89\xe0\x3b\x1e\x96\x3f\xe5\x6e\x9d\x75\x3b\x73\x71";

u8 mockedGetCertificate[]  = "\x00\x00\x00\x01\x00\x00\x00\x09\x05\x11\x82\x00\x00\x00\x00\x00\x04";

u8 mockedCertificate1[]    = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x45\x00" \
                             "\x04\x45\x02\xb8\x40\x00\x40\x06\x35\xf9\x7f\x00\x00\x01\x7f\x00" \
                             "\x00\x01\x09\x13\xe6\x7c\x1a\x29\xfc\xc3\x20\xc3\x26\x96\x80\x18" \
                             "\x02\x00\x02\x3a\x00\x00\x01\x01\x08\x0a\xb4\x6a\x8a\x0c\xb4\x6a" \
                             "\x8a\x0c\x00\x00\x00\x01\x00\x00\x04\x09\x05\x11\x02\x00\x00\x00" \
                             "\x04\x6e\x01\x6e\x05\x00\x00\x35\x13\x91\xcc\xd1\x09\x28\x3c\x7c" \
                             "\xde\x04\xe3\x29\x65\xf8\x3f\xb0\x0b\x40\x73\x76\x91\xe7\x16\x05" \
                             "\xd7\x05\x01\x36\x5a\xb9\x43\x30\x82\x01\x97\x30\x82\x01\x3d\xa0" \
                             "\x03\x02\x01\x02\x02\x14\x3b\x9e\x12\x86\x60\x65\xb9\x63\x4d\x9a" \
                             "\x1e\x1f\xd7\x3e\xd8\xb3\xd2\x5e\x96\x31\x30\x0a\x06\x08\x2a\x86" \
                             "\x48\xce\x3d\x04\x03\x02\x30\x21\x31\x1f\x30\x1d\x06\x03\x55\x04" \
                             "\x03\x0c\x16\x44\x4d\x54\x46\x20\x6c\x69\x62\x73\x70\x64\x6d\x20" \
                             "\x45\x43\x50\x32\x35\x36\x20\x43\x41\x30\x1e\x17\x0d\x32\x33\x30" \
                             "\x34\x30\x33\x30\x35\x35\x34\x34\x32\x5a\x17\x0d\x33\x33\x30\x33" \
                             "\x33\x31\x30\x35\x35\x34\x34\x32\x5a\x30\x21\x31\x1f\x30\x1d\x06" \
                             "\x03\x55\x04\x03\x0c\x16\x44\x4d\x54\x46\x20\x6c\x69\x62\x73\x70" \
                             "\x64\x6d\x20\x45\x43\x50\x32\x35\x36\x20\x43\x41\x30\x59\x30\x13" \
                             "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d" \
                             "\x03\x01\x07\x03\x42\x00\x04\x3f\xcb\x4b\xf2\x82\x58\x12\x3e\x40" \
                             "\x0d\xde\xd2\x0d\xec\x67\x9f\xa6\x81\x72\xdd\x3f\x0c\x35\x6b\x8d" \
                             "\x92\x50\x7c\x7f\xb2\xb1\x15\x65\x3f\x18\x6a\x85\x5c\x31\x5b\xea" \
                             "\x68\x4c\xb7\x55\xe2\xa8\xa8\x7a\xd9\x0d\x7b\xfd\x89\xab\x62\xec" \
                             "\xbc\xb6\x26\x4b\x7f\xa5\xa9\xa3\x53\x30\x51\x30\x1d\x06\x03\x55" \
                             "\x1d\x0e\x04\x16\x04\x14\x29\x10\xf1\xfa\xdd\x78\x94\x07\x11\x92" \
                             "\x0a\x9f\x62\xbf\xb4\x82\xa9\x02\xc6\x5d\x30\x1f\x06\x03\x55\x1d" \
                             "\x23\x04\x18\x30\x16\x80\x14\x29\x10\xf1\xfa\xdd\x78\x94\x07\x11" \
                             "\x92\x0a\x9f\x62\xbf\xb4\x82\xa9\x02\xc6\x5d\x30\x0f\x06\x03\x55" \
                             "\x1d\x13\x01\x01\xff\x04\x05\x30\x03\x01\x01\xff\x30\x0a\x06\x08" \
                             "\x2a\x86\x48\xce\x3d\x04\x03\x02\x03\x48\x00\x30\x45\x02\x20\x46" \
                             "\xbd\xf0\x8b\x3d\xd6\x23\x42\x4f\xbb\x65\xdb\x50\x30\xc5\x7c\x6d" \
                             "\xf6\xfc\xbf\xaa\xc8\xfc\x0d\xaf\xd0\xa5\xc1\x05\x95\xcb\x6c\x02" \
                             "\x21\x00\x9b\x2d\xb4\x6b\x4f\x38\xc6\x7c\x37\xc8\x49\x79\xcc\x07" \
                             "\x2f\x1e\x45\xc2\x9f\xe2\x1b\xa3\xc1\xff\x80\x91\x14\x1e\x5a\x33" \
                             "\x68\xc0\x30\x82\x01\x9f\x30\x82\x01\x44\xa0\x03\x02\x01\x02\x02" \
                             "\x01\x01\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02\x30\x21" \
                             "\x31\x1f\x30\x1d\x06\x03\x55\x04\x03\x0c\x16\x44\x4d\x54\x46\x20" \
                             "\x6c\x69\x62\x73\x70\x64\x6d\x20\x45\x43\x50\x32\x35\x36\x20\x43" \
                             "\x41\x30\x1e\x17\x0d\x32\x33\x30\x34\x30\x33\x30\x35\x35\x34\x34" \
                             "\x33\x5a\x17\x0d\x33\x33\x30\x33\x33\x31\x30\x35\x35\x34\x34\x33" \
                             "\x5a\x30\x30\x31\x2e\x30\x2c\x06\x03\x55\x04\x03\x0c\x25\x44\x4d" \
                             "\x54\x46\x20\x6c\x69\x62\x73\x70\x64\x6d\x20\x45\x43\x50\x32\x35" \
                             "\x36\x20\x69\x6e\x74\x65\x72\x6d\x65\x64\x69\x61\x74\x65\x20\x63" \
                             "\x65\x72\x74\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01" \
                             "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00\x04\xe9\x8a" \
                             "\x24\x8d\xf3\x8b\x79\x11\x46\x77\x40\x87\x3b\xbc\x99\x03\x93\x85" \
                             "\x1b\xf3\xab\x4f\x68\x52\xb2\xba\x81\xc5\x5f\x9d\x05\x9b\x86\x64" \
                             "\x36\x49\x30\x93\x25\x8d\x29\xea\xc7\xfd\x11\x8a\xb5\xdb\x78\x43" \
                             "\x44\xbc\xcd\x63\x5e\x12\xb1\xe2\xcf\x7b\x1c\xeb\xa8\x2e\xa3\x5e" \
                             "\x30\x5c\x30\x0c\x06\x03\x55\x1d\x13\x04\x05\x30\x03\x01\x01\xff" \
                             "\x30\x0b\x06\x03\x55\x1d\x0f\x04\x04\x03\x02\x01\xfe\x30\x1d\x06" \
                             "\x03\x55\x1d\x0e\x04\x16\x04\x14\x92\x99\xfe\x73\x45\xfb\xe6\x42" \
                             "\x5a\x5a\xcf\x5b\xbe\x69\x05\x42\x81\x19\x2c\x5c\x30\x20\x06\x03" \
                             "\x55\x1d\x25\x01\x01\xff\x04\x16\x30\x14\x06\x08\x2b\x06\x01\x05" \
                             "\x05\x07\x03\x01\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x02\x30\x0a" \
                             "\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02\x03\x49\x00\x30\x46\x02" \
                             "\x21\x00\xd5\x82\x81\x1f\xfb\x11\x59\x49\x2d\x11\x92\xa3\x64\xd1" \
                             "\xac\xe0\xb3\xaf\xcc\xd8\xc5\xe2\xbc\x81\x1d\x91\xe9\xc0\xd9\xa4" \
                             "\x85\xbe\x02\x21\x00\xba\x84\x3d\x5f\xe1\xf2\x11\x0c\x1f\x95\x99" \
                             "\xdd\x51\xe3\x8d\x97\x19\x93\xb6\x33\x63\x1e\xd4\x5b\x02\x91\x91" \
                             "\xa7\x34\x77\x67\x4b\x30\x82\x02\x08\x30\x82\x01\xaf\xa0\x03\x02" \
                             "\x01\x02\x02\x01\x03\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03" \
                             "\x02\x30\x30\x31\x2e\x30\x2c\x06\x03\x55\x04\x03\x0c\x25\x44\x4d" \
                             "\x54\x46\x20\x6c\x69\x62\x73\x70\x64\x6d\x20\x45\x43\x50\x32\x35" \
                             "\x36\x20\x69\x6e\x74\x65\x72\x6d\x65\x64\x69\x61\x74\x65\x20\x63" \
                             "\x65\x72\x74\x30\x1e\x17\x0d\x32\x33\x30\x39\x31\x32\x30\x37\x31" \
                             "\x31\x31\x34\x5a\x17\x0d\x33\x33\x30\x39\x30\x39\x30\x37\x31\x31" \
                             "\x31\x34\x5a\x30\x2d\x31\x2b\x30\x29\x06\x03\x55\x04\x03\x0c\x22" \
                             "\x44\x4d\x54\x46\x20\x6c\x69\x62\x73\x70\x64\x6d\x20\x45\x43\x50" \
                             "\x32\x35\x36\x20\x72\x65\x73\x70\x6f\x6e\x64\x65\x72\x20\x63\x65" \
                             "\x72\x74\x30";

u8 mockedCertificate2[]    = "\x00\x00\x00\x01\x00\x00\x01\x77\x05\x11\x02\x00\x00\x6e\x01\x00" \
                             "\x00\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a" \
                             "\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00\x04\x0d\xf4\x6e\x4d\x65" \
                             "\xfa\x52\xfe\xce\xb0\xbd\xa0\x59\x40\x49\xa0\x7b\x8d\x67\xfc\x61" \
                             "\x91\xae\x7e\x7a\xa5\x60\x93\x78\x97\xe2\xab\x42\x90\x28\xca\x3e" \
                             "\x72\x51\x1e\x6d\xd7\x1b\xeb\x1a\x13\x11\xa5\x1d\x36\x4f\x27\xdf" \
                             "\x80\x66\x96\x41\x73\xea\x51\xdd\x54\xf9\x95\xa3\x81\xbc\x30\x81" \
                             "\xb9\x30\x0c\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x02\x30\x00\x30" \
                             "\x0b\x06\x03\x55\x1d\x0f\x04\x04\x03\x02\x05\xe0\x30\x1d\x06\x03" \
                             "\x55\x1d\x0e\x04\x16\x04\x14\xc8\x58\x02\x82\xe6\xa1\x28\x16\x5d" \
                             "\xde\x24\xc8\xa6\x52\xc5\xab\x54\x1c\xe0\x51\x30\x31\x06\x03\x55" \
                             "\x1d\x11\x04\x2a\x30\x28\xa0\x26\x06\x0a\x2b\x06\x01\x04\x01\x83" \
                             "\x1c\x82\x12\x01\xa0\x18\x0c\x16\x41\x43\x4d\x45\x3a\x57\x49\x44" \
                             "\x47\x45\x54\x3a\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x30\x2a" \
                             "\x06\x03\x55\x1d\x25\x01\x01\xff\x04\x20\x30\x1e\x06\x08\x2b\x06" \
                             "\x01\x05\x05\x07\x03\x01\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x02" \
                             "\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x09\x30\x1e\x06\x0a\x2b\x06" \
                             "\x01\x04\x01\x83\x1c\x82\x12\x06\x04\x10\x30\x0e\x30\x0c\x06\x0a" \
                             "\x2b\x06\x01\x04\x01\x83\x1c\x82\x12\x02\x30\x0a\x06\x08\x2a\x86" \
                             "\x48\xce\x3d\x04\x03\x02\x03\x47\x00\x30\x44\x02\x20\x30\x90\x5c" \
                             "\x67\x6f\x63\x85\x8a\x06\x1b\xac\xd6\x8c\xc3\xd7\xd5\x87\xc8\x36" \
                             "\x01\xa6\x4c\x56\xc4\x8c\x0c\x46\x3e\xc1\xbb\x68\x9c\x02\x20\x08" \
                             "\x68\x02\x1d\x06\x75\x4c\x99\x1c\x20\x96\x52\x14\x9d\xe4\xc5\x39" \
                             "\x88\x9d\xb4\x29\xf7\x53\x6b\x41\x1f\x0d\x26\xef\x80\x4c\x49";

u8 mockedChallenge[]       = "\x00\x00\x00\x01\x00\x00\x00\x25\x05\x11\x83\x00\x00\x67\xc6\x69" \
                             "\x73\x00\x00\x00\x00\x51\xff\x4a\xec\x00\x00\x00\x00\x29\xcd\xba" \
                             "\xab\x00\x00\x00\x00\xf2\xfb\xe3\x46\x00\x00\x00\x00";

u8 mockedChallengeAuth[]   = "\x00\x00\x00\x01\x00\x00\x00\xa7\x05\x11\x03\x80\x01\xa0\x57\x50" \
                             "\x30\x5d\x36\x9c\x58\xaf\x23\x41\xed\xed\xf5\xf4\xc7\x7b\x91\x52" \
                             "\x89\xe0\x3b\x1e\x96\x3f\xe5\x6e\x9d\x75\x3b\x73\x71\x67\xc6\x69" \
                             "\x73\xfc\x7f\x00\x00\x51\xff\x4a\xec\xfc\x7f\x00\x00\x29\xcd\xba" \
                             "\xab\xfc\x7f\x00\x00\xf2\xfb\xe3\x46\xfc\x7f\x00\x00\x00\x00\x00" \
                             "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                             "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa1" \
                             "\x56\x7a\xdd\x1a\x12\x6c\x28\x49\x6e\x8f\x16\x21\x56\x0a\xcc\xb5" \
                             "\x42\x34\xc7\x81\x35\x77\xda\xd8\xad\xde\x52\x52\xc3\xde\xa5\x2d" \
                             "\xc5\x22\x06\x86\x14\x18\x17\xd1\xdf\x90\x59\x78\x8b\xa8\x4b\x37" \
                             "\x85\x2f\xcb\xea\x5c\x91\xf7\x98\xe4\x9f\x18\xd3\x1c\x8e\x45";




