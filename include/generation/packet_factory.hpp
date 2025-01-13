#include "packet.hpp"
#include "../utils.hpp"

class PacketFactory {
private:
    u8 M_MeasurementsSize;
    u8 H_HashSize;
    u8 S_SignatureSize;
    
public:
    static void CreatePacket(void *packetArgs, u8 Code, u8 fuzzStrategy, MessageSPDM &response);
};