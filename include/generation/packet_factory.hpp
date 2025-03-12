#pragma once

#include "packet.hpp"
#include "../utils.hpp"

class PacketFactory {
private:
    u8 M_MeasurementsSize;
    u8 H_HashSize;
    u8 S_SignatureSize;
    
public:
    PacketFactory();

    void CreatePacket(u8 Code, u8 fuzzStrategy, MessageSPDM *response);
};