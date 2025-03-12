#include "../../include/generation/packet_factory.hpp"

PacketFactory::PacketFactory()
{
    M_MeasurementsSize = 48;
    H_HashSize = 32;
    S_SignatureSize = 32;
}

void PacketFactory::CreatePacket(u8 Code, u8 fuzzStrategy, MessageSPDM *response)
{
    SPDMPacket *packet;
    int *selectedAlgorithms;

    switch (Code) {
        case 0x01:
            packet = new Digests(fuzzStrategy, H_HashSize);
            break;
        case 0x02:
            packet = new Certificate(fuzzStrategy);
            break;
        case 0x03:
            packet = new ChallengeAuth(fuzzStrategy, H_HashSize, S_SignatureSize);
            break;
        case 0x04:
            packet = new Version(fuzzStrategy);
            break;
        case 0x60:
            packet = new Measurements(fuzzStrategy, S_SignatureSize);
            break;
        case 0x61:
            packet = new Capabilities(fuzzStrategy);
            break;
        case 0x63:
            packet = new Algorithms(fuzzStrategy);
            // Gets the selected algorithm sizes defined by Algorithms message
            selectedAlgorithms = packet->GetSelectedAlgorithms();
            M_MeasurementsSize = selectedAlgorithms[0];
            H_HashSize = selectedAlgorithms[1];
            S_SignatureSize = selectedAlgorithms[2];
            delete selectedAlgorithms;
            
            break;
        case 0x7F:
            packet = new Error(fuzzStrategy);
            break;
        default:
            return;
    }

    response->Size = packet->SerializePacket(response->Buffer);
    delete packet;
}