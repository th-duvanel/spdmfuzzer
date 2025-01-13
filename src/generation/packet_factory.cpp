#include "../../include/generation/packet_factory.hpp"

void
PacketFactory::CreatePacket(void *packetArgs, u8 Code, u8 fuzzStrategy, MessageSPDM &response)
{
    SPDMPacket *packet;

    switch (Code) {
        case 0x01:
            packet = new Digests(fuzzStrategy);
            break;
        case 0x02:
            packet = new Certificate(fuzzStrategy);
            break;
        case 0x03:
            packet = new ChallengeAuth(packetArgs, fuzzStrategy);
            break;
        case 0x04:
            packet = new Version(fuzzStrategy);
            break;
        case 0x60:
            packet = new Measurements(packetArgs, fuzzStrategy);
            break;
        case 0x61:
            packet = new Capabilities(fuzzStrategy);
            break;
        case 0x63:
            packet = new Algorithms((NegotiateAlgorithms*)packetArgs, fuzzStrategy);
            break;
        case 0x7F:
            packet = new Error(packetArgs, fuzzStrategy);
            break;
        default:
            return;
    }

    response.Size = packet->SerializePacket(response.Buffer);
    delete packet;
}