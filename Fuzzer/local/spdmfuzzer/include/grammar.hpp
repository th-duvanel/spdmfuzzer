#include "utils.hpp"

extern u32 command;
extern u32 finishCommand;
extern u32 headerMCTP;

extern std::map<std::string, u8> RequestResponseCode;
extern std::map<std::string, std::vector<std::string>> packetStructure;

class responsePacket {
    protected:
        u32  size;

        u8   SPDM;
        u8   major_and_minor;
        u8   reqresCode;
        u8   param1;
        u8   param2;

        responsePacket(u8 reqresCode, u8 majorVersion, u8 minorVersion, u8 param1, u8 param2);

        void* serializeHeader();

    public:
        virtual void* serialize() = 0;

        u32 getSize();
};

class Version : public responsePacket {
    private:
        u8   reserved;
        u8   entryCount;
        u16* entry;

    public:
        Version(bool random_size = false);

        void* serialize() override;
};

