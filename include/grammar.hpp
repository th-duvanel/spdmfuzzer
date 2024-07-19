#include "utils.hpp"

/** @file
 *  This file contains the SPDM grammar (packet structure)
 */

/**
 * @brief Global variable which represents the finish connection command from Requester.
 */
extern u32 finishCommand;

/**
 * @brief Possible Request Response codes from SPDM
 * 
 * This map contains the possible Request Response codes from SPDM, from a string (req res name to the number)
 */
extern std::map<std::string, u8> RequestResponseCode;

/**
 * @brief Internal packets grammar structure
 * 
 * This map contains the internal packets grammar structure, with the packet name and its fields.
 */
extern std::map<std::string, std::vector<std::string>> packetStructure;

/**
 * @class responsePacket
 * @brief Base class for all response packets grammar
 * 
 * This class is the base class for all response packets grammar, containing the common fields and methods.
 */
class responsePacket {
    protected:
        u32  size;  ///< Size of the packet

        u8   SPDM;  ///< SPDM version
        u8   major_and_minor; ///< Major and minor version
        u8   reqresCode; ///< Request Response code
        u8   param1; ///< First parameter
        u8   param2; ///< Second parameter

        /**
         * @brief Constructor for the responsePacket class
         * 
         * This constructor initializes the responsePacket class with the common fields.
         * 
         * @param reqresCode Request Response code
         * @param param1 First parameter
         * @param param2 Second parameter
         */
        responsePacket(u8 reqresCode, u8 param1, u8 param2);

        /**
         * @brief Serializes the header of the packet
         * 
         * This method serializes the header of the packet, returning a buffer with the serialized data.
         * 
         * @return u8* Buffer with the serialized data
         */
        u8* serializeHeader();

    public:

        /**
         * @brief Serializes the packet
         * 
         * This method serializes the packet, returning a void pointer with the serialized data.
         * 
         * @return void* Buffer with all the serialized data
         */
        virtual void* serialize() = 0;

        /**
         * @brief Gets the size of the packet
         * 
         * This method returns the size of the packet.
         * 
         * @return u32 Size of the packet
         */
        u32 getSize();
};

/**
 * @class Version
 * @brief VERSION esponse packet grammar
 * 
 * This class represents the Version response packet grammar, containing the fields and methods to serialize the packet.
 */
class Version : public responsePacket {
    private:
        u8   reserved;   ///< Reserved field
        u8   entryCount; ///< Entry count
        u16* entry;      ///< Entry field (2*entryCount size)

    public:
        /**
         * @brief Constructor for the Version class
         * 
         * This constructor initializes the Version class with the common fields and the specific fields for the Version packet.
         * 
         * @param random_size If the size of the packet should be randomized
         */
        Version(bool random_size = false);

        /**
         * @brief Destructor for the Version class
         * 
         * This destructor deallocates the entry field.
         */
        virtual ~Version();

        /**
         * @brief Serializes the packet
         * 
         * This method serializes the packet, returning a void pointer with the serialized data.
         * 
         * @return void* Buffer with all the serialized data
         */
        void* serialize() override;
};

