#include "utils.hpp"

/** @file
 *  This file contains the SPDM grammar (packet structure)
 */

/**
 * @brief Global variable which represents the finish connection command from Requester.
 */
extern u32 finishCommand;

/**
 * @brief Global variable which represents the size of Measurements Hash size algorithm message
 */
extern u8  M;

/**
 * @brief Possible Request Response codes from SPDM
 * 
 * This map contains the possible Request Response codes from SPDM, from a string (req res name to the number)
 */
extern std::map<std::string, u8> RequestResponseCode;

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
     * @param max Max size of the packet. If is set to zero or none, it will not use random size.
     * 
     * @return void* Buffer with all the serialized data
     */
    virtual void* serialize(size_t max = 0) = 0;

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

    struct ver_number {
        u8 major_version;  ///< Major version
        u8 minor_version;  ///< Minor version
        u8 update_version; ///< Update version
        u8 alpha;          ///< Alpha version
    } *entry;

public:
    /**
     * @brief Constructor for the Version class
     * 
     * This constructor initializes the Version class with the common fields and the specific fields for the Version packet.
     */
    Version();

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
     * @param max Max size of the packet. If is set to zero or none, it will not use random size.
     * 
     * @return void* Buffer with all the serialized data
     */
    void* serialize(size_t max = 0) override;
};


class Capabilities : public responsePacket {
private:
    u8  reserved;    ///< Reserved field
    u8  ct_exponent; ///< CT Exponent field
    u16 reserved_2;  ///< Reserved field
    
    struct flags {
        u8 cache_cap;
        u8 cert_cap;
        u8 chal_cap;
        u8 meas_cap;
        u8 meas_fresh_cap;
    } flags;

public:
    Capabilities();

    void* serialize(size_t max = 0) override;
};

