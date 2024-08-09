#include "utils.hpp"
#include "mocks.hpp"

/** @file
 *  This file contains the SPDM grammar (packet structure)
 */

/**
 * @brief Global variable which represents the finish connection command from Requester.
 */
extern u32 finishCommand;

/**
 * @brief Global variable which represents the size of Measurements Hash size algorithm message
 * This is a important variable because teh Responder should ensure the length during all measurement response messages.
 */
extern u8 M;
extern u8 H;

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
    u32 size;  ///< Size of the packet
    u8 fuzz_level; ///< Fuzz level for the packet

    u8 SPDM;  ///< SPDM version
    u8 major_and_minor; ///< Major and minor version
    u8 reqresCode; ///< Request Response code
    u8 param1; ///< First parameter
    u8 param2; ///< Second parameter

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
     * @param buffer with the serialized data
     */
    void serializeHeader(u8* buffer);

public:
    /**
     * @brief Destructor for the responsePacket class
     * 
     * This destructor is the default destructor for the responsePacket class.
     */
    virtual ~responsePacket();

    /**
     * @brief Serializes the packet
     * 
     * This method serializes the packet, returning a void pointer with the serialized data.
     * 
     * @param buffer Buffer with the serialized data
     */
    virtual void serialize(u8* buffer) = 0;

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
 * @brief VERSION response packet grammar
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
     * 
     * @param fuzz_level Fuzz level for the packet. Default is 0, each level can be explained in the doc session.
     */
    Version(u8 fuzz_level = 0);

    /**
     * @brief Destructor for the Version class
     * 
     * This destructor deallocates the entry field.
     */
    ~Version();

    /**
     * @brief Serializes the packet
     * 
     * This method serializes the packet, returning a void pointer with the serialized data.
     * 
     * @param max Max size of the packet. If is set to zero or none, it will not use random size.
     * 
     * @return void* Buffer with all the serialized data
     */
    void serialize(u8* buffer) override;
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
    Capabilities(u8 fuzz_level = 0);

    ~Capabilities();

    void serialize(u8* buffer) override;
};


class Algorithms : public responsePacket {
private:
    u8 meas_specs;  ///< Bit mask to select one specification supported by requester
    u8 reserved;    ///< Reserved field

    u32 meas_hash_algo; // Bit mask listing hashing algorithms for measurements
    u32 base_asym_sel;  // Bit mask listing assymmetric key signature algorithm selected
    u32 base_hash_sel;  // Bit mask listing hashing algorithm selected

    u8 reserved_2[12]; ///< Reserved field
    u8 ext_asym_sel_count;  // Number of extended asymmetric key algorithms selected (0 or 1)
    u8 ext_hash_sel_count;  // Number of hashing algorithm selected (0 or 1)
    u16 reserved_3; ///< Reserved field

    struct ext_sel {
        u8  registry_id;
        u8  reserved;
        u16 algorithm_id;
    } ext_sel[2];

public:
    Algorithms(u8 fuzz_level = 0);

    ~Algorithms();

    void serialize(u8* buffer) override;
};

class Digests : public responsePacket {
private:
    u8 **digests;

public:
    Digests(u8 fuzz_level = 0);

    ~Digests();

    void serialize(u8* buffer) override;
};

class Certificate : public responsePacket {
private:
    u16 portion_length;
    u16 remainder_length;

    struct cert_chain {
        u16 length;
        u16 reserved;
        u8 *root_hash;
        u8 *certificates;
    } *cert_chain;

public:
    Certificate(u8 fuzz_level = 0);

    ~Certificate();

    void serialize(u8* buffer) override;
};

class ChallengeAuth : public responsePacket {
private:
    u8 *cert_chain_hash;
    u8 nonce[32];
    u8 *mes_sum_hash;
    u16 opaque_length;
    u8 *opaque_data;
    u8 *singature;

public:
    ChallengeAuth(u8 fuzz_level = 0);

    ~ChallengeAuth();

    void serialize(u8* buffer) override;
};
