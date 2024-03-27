-- MCTP --

local mctp = Proto("MCTP-TCP", "Management Component Transport Protocol")

Header      = ProtoField.bytes("Header", "Physical Medium-Specific Header")
RSVD        = ProtoField.uint8("RSVD", "Reserved", base.DEC, NULL, 0xF)
HDR_Version = ProtoField.uint8("HDR_Version", "Header Version", base.DEC, NULL, 0xF0)
Dest_ID     = ProtoField.uint8("Dest_ID", "Destination ID")
Src_ID      = ProtoField.uint8("Src_ID", "Source ID")
SOM         = ProtoField.uint8("SOM", "First Packet", base.DEC, yesno_types, 0x1)
EOM         = ProtoField.uint8("EOM", "Last Packet", base.DEC, yesno_types, 0x2)
Pkt_SQ      = ProtoField.uint8("Pkt_SQ", "Packet sequence numer", base.DEC, NULL, 0xC)
TO          = ProtoField.uint8("TO", "Tag Owner", base.DEC, yesno_types, 0x10)
Tag         = ProtoField.uint8("Tag", "Message Tag", base.DEC, NULL, 0xE0)
IC          = ProtoField.uint8("IC", "Check bit", base.DEC, yesno_types, 0x80)
Type        = ProtoField.uint8("Type", "Message Type", base.DEC, NULL, 0x7F)

mctp.fields = {
    Header,
    RSVD,
    HDR_Version,
    Dest_ID,
    Src_ID,
    SOM,
    EOM,
    Pkt_SQ, 
    TO,
    Tag,
    IC,
    Type
}

local yesno_types = {
    [0] = "No",
    [1] = "Yes"
}


-- SPDM --

local spdm = Proto("SPDM", "Security Protocol Data Model")

local reqres_types = {
    -- Requests --
    [0x81] = "Request: GET_DIGESTS", -- 1.0.2
    [0x82] = "Request: GET_CERTIFICATE", -- 1.0.2
    [0x83] = "Request: CHALLENGE", -- 1.0.2
    [0x84] = "Request: GET_VERSION", -- 1.0.2
    [0xE0] = "Request: GET_MEASUREMENTS", -- 1.0.2
    [0xE1] = "Request: GET_CAPABILITIES", -- 1.0.2
    [0xE3] = "Request: NEGOTIATE_ALGORITHMS", -- 1.0.2
    [0xFE] = "Request: VENDOR_DEFINED_REQUEST",-- 1.0.2
    [0xFF] = "Request: RESPOND_IF_READY",-- 1.0.2
    [0xE4] = "Request: KEY_EXCHANGE", -- 1.1.0
    [0xE5] = "Request: FINISH", -- 1.1.0

    -- Responses --
    [0x01] = "Respond: DIGESTS", -- 1.0.2
    [0x02] = "Respond: CERTIFICATE", -- 1.0.2
    [0x03] = "Respond: CHALLENGE_AUTH", -- 1.0.2
    [0x04] = "Respond: VERSION", -- 1.0.2
    [0x60] = "Respond: MEASUREMENTS", -- 1.0.2
    [0x61] = "Respond: CAPABILITIES", -- 1.0.2
    [0x63] = "Respond: ALGORITHMS", -- 1.0.2
    [0x7E] = "Respond: VENDOR_DEFINED_RESPONSE",-- 1.0.2
    [0x64] = "Respond: KEY_EXCHANGE_RSP", -- 1.1.0
    [0x65] = "Respond: FINISH_RSP", -- 1.1.0
    [0x7F] = "Respond: ERROR"
}


Major     = ProtoField.uint8("Major", "Major Version", base.DEC, NULL, 0xF0)
Minor     = ProtoField.uint8("Minor", "Minor Version", base.DEC, NULL, 0xF)
ReqRes    = ProtoField.uint8("ReqRes", "Request Response Code", base.HEX, reqres_types)
Param1   = ProtoField.uint8("Param1", "Parameter 1")
Param2   = ProtoField.uint8("Param2", "Parameter 2")

Payload   = ProtoField.bytes("Payload", "Payload")
Reserved  = ProtoField.bytes("Reserved", "Reserved ")

VNumCount = ProtoField.uint8("VNumCount", "Version Number Count")
MajorV    = ProtoField.uint8("MajorV", "Major Version", base.HEX, NULL, 0xF0)
MinorV    = ProtoField.uint8("Minorv", "Minor Version", base.HEX, NULL, 0xF)
UVNum     = ProtoField.uint8("UVNum","Update Version Number", base.HEX, NULL, 0xF0)
Alpha     = ProtoField.uint8("Alpha", "Alpha", base.HEX, NULL, 0xF)

CTExp = ProtoField.uint8("CTExp", "CT Expoent")

local MSCAP = {
    [0] = "Not Supported",
    [1] = "Supports, but can't generate signatures",
    [2] = "Supports totally",
    [3] = "Reserved"
}

local PSKCAP = {
    [0] = "Not Supported",
    [1] = "Supports pre-shared ey",
    [2] = "Reserved",
    [3] = "Reserved"
}


ENCRYPT_CAP = ProtoField.uint8("ENCRYPT_CAP", "Supports Encryption", base.DEC, yesno_types, 0x40)
MAC_CAP = ProtoField.uint8("MAC_CAP", "Supports Message Authentication", base.DEC, yesno_types, 0x80)
MUT_AUTH_CAP = ProtoField.uint8("MUT_AUTH_CAP", "Supports Mutual Authentication", base.DEC, yesno_types, 0x1)
KEY_EX_CAP = ProtoField.uint8("KEY_EX_CAP", "Supports Key Exchange", base.DEC, yesno_types, 0x2)
PSK_CAP = ProtoField.uint8("PSK_CAP", "Supports Pre-Shared Key", base.DEC, PSKCAP, 0xc)
ENCAP_CAP = ProtoField.uint8("ENCAP_CAP", "Supports Encapsulation", base.DEC, yesno_types, 0x10)
HBEAT_CAP = ProtoField.uint8("HBEAT_CAP", "Supports Heartbeat", base.DEC, yesno_types, 0x20)
KEY_UPD_CAP = ProtoField.uint8("KEY_UPD_CAP", "Supports Key Update", base.DEC, yesno_types, 0x40)
HANDSHAKE_IN_CAP = ProtoField.uint8("HANDSHAKE_IN_CAP", "Supports responder that only exchange messages during Handshake", base.DEC, yesno_types, 0x80)
PUB_KEY_ID_CAP = ProtoField.uint8("PUB_KEY_ID_CAP", "Requester public key by Responder", base.DEC, yesno_types, 0x1)


CACHE_CAP      = ProtoField.uint8("CACHE_CAP", "Supports Negotiated State Caching", base.DEC, yesno_types, 0x1)
CERT_CAP       = ProtoField.uint8("CERT_CAP", "Supports GET_DIGESTS and GET_CERTIFICATE", base.DEC, yesno_types, 0x2)
CHAL_CAP       = ProtoField.uint8("CHAL_CAP", "Supports CHALLANGE message", base.DEC, yesno_types, 0x4)
MEAS_CAP       = ProtoField.uint8("MEAS_CAP", "Measurement Capabilities", base.DEC, MSCAP, 0x18)
MEAS_FRESH_CAP = ProtoField.uint8("MEAS_FRESH_CAP", "Returns fresh Measurements", base.DEC, yesno_types, 0x20)



TPM_ALG_RSASSA_2048 = ProtoField.uint8("TPM_ALG_RSASSA_2048", "TPM_ALG_RSASSA_2048", base.DEC, yesno_types, 0x1)
TPM_ALG_RSAPSS_2048 = ProtoField.uint8("TPM_ALG_RSAPSS_2048", "TPM_ALG_RSAPSS_2048", base.DEC, yesno_types, 0x2)
TPM_ALG_RSASSA_3072 = ProtoField.uint8("TPM_ALG_RSASSA_3072", "TPM_ALG_RSASSA_3072", base.DEC, yesno_types, 0x4)
TPM_ALG_RSAPSS_3072 = ProtoField.uint8("TPM_ALG_RSAPSS_3072", "TPM_ALG_RSAPSS_3072", base.DEC, yesno_types, 0x8)
TPM_ALG_ECDSA_ECC_NIST_P256 = ProtoField.uint8("TPM_ALG_ECDSA_ECC_NIST_P256", "TPM_ALG_ECDSA_ECC_NIST_P256", base.DEC, yesno_types, 0x10)
TPM_ALG_RSASSA_4096 = ProtoField.uint8("TPM_ALG_RSASSA_4096", "TPM_ALG_RSASSA_4096", base.DEC, yesno_types, 0x20)
TPM_ALG_RSAPSS_4096 = ProtoField.uint8("TPM_ALG_RSAPSS_4096", "TPM_ALG_RSAPSS_4096", base.DEC, yesno_types, 0x40)
TPM_ALG_ECDSA_ECC_NIST_P384 = ProtoField.uint8("TPM_ALG_ECDSA_ECC_NIST_P384", "TPM_ALG_ECDSA_ECC_NIST_P384", base.DEC, yesno_types, 0x80)
TPM_ALG_ECDSA_ECC_NIST_P521 = ProtoField.uint8("TPM_ALG_ECDSA_ECC_NIST_P521", "TPM_ALG_ECDSA_ECC_NIST_P521", base.DEC, yesno_types, 0x1)

TPM_ALG_SHA_256 = ProtoField.uint8("TPM_ALG_SHA_256", "TPM_ALG_SHA_256", base.DEC, yesno_types, 0x1)
TPM_ALG_SHA_384 = ProtoField.uint8("TPM_ALG_SHA_384", "TPM_ALG_SHA_384", base.DEC, yesno_types, 0x2)
TPM_ALG_SHA_512 = ProtoField.uint8("TPM_ALG_SHA_512", "TPM_ALG_SHA_512", base.DEC, yesno_types, 0x4)
TPM_ALG_SHA3_256 = ProtoField.uint8("TPM_ALG_SHA3_256", "TPM_ALG_SHA3_256", base.DEC, yesno_types, 0x8)
TPM_ALG_SHA3_384 = ProtoField.uint8("TPM_ALG_SHA3_384", "TPM_ALG_SHA3_384", base.DEC, yesno_types, 0x10)
TPM_ALG_SHA3_512 = ProtoField.uint8("TPM_ALG_SHA3_512", "TPM_ALG_SHA3_512", base.DEC, yesno_types, 0x20)

AES_128_GCM = ProtoField.uint8("AES_128_GCM", "AES_128_GCM", base.DEC, yesno_types, 0x1)
AES_256_GCM = ProtoField.uint8("AES_256_GCM", "AES_256_GCM", base.DEC, yesno_types, 0x2)
CHACHA20_POLY1305 = ProtoField.uint8("CHACHA20_POLY1305", "CHACHA20_POLY1305", base.DEC, yesno_types, 0x4)

Ffdhe2048 = ProtoField.uint8("Ffdhe2048", "ffdhe2048", base.DEC, yesno_types, 0x1)
Ffdhe3072 = ProtoField.uint8("Ffdhe3072", "ffdhe3072", base.DEC, yesno_types, 0x2)
Ffdhe4096 = ProtoField.uint8("Ffdhe4096", "ffdhe4096", base.DEC, yesno_types, 0x4)
Secp256r1 = ProtoField.uint8("Secp256r1", "secp256r1", base.DEC, yesno_types, 0x8)
Secp384r1 = ProtoField.uint8("Secp384r1", "secp384r1", base.DEC, yesno_types, 0x10)
Secp521r1 = ProtoField.uint8("Secp521r1", "secp521r1", base.DEC, yesno_types, 0x20)

SPDM_KEY_SCHED = ProtoField.uint8("SPDM_KEY_SCHED", "SPDM_KEY_SCHED", base.DEC, yesno_types, 0x1)

local AlgTypes = {
    [2] = "DHE",
    [3] = "AEADCipherSuite",
    [4] = "ReqBaseAsymAlg",
    [5] = "KeySchedule"
}

local BSymAlgo = {
    [0x1] = "TPM_ALG_RSASSA_2048",
    [0x2] = "TPM_ALG_RSAPSS_2048",
    [0x4] = "TPM_ALG_RSASSA_3072",
    [0x8] = "TPM_ALG_RSAPSS_3072",
    [0x10] = "TPM_ALG_ECDSA_ECC_NIST_P256",
    [0x20] = "TPM_ALG_RSASSA_4096",
    [0x40] = "TPM_ALG_RSAPSS_4096",
    [0x80] = "TPM_ALG_ECDSA_ECC_NIST_P384",
    [0x100] = "TPM_ALG_ECDSA_ECC_NIST_P521"
}

local BHshAlgo = {
    [0x1] = "TPM_ALG_SHA_256",
    [0x2] = "TPM_ALG_SHA_384",
    [0x4] = "TPM_ALG_SHA_512",
    [0x8] = "TPM_ALG_SHA3_256",
    [0x10] = "TPM_ALG_SHA3_384",
    [0x20] = "TPM_ALG_SHA3_512"
}

local SumHshTypes = {
    [0x0] = "No Measurement Summary Hash",
    [0x1] = "TCB Component Measurement Hash",
    [0xFF] = "All measurements Hash",
}

local ReqAttributes = {
    [0x0] = "Responder incapable of generating signature",
    [0x1] = "Responder shall generate a signature",
}

local DMTFHsh = {
    [0x0] = "Hash",
    [0x1] = "Raw Bit Stream"
}

local DMTFMes = {
    [0x0] = "Immutable ROM",
    [0x1] = "Mutable Firmware",
    [0x2] = "Hardware configuration and debug modes",
    [0x3] = "Firmware configuration",
}

local MutAuth = {
    [0x1] = "Authenticate request for Requester",
    [0x2] = "Responder request for mutual authentication",
    [0x3] = "Mutual authentication with implicit GET_DIGESTS"
}


Length   = ProtoField.uint32("Length", "Length", base.DEC) 
MSpecs   = ProtoField.uint8("MSpecs", "Measurement Specification")
ExtAsyC     = ProtoField.uint8("ExtAsyC", "Number of supported extended key algorithms")
ExtHshC     = ProtoField.uint8("ExtHshC", "Number of supported extended hashing algorithms")
ExtAsym     = ProtoField.uint32("ExtAsym", "Supported key algorithm")
ExtHsh      = ProtoField.uint32("ExtHsh", "Supported hashing algorithm")

AlgType  = ProtoField.uint8("AlgType", "Algorithm Type", base.HEX, AlgTypes)
AlgSup   = ProtoField.bytes("AlgSup", "Supported algorithms")
AlgExt   = ProtoField.bytes("AlgExt", "Extended supported algorithms")
EAlgCount = ProtoField.uint8("ExtAlgCount", "Number of extended supported algorithms", base.DEC, NULL, 15)
FAlgCount = ProtoField.uint8("FixedAlgCount", "Number of fixed supported algorithms", base.DEC, NULL, 240)

BaseSymSel = ProtoField.uint32("BaseSymSel", "Selected key signature algorithm", base.DEC, BSymAlgo)
BaseHshSel = ProtoField.uint32("BaseHshSel", "Selected hashing algorithm", base.DEC, BHshAlgo)
ExtAsySelC = ProtoField.uint8("ExtAsySelC", "Number of selected key algorithms")
ExtHshSelC = ProtoField.uint8("ExtHshSelC", "Number of selected hashing algorithms")

Quantity = ProtoField.uint8("Quantity", "Quantity of digests (n)", base.DEC)
DigSize = ProtoField.uint8("DigSize", "Size of each digest (H)", base.DEC)
Digest = ProtoField.bytes("Digest", "Digest")

Offset = ProtoField.uint16("Offset", "Offset to the message start", base.DEC)
WhichCert = ProtoField.uint8("WhichCert", "Certificate slot", base.DEC)

PortionLength = ProtoField.uint16("PortionLength", "Length of the portion", base.DEC)
RemLength = ProtoField.uint16("RemLength", "Remaining length", base.DEC)

CertChain = ProtoField.bytes("CertChain", "Certificate Chain")
RootHash = ProtoField.bytes("RootHash", "Root Hash")
Certificate = ProtoField.bytes("Certificate", "Certificate")

Nonce = ProtoField.bytes("Nonce", "Nonce")
HshType = ProtoField.uint8("HshType", "Hash Type", base.DEC, SumHshTypes)
RequestAttb = ProtoField.uint8("RequestAttb", "Request Attributes", base.DEC, ReqAttributes)
NBlocks = ProtoField.uint8("NBlocks", "Number of measurement blocks", base.DEC)
MRecLen = ProtoField.uint32("MRecLen", "Measurement Record Length")

Index = ProtoField.uint8("Index", "Index")
MSize = ProtoField.uint16("MSize", "Measurement Size")
SlotIDParam = ProtoField.uint8("SlotIDParam", "Slot ID Parameter", base.DEC, NULL, 0xF)
Measurement = ProtoField.bytes("Measurement", "Measurement")

DMTFHash = ProtoField.uint8("DMTFHash", "DMTF Hash", base.DEC, DMTFHsh, 0x80)
DMTFMes = ProtoField.uint8("DMTFMes", "DMTF Measurement", base.DEC, DMTFMes, 0x7F)
DMTFSize = ProtoField.uint16("DMTFSize", "DMTF Size")
DMTFMes = ProtoField.bytes("DMTFMes", "DMTF Measurement")

CChainHsh = ProtoField.bytes("CChainHsh", "Certificate Chain Hash")
MSumHsh = ProtoField.bytes("MSumHsh", "Measurement Summary Hash")
OpaqueL = ProtoField.uint16("OpaqueL", "Length of the opaque data", base.DEC)
OpaqueD = ProtoField.bytes("OpaqueD", "Opaque Data")
Signature = ProtoField.bytes("Signature", "Signature")

ReqSessionID = ProtoField.uint16("ReqSessionID", "Requester Session ID", base.DEC)
RandomData = ProtoField.bytes("RandomData", "Request provided random Data")
ExcData = ProtoField.bytes("ExcData", "Exchange Data")
RequesterVerifyData = ProtoField.bytes("RequesterVerifyData", "Requester Verify Data")

ReqCode = ProtoField.uint8("ReqCode", "Request Code", base.DEC)
Token = ProtoField.uint8("Token", "Token", base.DEC)

StandardID = ProtoField.uint16("StandardID", "Standard ID", base.DEC)
VendorID = ProtoField.bytes("VendorID", "Vendor ID", base.DEC)
ReqLength = ProtoField.uint16("ReqLength", "Request Length", base.DEC)
VendorPayload = ProtoField.bytes("VendorPayload", "Vendor Payload")

HeartbeatPeriod = ProtoField.uint8("HeartbeatPeriod", "Heartbeat Period", base.DEC)
RspSessionID = ProtoField.uint16("RspSessionID", "Responder Session ID", base.DEC)
MutAuthReq = ProtoField.uint8("MutAuthReq", "Mutual Authentication Request", base.DEC, MutAuth)
ResponderVerifyData = ProtoField.bytes("ResponderVerifyData", "Responder Verify Data")


spdm.fields = {
    Major,
    Minor,
    ReqRes,
    Param1,
    Param2,
    Payload,

    -- Version --
    Reserved,
    VNumCount,
    MajorV,
    MinorV,
    UVNum,
    Alpha,


    -- Get Capabilities and Capabilities--
    CTExp,
    CACHE_CAP,
    CERT_CAP,
    CHAL_CAP,
    MEAS_CAP,
    MEAS_FRESH_CAP,
    ENCRYPT_CAP,
    MAC_CAP,
    MUT_AUTH_CAP,
    KEY_EX_CAP,
    PSK_CAP,
    ENCAP_CAP,
    HBEAT_CAP,
    KEY_UPD_CAP,
    HANDSHAKE_IN_CAP,
    PUB_KEY_ID_CAP,

    -- Algorithms --
    TPM_ALG_RSASSA_2048,
    TPM_ALG_RSAPSS_2048,
    TPM_ALG_RSASSA_3072,
    TPM_ALG_RSAPSS_3072,
    TPM_ALG_ECDSA_ECC_NIST_P256,
    TPM_ALG_RSASSA_4096,
    TPM_ALG_RSAPSS_4096,
    TPM_ALG_ECDSA_ECC_NIST_P384,
    TPM_ALG_ECDSA_ECC_NIST_P521,
    TPM_ALG_SHA_256,
    TPM_ALG_SHA_384,
    TPM_ALG_SHA_512,
    TPM_ALG_SHA3_256,
    TPM_ALG_SHA3_384,
    TPM_ALG_SHA3_512,
    AES_128_GCM,
    AES_256_GCM,
    CHACHA20_POLY1305,
    Ffdhe2048,
    Ffdhe3072,
    Ffdhe4096,
    Secp256r1,
    Secp384r1,
    Secp521r1,
    SPDM_KEY_SCHED,


    -- Neg Algorithms --
    Length,
    MSpecs,
    ExtAsyC,
    ExtHshC,
    ExtAsym,
    ExtHsh,

    AlgType,
    AlgSup,
    AlgExt,
    EAlgCount,
    FAlgCount,

    -- Algorithms --
    BaseSymSel,
    BaseHshSel,
    ExtAsySelC,
    ExtHshSelC,

    -- Digests --
    Quantity,
    DigSize,
    Digest,

    -- Get Cert --
    Offset,
    WhichCert,

    -- Cert --
    PortionLength,
    RemLength,
    CertChain,

    -- Cert Chain --
    RootHash,
    Certificate,

    -- Challange --
    Nonce,
    HshType,

    -- Challange Auth --
    CChainHsh,
    MSumHsh,
    OpaqueL,
    OpaqueD,
    Signature,

    -- Get Measurements --
    RequestAttb,

    -- Measurements --
    NBlocks,
    MRecLen,
    SlotIDParam,

    -- Measurement block --
    Index,
    MSize,
    Measurement,

    -- DMTF Measurement --
    DMTFHash,
    DMTFMes,
    DMTFSize,
    DMTFMes,

    -- Error --
    ExtErrorData,


    -- Respond If Ready --
    ReqCode,
    Token,

    -- Vendor Defined --
    StandardID,
    VendorID,
    ReqLength,
    VendorPayload,

    -- Key Exchange --
    ReqSessionID,
    RandomData,
    ExcData,
    RequesterVerifyData,


    -- Key Enchange Response --
    HeartbeatPeriod,
    RspSessionID,
    MutAuthReq,
    ResponderVerifyData,

    -- globals --
    H,  -- Hash selected size in ALGORITHMS --
    S,  -- Signature algorithm selected size in ALGORITHMS --

    D,  -- D and C sizes defined in DHE ALGORITHMS selected --
    C,
    NChains,
    Chain,
    LenChain

}

D = 0
C = 0

LenChain = 0
Chain = ""

-- Global variables for SPDM --

function countSetBits(byte)
    local count = 0
    while byte > 0 do
        count = count + bit.band(byte, 1)
        byte = bit.rshift(byte, 1)
    end
    return count
end


function spdm.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    --if length < 4 then return end -- Verificação de comprimento mínimo do cabeçalho

    --local subtree_1 = tree:add(mctp, buffer(), "Management Component Transport Protocol Data")
    --
    --subtree_1:add(Header, buffer(0, 4))
    --if length == 4 then 
    --    pinfo.cols.protocol = mctp.name
    --    pinfo.cols.info = "Physical-Media Header"
    --    return 
    --end


    pinfo.cols.protocol = spdm.name


    --subtree_1:add(RSVD, buffer(4, 1))

    local header_length = -4
    if length >= header_length + 2 then
        --local flags = buffer(header_length, 1):uint()
        --subtree_1:add(Dest_ID, buffer(header_length + 1, 1))
        --subtree_1:add(Src_ID, buffer(header_length + 2, 1))

        --subtree_1:add(SOM, buffer(header_length + 3, 1))
        --subtree_1:add(EOM, buffer(header_length + 3, 1))
        --subtree_1:add(Pkt_SQ, buffer(header_length + 3, 1))
        --subtree_1:add(TO, buffer(header_length + 3, 1))
        --subtree_1:add(Tag, buffer(header_length + 3, 1))

        local subtree_1 = tree:add(mctp, buffer(0, 1), "Management Component Transport Protocol Data")
        local subtree_2 = tree:add(spdm, buffer(1, length - 1), "Security Protocol Data Model")

        subtree_1:add(IC, buffer(header_length + 4, 1))
        subtree_1:add(Type, buffer(header_length + 4, 1))

        -- checa se mensagem é do tipo SPDM --
        if buffer(header_length + 4, 1):uint() == 5 then
            subtree_2:add(Major, buffer(header_length + 5, 1))
            subtree_2:add(Minor, buffer(header_length + 5, 1))
            subtree_2:add(ReqRes, buffer(header_length + 6, 1))

            local info = buffer(header_length + 6, 1):uint()

            local p1 = buffer(header_length + 7, 1)
            local p2 = buffer(header_length + 8, 1)

            subtree_2:add(Param1, p1)
            subtree_2:add(Param2, p2)

            local begin = header_length + 9

            if info == 0x81 then
                pinfo.cols.info = "Request: GET_DIGESTS"
                return
            elseif info == 0x82 then
                pinfo.cols.info = "Request: GET_CERTIFICATE"

                local get_cert = subtree_2:add(spdm, buffer(begin, 4), "Get Certificate Message")
                get_cert:add(WhichCert, p1)
                get_cert:add_le(Offset, buffer(begin, 2))
                get_cert:add_le(Length, buffer(begin + 2, 2))

            elseif info == 0x83 then
                pinfo.cols.info = "Request: CHALLENGE"

                local challenge = subtree_2:add(spdm, buffer(begin, 32), "Challenge Message")
                challenge:add(WhichCert, countSetBits(p1:uint()))
                challenge:add(HshType, p2)
                challenge:add(Nonce, buffer(begin, 32))
                
            elseif info == 0x84 then
                pinfo.cols.info = "Request: GET_VERSION"
            elseif info == 0xE4 then
                pinfo.cols.info = "Request: KEY_EXCHANGE"

                local oLength = buffer(begin + 36 + D, 2):le_uint()

                local key_ex = subtree_2:add(spdm, buffer(begin, 38 + D + oLength), "Key Exchange Message")

                key_ex:add(HshType, p1)
                key_ex:add(WhichCert, countSetBits(p2:uint()))
                key_ex:add_le(ReqSessionID, buffer(begin, 2))
                key_ex:add_le(Reserved, buffer(begin + 2, 2))
                key_ex:add_le(RandomData, buffer(begin + 4, 32))
                key_ex:add_le(ExcData, buffer(begin + 36, D))  -- ToDo: Add ECDHE separation --
                key_ex:add_le(OpaqueL, buffer(begin + 36 + D, 2))
                key_ex:add_le(OpaqueD, buffer(begin + 38 + D, oLength))

            elseif info == 0xE5 then
                pinfo.cols.info = "Request: FINISH"

                local auxS = S
                if p1:uint() == 0 then
                    auxS = 0
                end
                local finish = subtree_2:add(spdm, buffer(begin, H + auxS), "Finish Message")

                if auxS ~= 0 then
                    finish:add_le(Signature, buffer(begin, S))
                end

                finish:add_le(RequesterVerifyData, buffer(begin + auxS, H))
            
            elseif info == 0xE0 then
                pinfo.cols.info = "Request: GET_MEASUREMENTS"

                local get_meas = subtree_2:add(spdm, buffer(begin, 32), "Get Measurements Message")
                get_meas:add(RequestAttb, p1)
                get_meas:add(Nonce, buffer(begin, 32))
                get_meas:add(SlotIDParam, buffer(begin + 32, 1))

            elseif info == 0xE1 then
                pinfo.cols.info = "Request: GET_CAPABILITIES"

                local get_cap = subtree_2:add(spdm, buffer(begin, 8), "Get Capabilities Message")

                get_cap:add(Reserved, buffer(begin, 1))
                get_cap:add(CTExp, buffer(begin + 1, 1))
                get_cap:add_le(Reserved, buffer(begin + 2, 2))

                local flags = get_cap:add(spdm, buffer(begin + 4, 4), "Flags")

                flags:add(Reserved, buffer(begin + 4, 1))
                flags:add(CERT_CAP, buffer(begin + 4, 1))
                flags:add(CHAL_CAP, buffer(begin + 4, 1))
                flags:add(MEAS_CAP, buffer(begin + 4, 1))
                flags:add(MEAS_FRESH_CAP, buffer(begin + 4, 1))
                flags:add(ENCRYPT_CAP, buffer(begin + 4, 1))
                flags:add(MAC_CAP, buffer(begin + 4, 1))
                flags:add(MUT_AUTH_CAP, buffer(begin + 5, 1))
                flags:add(KEY_EX_CAP, buffer(begin + 5, 1))
                flags:add(PSK_CAP, buffer(begin + 5, 1))
                flags:add(ENCAP_CAP, buffer(begin + 5, 1))
                flags:add(HBEAT_CAP, buffer(begin + 5, 1))
                flags:add(KEY_UPD_CAP, buffer(begin + 5, 1))
                flags:add(HANDSHAKE_IN_CAP, buffer(begin + 5, 1))
                flags:add(PUB_KEY_ID_CAP, buffer(begin + 6, 1))
                flags:add(Reserved, buffer(begin + 6, 1))
                flags:add(Reserved, buffer(begin + 7, 1))


            elseif info == 0xE3 then
                pinfo.cols.info = "Request: NEGOTIATE_ALGORITHMS"

                local n = tonumber(buffer(begin + 1, 1) .. buffer(begin, 1), 16)

                local neg_alg = subtree_2:add(spdm, buffer(begin, n - 4), "Negotiate Algorithms Message")

                neg_alg:add(Length, n)
                neg_alg:add(MSpecs, buffer(begin + 2, 1))
                neg_alg:add(Reserved, buffer(begin + 3, 1))
                

                
                -- Base Asym Algorithms
                local baseasym = neg_alg:add(spdm, buffer(begin + 4, 1), "Supported Base Asymmetric Algorithms")
                baseasym:add(TPM_ALG_RSASSA_2048, buffer(begin + 4, 1))
                baseasym:add(TPM_ALG_RSAPSS_2048, buffer(begin + 4, 1))
                baseasym:add(TPM_ALG_RSASSA_3072, buffer(begin + 4, 1))
                baseasym:add(TPM_ALG_RSAPSS_3072, buffer(begin + 4, 1))
                baseasym:add(TPM_ALG_ECDSA_ECC_NIST_P256, buffer(begin + 4, 1))
                baseasym:add(TPM_ALG_RSASSA_4096, buffer(begin + 4, 1))
                baseasym:add(TPM_ALG_RSAPSS_4096, buffer(begin + 4, 1))
                baseasym:add(TPM_ALG_ECDSA_ECC_NIST_P384, buffer(begin + 4, 1))
                baseasym:add(TPM_ALG_ECDSA_ECC_NIST_P521, buffer(begin + 5, 1))

                -- Base hash Algorithms
                local basehsh = neg_alg:add(spdm, buffer(begin + 8, 1), "Supported Base Hash Algorithms")
                basehsh:add(TPM_ALG_SHA_256, buffer(begin + 8, 1))
                basehsh:add(TPM_ALG_SHA_384, buffer(begin + 8, 1))
                basehsh:add(TPM_ALG_SHA_512, buffer(begin + 8, 1))
                basehsh:add(TPM_ALG_SHA3_256, buffer(begin + 8, 1))
                basehsh:add(TPM_ALG_SHA3_384, buffer(begin + 8, 1))
                basehsh:add(TPM_ALG_SHA3_512, buffer(begin + 8, 1))

                neg_alg:add(Reserved, buffer(begin + 12, 12))
                
                neg_alg:add(ExtAsyC, buffer(begin + 24, 1))
                neg_alg:add(ExtHshC, buffer(begin + 25, 1))

                local A = buffer(begin + 24, 1):uint()
                local E = buffer(begin + 25, 1):uint()

                neg_alg:add_le(Reserved, buffer(begin + 26, 2))

                local i
                    
                if A ~= 0 then
                    local asymL = neg_alg:add(spdm, buffer(begin + 28, 4*A), "List of Asymmetric Algorithms")

                    for i = 0, 4*A, 4 do
                        asymL:add_le(ExtAsym, buffer(begin + 28 + i, 4))
                    end
                end

                if E ~= 0 then
                    local hashL = neg_alg:add(spdm, buffer(begin + 28 + 4*A, 4*E), "List of Hashing Algorithms")

                    for i = 0, 4*E, 4 do
                        hashL:add_le(ExtHsh, buffer(begin + 28 + 4*A + i, 4))
                    end
                end
                
                local struct_beg = begin + 28 + 4*A + 4*E
                local trees = {}

                i = 0
                local algStructSize = n - 32 - 4*E - 4*A

                while i ~= algStructSize do
                    local algC = buffer(struct_beg + 1 + i, 1):uint()

                    local ExtAlgCount = bit.band(algC, 15)
                    local FixedAlgCount = bit.rshift(bit.band(algC, 240), 4)
                    local type = buffer(struct_beg + i, 1):uint()

                    trees[i] = neg_alg:add(spdm, buffer(struct_beg + i, 2 + FixedAlgCount + 4*ExtAlgCount), "Algorithm Request")

                    trees[i]:add(AlgType, buffer(struct_beg + i, 1))
                    trees[i]:add(FAlgCount, buffer(struct_beg + i + 1, 1))
                    trees[i]:add(EAlgCount, buffer(struct_beg + i + 1, 1))

                    local supported = trees[i]:add(spdm, buffer(struct_beg + i + 2, 2), "Supported Algorithms")

                    if type == 0x2 then
                        supported:add(Ffdhe2048, buffer(struct_beg + i + 2, 1))
                        supported:add(Ffdhe3072, buffer(struct_beg + i + 2, 1))
                        supported:add(Ffdhe4096, buffer(struct_beg + i + 2, 1))
                        supported:add(Secp256r1, buffer(struct_beg + i + 2, 1))
                        supported:add(Secp384r1, buffer(struct_beg + i + 2, 1))
                        supported:add(Secp521r1, buffer(struct_beg + i + 2, 1))
                        else if type == 0x3 then
                            supported:add(AES_128_GCM, buffer(struct_beg + i + 2, 1))
                            supported:add(AES_256_GCM, buffer(struct_beg + i + 2, 1))
                            supported:add(CHACHA20_POLY1305, buffer(struct_beg + i + 2, 1))
                            else if type == 0x4 then
                                supported:add(TPM_ALG_RSASSA_2048, buffer(struct_beg + i + 2, 1))
                                supported:add(TPM_ALG_RSAPSS_2048, buffer(struct_beg + i + 2, 1))
                                supported:add(TPM_ALG_RSASSA_3072, buffer(struct_beg + i + 2, 1))
                                supported:add(TPM_ALG_RSAPSS_3072, buffer(struct_beg + i + 2, 1))
                                supported:add(TPM_ALG_ECDSA_ECC_NIST_P256, buffer(struct_beg + i + 2, 1))
                                supported:add(TPM_ALG_RSASSA_4096, buffer(struct_beg + i + 2, 1))
                                supported:add(TPM_ALG_RSAPSS_4096, buffer(struct_beg + i + 2, 1))
                                supported:add(TPM_ALG_ECDSA_ECC_NIST_P384, buffer(struct_beg + i + 3, 1))
                                else if type == 0x5 then
                                    supported:add(SPDM_KEY_SCHED, buffer(struct_beg + i + 2, 1))
                                end
                            end
                        end
                    end


                    if ExtAlgCount ~= 0 then
                        trees[i]:add(AlgExt, buffer(struct_beg + i + 2 + FixedAlgCount, 4*ExtAlgCount))
                    else
                        trees[i]:add(AlgExt, "None")
                    end

                    i = i + 2 + FixedAlgCount + 4*ExtAlgCount
                end

            elseif info == 0xFF then
                pinfo.cols.info = "Request: RESPOND_IF_READY"

                local res_ready = subtree_2:add(spdm, buffer(begin - 2, 2), "Respond If Ready Message")

                res_ready:add(ReqCode, p1)
                res_ready:add(Token, p2)

            elseif info == 0xFE then
                pinfo.cols.info = "Request: VENDOR_DEFINED_REQUEST"

                local Len = buffer(begin + 2, 1):uint()
                local reqLength = buffer(begin + 3 + Len, 2):le_uint()

                local ven_req = subtree_2:add(spdm, buffer(begin, Len + reqLength + 5), "Vendor Defined Request")

                ven_req:add_le(StandardID, buffer(begin, 2))
                ven_req:add(Length, buffer(begin + 2, 1))
                ven_req:add_le(VendorID, buffer(begin + 3, Len))
                ven_req:add_le(ReqLength, buffer(begin + 3 + Len, 2))
                ven_req:add_le(VendorPayload, buffer(begin + 5 + Len, reqLength))

            elseif info == 0x01 then
                pinfo.cols.info = "Respond: DIGESTS"

                NChains = countSetBits(p2:uint())

                local dig = subtree_2:add(spdm, buffer(begin, 2), "Digests Message")
                dig:add(Quantity, NChains)
                dig:add(DigSize, H)

                local digests = {}

                for i = 0, (NChains - 1)*H, H do
                    digests[i] = subtree_2:add(spdm, buffer(begin + i, H), "Certificate Digest")
                    digests[i]:add(Digest, buffer(begin + i, H))
                end

            elseif info == 0x02 then
                pinfo.cols.info = "Respond: CERTIFICATE"

                local pLength = buffer(begin, 2):le_uint()
                local rLength = buffer(begin + 2, 2):le_uint()

                local cert = subtree_2:add(spdm, buffer(begin, 4 + pLength), "Certificate Message")
                
                cert:add(WhichCert, p1)
                cert:add_le(PortionLength, buffer(begin, 2))
                cert:add_le(RemLength, buffer(begin + 2, 2))
                cert:add(CertChain, buffer(begin + 4, pLength))

                local tbt = tvb(buffer(begin + 4, pLength))
                print(tbt)

                Chain = Chain .. tostring(buffer(begin + 4, pLength))
                LenChain = LenChain + pLength

                if rLength ~= 0 then
                    pinfo.cols.info = "Respond: CERTIFICATE (PART) " .. tostring(p1) .. "th chain"
                else             
                    pinfo.cols.info = "Respond: CERTIFICATE (FULL) " .. tostring(p1) .. "th chain"

                    local Aux = ByteArray.new(Chain)
                    local tvb = ByteArray.tvb(Aux, "Certificate Chain")
                    --print(Chain)
                    --print(Chain:len())   
                    --print("\n\n")

                    local cert_chain = subtree_2:add(spdm, buffer(begin + 4, pLength), "Certificate Chain")

                    cert_chain:add(Length, Aux:le_uint(0, 2))
                    cert_chain:add(Reserved, Aux:le_uint(2, 2))
                    cert_chain:add(RootHash, Aux:raw(4, H))
                    cert_chain:add(Certificate, Aux:raw(4 + H, LenChain - 4 - H))

                    Chain = ""
                end

            elseif info == 0x03 then
                pinfo.cols.info = "Respond: CHALLENGE_AUTH"

                local cha_auth = subtree_2:add(spdm, buffer(begin, 32), "Challenge Auth Message")
                cha_auth:add(WhichCert, countSetBits(p1:uint()))
                cha_auth:add(Quantity, countSetBits(p2:uint()))
                cha_auth:add(CChainHsh, buffer(begin, H))
                cha_auth:add(Nonce, buffer(begin + H, 32))
                cha_auth:add(MSumHsh, buffer(begin + H + 32, H))
                cha_auth:add_le(OpaqueL, buffer(begin + 2*H + 32, 2))

                local oLength = buffer(begin + 2*H + 32, 2):le_uint()

                if oLength ~= 0 then
                    cha_auth:add(OpaqueD, buffer(begin + 2*H + 34, oLength))
                end

                cha_auth:add(Signature, buffer(begin + 2*H + 34 + oLength, S))
                

            elseif info == 0x04 then
                pinfo.cols.info = "Respond: VERSION"
                local n = buffer(header_length + 10, 1):uint()

                local get_ver = subtree_2:add(spdm, buffer(begin, 2*n + 2), "Version Message")
                
                get_ver:add(Reserved, buffer(begin, 1))
                get_ver:add(VNumCount,  buffer(begin + 1, 1))

                local i = 0

                n = n + n

                while i < n do
                    local ver_num = get_ver:add(spdm, buffer(begin + 2 + i, 2), "Supported Version Number")

                    ver_num:add(MajorV, buffer(begin + 2 + i, 1))
                    ver_num:add(MinorV, buffer(begin + 2 + i, 1))
                    ver_num:add(UVNum , buffer(begin + 3 + i, 1))
                    ver_num:add(Alpha , buffer(begin + 3 + i, 1))

                    i = i + 2
                end
                
            elseif info == 0x60 then
                pinfo.cols.info = "Respond: MEASUREMENTS"

                local mes = subtree_2:add(spdm, buffer(begin, 2), "Measurements Message")

                mes:add(SlotIDParam, p2)
                mes:add(NBlocks, buffer(begin, 1))
                mes:add_le(MRecLen, buffer(begin + 1, 3))

                local blocks_num = buffer(begin, 1):uint()        -- Number of measurement blocks
                local blocks_len = buffer(begin + 1, 3):le_uint() -- Length of all measurement blocks

                local mesBlocks = {}
                local i = 0

                while i < blocks_len do
                    local mSize = buffer(begin + 6 + i, 2):le_uint()    -- Block size

                    mesBlocks[i] = subtree_2:add(spdm, buffer(begin + 4 + i, mSize + 4), "Measurement Block")

                    mesBlocks[i]:add(Index, buffer(begin + 4 + i, 1))
                    mesBlocks[i]:add(MSpecs, buffer(begin + 5 + i, 1))
                    mesBlocks[i]:add_le(MSize, buffer(begin + 6 + i, 2))

                    local specs = buffer(begin + 5 + i, 1):uint()

                    if specs == 0 then  -- DMTF Measurement Field --
                        mesBlocks[i]:add(DMTFHash, buffer(begin + 8 + i, 1))
                        mesBlocks[i]:add(DMTFMes, buffer(begin + 8 + i, 1))
                        mesBlocks[i]:add_le(DMTFSize, buffer(begin + 10 + i, 2))
                        mesBlocks[i]:add(DMTFMes, buffer(begin + 12 + i, mSize - 3))
                    else
                        mesBlocks[i]:add_le(Measurement, buffer(begin + 8 + i, mSize))
                    end

                    i = i + mSize + 4
                end

                local oLength = buffer(begin + 36 + blocks_len, 2):le_uint()

                mes:add_le(Nonce, buffer(begin + 4 + blocks_len, 32))
                mes:add_le(OpaqueL, buffer(begin + 36 + blocks_len, 2))

                if oLength ~= 0 then
                    mes:add_le(OpaqueD, buffer(begin + 38 + blocks_len, oLength))
                end
                mes:add_le(Signature, buffer(begin + 38 + blocks_len + oLength, S))

            elseif info == 0x61 then
                pinfo.cols.info = "Respond: CAPABILITIES"

                local cap = subtree_2:add(spdm, buffer(begin, 8), "Capabilities Message")

                cap:add(Reserved, buffer(begin, 1))
                cap:add(CTExp, buffer(begin + 1, 1))
                cap:add_le(Reserved, buffer(begin + 2, 2))

                local flags = cap:add(spdm, buffer(begin + 4, 4), "Flags")

                flags:add(CACHE_CAP, buffer(begin + 4, 1))
                flags:add(CERT_CAP, buffer(begin + 4, 1))
                flags:add(CHAL_CAP, buffer(begin + 4, 1))
                flags:add(MEAS_CAP, buffer(begin + 4, 1))
                flags:add(MEAS_FRESH_CAP, buffer(begin + 4, 1))
                flags:add(ENCRYPT_CAP, buffer(begin + 4, 1))
                flags:add(MAC_CAP, buffer(begin + 4, 1))
                flags:add(MUT_AUTH_CAP, buffer(begin + 5, 1))
                flags:add(KEY_EX_CAP, buffer(begin + 5, 1))
                flags:add(PSK_CAP, buffer(begin + 5, 1))
                flags:add(ENCAP_CAP, buffer(begin + 5, 1))
                flags:add(HBEAT_CAP, buffer(begin + 5, 1))
                flags:add(KEY_UPD_CAP, buffer(begin + 5, 1))
                flags:add(HANDSHAKE_IN_CAP, buffer(begin + 5, 1))
                flags:add(PUB_KEY_ID_CAP, buffer(begin + 6, 1))
                flags:add(Reserved, buffer(begin + 6, 1))
                flags:add(Reserved, buffer(begin + 7, 1))


            elseif info == 0x63 then
                pinfo.cols.info = "Respond: ALGORITHMS"

                local n = buffer(begin, 2):le_uint()

                local alg = subtree_2:add(spdm, buffer(begin, n - 4), "Negotiate Algorithms Message")

                alg:add_le(Length, buffer(begin, 2))
                alg:add(MSpecs, buffer(begin + 2, 1))
                alg:add(Reserved, buffer(begin + 3, 1))

                -- Selected algorithms for measurements --
                local basehsh = alg:add(spdm, buffer(begin + 4, 1), "Selected Hash algorithms for measurements")
                basehsh:add(TPM_ALG_SHA_256, buffer(begin + 4, 1))
                basehsh:add(TPM_ALG_SHA_384, buffer(begin + 4, 1))
                basehsh:add(TPM_ALG_SHA_512, buffer(begin + 4, 1))
                basehsh:add(TPM_ALG_SHA3_256, buffer(begin + 4, 1))
                basehsh:add(TPM_ALG_SHA3_384, buffer(begin + 4, 1))
                basehsh:add(TPM_ALG_SHA3_512, buffer(begin + 4, 1))

                alg:add_le(BaseSymSel, buffer(begin + 8, 4))

                local SignSize = buffer(begin + 8, 4):le_uint()

                if (SignSize == 0x1 or SignSize == 0x2) then
                    S = 256
                elseif (SignSize == 0x4 or SignSize == 0x8) then
                    S = 384
                elseif (SignSize == 0x20 or SignSize == 0x40) then
                    S = 512
                elseif (SignSize == 0x10) then
                    S = 64
                elseif (SignSize == 0x80) then
                    S = 96
                elseif (SignSize == 0x100) then
                    S = 66
                end

                alg:add_le(BaseHshSel, buffer(begin + 12, 4))

                local HashSize = buffer(begin + 12, 4):le_uint()

                if (HashSize == 0x1 or HashSize == 0x8) then
                    H = 32
                elseif (HashSize == 0x2 or HashSize == 0x10) then
                    H = 48
                elseif (HashSize == 0x4 or HashSize == 0x20) then
                    H = 64
                end
                
                alg:add_le(Reserved, buffer(begin + 16, 12))
                
                alg:add(ExtAsySelC, buffer(begin + 28, 1))
                alg:add(ExtHshSelC, buffer(begin + 29, 1))

                local A = buffer(begin + 28, 1):uint()
                local E = buffer(begin + 29, 1):uint()

                alg:add_le(Reserved, buffer(begin + 30, 2))

                local i
                    
                if A ~= 0 then
                    local asymL = alg:add(spdm, buffer(begin + 28, 4*A), "List of Asymmetric Algorithms")

                    for i = 0, 4*A, 4 do
                        asymL:add_le(ExtAsym, buffer(begin + 28 + i, 4))
                    end
                end

                if E ~= 0 then
                    local hashL = alg:add(spdm, buffer(begin + 28 + 4*A, 4*E), "List of Hashing Algorithms")

                    for i = 0, 4*E, 4 do
                        hashL:add_le(ExtHsh, buffer(begin + 28 + 4*A + i, 4))
                    end
                end
                
                local struct_beg = begin + 32 + 4*A + 4*E
                local trees = {}

                i = 0
                local algStructSize = n - 36 - 4*E - 4*A

                while i ~= algStructSize do
                    local algC = buffer(struct_beg + 1 + i, 1):uint()

                    local ExtAlgCount = bit.band(algC, 15)
                    local FixedAlgCount = bit.rshift(bit.band(algC, 240), 4)
                    local type = buffer(struct_beg + i, 1):uint()

                    trees[i] = alg:add(spdm, buffer(struct_beg + i, 2 + FixedAlgCount + 4*ExtAlgCount), "Algorithm Response")

                    trees[i]:add(AlgType, buffer(struct_beg + i, 1))
                    trees[i]:add(FAlgCount, buffer(struct_beg + i + 1, 1))
                    trees[i]:add(EAlgCount, buffer(struct_beg + i + 1, 1))

                    local supported = trees[i]:add(spdm, buffer(struct_beg + i + 2, 2), "Accepted Algorithms")

                    if type == 0x2 then
                        supported:add(Ffdhe2048, buffer(struct_beg + i + 2, 1))
                        supported:add(Ffdhe3072, buffer(struct_beg + i + 2, 1))
                        supported:add(Ffdhe4096, buffer(struct_beg + i + 2, 1))
                        supported:add(Secp256r1, buffer(struct_beg + i + 2, 1))
                        supported:add(Secp384r1, buffer(struct_beg + i + 2, 1))
                        supported:add(Secp521r1, buffer(struct_beg + i + 2, 1))

                        local selectedDHE = buffer(struct_beg + i + 2, 1):uint()

                        if     selectedDHE == 0x1 then
                            D = 256
                        elseif selectedDHE == 0x2 then
                            D = 384
                        elseif selectedDHE == 0x4 then
                            D = 521
                        elseif selectedDHE == 0x8 then
                            D = 64
                            C = 32
                        elseif selectedDHE == 0x10 then
                            D = 96
                            C = 48
                        elseif selectedDHE == 0x20 then
                            D = 132
                            C = 66
                        end

                    elseif type == 0x3 then
                        supported:add(AES_128_GCM, buffer(struct_beg + i + 2, 1))
                        supported:add(AES_256_GCM, buffer(struct_beg + i + 2, 1))
                        supported:add(CHACHA20_POLY1305, buffer(struct_beg + i + 2, 1))
                    elseif type == 0x4 then
                        supported:add(TPM_ALG_RSASSA_2048, buffer(struct_beg + i + 2, 1))
                        supported:add(TPM_ALG_RSAPSS_2048, buffer(struct_beg + i + 2, 1))
                        supported:add(TPM_ALG_RSASSA_3072, buffer(struct_beg + i + 2, 1))
                        supported:add(TPM_ALG_RSAPSS_3072, buffer(struct_beg + i + 2, 1))
                        supported:add(TPM_ALG_ECDSA_ECC_NIST_P256, buffer(struct_beg + i + 2, 1))
                        supported:add(TPM_ALG_RSASSA_4096, buffer(struct_beg + i + 2, 1))
                        supported:add(TPM_ALG_RSAPSS_4096, buffer(struct_beg + i + 2, 1))
                        supported:add(TPM_ALG_ECDSA_ECC_NIST_P384, buffer(struct_beg + i + 3, 1))
                    elseif type == 0x5 then
                        supported:add(SPDM_KEY_SCHED, buffer(struct_beg + i + 2, 1))

                    end


                    if ExtAlgCount ~= 0 then
                        trees[i]:add(AlgExt, buffer(struct_beg + i + 2 + FixedAlgCount, 4*ExtAlgCount))
                    else
                        trees[i]:add(AlgExt, "None")
                    end

                    i = i + 2 + FixedAlgCount + 4*ExtAlgCount
                end

            elseif info == 0x64 then
                pinfo.cols.info = "Respond: KEY_EXCHANGE_RESPONSE"

                local oLength = buffer(begin + 36 + D + H, 2):le_uint()

                local key_ex = subtree_2:add(spdm, buffer(begin, 38 + D + H + oLength + S), "Key Exchange Response Message")
                key_ex:add(HeartbeatPeriod, p1)
                key_ex:add_le(RspSessionID, buffer(begin, 2))
                key_ex:add(MutAuthReq, buffer(begin + 2, 1))
                key_ex:add(SlotIDParam, buffer(begin + 3, 1))
                key_ex:add(RandomData, buffer(begin + 4, 32))
                key_ex:add(ExcData, buffer(begin + 36, D))
                key_ex:add(MSumHsh, buffer(begin + 36 + D, H))
                key_ex:add_le(OpaqueL, buffer(begin + 36 + D + H, 2))
                key_ex:add_le(OpaqueD, buffer(begin + 38 + D + H, oLength))
                key_ex:add_le(Signature, buffer(begin + 38 + D + H + oLength, S))

                -- ToDo: check if Session Handhskae is encrypted -> if so, add below H bytes
                -- key_ex:add_le(ResponderVerifyData, buffer(begin + 38 + D + H + oLength + S, H))

            elseif info == 0x65 then
                pinfo.cols.info = "Respond: FINISH_RESPONSE"
            
                local finish_resp = subtree_2:add(spdm, buffer(begin, H), "Finish Response Message")
                finish_resp:add_le(ResponderVerifyData, buffer(begin, H))

            elseif info == 0x7E then
                pinfo.cols.info = "Respond: VENDOR_DEFINED_RESPONSE"

                local Len = buffer(begin + 2, 1):uint()
                local reqLength = buffer(begin + 3 + Len, 2):le_uint()

                local ven_res = subtree_2:add(spdm, buffer(begin, Len + reqLength + 5), "Vendor Defined Response")

                ven_res:add_le(StandardID, buffer(begin, 2))
                ven_res:add(Length, buffer(begin + 2, 1))
                ven_res:add_le(VendorID, buffer(begin + 3, Len))
                ven_res:add_le(ReqLength, buffer(begin + 3 + Len, 2))
                ven_res:add_le(VendorPayload, buffer(begin + 5 + Len, reqLength))
            elseif info == 0x7F then
                pinfo.cols.info = "Respond: ERROR"
            else
                pinfo.cols.info = "Reserved/In development"
            end
            
            local spdm_length = length - 9 - 4
            if spdm_length == 0 then return end
        end
    end
end


local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(2323, spdm)

