
local spdm = Proto("SPDM", "Security Protocol Data Model")
local mctp = Proto("MCTP-TCP", "Management Component Transport Protocol")


-- MCTP --

Header      = ProtoField.bytes("Header", "Physical Medium-Specific Header")
RSVD        = ProtoField.uint8("RSVD", "Reserved", base.DEC, NULL, 0xF)
HDR_Version = ProtoField.uint8("HDR_Version", "Header Version", base.DEC, NULL, 0xF0)
Dest_ID     = ProtoField.uint8("Dest_ID", "Destination ID")
Src_ID      = ProtoField.uint8("Src_ID", "Source ID")


local yesno_types = {
    [0] = "No",
    [1] = "Yes"
}

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


-- SPDM --

local reqres_types = {
        -- Requests --
        [0x81] = "Request: GET_DIGESTS", -- 1.0.2
        [0x82] = "Request: GET_CERTIFICATE", -- 1.0.2
        [0x83] = "Request: CHALLENGE", -- 1.0.2
        [0x84] = "Request: GET_VERSION", -- 1.0.2
        [0x87] = "Request: GET_ENDPOINT_INFO",
        [0xE0] = "Request: GET_MEASUREMENTS", -- 1.0.2
        [0xE1] = "Request: GET_CAPABILITIES", -- 1.0.2
        [0xE2] = "Request: GET_SUPPORTED_EVENT_TYPES",
        [0xE3] = "Request: NEGOTIATE_ALGORITHMS", -- 1.0.2
        [0xFE] = "Request: VENDOR_DEFINED_REQUEST",-- 1.0.2
        [0xFF] = "Request: RESPOND_IF_READY",-- 1.0.2
    
        -- Responses --
        [0x01] = "Respond: DIGESTS", -- 1.0.2
        [0x02] = "Respond: CERTIFICATE", -- 1.0.2
        [0x03] = "Respond: CHALLENGE_AUTH", -- 1.0.2
        [0x04] = "Respond: VERSION", -- 1.0.2
        [0x60] = "Respond: MEASUREMENTS", -- 1.0.2
        [0x61] = "Respond: CAPABILITIES", -- 1.0.2
        [0x63] = "Respond: ALGORITHMS", -- 1.0.2
        [0x64] = "Respond: KEY_EXCHANGE_RSP",
        [0x7E] = "Respond: VENDOR_DEFINED_RESPONSE",-- 1.0.2
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
    [2] = "Supports",
    [3] = "Reserved"
}


CACHE_CAP      = ProtoField.uint8("CACHE_CAP", "Supports Negotiated State Caching", base.DEC, yesno_types, 0x1)
CERT_CAP       = ProtoField.uint8("CERT_CAP", "Supports GET_DIGESTS and GET_CERTIFICATE", base.DEC, yesno_types, 0x2)
CHAL_CAP       = ProtoField.uint8("CHAL_CAP", "Supports CHALLANGE message", base.DEC, yesno_types, 0x4)
MEAS_CAP       = ProtoField.uint8("MEAS_CAP", "MEASUREMENT Capabilities", base.DEC, MSCAP, 0x18)
MEAS_FRESH_CAP = ProtoField.uint8("MEAS_FRESH_CAP", "???", base.DEC, yesno_types, 0x20)


local BSymAlgo = {
    [1] = "TPM_ALG_RSASSA_2048",
    [2] = "TPM_ALG_RSAPSS_2048",
    [4] = "TPM_ALG_RSASSA_3072",
    [8] = "TPM_ALG_RSAPSS_3072",
    [16] = "TPM_ALG_ECDSA_ECC_NIST_P256",
    [32] = "TPM_ALG_RSASSA_4096",
    [64] = "TPM_ALG_RSAPSS_4096",
    [128] = "TPM_ALG_ECDSA_ECC_NIST_P384",
    [256] = "TPM_ALG_ECDSA_ECC_NIST_P521"
}


local BHshAlgo = {
    [0] = "Raw",
    [1] = "TPM_ALG_SHA_256",
    [2] = "TPM_ALG_SHA_384",
    [4] = "TPM_ALG_SHA_512",
    [8] = "TPM_ALG_SHA3_256",
    [16] = "TPM_ALG_SHA3_384",
    [32] = "TPM_ALG_SHA3_512"
}

local AlgTypes = {
    [2] = "DHE",
    [3] = "AEADCipherSuite",
    [4] = "ReqBaseAsymAlg",
    [5] = "KeySchedule"
}


Length   = ProtoField.uint16("Length", "Length", base.DEC) 
MSpecs   = ProtoField.uint8("MSpecs", "Measurement Specification")
BaseSymAlg   = ProtoField.uint32("BaseSymAlg", "Supported key signature algorithms", base.DEC, BSymAlgo)
BaseHshAlg   = ProtoField.uint32("BaseHshAlg", "Supported hashing algorithms", base.DEC, BHshAlgo)
ExtAsyC     = ProtoField.uint8("ExtAsyC", "Number of supported key algorithms")
ExtHshC     = ProtoField.uint8("ExtHshC", "Number of supported hashing algorithms")
ExtAsym     = ProtoField.uint32("ExtAsym", "Supported key algorithm")
ExtHsh      = ProtoField.uint32("ExtHsh", "Supported hashing algorithm")

AlgType  = ProtoField.uint8("AlgType", "Algorithm Type", base.HEX, AlgTypes)
AlgSup   = ProtoField.bytes("AlgSup", "Supported algorithms")
AlgExt   = ProtoField.bytes("AlgExt", "Extended supported algorithms")
EAlgCount = ProtoField.uint8("ExtAlgCount", "Number of extended supported algorithms", base.DEC, NULL, 15)
FAlgCount = ProtoField.uint8("FixedAlgCount", "Number of fixed supported algorithms", base.DEC, NULL, 240)

MHshAlg = ProtoField.uint8("MHshAlg", "Bit mask for supported hashing algorithms", base.DEC, BHshAlgo)
BaseSymSel = ProtoField.uint32("BaseSymSel", "Selected key signature algorithm", base.DEC, BSymAlgo)
BaseHshSel = ProtoField.uint32("BaseHshSel", "Selected hashing algorithm", base.DEC, BHshAlgo)
ExtAsySelC = ProtoField.uint8("ExtAsySelC", "Number of selected key algorithms")
ExtHshSelC = ProtoField.uint8("ExtHshSelC", "Number of selected hashing algorithms")



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


    -- Get Capabilities --
    -- Reserved_GC1,
    -- CTExp,
    -- Reserved_GC2,
    -- Flags,
    -- TransSize,
    -- MaxSize,
    -- Sup

    -- Capabilities --
    CTExp,
    CACHE_CAP,
    CERT_CAP,
    CHAL_CAP,
    MEAS_CAP,
    MEAS_FRESH_CAP,

    -- Neg Algorithms --
    Length,
    MSpecs,
    BaseSymAlg,
    BaseHshAlg,
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
    -- MSpecsSel --
    MHshAlg,
    BaseSymSel,
    BaseHshSel,
    ExtAsySelC,
    ExtHshSelC




}


function spdm.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length < 4 then return end -- Verificação de comprimento mínimo do cabeçalho

    local subtree_1 = tree:add(mctp, buffer(), "Management Component Transport Protocol Data")
    
    subtree_1:add(Header, buffer(0, 4))
    if length == 4 then 
        pinfo.cols.protocol = mctp.name
        pinfo.cols.info = "Physical-Media Header"
        return 
    end

    pinfo.cols.protocol = spdm.name

    subtree_1:add(RSVD, buffer(4, 1))

    local header_length = 4
    if length >= header_length + 2 then
        local flags = buffer(header_length, 1):uint()
        subtree_1:add(Dest_ID, buffer(header_length + 1, 1))
        subtree_1:add(Src_ID, buffer(header_length + 2, 1))

        subtree_1:add(SOM, buffer(header_length + 3, 1))
        subtree_1:add(EOM, buffer(header_length + 3, 1))
        subtree_1:add(Pkt_SQ, buffer(header_length + 3, 1))
        subtree_1:add(TO, buffer(header_length + 3, 1))
        subtree_1:add(Tag, buffer(header_length + 3, 1))

        subtree_1:add(IC, buffer(header_length + 4, 1))
        subtree_1:add(Type, buffer(header_length + 4, 1))

        -- checa se mensagem é do tipo SPDM --
        if buffer(header_length + 4, 1):uint() == 5 then
            local subtree_2 = tree:add(spdm, buffer(header_length + 5, length - 9), "Security Protocol Data Model")

            subtree_2:add(Major, buffer(header_length + 5, 1))
            subtree_2:add(Minor, buffer(header_length + 5, 1))
            subtree_2:add(ReqRes, buffer(header_length + 6, 1))

            local info = buffer(header_length + 6, 1):uint()

            local p1 = buffer(header_length + 7, 1)
            local p2 = buffer(header_length + 8, 1)

            subtree_2:add(Param1, p1)
            subtree_2:add(Param2, p2)

            local spdm_length = length - 9 - 4

            local begin = header_length + 9

            if info == 0x81 then
                pinfo.cols.info = "Request: GET_DIGESTS"
            elseif info == 0x82 then
                pinfo.cols.info = "Request: GET_CERTIFICATE"
            elseif info == 0x83 then
                pinfo.cols.info = "Request: CHALLENGE"
            elseif info == 0x84 then
                pinfo.cols.info = "Request: GET_VERSION"
                return
            elseif info == 0xE0 then
                pinfo.cols.info = "Request: GET_MEASUREMENTS"
            elseif info == 0xE1 then
                pinfo.cols.info = "Request: GET_CAPABILITIES"
                return


            elseif info == 0xE3 then
                pinfo.cols.info = "Request: NEGOTIATE_ALGORITHMS"

                local n = tonumber(buffer(begin + 1, 1) .. buffer(begin, 1), 16)

                local neg_alg = subtree_2:add(spdm, buffer(begin, n - 4), "Negotiate Algorithms Message")

                neg_alg:add(Length, n)
                neg_alg:add(MSpecs, buffer(begin + 2, 1))
                neg_alg:add(Reserved, buffer(begin + 3, 1))
                
                neg_alg:add(BaseSymAlg, buffer(begin + 4, 4))
                neg_alg:add(BaseHshAlg, buffer(begin + 8, 4))
                neg_alg:add(Reserved, buffer(begin + 12, 12))
                
                neg_alg:add(ExtAsyC, buffer(begin + 24, 1))
                neg_alg:add(ExtHshC, buffer(begin + 25, 1))

                local A = buffer(begin + 24, 1):uint()
                local E = buffer(begin + 25, 1):uint()

                neg_alg:add(Reserved, buffer(begin + 26, 2))

                local asymL = neg_alg:add(spdm, buffer(begin + 28, 4*A), "List of Asymmetric Algorithms")
                local hashL = neg_alg:add(spdm, buffer(begin + 28 + 4*A, 4*E), "List of Hashing Algorithms")

                local i
                    
                if A ~= 0 then
                    for i = 0, 4*A, 4 do
                        asymL:add(ExtAsym, buffer(begin + 28 + i, 4))
                    end

                    for i = 0, 4*E, 4 do
                        hashL:add(ExtHsh, buffer(begin + 28 + 4*A + i, 4))
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

                    trees[i] = neg_alg:add(spdm, buffer(struct_beg + i, 2 + FixedAlgCount + 4*ExtAlgCount), "Algorithm Request")

                    trees[i]:add(AlgType, buffer(struct_beg + i, 1))
                    trees[i]:add(FAlgCount, buffer(struct_beg + i + 1, 1))
                    trees[i]:add(EAlgCount, buffer(struct_beg + i + 1, 1))
                    trees[i]:add(AlgSup, buffer(struct_beg + i + 2, FixedAlgCount))

                    if ExtAlgCount ~= 0 then
                        trees[i]:add(AlgExt, buffer(struct_beg + i + 2 + FixedAlgCount, 4*ExtAlgCount))
                    else
                        trees[i]:add(AlgExt, "None")
                    end

                    i = i + 2 + FixedAlgCount + 4*ExtAlgCount
                end

            elseif info == 0xFF then
                pinfo.cols.info = "Request: RESPOND_IF_READY"
            elseif info == 0xFE then
                pinfo.cols.info = "Request: VENDOR_DEFINED_REQUEST"
            elseif info == 0x01 then
                pinfo.cols.info = "Respond: DIGESTS"
            elseif info == 0x02 then
                pinfo.cols.info = "Respond: CERTIFICATE"
            elseif info == 0x03 then
                pinfo.cols.info = "Respond: CHALLENGE_AUTH"
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

                    ver_num:add(MajorV, buffer(begin + 3 + i, 1))
                    ver_num:add(MinorV, buffer(begin + 3 + i, 1))
                    ver_num:add(UVNum , buffer(begin + 4 + i, 1))
                    ver_num:add(Alpha , buffer(begin + 4 + i, 1))

                    i = i + 2
                end
                
            elseif info == 0x60 then
                pinfo.cols.info = "Respond: MEASUREMENTS"
            elseif info == 0x61 then
                pinfo.cols.info = "Respond: CAPABILITIES"

                local cap = subtree_2:add(spdm, buffer(begin, 8), "Capabilities Message")

                cap:add(Reserved, buffer(begin, 1))
                cap:add(CTExp, buffer(begin + 1, 1))
                cap:add(Reserved, buffer(begin + 2, 2))

                local flags = cap:add(spdm, buffer(begin + 4, 4), "Flags")

                flags:add(CACHE_CAP, buffer(begin + 4, 1))
                flags:add(CERT_CAP, buffer(begin + 4, 1))
                flags:add(CHAL_CAP, buffer(begin + 4, 1))
                flags:add(MEAS_CAP, buffer(begin + 4, 1))
                flags:add(MEAS_FRESH_CAP, buffer(begin + 4, 1))
                --flags:add(Reserved, buffer(begin + 4, 1))
                flags:add(Reserved, buffer(begin + 5, 1))
                flags:add(Reserved, buffer(begin + 6, 1))
                flags:add(Reserved, buffer(begin + 7, 1))


            elseif info == 0x63 then
                pinfo.cols.info = "Respond: ALGORITHMS"

                local n = tonumber(buffer(begin + 1, 1) .. buffer(begin, 1), 16)

                local alg = subtree_2:add(spdm, buffer(begin, n - 4), "Negotiate Algorithms Message")

                alg:add(Length, n)
                alg:add(MSpecs, buffer(begin + 2, 1))
                alg:add(Reserved, buffer(begin + 3, 1))
                alg:add(MHshAlg, buffer(begin + 4, 1))
                
                
                alg:add(BaseSymSel, buffer(begin + 8, 4))
                alg:add(BaseHshSel, buffer(begin + 12, 4))
                alg:add(Reserved, buffer(begin + 16, 12))
                
                alg:add(ExtAsySelC, buffer(begin + 28, 1))
                alg:add(ExtHshSelC, buffer(begin + 29, 1))

                local A = buffer(begin + 28, 1):uint()
                local E = buffer(begin + 29, 1):uint()

                alg:add(Reserved, buffer(begin + 30, 2))

                local asymL = alg:add(spdm, buffer(begin + 32, 4*A), "List of Asymmetric Algorithms")
                local hashL = alg:add(spdm, buffer(begin + 32 + 4*A, 4*E), "List of Hashing Algorithms")

                local i
                    
                if A ~= 0 then
                    for i = 0, 4*A, 4 do
                        asymL:add(ExtAsym, buffer(begin + 32 + i, 4))
                    end

                    for i = 0, 4*E, 4 do
                        hashL:add(ExtHsh, buffer(begin + 36 + 4*A + i, 4))
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

                    trees[i] = alg:add(spdm, buffer(struct_beg + i, 2 + FixedAlgCount + 4*ExtAlgCount), "Algorithm Request")

                    trees[i]:add(AlgType, buffer(struct_beg + i, 1))
                    trees[i]:add(FAlgCount, buffer(struct_beg + i + 1, 1))
                    trees[i]:add(EAlgCount, buffer(struct_beg + i + 1, 1))
                    trees[i]:add(AlgSup, buffer(struct_beg + i + 2, FixedAlgCount))

                    if ExtAlgCount ~= 0 then
                        trees[i]:add(AlgExt, buffer(struct_beg + i + 2 + FixedAlgCount, 4*ExtAlgCount))
                    else
                        trees[i]:add(AlgExt, "None")
                    end

                    i = i + 2 + FixedAlgCount + 4*ExtAlgCount
                end



            elseif info == 0x7E then
                pinfo.cols.info = "Respond: VENDOR_DEFINED_RESPONSE"
            elseif info == 0x7F then
                pinfo.cols.info = "Respond: ERROR"
            else
                pinfo.cols.info = "Reserved/In development"
            end
            
            local spdm_length = length - 9 - 4
            if spdm_length == 0 then return end

            subtree_2:add(Payload, buffer(begin, spdm_length))
        end
    end
end


local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(2323, spdm)

