
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
        [0x85] = "Request: CHUNK_SEND",
        [0x86] = "Request: CHUNK_GET",
        [0x87] = "Request: GET_ENDPOINT_INFO",
        [0xE0] = "Request: GET_MEASUREMENTS", -- 1.0.2
        [0xE1] = "Request: GET_CAPABILITIES", -- 1.0.2
        [0xE2] = "Request: GET_SUPPORTED_EVENT_TYPES",
        [0xE3] = "Request: NEGOTIATE_ALGORITHMS", -- 1.0.2
        [0xE4] = "Request: KEY_EXCHANGE",
        [0xE5] = "Request: FINISH",
        [0xE6] = "Request: PSK_EXCHANGE",
        [0xE7] = "Request: PSK_FINISH",
        [0xE8] = "Request: HEARTBEAT",
        [0xE9] = "Request: KEY_UPDATE",
        [0xEA] = "Request: GET_ENCAPSULATED_REQUEST",
        [0xEB] = "Request: DELIVER_ENCAPSULATED_RESPONSE",
        [0xEC] = "Request: END_SESSION",
        [0xED] = "Request: GET_CSR",
        [0xEE] = "Request: SET_CERTIFICATE",
        [0xEF] = "Request: GET_MEASUREMENT_EXTENSION_LOG",
        [0xF0] = "Request: SUBSCRIBE_EVENT_TYPES",
        [0xF1] = "Request: SEND_EVENT",
        [0xFC] = "Request: GET_KEY_PAIR_INFO",
        [0xFD] = "Request: SET_KEY_PAIR_INFO",
        [0xFE] = "Request: VENDOR_DEFINED_REQUEST",-- 1.0.2
        [0xFF] = "Request: RESPOND_IF_READY",-- 1.0.2
    
        -- Responses --
        [0x01] = "Respond: DIGESTS", -- 1.0.2
        [0x02] = "Respond: CERTIFICATE", -- 1.0.2
        [0x03] = "Respond: CHALLENGE_AUTH", -- 1.0.2
        [0x04] = "Respond: VERSION", -- 1.0.2
        [0x05] = "Respond: CHUNK_SEND_ACK",
        [0x06] = "Respond: CHUNK_RESPONSE",
        [0x07] = "Respond: ENDPOINT_INFO",
        [0x60] = "Respond: MEASUREMENTS", -- 1.0.2
        [0x61] = "Respond: CAPABILITIES", -- 1.0.2
        [0x62] = "Respond: SUPPORTED_EVENT_TYPES",
        [0x63] = "Respond: ALGORITHMS", -- 1.0.2
        [0x64] = "Respond: KEY_EXCHANGE_RSP",
        [0x65] = "Respond: FINISH_RSP",
        [0x66] = "Respond: PSK_EXCHANGE_RSP",
        [0x67] = "Respond: PSK_FINISH_RSP",
        [0x68] = "Respond: HEARTBEAT_ACK",
        [0x69] = "Respond: KEY_UPDATE_ACK",
        [0x6A] = "Respond: ENCAPSULATED_REQUEST",
        [0x6B] = "Respond: ENCAPSULATED_RESPONSE_ACK",
        [0x6C] = "Respond: END_SESSION_ACK",
        [0x6D] = "Respond: CSR",
        [0x6E] = "Respond: SET_CERTIFICATE_RSP",
        [0x6F] = "Respond: MEASUREMENT_EXTENSION_LOG",
        [0x70] = "Respond: SUBSCRIBE_EVENT_TYPES_ACK",
        [0x71] = "Respond: EVENT_ACK",
        [0x7C] = "Respond: KEY_PAIR_INFO",
        [0x7D] = "Respond: SET_KEY_PAIR_INFO_ACK",
        [0x7E] = "Respond: VENDOR_DEFINED_RESPONSE",-- 1.0.2
        [0x7F] = "Respond: ERROR"
}


Major      = ProtoField.uint8("Major", "Major Version", base.DEC, NULL, 0xF0)
Minor      = ProtoField.uint8("Minor", "Minor Version", base.DEC, NULL, 0xF)
ReqRes     = ProtoField.uint8("ReqRes", "Request Response Code", base.HEX, reqres_types)
Param_1    = ProtoField.uint8("Param_1", "Parameter 1")
Param_2    = ProtoField.uint8("Param_2", "Parameter 2")

Payload    = ProtoField.bytes("Payload", "Payload")

Reserved   = ProtoField.bytes("Reserved", "Reserved ")
VNumCount  = ProtoField.uint8("VNumCount", "Version Number Count")
MajorV     = ProtoField.uint8("MajorV", "Major Version", base.HEX, NULL, 0xF0)
MinorV     = ProtoField.uint8("Minorv", "Minor Version", base.HEX, NULL, 0xF)
UVNum      = ProtoField.uint8("UVNum","Update Version Number", base.HEX, NULL, 0xF0)
Alpha      = ProtoField.uint8("Alpha", "Alpha", base.HEX, NULL, 0xF)

CTExp = ProtoField.uint8("CTExp", "CT Expoent")

local MSCAP = {
    [0] = "Not Supported",
    [1] = "Supports, but can't generate signatures",
    [2] = "Supports",
    [3] = "Reserved"
}


CACHE_CAP = ProtoField.uint8("CACHE_CAP", "Supports Negotiated State Caching", base.DEC, yesno_types, 0x1)
CERT_CAP = ProtoField.uint8("CERT_CAP", "Supports GET_DIGESTS and GET_CERTIFICATE", base.DEC, yesno_types, 0x2)
CHAL_CAP = ProtoField.uint8("CHAL_CAP", "Supports CHALLANGE message", base.DEC, yesno_types, 0x4)
MEAS_CAP = ProtoField.uint8("MEAS_CAP", "MEASUREMENT Capabilities", base.DEC, MSCAP, 0x18)
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
    [1] = "TPM_ALG_SHA_256",
    [2] = "TPM_ALG_SHA_384",
    [4] = "TPM_ALG_SHA_512",
    [8] = "TPM_ALG_SHA3_256",
    [16] = "TPM_ALG_SHA3_384",
    [32] = "TPM_ALG_SHA3_512"
}

Length = ProtoField.uint16("Length", "Length of the entire message", base.DEC) 
MSpecs = ProtoField.uint8("MSpecs", "Measurement Specification")
SymAlg = ProtoField.uint32("SymAlg", "Supported key signature algorithms", base.DEC, BSymAlgo)
HshAlg = ProtoField.uint32("HshAlg", "Supported hashing algorithms", base.DEC, BHshAlgo)
AsyC = ProtoField.uint8("AsyC", "Number of supported key algorithms")
HshC = ProtoField.uint8("HshC", "Number of supported hashing algorithms")
Asym = ProtoField.uint32("Asym", "Supported key algorithm")
Hsh = ProtoField.uint32("Hsh", "Supported hashing algorithm")

MHshAlg = ProtoField.uint32("MHshAlg", "Supported hashing algorithms")

--TransSize = ProtoField.bytes("TransSize", "Data Transfer Size")
--MaxSize = ProtoField.bytes("MaxSize", "Maximum Mensage Size")
--Sup     = ProtoField.bytes("Sup", "Supported Algorithms")

spdm.fields = {
    Major,
    Minor,
    ReqRes,
    Param_1,
    Param_2,
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
    SymAlg,
    HshAlg,
    AsyC,
    HshC,
    Asym,
    Hsh,

    -- Algorithms --
    -- MSpecsSel --
    MHshAlg




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

            subtree_2:add(Param_1, buffer(header_length + 7, 1))
            subtree_2:add(Param_2, buffer(header_length + 8, 1))

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
                --local get_cap = subtree_2:add(spdm, buffer(begin, 8), "Version Message")

                --get_cap:add(Reserved, buffer(begin, 1))
                --get_cap:add(CTExp, buffer(begin + 1, 1))
                --get_cap:add(Reserved, buffer(begin + 2 2))
                --get_cap:add(Flags, buffer(begin + 4, 4))
                --get_cap:add(TransSize, buffer(begin + 8, 4))
                --get_cap:add(MaxSize, buffer(begin + 12, 4))
                --get_cap:add(Sup, buffer(begin + 16, 1))

            elseif info == 0xE3 then
                pinfo.cols.info = "Request: NEGOTIATE_ALGORITHMS"
                local n = buffer(begin, 2):uint()

                local neg_alg = subtree_2:add(spdm, buffer(begin, n), "Negotiate Algorithms Message")

                neg_alg:add(Length, buffer(begin, 2))
                neg_alg:add(MSpecs, buffer(begin + 2, 1))
                neg_alg:add(Reserved, buffer(begin + 3, 1))
                
                neg_alg:add(BSymAlgo, buffer(begin + 4, 4))
                neg_alg:add(BHshAlgo, buffer(begin + 8, 4))
                neg_alg:add(Reserved, buffer(begin + 12, 12))
                
                neg_alg:add(AsyC, buffer(begin + 24, 1))
                neg_alg:add(HshC, buffer(begin + 25, 1))

                local A = buffer(begin + 24, 1):uint()
                local E = buffer(begin + 25, 1):uint()

                neg_alg:add(Reserved, buffer(begin + 26, 2))

                local asymL = neg_alg:add(spdm, buffer(begin + 28, 4*A), "List of Asymmetric Algorithms")
                local hashL = neg_alg:add(spdm, buffer(begin + 28 + 4*A, 4*E), "List of Hashing Algorithms")

                local i

                for i = 0, 4*A, 4 do
                    asymL:add(Asym, buffer(begin + 28 + i, 4))
                end

                for i = 0, 4*E, 4 do
                    hashL:add(Hsh, buffer(begin + 28 + 4*A + i, 4))
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

                local cap = subtree_2:add(spdm, buffer(begin, 8))

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

                local n = buffer(begin, 2):uint()

                local neg_alg = subtree_2:add(spdm, buffer(begin, n), "Algorithms Message")

                neg_alg:add(Length, buffer(begin, 2))
                neg_alg:add(MSpecs, buffer(begin + 2, 1))
                neg_alg:add(Reserved, buffer(begin + 3, 1))
                neg_alg:add(MHshAlg, buffer(begin + 3, 4))
                
                local hash = neg_alg:add(spdm, buffer(begin + 11, 10), "Hashing Algorithms")

                local asym = neg_alg:add(spdm, buffer(begin + 7, 10), "Asymmetric key Algorithms")


                asym:add(BSymAlgo, buffer(begin + 7, 4))
                asym:add(AsyC, buffer(begin + 23, 1))
                local A = buffer(begin + 23, 1):uint()

                local asym_list = asym:add(spdm, buffer(begin + 27, 4*A), "List")
                local i = 0

                while i < 4*A do
                    asym_list:add(Asym, buffer(begin + 27 + i, 4))
                    i = i + 4
                end

                hash:add(BHshAlgo, buffer(begin + 12, 4))
                hash:add(HshC, buffer(begin + 29, 1))
                local E = buffer(begin + 28, 1):uint()

                local hsh_list = hash:add(spdm, buffer(begin + 27 + 4*A, 4*E))
                i = 0

                while i < 4*E do
                    hsh_list:add(Hsh, buffer(begin + 27 + 4*A + i, 4))
                    i = i + 4
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

