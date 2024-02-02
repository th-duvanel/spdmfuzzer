
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
        [0x81] = "Request: GET_DIGESTS", 
        [0x82] = "Request: GET_CERTIFICATE", 
        [0x83] = "Request: CHALLENGE", 
        [0x84] = "Request: GET_VERSION", 
        [0x85] = "Request: CHUNK_SEND",
        [0x86] = "Request: CHUNK_GET",
        [0x87] = "Request: GET_ENDPOINT_INFO",
        [0xE0] = "Request: GET_MEASUREMENTS", 
        [0xE1] = "Request: GET_CAPABILITIES", 
        [0xE2] = "Request: GET_SUPPORTED_EVENT_TYPES",
        [0xE3] = "Request: NEGOTIATE_ALGORITHMS", 
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
        [0xFE] = "Request: VENDOR_DEFINED_REQUEST",
        [0xFF] = "Request: RESPOND_IF_READY",
    
        -- Responses --
        [0x01] = "Respond: DIGESTS", 
        [0x02] = "Respond: CERTIFICATE", 
        [0x03] = "Respond: CHALLENGE_AUTH", 
        [0x04] = "Respond: VERSION", 
        [0x05] = "Respond: CHUNK_SEND_ACK",
        [0x06] = "Respond: CHUNK_RESPONSE",
        [0x07] = "Respond: ENDPOINT_INFO",
        [0x60] = "Respond: MEASUREMENTS", 
        [0x61] = "Respond: CAPABILITIES", 
        [0x62] = "Respond: SUPPORTED_EVENT_TYPES",
        [0x63] = "Respond: ALGORITHMS", 
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
        [0x7E] = "Respond: VENDOR_DEFINED_RESPONSE",
        [0x7F] = "Respond: ERROR"
}


Major      = ProtoField.uint8("Major", "Major Version", base.DEC, NULL, 0xF0)
Minor      = ProtoField.uint8("Minor", "Minor Version", base.DEC, NULL, 0xF)
ReqRes     = ProtoField.uint8("ReqRes", "Request Response Code", base.HEX, reqres_types)
Param_1    = ProtoField.uint8("Param_1", "Parameter 1")
Param_2    = ProtoField.uint8("Param_2", "Parameter 2")

Payload    = ProtoField.bytes("Payload", "Payload")

spdm.fields = {
    Major,
    Minor,
    ReqRes,
    Param_1,
    Param_2,
    Payload
}


function spdm.dissector(buffer, pinfo, tree)
    length = buffer:len()
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

            subtree_2:add(Param_1, buffer(header_length + 7, 1))
            subtree_2:add(Param_2, buffer(header_length + 8, 1))

            local info = buffer(header_length + 6, 1):uint()

            if info == 0x81 then
                pinfo.cols.info = "Request: GET_DIGESTS"
            elseif info == 0x82 then
                pinfo.cols.info = "Request: GET_CERTIFICATE"
            elseif info == 0x83 then
                pinfo.cols.info = "Request: CHALLENGE"
            elseif info == 0x84 then
                pinfo.cols.info = "Request: GET_VERSION"
            elseif info == 0xE0 then
                pinfo.cols.info = "Request: GET_MEASUREMENTS"
            elseif info == 0xE1 then
                pinfo.cols.info = "Request: GET_CAPABILITIES"
            elseif info == 0xE3 then
                pinfo.cols.info = "Request: NEGOTIATE_ALGORITHMS"
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

                
            elseif info == 0x60 then
                pinfo.cols.info = "Respond: MEASUREMENTS"
            elseif info == 0x61 then
                pinfo.cols.info = "Respond: CAPABILITIES"
            elseif info == 0x63 then
                pinfo.cols.info = "Respond: ALGORITHMS"
            elseif info == 0x7E then
                pinfo.cols.info = "Respond: VENDOR_DEFINED_RESPONSE"
            elseif info == 0x7F then
                pinfo.cols.info = "Respond: ERROR"
            end

            local spdm_length = length - 9 - 4
            if spdm_length == 0 then return end

            subtree_2:add(Payload, buffer(header_length + 9, spdm_length))
        end
    end
end


local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(2323, spdm)

