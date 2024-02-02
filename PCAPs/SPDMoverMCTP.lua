
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
    [0x84] = "GET VERSION"
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

    pinfo.cols.protocol = spdm.name

    local subtree_1 = tree:add(mctp, buffer(), "Management Component Transport Protocol Data")
    
    subtree_1:add(Header, buffer(0, 4))
    if length == 4 then return end

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
            local subtree_2 = tree:add(spdm, buffer(header_length + 5, length - 9), "Security Protocol Data Model)

            subtree_2:add(Major, buffer(header_length + 5, 1))
            subtree_2:add(Minor, buffer(header_length + 5, 1))
            subtree_2:add(ReqRes, buffer(header_length + 6, 1))

            local info = buffer(header_length + 6, 1):uint()
            if info == 0x84 then
                pinfo.cols.info = "GET VERSION"
            end


            subtree_2:add(Param_1, buffer(header_length + 7, 1))
            subtree_2:add(Param_2, buffer(header_length + 8, 1))
        
            local spdm_length = length - 9 - 4

            if spdm_length == 0 then return end

            subtree_2:add(Payload, buffer(header_length + 9, spdm_length))
        end
    end
end


local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(2323, spdm)

