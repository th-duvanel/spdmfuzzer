
local mctp = Proto("MCTP/TCP", "Management Component Transport Protocol")
local spdm = Proto("SPDM/MCTP", "Security Protocol Data Model")

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

Major      = ProtoField.uint8("Major", "Major Version", base.DEC, NULL, 0xF0)
Minor      = ProtoField.uint8("Minor", "Minor Version", base.DEC, NULL, 0xF)
ReqRes     = ProtoField.uint8("ReqRes", "Request Response Code")
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


function mctp.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length < 4 then return end -- Verificação de comprimento mínimo do cabeçalho

    pinfo.cols.protocol = mctp.name

    local subtree = tree:add(mctp, buffer(), "MCTP Protocol Data")
    
    subtree:add(mctp.fields.physical_header, buffer(0, 4))
    if length == 4 then return end

    subtree:add(mctp.fields.reserved_version, buffer(4, 1))

    local header_length = 4
    if length >= header_length + 2 then
        local flags = buffer(header_length, 1):uint()
        subtree:add(mctp.fields.Dest_ID, buffer(header_length + 1, 1))
        subtree:add(mctp.fields.Src_ID, buffer(header_length + 2, 1))

        subtree:add(mctp.fields.SOM, buffer(header_length + 3, 1))
        subtree:add(mctp.fields.EOM, buffer(header_length + 3, 1))
        subtree:add(mctp.fields.Pkt_SQ, buffer(header_length + 3, 1))
        subtree:add(mctp.fields.TO, buffer(header_length + 3, 1))
        subtree:add(mctp.fields.Tag, buffer(header_length + 3, 1))

        subtree:add(mctp.fields.IC, buffer(header_length + 4, 1))
        subtree:add(mctp.fields.message_type, buffer(header_length + 4, 1))

        is_spdm = buffer(header_length + 4, 1)
        if is_spdm == 5 then -- Verificação se é cabeçalho SPDM --
            spdm.dissector(buffer(header_length + 5), pinfo, subtree)
        end
    end
end


function spdm.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length < 6 then return end
    
    pinfo.cols.protocol = spdm.name

    local subtree = tree:add(spdm, buffer(), "SPDM Protocol")

    subtree:add(spdm.fields.Major, buffer(0, 1))
    subtree:add(spdm.fields.Minor, buffer(0, 1))
    subtree:add(spdm.fields.ReqRes, buffer(1, 1))
    subtree:add(spdm.fields.Param_1, buffer(2, 1))
    subtree:add(spdm.fields.Param_2, buffer(3, 1))

    subtree:add(spdm.fields.Payload, buffer(4, length - 4))
end



local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(2323, mctp)
