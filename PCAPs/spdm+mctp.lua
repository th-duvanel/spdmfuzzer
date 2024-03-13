local mctp_protocol = Proto("MCTP", "Management Component Transport Protocol")
local spdm_protocol = Proto("SPDM", "Security Protocol Data Model")


local mctp_fields    = {
    physical_header  = ProtoField.bytes("mctp.physical_header", "Physical Medium-Specific Header")
    reserved_version = ProtoField.uint8("mctp.reserved", "MCTP Reserved", base.DEC, NULL, 0xF0)
    hdr_version      = ProtoField.uint8("mctp.hdr_version", "HDR Reserved", base.DEC, NULL, 0xF0)
    dest_endpoint_id = ProtoField.uint8("mctp.dest_endpoint_id", "Destination Endpoint ID")
    src_endpoint_id  = ProtoField.uint8("mctp.src_endpoint_id", "Source Endpoint ID")

    som              = ProtoField.uint8("mctp.som", "Start of Message", base.DEC, NULL, 0x1)
    eom              = ProtoField.uint8("mctp.eom", "End of Message", base.DEC, NULL, 0x1)
    pkt_sequence     = ProtoField.uint8("mctp.pckt_sequence", "Packet Sequence", base.DEC, NULL, 0x1)
    tag_owner        = ProtoField.uint8("mctp.tag_owner", "Tag Owner", base.DEC, NULL, 0x1)
    msg_tag          = ProtoField.uint8("mctp.msg_tag", "Message Tag", base.DEC, NULL, 0x1)

    message_type     = ProtoField.uint8("mctp.message_type", "Message Type")
}

local spdm_fields    = {
    spdm_version     = ProtoField.uint8("spdm.spdm_version", "SPDM Version")
    req_res_code     = ProtoField.uint8("spdm.req_res_code", "Request/Response Code")
    parameter_1      = ProtoField.uint8("spdm.parameter_1", "Parameter 1")
    parameter_2      = ProtoField.uint8("spdm.parameter_2", "Parameter 2")
    payload         =  ProtoField.bytes("spdm.payload", "Payload")
}

local function get_concat(x) return bit.band(x, 0x01) end


local function get_bit(byte, position)
    return bit.band(byte, bit.lshift(1, position)) ~= 0
end



function mctp_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()

    if length < 4 then return end

    pinfo.cols.protocol = mctp_protocol.name

    local subtree = tree:add(mctp_protocol, buffer(), "Management Component Transport Protocol Data")

    subtree:add(fields.physical_header, buffer(0, 4))
    if length == 4 then return end

    local Reserved = bit.band(buffer(4, 1):uint(), 0xF0) / 16
    local HDR      = bit.band(buffer(4, 1):uint(), 0xF0)

    subtree:add(mctp.reserved_version, buffer(4, 1), Reserved)
    subtree:add(mctp.hdr_version, buffer(4, 1), HDR)

    local header_length = 4
    if length >= header_length + 2 then

        subtree:add(mctp.dest_endpoint_id, buffer(header_length + 1, 1))
        subtree:add(mctp.src_endpoint_id, buffer(header_length + 2, 1))

        local SOM     = bit.band(buffer(header_length + 2, 1):uint(), 0x01)
        local EOM     = bit.band(buffer(header_length + 2, 1):uint(), 0x02) / 2
        local PKT_seq = bit.band(buffer(header_length + 2, 1):uint(), 0x0C) / 4
        local TAG_own = bit.band(buffer(header_length + 2, 1):uint(), 0x10) / 16
        local MSG_tg  = bit.band(buffer(header_length + 2, 1):uint(), 0xE0) / 32

        subtree:add(mctp.som, buffer(header_length + 2, 1), SOM)
        subtree:add(mctp.eom, buffer(header_length + 2, 1), EOM)
        subtree:add(mctp.pkt_sequence, buffer(header_length + 2, 1), PKT_seq)
        subtree:add(mctp.tag_owner, buffer(header_length + 2, 1), TAG_own)
        subtree:add(mctp.msg_tag, buffer(header_length + 2, 1), MSG_tg)

        subtree:add(mctp.message_type, buffer(header_length + 4, 1))
    end

end


function spdm_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    
    if length < 5 then return end

    pinfo.cols.protocol = spdm_protocol.name

    local subtree = tree:add(spdm_protocol, buffer(), "Security Data Model Protocol Data")

    subtree:add(spdm.spdm_version, buffer(0, 1))
    subtree:add(spdm.req_res_code, buffer(1, 1))
    subtree:add(spdm.parameter_1, buffer(2, 1))
    subtree:add(spdm.parameter_2, buffer(3, 1))

    subtree:add(fields.payload, buffer(4, length - 4))
end


local SPDM_port = DissectorTable.get("SPDM.port")
SPDM_port:add(2323, spdm_protocol)