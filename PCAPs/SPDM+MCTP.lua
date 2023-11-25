
-- Criando um dissector para o protocolo MCTP
local mctp_protocol = Proto("SPDM-MCTP", "SPDM-MCTP Protocol")

-- Definição dos campos do cabeçalho MCTP
local fields = mctp_protocol.fields
fields.physical_header = ProtoField.bytes("mctp.physical_header", "Physical Medium-Specific Header")
fields.reserved_version = ProtoField.uint8("mctp.reserved_version", "Reserved and Version", base.HEX)
fields.dest_endpoint_id = ProtoField.uint8("mctp.dest_endpoint_id", "Destination Endpoint ID")
fields.src_endpoint_id = ProtoField.uint8("mctp.src_endpoint_id", "Source Endpoint ID")
fields.sepktbtag = ProtoField.bytes("mctp.sepktbtag", "SOM EOM PKTSeq TOBit MSGtag")
fields.message_type = ProtoField.uint8("mctp.message_type", "Message Type")
fields.spdm_version = ProtoField.uint8("mctp.spdm_version", "SPDM Version")
fields.request_response_code = ProtoField.uint8("mctp.request_response_code", "Request/Response Code")
fields.parameter_1 = ProtoField.uint8("mctp.parameter_1", "Parameter 1")
fields.parameter_2 = ProtoField.uint8("mctp.parameter_2", "Parameter 2")
fields.payload = ProtoField.bytes("mctp.payload", "Payload")
fields.message_integrity_check = ProtoField.uint8("mctp.message_integrity_check", "Message Integrity Check")


local function get_bit(byte, position)
    return bit.band(byte, bit.lshift(1, position)) ~= 0
end

-- Função de dissector para análise de pacotes MCTP
function mctp_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length < 4 then return end -- Verificação de comprimento mínimo do cabeçalho

    pinfo.cols.protocol = mctp_protocol.name

    local subtree = tree:add(mctp_protocol, buffer(), "SPDM-MCTP Protocol Data")
    
    subtree:add(fields.physical_header, buffer(0, 4))
    if length == 4 then return end

    subtree:add(fields.reserved_version, buffer(4, 1))

    local header_length = 4
    if length >= header_length + 2 then
        local flags = buffer(header_length, 1):uint()
        subtree:add(fields.dest_endpoint_id, buffer(header_length + 1, 1))
        subtree:add(fields.src_endpoint_id, buffer(header_length + 2, 1))
        subtree:add(fields.sepktbtag, buffer(header_length + 3, 1))
        subtree:add(fields.message_type, buffer(header_length + 4, 1))
        subtree:add(fields.spdm_version, buffer(header_length + 5, 1))
        subtree:add(fields.request_response_code, buffer(header_length + 6, 1))
        subtree:add(fields.parameter_1, buffer(header_length + 7, 1))
        subtree:add(fields.parameter_2, buffer(header_length + 8, 1))

        local payload_start = header_length + 9
        local payload_end = length - 1
        if payload_end >= payload_start then
            subtree:add(fields.payload, buffer(payload_start, payload_end - payload_start))
        end

        subtree:add(fields.message_integrity_check, buffer(length - 1, 1))
    end
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(2323, mctp_protocol)
