-- Define the new protocol
sprayer_proto = Proto("Sprayer", "Sprayer Header")

-- Define the fields in the Sprayer header
local f_src_port = ProtoField.uint16("sprayer.src_port", "Source Port")
local f_padding = ProtoField.uint8("sprayer.padding", "Padding")
local f_qp_id = ProtoField.uint24("sprayer.qp_id", "QP ID")

-- Add the fields to the protocol
sprayer_proto.fields = { f_src_port, f_padding, f_qp_id }

-- Define the dissector function for the Sprayer header
function sprayer_proto.dissector(buffer, pinfo, tree)
    local sprayer_tree = tree:add(sprayer_proto, buffer())

    -- Extract the fields from the buffer
    local src_port = buffer(0, 2):uint()
    local padding = buffer(2, 1):uint()
    local qp_id = buffer(3, 3):uint()

    -- Add the fields to the tree
    sprayer_tree:add(f_src_port, buffer(0, 2))
    sprayer_tree:add(f_padding, buffer(2, 1))
    sprayer_tree:add(f_qp_id, buffer(3, 3))

    -- Set the protocol name in the packet details pane
    pinfo.cols.protocol = sprayer_proto.name
end

-- Register the Sprayer protocol as a dissector for UDP port 1234
udp_table = DissectorTable.get("udp.port")
udp_table:add(3000, sprayer_proto)

-- Define the main dissector function for the packet
function sprayer_dissector(buffer, pinfo, tree)
    -- Call the built-in dissector for the Ethernet header
    local eth_dis = Dissector.get("eth_withoutfcs")
    eth_dis:call(buffer, pinfo, tree)

    -- Call the built-in dissector for the IPv4 header
    local ipv4_dis = Dissector.get("ipv4")
    ipv4_dis:call(buffer(14), pinfo, tree)

    -- Call the built-in dissector for the UDP header
    local udp_dis = Dissector.get("udp")
    udp_dis:call(buffer(14 + 20), pinfo, tree)
    local payload_len = buffer:len() - (14 + 20)
    print("InfiniBand payload length: " .. payload_len)

    -- Call the Sprayer dissector for the Sprayer header
    sprayer_proto:call(buffer(14 + 20 + 8), pinfo, tree)

    -- Call the built-in dissector for the BTH header
    local ib_dis = Dissector.get("infiniband.payload")
    local payload_len = buffer:len() - (14 + 20 + 8 + 6)
    print("InfiniBand payload length: " .. payload_len)
    ib_dis:call(buffer(14 + 20 + 8 + 6), pinfo, tree)
end

-- Register the main dissector function for the packet
local sprayer_port = 3000
local sprayer_dis = Dissector.get("sprayer")
DissectorTable.get("udp.port"):add(sprayer_port, sprayer_dis)