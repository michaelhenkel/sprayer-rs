#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkKey {
    pub prefix: u32,
    pub prefix_len: u8
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NetworkKey {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Interface {
    pub mac: [u8;6],
    pub ifidx: u32,
    pub next_hop: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Interface {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub ip_proto: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowNextHop {
    pub src_mac: [u8;6],
    pub dst_mac: [u8;6],
    pub src_ip: u32,
    pub dst_ip: u32,
    pub ifidx: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowNextHop {}