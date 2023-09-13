#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkKey {
    pub prefix: u32,
    pub prefix_len: u8
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NetworkKey {}