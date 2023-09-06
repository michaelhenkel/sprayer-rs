#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ports {
    pub ports: [u16;64],
    pub index: usize,
    pub links: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Ports {}