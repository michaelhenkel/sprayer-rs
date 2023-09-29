#![no_std]
use core::{cell::UnsafeCell, marker::PhantomData, mem, ptr::NonNull};
use aya_bpf::
    {
        bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_XSKMAP},
        cty::{c_long, c_void},
        helpers::{
            bpf_map_lookup_elem,
            bpf_map_update_elem,
            bpf_map_delete_elem,
        }
};
pub(crate) enum PinningType {
    None = 0,
    ByName = 1,
}
#[repr(transparent)]
pub struct XskMap<K, V> {
    def: UnsafeCell<bpf_map_def>,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

unsafe impl<K: Sync, V: Sync> Sync for XskMap<K, V> {}

impl<K, V> XskMap<K, V> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> XskMap<K, V> {
        XskMap {
            def: UnsafeCell::new(build_def::<K, V>(
                BPF_MAP_TYPE_XSKMAP,
                max_entries,
                flags,
                PinningType::None,
            )),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> XskMap<K, V> {
        XskMap {
            def: UnsafeCell::new(build_def::<K, V>(
                BPF_MAP_TYPE_XSKMAP,
                max_entries,
                flags,
                PinningType::ByName,
            )),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    /// Retrieve the value associate with `key` from the map.
    /// This function is unsafe. Unless the map flag `BPF_F_NO_PREALLOC` is used, the kernel does not
    /// make guarantee on the atomicity of `insert` or `remove`, and any element removed from the
    /// map might get aliased by another element in the map, causing garbage to be read, or
    /// corruption in case of writes.
    #[inline]
    pub unsafe fn get(&self, key: &K) -> Option<&V> {
        get(self.def.get(), key)
    }

    /// Retrieve the value associate with `key` from the map.
    /// The same caveat as `get` applies, but this returns a raw pointer and it's up to the caller
    /// to decide whether it's safe to dereference the pointer or not.
    #[inline]
    pub fn get_ptr(&self, key: &K) -> Option<*const V> {
        get_ptr(self.def.get(), key)
    }

    /// Retrieve the value associate with `key` from the map.
    /// The same caveat as `get` applies, and additionally cares should be taken to avoid
    /// concurrent writes, but it's up to the caller to decide whether it's safe to dereference the
    /// pointer or not.
    #[inline]
    pub fn get_ptr_mut(&self, key: &K) -> Option<*mut V> {
        get_ptr_mut(self.def.get(), key)
    }

    #[inline]
    pub fn insert(&self, key: &K, value: &V, flags: u64) -> Result<(), c_long> {
        insert(self.def.get(), key, value, flags)
    }

    #[inline]
    pub fn remove(&self, key: &K) -> Result<(), c_long> {
        remove(self.def.get(), key)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Interface {
    pub mac: [u8;6],
    pub ifidx: u32,
    pub ip: u32,
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

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SrcDst{
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct BthHdr{
    pub opcode: u8,
    pub sol_event: u8,
    pub part_key: u16,
    pub res: u8,
    pub dest_qpn: [u8;3],
    pub ack: u8,
    pub psn_seq: [u8;3],
}
impl BthHdr {
    pub const LEN: usize = mem::size_of::<BthHdr>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Bth {
    pub first_psn_seq: u32,
    pub prev_psn_seq: u32,
    pub cur_psn_seq: u32,
    pub next_psn_seq: u32,
    pub opcode: u8,
    pub out_of_order: u8,
    pub padding: [u8;2],
}
impl Bth {
    pub const LEN: usize = mem::size_of::<Bth>();
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Bth {}

const fn build_def<K, V>(ty: u32, max_entries: u32, flags: u32, pin: PinningType) -> bpf_map_def {
    bpf_map_def {
        type_: ty,
        key_size: mem::size_of::<K>() as u32,
        value_size: mem::size_of::<V>() as u32,
        max_entries,
        map_flags: flags,
        id: 0,
        pinning: pin as u32,
    }
}

#[inline]
fn get_ptr_mut<K, V>(def: *mut bpf_map_def, key: &K) -> Option<*mut V> {
    unsafe {
        let value = bpf_map_lookup_elem(def as *mut _, key as *const _ as *const c_void);
        // FIXME: alignment
        NonNull::new(value as *mut V).map(|p| p.as_ptr())
    }
}

#[inline]
fn get_ptr<K, V>(def: *mut bpf_map_def, key: &K) -> Option<*const V> {
    get_ptr_mut(def, key).map(|p| p as *const V)
}

#[inline]
unsafe fn get<'a, K, V>(def: *mut bpf_map_def, key: &K) -> Option<&'a V> {
    get_ptr(def, key).map(|p| &*p)
}

#[inline]
fn insert<K, V>(def: *mut bpf_map_def, key: &K, value: &V, flags: u64) -> Result<(), c_long> {
    let ret = unsafe {
        bpf_map_update_elem(
            def as *mut _,
            key as *const _ as *const _,
            value as *const _ as *const _,
            flags,
        )
    };
    (ret == 0).then_some(()).ok_or(ret)
}

#[inline]
fn remove<K>(def: *mut bpf_map_def, key: &K) -> Result<(), c_long> {
    let ret = unsafe { bpf_map_delete_elem(def as *mut _, key as *const _ as *const c_void) };
    (ret == 0).then_some(()).ok_or(ret)
}