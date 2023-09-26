use afxdp::buf_vec::BufVec;
use log::{info, warn, debug};
use network_types::ip;
use rlimit::{setrlimit, Resource};
use arraydeque::{ArrayDeque, Wrapping};
use afxdp::mmap_area::{MmapArea, MmapAreaOptions, MmapError};
use afxdp::socket::{Socket, SocketOptions, SocketRx, SocketTx};
use afxdp::umem::{Umem, UmemCompletionQueue, UmemFillQueue};
use afxdp::PENDING_LEN;
use afxdp::{buf::Buf, buf_pool::BufPool};
use afxdp::{buf_mmap::BufMmap, buf_pool_vec::BufPoolVec};
use libbpf_sys::{
    XSK_RING_CONS__DEFAULT_NUM_DESCS,
    XSK_RING_PROD__DEFAULT_NUM_DESCS,
    xsk_socket__update_xskmap,
    xsk_socket,
    bpf_object__find_map_by_name,
    bpf_object,
    bpf_map__fd,
    bpf_object__find_program_by_name,
    bpf_object__find_map_fd_by_name,
    bpf_prog_get_fd_by_id,
    
};
use std::sync::{Arc, Mutex};
use std::cmp::min;
use std::slice;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    udp::UdpHdr,
};
use tokio::sync::mpsc;
use futures;

#[derive(Default, Copy, Clone)]
pub struct BufCustom {}

pub struct Buffer{
    ingress_intf: String,
    egress_intf: String,
    ingress_map_fd: i32,
    egress_map_fd: i32,
}

impl Buffer {
    pub fn new(ingress_intf: String, egress_intf: String, ingress_map_fd: i32, egress_map_fd: i32) -> Buffer {
        Buffer{
            ingress_intf,
            egress_intf,
            ingress_map_fd,
            egress_map_fd,
        }
    }
    pub async fn run(&self) {
        let options = MmapAreaOptions{ huge_tlb: false };
        let map_area = MmapArea::new(65535, 2048, options);
        let (area, mut bufs) = match map_area {
            Ok((area, bufs)) => (area, bufs),
            Err(err) => panic!("no mmap for you: {:?}", err),
        };
        let mut rx_state = State::new(area.clone(), &mut bufs, StateType::Rx, self.ingress_intf.clone(), self.ingress_map_fd);
        let mut tx_state = State::new(area.clone(), &mut bufs, StateType::Tx, self.egress_intf.clone(), self.egress_map_fd);
        let custom = BufCustom {};
        loop {
            let r = rx_state.cq.service(&mut bufs, 64);
            match r {
                Ok(n) => {
                    //info!("serviced {} packets", n)
                }
                Err(err) => panic!("error: {:?}", err),
            }
            let rx = match rx_state.socket{
                SocketType::Rx(ref mut rx) => { Some(rx) }
                _ => None,
            };

            let tx = match tx_state.socket{
                SocketType::Tx(ref mut tx) => { Some(tx) }
                _ => None,
            };
            if let Some(rx) = rx {
                if let Some(tx) = tx {
                    match rx.try_recv(&mut rx_state.v, 64, custom) {
                        Ok(n) => {
                            if n > 0 {
                                info!("received {} packets", n);
                                //let res = self.process();
                                //if res.len() > 0 {
                                //    self.sync_tx.send(res).await;
                                //}
                                for elem in rx_state.v.iter(){

                                }
                                if let Some(v) = rx_state.v.pop_front(){
                                    self.parse(&v);
                                    tx_state.v.push_front(v);
                                    tx.try_send(&mut tx_state.v, 64);
                                    rx_state.fq_deficit += n;
                                }

                            } else {
                                if rx_state.fq.needs_wakeup() {
                                    rx.wake();
                                }
                            }
                        }
                        Err(err) => {
                            panic!("error: {:?}", err);
                        }
                    }

                }
            }
        }
    }

    pub fn parse<'a>(&self, buf: &BufMmap<'a, BufCustom>) {
        let data = buf.get_data();
        let data_prt = data.as_ptr() as usize;
        let eth_hdr = (data_prt + 0) as *const EthHdr;
        let ipv4_hdr = (data_prt + EthHdr::LEN) as *const Ipv4Hdr;
        let udp_hdr = (data_prt + EthHdr::LEN + Ipv4Hdr::LEN) as *const UdpHdr;
        let udp_data_len = u16::from_be(unsafe { (*udp_hdr).len }) as usize;
        let udp_src_port = u16::from_be(unsafe { (*udp_hdr).source });
        info!("udp data len: {}", udp_data_len);
        let udp_data_ptr = (data_prt + EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) as *const u8;
        let s = unsafe { slice::from_raw_parts(udp_data_ptr, udp_data_len - UdpHdr::LEN) };
        info!("udp data: {:?}", s);
        let src_mac = mac_to_string( unsafe { &(*eth_hdr).src_addr });
        let dst_mac = mac_to_string( unsafe { &(*eth_hdr).dst_addr });
        let src_ip = decimal_to_ip(u32::from_be(unsafe { (*ipv4_hdr).src_addr }));
        let dst_ip = decimal_to_ip(u32::from_be(unsafe { (*ipv4_hdr).dst_addr }));
        info!("src_mac: {}, dst_mac: {}, src_ip: {}, dst_ip: {}", src_mac, dst_mac, src_ip, dst_ip);

    }
}

pub struct State<'a>{
    pub cq: UmemCompletionQueue<'a, BufCustom>,
    pub fq: UmemFillQueue<'a, BufCustom>,
    pub socket: SocketType<'a>,
    pub v: ArrayDeque<[BufMmap<'a, BufCustom>; PENDING_LEN], Wrapping>,
    pub fq_deficit: usize,
}

pub enum StateType{
    Rx,
    Tx,
}

impl <'a>State<'a>{
    pub fn new(area: Arc<MmapArea<'a, BufCustom>>, bufs: &mut Vec<BufMmap<'a, BufCustom>>, state_type: StateType, intf: String, map_fd: i32) -> State<'a> {
        let intf = intf.as_str();
        let umem = Umem::new(
            area.clone(),
            XSK_RING_CONS__DEFAULT_NUM_DESCS,
            XSK_RING_PROD__DEFAULT_NUM_DESCS,
        );
        let (umem1, cq, mut fq) = match umem {
            Ok(umem) => umem,
            Err(err) => panic!("no umem for you: {:?}", err),
        };
        let mut options = SocketOptions::default();
        let mut options = SocketOptions::default();
        options.zero_copy_mode = false;
        options.copy_mode = true;
        let (skt, skt_type) = match state_type{
            StateType::Rx => {
                let socket = Socket::new_rx(
                    umem1.clone(),
                    intf,
                    0,
                    XSK_RING_CONS__DEFAULT_NUM_DESCS,
                    options,
                    1
                );
                let (skt, rx) = match socket {
                    Ok(skt) => skt,
                    Err(err) => panic!("no socket for you: {:?}", err),
                };
                (skt, SocketType::Rx(rx))
            },
            StateType::Tx => {
                let socket = Socket::new_tx(
                    umem1.clone(),
                    intf,
                    0,
                    XSK_RING_PROD__DEFAULT_NUM_DESCS,
                    options,
                    1
                );
                let (skt, tx) = match socket {
                    Ok(skt) => skt,
                    Err(err) => panic!("no socket for you: {:?}", err),
                };
                (skt, SocketType::Tx(tx))
            },
        };


        let r = fq.fill(
            bufs,
            min(XSK_RING_PROD__DEFAULT_NUM_DESCS as usize, 65535),
        );
        match r {
            Ok(n) => {
                if n != min(XSK_RING_PROD__DEFAULT_NUM_DESCS as usize, 65535) {
                    panic!(
                        "Initial fill of umem incomplete. Wanted {} got {}.",
                        65535, n
                    );
                }
            }
            Err(err) => panic!("error: {:?}", err),
        }

        let xsk_sock = skt.socket.as_ref() as *const xsk_socket as *mut xsk_socket;        
        unsafe { xsk_socket__update_xskmap(xsk_sock, map_fd) };

        let mut v: ArrayDeque<[BufMmap<BufCustom>; PENDING_LEN], Wrapping> = ArrayDeque::new();
        State { cq, fq, socket: skt_type, v, fq_deficit: 0 }

    }
}

pub enum SocketType<'a>{
    Rx(SocketRx<'a, BufCustom>),
    Tx(SocketTx<'a, BufCustom>),
}

fn decimal_to_ip(decimal: u32) -> String {
    let octet1 = (decimal >> 24) & 0xFF;
    let octet2 = (decimal >> 16) & 0xFF;
    let octet3 = (decimal >> 8) & 0xFF;
    let octet4 = decimal & 0xFF;
    format!("{}.{}.{}.{}", octet1, octet2, octet3, octet4)
}

fn mac_to_string(mac: &[u8; 6]) -> String {
    format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", 
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}