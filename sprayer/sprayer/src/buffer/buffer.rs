use afxdp::buf_vec::BufVec;
use aya::Bpf;
use aya::maps::{MapData, HashMap};
use common::{BthHdr, Bth};
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
use std::collections::BTreeMap;
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

const BITMAP_SIZE: usize = 256 / 8 + 1;
pub struct Qp<'a>{
    pub last_seq_number: u32,
    pub buf_map: BTreeMap<u32, BufMmap<'a, BufCustom>>,
    pub bitmap: [u8; BITMAP_SIZE],
}

impl <'a>Qp<'a>{
    pub fn new() -> Qp<'a>{
        Qp{
            last_seq_number: 0,
            buf_map: BTreeMap::new(),
            bitmap: [0; BITMAP_SIZE],
        }
    }
    pub fn add_buf(&mut self, seq_number: u32, buf: BufMmap<'a, BufCustom>){
        let index = seq_number / 8;
        let offset = seq_number % 8;
        self.bitmap[index as usize] |= 1 << offset;
        self.buf_map.insert(seq_number, buf);
    }
    pub fn check_sequence(&self) -> Vec<u32>{
        let mut sequences_to_send = Vec::new();
        for i in self.bitmap.iter(){
            for bit in 0..8{
                if i & (1 << bit) == 1{
                    sequences_to_send.push(bit);
                } else {
                    break;
                }
            }
        }
        sequences_to_send
    }
}

pub struct QpBuffer<'a>{
    pub qp_maps: BTreeMap<u32, Qp<'a>>,
}

impl <'a>QpBuffer<'a>{
    pub fn handle(&mut self, qp_id: u32, seq_number: u32, buf: BufMmap<'a, BufCustom>){
        match self.qp_maps.get_mut(&qp_id){
            Some(qp) => {
                qp.add_buf(seq_number, buf);
                qp.check_sequence();
            },
            None => {
                let mut qp = Qp::new();
                qp.add_buf(seq_number, buf);
                self.qp_maps.insert(qp_id, qp);
            },
        }
    }
}
#[derive(Default, Copy, Clone)]
pub struct BufCustom {}

pub struct Buffer{
    ingress_intf: String,
    egress_intf: String,
    ingress_map_fd: i32,
    egress_map_fd: i32,
    xdp_decap_bpf: Bpf
    //bth_map: HashMap<&'a mut MapData, u32, Bth>
}

impl Buffer {
    pub fn new(ingress_intf: String, egress_intf: String, ingress_map_fd: i32, egress_map_fd: i32, xdp_decap_bpf: Bpf) -> Buffer {
        Buffer{
            ingress_intf,
            egress_intf,
            ingress_map_fd,
            egress_map_fd,
            xdp_decap_bpf,
            //bth_map,
        }
    }
    pub async fn run(&mut self) -> anyhow::Result<()>{

        let bth_map = if let Some(bth_map) = self.xdp_decap_bpf.map_mut("BTHMAP"){
            let  bth_map: HashMap<_, u32, Bth> = HashMap::try_from(bth_map).unwrap();
            bth_map
        } else {
            panic!("BTHMAP map not found");
        };

        let mut qp_buf = QpBuffer{ qp_maps: BTreeMap::new() };
        //let mut buf_map = BTreeMap::new();
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
                                for _ in 0..n {
                                    if let Some(v) = rx_state.v.pop_front(){
                                        let (qp_id, seq_num) = parse(&v);
                                        //let bth = match bth_map.get(&qp_id, 0){
                                        //    Ok(bth) => bth,
                                        //    Err(err) => panic!("error: {:?}", err),
                                        //};
                                        //info!("bth: {:?}", bth);
                                        qp_buf.handle(qp_id, seq_num, v);

                                        /* 
                                        buf_map.insert(res, v);
                                        let new_v = buf_map.remove(&res).unwrap();
                                        tx_state.v.push_front(new_v);
                                        tx.try_send(&mut tx_state.v, 64);
                                        */
                                        rx_state.fq_deficit += n;
                                    }
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
        Ok(())
    }


}

pub fn parse<'a>(buf: &BufMmap<'a, BufCustom>) -> (u32,u32){        
    let data = buf.get_data();
    let data_prt = data.as_ptr() as usize;
    let bth_hdr = (data_prt + 0) as *const Bth;
    let bth = unsafe { *bth_hdr };
    info!("bth: {:?}", bth);
    let bth_hdr = (data_prt + Bth::LEN + EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) as *const BthHdr;
    let qp_id = unsafe { (*bth_hdr).dest_qpn };
    let qp_id = u32::from_be_bytes([0, qp_id[0], qp_id[1], qp_id[2]]);
    let seq_number = unsafe { (*bth_hdr).psn_seq };
    let seq_number = u32::from_be_bytes([0, seq_number[0], seq_number[1], seq_number[2]]);
    (qp_id,seq_number)
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

fn elem_to_u32(b: &[u8]) -> u32{
    let s = String::from_utf8(b.to_vec()).unwrap();
    let x: u32 = s.parse().unwrap();
    x
  }
  
  fn parser(data: &[u8]) -> Vec<Vec<u8>>{
    let mut data_container = Vec::new();
  
    let mut temp = Vec::new();
    for elem in data{
      if *elem == 124{
        data_container.push(temp);
        temp = Vec::new();
        continue;
      }
      if *elem >= 48 && *elem <= 57{
        temp.push(*elem);
      }
    }
    data_container.push(temp);
    data_container
  }