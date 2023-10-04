use aya::Bpf;
use aya::maps::HashMap;
use common::BthHdr;
use log::{info, warn};
use arraydeque::{ArrayDeque, Wrapping};
use afxdp::mmap_area::{MmapArea, MmapAreaOptions};
use afxdp::socket::{Socket, SocketOptions, SocketRx, SocketTx};
use afxdp::umem::{Umem, UmemCompletionQueue, UmemFillQueue};
use afxdp::PENDING_LEN;
use afxdp::{buf::Buf, buf_mmap::BufMmap};
use libbpf_sys::{
    XSK_RING_CONS__DEFAULT_NUM_DESCS,
    XSK_RING_PROD__DEFAULT_NUM_DESCS,
    xsk_socket__update_xskmap,
    xsk_socket,
};
use std::collections::HashMap as ColHashMap;
use std::sync::Arc;
use std::cmp::min;
use network_types::{
    eth::EthHdr,
    ip::Ipv4Hdr,
    udp::UdpHdr,
};
use common::{SprayerHdr, QpFirst};
#[derive(Default, Copy, Clone)]
pub struct BufCustom {}

const BUFF_SIZE: usize = 2048;
const BUF_NUM: usize = 65535 * 2;
const BATCH_SIZE: usize = 64;
pub struct Buffer{
    ingress_intf: String,
    egress_intf: String,
    ingress_map_fd: i32,
    egress_map_fd: i32,
    xdp_decap_bpf: Bpf,
}
impl Buffer {
    pub fn new(ingress_intf: String, egress_intf: String, ingress_map_fd: i32, egress_map_fd: i32, xdp_decap_bpf: Bpf) -> Buffer {
        Buffer{
            ingress_intf,
            egress_intf,
            ingress_map_fd,
            egress_map_fd,
            xdp_decap_bpf,
        }
    }
    pub async fn run(&mut self) -> anyhow::Result<()>{
        let options = MmapAreaOptions{ huge_tlb: false };
        let map_area = MmapArea::new(BUF_NUM, BUFF_SIZE, options);
        let (area, mut bufs) = match map_area {
            Ok((area, bufs)) => (area, bufs),
            Err(err) => panic!("no mmap for you: {:?}", err),
        };
        let mut rx_state = State::new(area.clone(), &mut bufs, StateType::Rx, self.ingress_intf.clone(), self.ingress_map_fd);
        let mut tx_state = State::new(area.clone(), &mut bufs, StateType::Tx, self.egress_intf.clone(), self.egress_map_fd);
        let mut queue_ring: ColHashMap<(QpFirst,u32),BufMmap<BufCustom>> = ColHashMap::new();
        
        let custom = BufCustom {};
        loop {
            let r = rx_state.cq.service(&mut bufs, BATCH_SIZE);
            match r {
                Ok(_n) => {
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
                    match rx.try_recv(&mut rx_state.v, BATCH_SIZE, custom) {
                        Ok(n) => {
                            if n > 0 {
                                for _ in 0..n {
                                    if let Some(mut v) = rx_state.v.pop_front(){
                                        let data: &[u8] = v.get_data();
                                        let data_ptr = data.as_ptr() as usize;
                                        let sprayer_hdr = (data_ptr + EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) as *const SprayerHdr;
                                        let bth_hdr = (data_ptr + EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + SprayerHdr::LEN) as *const BthHdr;
                                        
                                        let op_code = unsafe { u8::from_be((*bth_hdr).opcode) };
                                        let dst_qpn = {
                                            let dst_qp = unsafe { (*bth_hdr).dest_qpn };
                                            u32::from_be_bytes([0, dst_qp[0], dst_qp[1], dst_qp[2]])
                                        };
                                        let first = {
                                            let first = unsafe { (*sprayer_hdr).first };
                                            u32::from_be_bytes([0, first[0], first[1], first[2]])
                                        };
                                        let seq_num = {
                                            let seq_num = unsafe { (*bth_hdr).psn_seq };
                                            u32::from_be_bytes([0, seq_num[0], seq_num[1], seq_num[2]])
                                        };
                                        let qp_first = QpFirst { dst_qpn, first };

                                        info!("qp_id: {}, seq: {}, op_code:{}, first: {}", dst_qpn,seq_num,op_code,first);
                                        
                                        if let Some(qp_seq_map) = self.xdp_decap_bpf.map_mut("QPSEQMAP"){
                                            let mut qp_seq_map: HashMap<_, QpFirst, u32> = HashMap::try_from(qp_seq_map)?;
                                            if let Ok(mut next_seq_num) = qp_seq_map.get(&qp_first, 0){
                                                if next_seq_num == seq_num {
                                                    next_seq_num += 1;
                                                    remove_sprayer_hdr(&mut v);
                                                    let data = v.get_data();
                                                    let data_ptr = data.as_ptr();
                                                    let eth_hdr = unsafe { &*(data_ptr as *const EthHdr) };
                                                    let dst_mac = mac_to_int(eth_hdr.dst_addr);
                                                    let src_mac = mac_to_int(eth_hdr.src_addr);
                                                    info!("src_mac: {}, dst_mac 2: {}",int_to_mac(src_mac as i64), int_to_mac(dst_mac as i64));
                                                    info!("pushing 1 {}", seq_num);
                                                    tx_state.v.push_back(v);
                                                    if op_code == 2 {
                                                        match qp_seq_map.remove(&qp_first){
                                                            Ok(_) => {},
                                                            Err(err) => {
                                                                warn!("1 qp_id: {}, seq: {}, op_code:{}, error: {:?}", dst_qpn,seq_num,op_code,err);
                                                                break;
                                                            }
                                                        };
                                                    } else {
                                                        qp_seq_map.insert(&qp_first, next_seq_num, 0)?;
                                                    }
                                                } else {
                                                    queue_ring.insert((qp_first, seq_num), v);
                                                }
                                                while let Some(mut v) = queue_ring.remove(&(qp_first, next_seq_num)){
                                                    next_seq_num += 1;
                                                    remove_sprayer_hdr(&mut v);
                                                    tx_state.v.push_back(v);
                                                    if op_code == 2 {
                                                        match qp_seq_map.remove(&qp_first){
                                                            Ok(_) => {},
                                                            Err(err) => {
                                                                warn!("2 qp_id: {}, seq: {}, op_code:{}, error: {:?}", dst_qpn,seq_num,op_code,err);
                                                                break;
                                                            }
                                                        };
                                                    } else {
                                                        qp_seq_map.insert(&qp_first, next_seq_num, 0)?;
                                                    }
                                                }
                                            } else {
                                                queue_ring.insert((qp_first, seq_num), v);
                                            }
                                        }                                        
                                    }
                                }

                                if tx_state.v.len() > 0 {
                                    if tx.try_send(&mut tx_state.v, BATCH_SIZE).is_ok(){
                                        rx_state.fq_deficit += n;
                                    }
                                }
                                if rx_state.fq_deficit > 0 {
                                    let r = rx_state.fq.fill(&mut bufs, rx_state.fq_deficit);
                                    match r {
                                        Ok(n) => {
                                            rx_state.fq_deficit -= n;
                                        }
                                        Err(err) => panic!("error: {:?}", err),
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
    }

    pub fn send<'a>(&mut self, buf: BufMmap<'a, BufCustom>, mut tx_state: State<'a>){
        tx_state.v.push_back(buf);
    }
}

fn remove_sprayer_hdr<'a>(v: &mut BufMmap<'a, BufCustom>) {
    let data: &mut [u8] = v.get_data_mut();
    let data_ptr = data.as_mut_ptr();
    let eth_hdr_ptr = data_ptr as *mut EthHdr;
    let eth_hdr = unsafe { eth_hdr_ptr.read() };
    let ipv4_hdr_ptr = (data_ptr as usize + EthHdr::LEN) as *mut Ipv4Hdr;
    let ipv4_hdr = unsafe { ipv4_hdr_ptr.read() };
    let udp_hdr_ptr = (data_ptr as usize + EthHdr::LEN + Ipv4Hdr::LEN) as *mut UdpHdr;
    let udp_hdr = unsafe { udp_hdr_ptr.read() };
    let bth_hdr_ptr = (data_ptr as usize + EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + SprayerHdr::LEN) as *mut BthHdr;
    let bth_hdr = unsafe { bth_hdr_ptr.read() };
    data.rotate_left(SprayerHdr::LEN);
    let eth_hdr_ptr = data_ptr as *mut EthHdr;
    unsafe { eth_hdr_ptr.write(eth_hdr) };
    let ipv4_hdr_ptr = (data_ptr as usize + EthHdr::LEN) as *mut Ipv4Hdr;
    unsafe { ipv4_hdr_ptr.write(ipv4_hdr) };
    let udp_hdr_ptr = (data_ptr as usize + EthHdr::LEN + Ipv4Hdr::LEN) as *mut UdpHdr;
    unsafe { udp_hdr_ptr.write(udp_hdr) };
    let bth_hdr_ptr = (data_ptr as usize + EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) as *mut BthHdr;
    unsafe { bth_hdr_ptr.write(bth_hdr) };
    v.set_len(v.get_len()-SprayerHdr::LEN as u16);
}

#[inline(always)]
fn int_to_mac(mut value: i64) -> String {
    let mut bytes = [0u8; 6];
    for i in (0..6).rev() {
        bytes[i] = (value & 0xff) as u8;
        value >>= 8;
    }
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
}

#[inline(always)]
fn mac_to_int(mac: [u8;6]) -> u64 {
    let mut mac_dec: u64 = 0;
    for i in 0..6 {
        mac_dec = mac_dec << 8;
        mac_dec = mac_dec | mac[i] as u64;
    }
    mac_dec
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
            min(XSK_RING_PROD__DEFAULT_NUM_DESCS as usize, BUF_NUM),
        );
        match r {
            Ok(n) => {
                if n != min(XSK_RING_PROD__DEFAULT_NUM_DESCS as usize, BUF_NUM) {
                    panic!(
                        "Initial fill of umem incomplete. Wanted {} got {}.",
                        BUF_NUM, n
                    );
                }
            }
            Err(err) => panic!("error: {:?}", err),
        }

        let xsk_sock = skt.socket.as_ref() as *const xsk_socket as *mut xsk_socket;        
        unsafe { xsk_socket__update_xskmap(xsk_sock, map_fd) };

        let v: ArrayDeque<[BufMmap<BufCustom>; PENDING_LEN], Wrapping> = ArrayDeque::new();
        State { cq, fq, socket: skt_type, v, fq_deficit: 0 }

    }
}

pub enum SocketType<'a>{
    Rx(SocketRx<'a, BufCustom>),
    Tx(SocketTx<'a, BufCustom>),
}
