use aya::Bpf;
use aya::maps::HashMap;
use common::BthHdr;
use log::{info, warn, debug};
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
    
    //bth_map: HashMap<&'a mut MapData, u32, Bth>
}
//let mut v: ArrayDeque<[BufMmap<BufCustom>; PENDING_LEN], Wrapping> = ArrayDeque::new();
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
        let mut queue_ring: ColHashMap<(u32,u32),BufMmap<BufCustom>> = ColHashMap::new();
        
        let custom = BufCustom {};
        loop {
            let r = rx_state.cq.service(&mut bufs, BATCH_SIZE);
            match r {
                Ok(_n) => {
                    //////info!("serviced {} packets", n)
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
                                    if let Some(v) = rx_state.v.pop_front(){
                                        let data: &[u8] = v.get_data();
                                        let data_prt = data.as_ptr() as usize;
                                        let bth_hdr = (data_prt + EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) as *const BthHdr;
                                        let psn_seq_num = unsafe { (*bth_hdr).psn_seq };
                                        let psn_seq_num = u32::from_be_bytes([0, psn_seq_num[0], psn_seq_num[1], psn_seq_num[2]]);
                                        let qp_id = unsafe { (*bth_hdr).dest_qpn };
                                        let qp_id = u32::from_be_bytes([0, qp_id[0], qp_id[1], qp_id[2]]);
                                        let op_code = unsafe { u8::from_be((*bth_hdr).opcode) };
                                        if let Some(qp_seq_map) = self.xdp_decap_bpf.map_mut("QPSEQMAP"){
                                            let mut qp_seq_map: HashMap<_, u32, u32> = HashMap::try_from(qp_seq_map)?;
                                            if let Ok(mut next_seq_num) = qp_seq_map.get(&qp_id, 0){
                                                if next_seq_num == psn_seq_num {
                                                    next_seq_num += 1;
                                                    tx_state.v.push_back(v);
                                                    if op_code == 2 {
                                                        match qp_seq_map.remove(&qp_id){
                                                            Ok(_) => {},
                                                            Err(err) => {
                                                                warn!("1 qp_id: {}, seq: {}, op_code:{}, error: {:?}", qp_id,psn_seq_num,op_code,err);
                                                                break;
                                                            }
                                                        };
                                                    } else {
                                                        qp_seq_map.insert(&qp_id, next_seq_num, 0)?;
                                                    }
                                                } else {
                                                    queue_ring.insert((qp_id, psn_seq_num), v);
                                                }
                                                while let Some(v) = queue_ring.remove(&(qp_id, next_seq_num)){
                                                    next_seq_num += 1;
                                                    tx_state.v.push_back(v);
                                                    if op_code == 2 {
                                                        match qp_seq_map.remove(&qp_id){
                                                            Ok(_) => {},
                                                            Err(err) => {
                                                                warn!("2 qp_id: {}, seq: {}, op_code:{}, error: {:?}", qp_id,psn_seq_num,op_code,err);
                                                                break;
                                                            }
                                                        };
                                                    } else {
                                                        qp_seq_map.insert(&qp_id, next_seq_num, 0)?;
                                                    }
                                                }
                                            } else {
                                                queue_ring.insert((qp_id, psn_seq_num), v);
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
        Ok(())
    }

    pub fn send<'a>(&mut self, buf: BufMmap<'a, BufCustom>, mut tx_state: State<'a>){
        tx_state.v.push_back(buf);
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
