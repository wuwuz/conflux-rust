// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    hash::keccak,
    node_table::{NodeId, *},
    service::{UdpIoContext, UDP_PROTOCOL_COORDINATE},
    Error, ErrorKind, IpFilter, ThrottlingReason,
};
use vivaldi::{
    vector::Dimension2,
};
use parking_lot::{RwLock};

use cfx_bytes::Bytes;
use cfx_types::{H256, H520};
use cfxkey::{recover, sign, KeyPair, Secret};
use rlp::{Rlp, RlpStream};
use std::{
    collections::{hash_map::Entry, HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    sync::{Arc, Mutex},
    iter::FromIterator,
};
use throttling::time_window_bucket::TimeWindowBucket;
use lazy_static::*;
//use metrics::{register_meter_with_group, Meter};
use metrics::{Gauge, GaugeUsize};
use rand::Rng;

lazy_static! {
    static ref COORDINATE_ERROR_METER: Arc<dyn Gauge<usize>> =
        GaugeUsize::register_with_group("coordinate_metric", "coordinate_error");
}

const COORDINATE_PROTOCOL_VERSION: u32 = 1;

const PACKET_PING: u8 = 1;
const PACKET_PONG: u8 = 2;

//const PING_TIMEOUT: Duration = Duration::from_millis(500);
const PING_TIMEOUT: Duration = Duration::from_millis(5000);
//const PONG_TIMEOUT: Duration = Duration::from_millis(500);

pub const COORDINATE_NEIGHBOR_COUNT: u32 = 16;
const MAX_NODES_PING: usize = 32; // Max nodes to add/ping at once
const UPDATE_MAX_STEPS: u32 = 5; // Max iterations of coordainte update.

const DEFAULT_THROTTLING_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_THROTTLING_LIMIT_PING: usize = 20;
const DEFAULT_THROTTLING_LIMIT_FIND_NODES: usize = 10;
pub const HISTORY_RTT_DATA_WINDOW_SIZE: usize = 5;

struct PingRequest {
    // Time when the request was sent
    sent_at: Instant,
    // The node to which the request was sent
    node: NodeEntry,
    // The hash sent in the Ping request
    echo_hash: H256,
}

#[derive(Debug)]
struct HistoryRTTData {
    data: VecDeque<u64>,
    //sum: u64,
    //pub mean: u64,
    median: u64,
}

impl HistoryRTTData {
    pub fn new() -> Self {
        HistoryRTTData {
            data: Default::default(),
            //mean: 0,
            median: 0,
        }
    }
    pub fn observe(&mut self, rtt: u64) {
        if self.data.len() == HISTORY_RTT_DATA_WINDOW_SIZE {
            self.data.pop_front();
        }
        self.data.push_back(rtt);

        let mut tmp: Vec<u64> = self.data.iter().cloned().collect();
        tmp.sort();
        self.median = tmp[self.data.len() / 2 as usize];
    }
    pub fn get_median(&self) -> u64 {
        self.median
    }
}


#[allow(dead_code)]
pub struct CoordinateManager {
    id: NodeId,
    id_hash: H256,
    secret: Secret,
    public_endpoint: NodeEndpoint,
    in_flight_pings: HashMap<NodeId, PingRequest>,
    check_timestamps: bool,
    adding_nodes: Vec<NodeEntry>,
    neighbor_set: HashMap<NodeId, NodeEntry>,
    ip_filter: IpFilter,
    update_initiated: bool,
    update_round: Option<u32>,
    // The pointer to the Vivaldi Model, 
    // only one copy in the network service inner
    vivaldi_model: Arc<RwLock<vivaldi::Model<Dimension2>>>,

    // Limits the response for PING/FIND_NODE packets
    ping_throttling: TimeWindowBucket<IpAddr>,
    find_nodes_throttling: TimeWindowBucket<IpAddr>,

    // history rtt data -- smoothing the update procedure
    history_rtt: HashMap<NodeId, Arc<Mutex<HistoryRTTData>>>,
}

impl CoordinateManager {
    pub fn new(
        key: &KeyPair, public: NodeEndpoint, ip_filter: IpFilter,
        model: Arc<RwLock<vivaldi::Model<Dimension2>>>
    ) -> CoordinateManager {
        CoordinateManager {
            id: key.public().clone(),
            id_hash: keccak(key.public()),
            secret: key.secret().clone(),
            public_endpoint: public,
            in_flight_pings: HashMap::new(),
            check_timestamps: true,
            update_initiated: false,
            adding_nodes: Vec::new(),
            neighbor_set: HashMap::new(),
            update_round: None,
            ip_filter,
            vivaldi_model: model.clone(),
            ping_throttling: TimeWindowBucket::new(
                DEFAULT_THROTTLING_INTERVAL,
                DEFAULT_THROTTLING_LIMIT_PING,
            ),
            find_nodes_throttling: TimeWindowBucket::new(
                DEFAULT_THROTTLING_INTERVAL,
                DEFAULT_THROTTLING_LIMIT_FIND_NODES,
            ),
            history_rtt: HashMap::new(),
        }
    }

    fn is_allowed(&self, entry: &NodeEntry) -> bool {
        entry.endpoint.is_allowed(&self.ip_filter) && entry.id != self.id
    }

    pub fn try_ping_nodes(
        &mut self, uio: &UdpIoContext, nodes: Vec<NodeEntry>,
    ) {
        for node in nodes {
            self.try_ping(uio, node);
        }
    }

    pub fn try_ping_neighbors(
        &mut self, uio: &UdpIoContext, 
    ) {
        let nodes = 
            self.neighbor_set
            .iter()
            .map(|(_k, v)| v.clone())
            .collect();
        self.try_ping_nodes(uio, nodes);
    }

    fn try_ping(&mut self, uio: &UdpIoContext, node: NodeEntry) {
        if !self.is_allowed(&node) {
            trace!("Node {:?} not allowed", node);
            return;
        }
        if self.in_flight_pings.contains_key(&node.id) {
            trace!("Node {:?} in flight requests", node);
            return;
        }
        if self.adding_nodes.iter().any(|n| n.id == node.id) {
            trace!("Node {:?} in adding nodes", node);
            return;
        }

        if self.in_flight_pings.len() < MAX_NODES_PING {
            self.ping(uio, &node).unwrap_or_else(|e| {
                warn!("Error sending Ping packet: {:?}", e);
            });
        } else {
            self.adding_nodes.push(node);
        }
    }

    fn ping(
        &mut self, uio: &UdpIoContext, node: &NodeEntry,
    ) -> Result<(), Error> {
        let mut rlp = RlpStream::new_list(5);
        rlp.append(&COORDINATE_PROTOCOL_VERSION);
        self.public_endpoint.to_rlp_list(&mut rlp);
        node.endpoint.to_rlp_list(&mut rlp);
        //rlp.append(&expire_timestamp());
        rlp.append(&produce_timestamp());
        let mut rng = rand::thread_rng();
        let packet_random_num = rng.gen::<u32>();
        rlp.append(&packet_random_num);

        let hash = self.send_packet(
            uio,
            PACKET_PING,
            //&node.endpoint.udp_address(),
            node,
            &rlp.drain(),
        )?;

        self.in_flight_pings.insert(
            node.id.clone(),
            PingRequest {
                sent_at: Instant::now(),
                node: node.clone(),
                echo_hash: hash,
            },
        );

        trace!("Sent Ping to {:?} ; node_id={:#x}", &node.endpoint, node.id);
        Ok(())
    }

    fn send_packet(
        &mut self, uio: &UdpIoContext, packet_id: u8, //address: &SocketAddr,
        //address: &NodeEndpoint,
        node: &NodeEntry,
        payload: &[u8],
    ) -> Result<H256, Error>
    {
        match packet_id {
            PACKET_PING => {
                debug!("Sending Coordinate Ping Packet to {:?}", node);
            }
            PACKET_PONG => {
                debug!("Sending Coordinate Pong Packet to {:?}", node);
            }
            _ => {
                debug!("Error: Sending Unknown Packet to {:?}", node);
            }
        }
        let packet = assemble_packet(packet_id, payload, &self.secret)?;
        let hash = H256::from_slice(&packet[1..=32]);
        self.send_to(uio, packet, node.clone());
        Ok(hash)
    }

    fn send_to(
        &mut self, uio: &UdpIoContext, payload: Bytes, //address: SocketAddr,
        node: NodeEntry,
    ) {
        uio.send(payload, node.endpoint.address);
        //FIXME
        /*
        match uio.send_with_latency(payload, node) {
            Err(e)=> {debug!("test udp: cannot send with latency, error = {:?}", e);}
            _ => {}
        }
        */
    }

    pub fn on_packet(
        &mut self, uio: &UdpIoContext, packet: &[u8], from: SocketAddr,
    ) -> Result<(), Error> {
        // validate packet
        if packet.len() < 32 + 65 + 4 + 1 {
            return Err(ErrorKind::BadProtocol.into());
        }

        let hash_signed = keccak(&packet[32..]);
        if hash_signed[..] != packet[0..32] {
            return Err(ErrorKind::BadProtocol.into());
        }

        let signed = &packet[(32 + 65)..];
        let signature = H520::from_slice(&packet[32..(32 + 65)]);
        let node_id = recover(&signature.into(), &keccak(signed))?;

        let packet_id = signed[0];
        let rlp = Rlp::new(&signed[1..]);
        match packet_id {
            PACKET_PING => {
                self.on_ping(uio, &rlp, &node_id, &from, hash_signed.as_bytes())
            }
            PACKET_PONG => self.on_pong(uio, &rlp, &node_id, &from),
            //PACKET_FIND_NODE => self.on_find_node(uio, &rlp, &node_id, &from),
            //PACKET_NEIGHBOURS => self.on_neighbours(uio, &rlp, &node_id, &from),
            _ => {
                debug!("Unknown UDP packet: {}", packet_id);
                Ok(())
            }
        }
    }

    /*
    /// Validate that given timestamp is in within one second of now or in the
    /// future
    fn check_timestamp(&self, timestamp: u64) -> Result<(), Error> {
        let secs_since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if self.check_timestamps && timestamp < secs_since_epoch {
            debug!("Expired packet");
            return Err(ErrorKind::Expired.into());
        }
        Ok(())
    }
    */

    fn on_ping(
        &mut self, uio: &UdpIoContext, rlp: &Rlp, node_id: &NodeId,
        from: &SocketAddr, echo_hash: &[u8],
    ) -> Result<(), Error>
    {
        debug!("Got ping from {:?}", &from);

        trace!("Got Ping from {:?}", &from);

        /*
        if !self.ping_throttling.try_acquire(from.ip()) {
            return Err(ErrorKind::Throttling(
                ThrottlingReason::PacketThrottled("PING"),
            )
            .into());
        }
        */

        let ping_from = NodeEndpoint::from_rlp(&rlp.at(1)?)?;
        let ping_to = NodeEndpoint::from_rlp(&rlp.at(2)?)?;
        let timestamp: u64 = rlp.val_at(3)?;
        let packet_random_num: u32 = rlp.val_at(4)?;
        //self.check_timestamp(timestamp)?;
        let elapsed = produce_timestamp() as i64 - timestamp as i64;
        if elapsed < 0 {
            debug!("Coordinate: elapsed time < 0");
        }
        debug!("Coordinate: receive ping from {:?}, random = {}, time = {} ms", &from, packet_random_num, elapsed);

        // MODIFY: Add a new field here --- the node's coordinate
        let mut response = RlpStream::new_list(5);
        let pong_to = NodeEndpoint {
            address: from.clone(),
            udp_port: ping_from.udp_port,
        };
        // Here the PONG's `To` field should be the node we are
        // sending the request to
        // WARNING: this field _should not be used_, but old Parity versions
        // use it in order to get the node's address.
        // So this is a temporary fix so that older Parity versions don't brake
        // completely.
        ping_to.to_rlp_list(&mut response);
        // pong_to.to_rlp_list(&mut response);

        response.append(&echo_hash);
        //response.append(&produce_timestamp());
        response.append(&timestamp);


        // Here: add the coordinate
        {
            let model = self.vivaldi_model.read();
            let coord = model.get_coordinate().clone();
            response.append(&coord);
        }
        response.append(&packet_random_num);

        // Remove PONG
        let entry = NodeEntry {
            id: node_id.clone(),
            endpoint: pong_to,
        };
        self.send_packet(uio, PACKET_PONG, &entry, &response.drain())?;

        // TODO handle the error before sending pong
        if !entry.endpoint.is_valid() {
            debug!("Got bad address: {:?}", entry);
        } else if !self.is_allowed(&entry) {
            debug!("Address not allowed: {:?}", entry);
        } else {
            uio.node_db
                .write()
                .note_success(node_id, None, false /* trusted_only */);
        }
        Ok(())
    }

    fn on_pong(
        &mut self, _uio: &UdpIoContext, rlp: &Rlp, node_id: &NodeId,
        from: &SocketAddr,
    ) -> Result<(), Error>
    {
        trace!("Got Pong from {:?} ; node_id={:#x}", &from, node_id);
        let _pong_to = NodeEndpoint::from_rlp(&rlp.at(0)?)?;
        let echo_hash: H256 = rlp.val_at(1)?;
        let timestamp: u64 = rlp.val_at(2)?;
        let recv_coordinate: vivaldi::Coordinate<Dimension2> = rlp.val_at(3)?;
        let packet_random_num: u32 = rlp.val_at(4)?;
        let mut rtt = produce_timestamp() as i64 - timestamp as i64;
        if rtt < 0 {
            debug!("Coordinate: negative rtt = {}", rtt);
            return Err("rtt < 0".into())
        }
        debug!("Coordinate: receive Coordinate Pong from {:?}, random = {}, original_rtt={} ms", &from, &packet_random_num, &rtt);
        if rtt == 0 {
            debug!("Coordinate: receive Coordinate Pong from {:?} 0ms!", &from);
            rtt += 10;
        }
        /*
        // simulate a 3 cluster
        let self_group_id = self.id.to_low_u64_le() % 3;
        let opponent_group_id = node_id.to_low_u64_le() % 3;

        //FIXME: still 3 group!!!!!!!!!!!!!!!!!!!!!!!!!!!
        // if they are not in the same group, the rtt is 500ms
        if self_group_id != opponent_group_id  {
            rtt += 1000;
        } else {
            // otherwise, the rtt is 50ms
            rtt += 50;
        }

        debug!("Recv Coordinate Pong from {:?} rtt {} ms", &from, &rtt);
        */

        //self.check_timestamp(timestamp)?;

        let expected_node = match self.in_flight_pings.entry(*node_id) {
            Entry::Occupied(entry) => {
                let expected_node = {
                    let request = entry.get();
                    if request.echo_hash != echo_hash {
                        debug!("Got unexpected Pong from {:?} ; packet_hash={:#x} ; expected_hash={:#x}", &from, request.echo_hash, echo_hash);
                        None
                    } else {
                        Some(request.node.clone())
                    }
                };

                if expected_node.is_some() {
                    entry.remove();
                }
                expected_node
            }
            Entry::Vacant(_) => None,
        };

        if let Some(_node) = expected_node {
            // update the model based on rtt and remote coordinate
            if self.history_rtt.contains_key(node_id) == false {
                self.history_rtt.insert(node_id.clone(), Arc::new(Mutex::new(HistoryRTTData::new())));
            }
            if let Some(h) = self.history_rtt.get_mut(node_id) {
                let mut history = h.lock().unwrap();
                history.observe(rtt as u64);
                //debug!("history = {:?}", history);
                let mut model = self.vivaldi_model.write();
                let med = history.get_median();
                debug!("Coordinate: the median is {}", med);
                model.observe(&recv_coordinate, Duration::from_millis(history.get_median()));
                debug!("Coordinate: new Coord = {:?}", model.get_coordinate());
                COORDINATE_ERROR_METER.update((model.get_coordinate().error() * 1000.0) as usize);
            }
            Ok(())
        } else {
            debug!("Got unexpected Pong from {:?} ; request not found", &from);
            Ok(())
        }
    }

    /// Starts the updating process at round 0
    fn start(&mut self) {
        trace!("Starting Updating Coordainte");
        self.update_round = Some(0);
    }

    /// Complete the updating process
    //fn stop(&mut self) {
    //    trace!("Completing Coordinate Updating");
    //    self.update_round = None;
    //}

    fn check_expired(&mut self, uio: &UdpIoContext, time: Instant) {
        let mut nodes_to_expire = Vec::new();
        self.in_flight_pings.retain(|node_id, ping_request| {
            if time.duration_since(ping_request.sent_at) > PING_TIMEOUT {
                debug!(
                    "Removing expired PING request for node_id={:#x}",
                    node_id
                );
                nodes_to_expire.push(*node_id);
                false
            } else {
                true
            }
        });

        // keep the failure notice to update the node_db
        /* 
        for node_id in nodes_to_expire {
            self.expire_node_request(uio, node_id);
        }
        */
    }

    fn expire_node_request(&mut self, uio: &UdpIoContext, node_id: NodeId) {
        uio.node_db.write().note_failure(
            &node_id, false, /* by_connection */
            true,  /* trusted_only */
        );
    }

    fn update_new_nodes(&mut self, uio: &UdpIoContext) {
        while self.in_flight_pings.len() < MAX_NODES_PING {
            match self.adding_nodes.pop() {
                Some(next) => self.try_ping(uio, next),
                None => break,
            }
        }
    }

    fn update(&mut self, uio: &UdpIoContext, session_node_entries: &Vec<NodeEntry>) {
        let update_round = match self.update_round {
            Some(r) => r,
            None => return,
        };
        if update_round == 0 {
            // the first round -- select neighbor set
            self.neighbor_set = HashMap::from_iter(
                uio
                .node_db
                .read()
                .sample_trusted_nodes(COORDINATE_NEIGHBOR_COUNT, &self.ip_filter)
                .into_iter()
                .map(|entry| (entry.id.clone(), entry))
            );
            

            // Add all the entries of the connected sessions
            //self.neighbor_set.extend(*session_node_entries);
            //self.neighbor_set.append(*session_node_entries);
            for entry in session_node_entries.iter() {
                if !self.neighbor_set.contains_key(&entry.id) {
                    self.neighbor_set.insert(entry.id.clone(), entry.clone());
                }
            }

            debug!("coordinate neighbors: {:?}", &self.neighbor_set);
        }
        if update_round == UPDATE_MAX_STEPS {
            trace!("Coordinate updating refresh due to beyond max round count.");
            self.refresh();
            return;
        }
        trace!("Starting round {:?}", self.update_round);

        self.try_ping_neighbors(uio);

        self.update_round = Some(update_round + 1);
    }

    pub fn round(&mut self, uio: &UdpIoContext, session_node_entries: &Vec<NodeEntry>) {
        self.check_expired(uio, Instant::now());
        self.update_new_nodes(uio);

        if self.update_round.is_some() {
            self.update(uio, session_node_entries);
        } else if self.in_flight_pings.is_empty() && !self.update_initiated {
            // Start update if the first pings have been sent (or timed
            // out)
            self.update_initiated = true;
            // select neighbor ! 
            self.refresh();
        }
    }

    pub fn refresh(&mut self) {
        self.update_round = None;
        self.start();
    }
}

/*
fn expire_timestamp() -> u64 {
    (SystemTime::now() + EXPIRY_TIME)
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
*/
fn produce_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn assemble_packet(
    packet_id: u8, bytes: &[u8], secret: &Secret,
) -> Result<Bytes, Error> {
    let mut packet = Bytes::with_capacity(bytes.len() + 32 + 65 + 1 + 1);
    packet.push(UDP_PROTOCOL_COORDINATE);
    packet.resize(1 + 32 + 65, 0); // Filled in below
    packet.push(packet_id);
    packet.extend_from_slice(bytes);

    let hash = keccak(&packet[(1 + 32 + 65)..]);
    let signature = match sign(secret, &hash) {
        Ok(s) => s,
        Err(e) => {
            warn!("Error signing UDP packet");
            return Err(Error::from(e));
        }
    };
    packet[(1 + 32)..(1 + 32 + 65)].copy_from_slice(&signature[..]);
    let signed_hash = keccak(&packet[(1 + 32)..]);
    packet[1..=32].copy_from_slice(signed_hash.as_bytes());
    Ok(packet)
}