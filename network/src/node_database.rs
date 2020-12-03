// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    ip::{NodeIpLimit, NodeTagIndex, ValidateInsertResult},
    node_table::{Node, NodeContact, NodeEntry, NodeId, NodeTable},
    IpFilter,
};
use io::StreamToken;
use std::{collections::{HashSet, HashMap}, net::IpAddr, time::Duration, cmp::min};
use vivaldi::{
    vector::Dimension2, vector::Vector,
};
use rand::prelude::*;
use rand::distributions::WeightedIndex;

const TRUSTED_NODES_FILE: &str = "trusted_nodes.json";
const UNTRUSTED_NODES_FILE: &str = "untrusted_nodes.json";
const BLACKLISTED_NODES_FILE: &str = "blacklisted_nodes.json";

pub const MAX_CLUSTER_NUM: usize = 3; // 8

/// Node database maintains all P2P nodes in trusted and untrusted node tables,
/// and supports to limit the number of nodes for the same IP address.
///
/// # Insert a node
///
/// There are 3 scenarios to insert a node into database:
/// 1. Receive the "hello" handshaking message from ingress TCP connection,
/// and add the node with `StreamToken` as untrusted if not exists in database.
/// Otherwise, overwrite the existing node in trusted or untrusted table,
/// including endpoint, last contact and connection information.
/// 2. Receive the "pong" message from UDP discovery, and add the node as
/// trusted if not exists, or promote it to trusted if it is untrusted.
/// Otherwise, just update the last contact information in trusted table.
/// 3. RPC explicitly add a trusted node. If the node is an existing
/// untrusted one, promote it to trusted.
///
/// # Update node information
///
/// ## note_success
/// When actively connect to a sampled trusted node, updates the node last
/// contact time. On the other hand, when received "ping" message from "UDP"
/// message, update the node last contact time.
///
/// ## note_failure
/// Mark the node's last contact to failure for any error, e.g.
/// - UDP request timeout.
/// - Failed to create TCP connection/session.
/// - Failed to communicate due to invalid protocol message.
///
/// # Promote/Demote
///
/// ## Promote
/// Periodically promote untrusted nodes from ingress TCP connection with
/// configured timespan.
///
/// ## Demote
/// Demote a node to untrusted when failed to handle protocol messages.
///
/// # Subnet limitation
///
/// Attacker could easily simulate a large amount of malicious nodes of
/// different node IDs with same IP address or IPs from same subnet. To
/// avoid such kind of attack, user could limits the number of nodes for
/// one IP address and subnet. By default, only 1 node allowed for a
/// single IP address and 32 nodes for a subnet C (ip/24), and will evict
/// an existing old node in following 2 scenarios:
///
/// ## Scenario 1: add or update node with existing IP address
/// For example, "node_1" with "IP_1" already in database, and to add a new node
/// "node_2" with the same address "IP_1". "node_1" will be evicted, and then
/// add "node_2" with "IP_1".
///
/// ## Scenario 2: add or update node with new IP address
/// If the subnet quota of the IP address is not enough, some node in the
/// same subnet may be evicted. If evict one, then add or update the node
/// with new IP address. Otherwise, do not add or update the node.
///
/// ## Eviction rule
/// If the subnet quota is not enough, the rule to select evictee is as
/// following: 1. Select untrusted node prior to trusted node.
/// 2. Select node that has been contacted long time ago.
/// 3. Randomly select one without "fresher" bias.
pub struct NodeDatabase {
    // Trusted nodes to establish outgoing connections.
    // A trusted node comes in 2 ways:
    // 1. Incoming TCP connection for a long time.
    // 2. Received trusted neighbors from UDP discovery.
    trusted_nodes: NodeTable,

    // Add or updated by incoming TCP connection or PING discovery message.
    untrusted_nodes: NodeTable,

    // Blacklisted nodes are refused to connect or update via UDP discovery.
    // Generally, node is blacklisted due to protocol mismatch in runtime.
    blacklisted_nodes: NodeTable,
    // Maximum duration to blacklist a node since last contact.
    blacklisted_lifetime: Duration,

    // IP address/subnet index for trusted and untrusted nodes.
    ip_limit: NodeIpLimit,

    // Only used for sampling trusted nodes with desired tag.
    // It is updated in following cases:
    // 1. add tag indices when initialize the trusted node table
    // 2. add tag indices when promote a node
    // 3. remove tag indices when demote a node
    // 4. remove tag indices when delete a trusted node
    trusted_node_tag_index: NodeTagIndex,

    pub node_coordinate: HashMap<NodeId, vivaldi::Coordinate<Dimension2>>,
    pub centers: Vec<vivaldi::vector::Dimension2>,
    pub cluster_result: HashMap<NodeId, usize>,
    pub cluster_group: Vec<HashSet<NodeId>>,
}

impl NodeDatabase {
    pub fn new(path: Option<String>, subnet_quota: usize) -> Self {
        let trusted_nodes = NodeTable::new(path.clone(), TRUSTED_NODES_FILE);
        let untrusted_nodes =
            NodeTable::new(path.clone(), UNTRUSTED_NODES_FILE);
        let ip_limit = NodeIpLimit::new(subnet_quota);
        let trusted_node_tag_index =
            NodeTagIndex::new_with_node_table(&trusted_nodes);
        let node_coordinate = HashMap::new();
        let centers = Vec::new();
        let cluster_result = HashMap::new();
        let cluster_group = Vec::new();

        let mut db = NodeDatabase {
            trusted_nodes,
            untrusted_nodes,
            blacklisted_nodes: NodeTable::new(path, BLACKLISTED_NODES_FILE),
            blacklisted_lifetime: Duration::from_secs(7 * 24 * 3600),
            ip_limit,
            trusted_node_tag_index,
            node_coordinate,
            centers,
            cluster_result,
            cluster_group,
        };

        db.init(false /* trusted */);
        db.init(true /* trusted */);

        db
    }

    /// Add a new untrusted node if not exists. Otherwise, update the existing
    /// node with specified `entry` and `stream_token`.
    pub fn insert_with_token(
        &mut self, entry: NodeEntry, stream_token: StreamToken,
    ) {
        if self.evaluate_blacklisted(&entry.id) {
            return;
        }

        let mut node = Node::new(entry.id, entry.endpoint);
        node.last_contact = Some(NodeContact::success());
        node.last_connected = Some(NodeContact::success());
        node.stream_token = Some(stream_token);

        let ip = node.endpoint.address.ip();

        if self.trusted_nodes.contains(&node.id) {
            if self.insert_ip_limit(
                node.id.clone(),
                ip,
                true, /* trusted */
            ) {
                self.trusted_nodes
                    .add_node(node, false /* preserve_last_contact */);
            }
        } else if self.insert_ip_limit(
            node.id.clone(),
            ip,
            false, /* trusted */
        ) {
            self.untrusted_nodes
                .add_node(node, false /* preserve_last_contact */);
        }
    }

    fn insert_ip_limit(
        &mut self, id: NodeId, ip: IpAddr, trusted: bool,
    ) -> bool {
        let mut evictee = None;

        match self.ip_limit.validate_insertion(&id, &ip, self) {
            ValidateInsertResult::AlreadyExists => return true,
            ValidateInsertResult::QuotaNotEnough => return false,
            ValidateInsertResult::QuotaEnough => {}
            ValidateInsertResult::OccupyIp(id) => evictee = Some(id),
            ValidateInsertResult::Evict(id) => evictee = Some(id),
        }

        if let Some(id) = &evictee {
            self.remove(id);
        }

        self.ip_limit.insert(id, ip, trusted, evictee)
    }

    /// Add a new trusted node if not exists. Otherwise, update the existing
    /// node with the specified `entry`, and promote the node to trusted if it
    /// is untrusted.
    pub fn insert_with_conditional_promotion(&mut self, entry: NodeEntry) {
        if self.evaluate_blacklisted(&entry.id) {
            return;
        }

        let mut node = Node::new(entry.id, entry.endpoint);
        node.last_contact = Some(NodeContact::success());

        let ip = node.endpoint.address.ip();

        if self.untrusted_nodes.contains(&node.id) {
            if let Some(NodeContact::Demoted(_)) =
                self.untrusted_nodes.get(&node.id).unwrap().last_contact
            {
                return;
            }

            if let Some(old_node) = self.promote_with_untrusted(&node.id, ip) {
                node.last_connected = old_node.last_connected;
                node.stream_token = old_node.stream_token;
                self.trusted_node_tag_index.add_node(&node);
                self.trusted_nodes
                    .add_node(node, false /* preserve_last_contact */);
            }
        } else if self.insert_ip_limit(
            node.id.clone(),
            ip,
            true, /* trusted */
        ) {
            self.trusted_nodes.update_last_contact(node);
        }
    }

    fn promote_with_untrusted(
        &mut self, id: &NodeId, new_ip: IpAddr,
    ) -> Option<Node> {
        let mut evictee = None;

        match self.ip_limit.validate_insertion(id, &new_ip, self) {
            ValidateInsertResult::AlreadyExists => {}
            ValidateInsertResult::QuotaNotEnough => return None,
            ValidateInsertResult::QuotaEnough => {}
            ValidateInsertResult::OccupyIp(id) => evictee = Some(id),
            ValidateInsertResult::Evict(id) => evictee = Some(id),
        }

        if let Some(id) = &evictee {
            self.remove(id);
        }

        self.ip_limit.remove(id);
        self.ip_limit.insert(id.clone(), new_ip, true, evictee);

        self.untrusted_nodes.remove_with_id(id)
    }

    /// Add a new trusted node if not exists, or promote the existing untrusted
    /// node.
    pub fn insert_trusted(&mut self, entry: NodeEntry) {
        if self.evaluate_blacklisted(&entry.id) {
            return;
        }

        if self.trusted_nodes.contains(&entry.id) {
            return;
        }

        let mut node = Node::new(entry.id.clone(), entry.endpoint);
        let ip = node.endpoint.address.ip();

        if self.untrusted_nodes.contains(&node.id) {
            if let Some(old_node) = self.promote_with_untrusted(&node.id, ip) {
                node.last_contact = old_node.last_contact;
                node.last_connected = old_node.last_connected;
                node.stream_token = old_node.stream_token;
                self.trusted_node_tag_index.add_node(&node);
                self.trusted_nodes
                    .add_node(node, false /* preserve_last_contact */);
            }
        } else if self.insert_ip_limit(
            node.id.clone(),
            ip,
            true, /* trusted */
        ) {
            self.trusted_nodes
                .add_node(node, false /* preserve_last_contact */);
        }
    }

    /// Mark as failure for the specified node.
    pub fn note_failure(
        &mut self, id: &NodeId, by_connection: bool, trusted_only: bool,
    ) {
        self.trusted_nodes.note_unsuccess_contact(
            id,
            by_connection,
            Some(NodeContact::failure()),
        );

        if !trusted_only {
            self.untrusted_nodes.note_unsuccess_contact(
                id,
                by_connection,
                Some(NodeContact::failure()),
            );
        }
    }

    /// Mark as demoted for the specified node.
    pub fn note_demoted(&mut self, id: &NodeId, by_connection: bool) {
        assert!(!self.trusted_nodes.contains(id));
        self.untrusted_nodes.note_unsuccess_contact(
            id,
            by_connection,
            Some(NodeContact::demoted()),
        );
    }

    /// Mark as success for the specified node.
    pub fn note_success(
        &mut self, id: &NodeId, token: Option<StreamToken>, trusted_only: bool,
    ) {
        self.trusted_nodes.note_success(id, token.is_some(), token);

        if !trusted_only {
            self.untrusted_nodes
                .note_success(id, token.is_some(), token);
        }
    }

    /// Get node from trusted and/or untrusted node table for the specified id.
    pub fn get(&self, id: &NodeId, trusted_only: bool) -> Option<&Node> {
        self.trusted_nodes.get(id).or_else(|| {
            if trusted_only {
                None
            } else {
                self.untrusted_nodes.get(id)
            }
        })
    }

    /// Get node from trusted/untrusted node tables for the specified id.
    pub fn get_with_trusty(&self, id: &NodeId) -> Option<(bool, &Node)> {
        if let Some(node) = self.trusted_nodes.get(id) {
            Some((true, node))
        } else if let Some(node) = self.untrusted_nodes.get(id) {
            Some((false, node))
        } else {
            None
        }
    }

    pub fn sample_trusted_nodes(
        &self, count: u32, filter: &IpFilter,
    ) -> Vec<NodeEntry> {
        if !self.ip_limit.is_enabled() {
            return self.trusted_nodes.sample_nodes(count, filter);
        }

        let mut entries = Vec::new();

        for id in self.ip_limit.sample_trusted(count) {
            if let Some(node) = self.get(&id, true /* trusted_only */) {
                entries.push(NodeEntry {
                    id,
                    endpoint: node.endpoint.clone(),
                });
            }
        }

        entries
    }

    pub fn sample_trusted_node_ids_within_group(
        &self, count: u32, group_id: usize, 
        existed_nodes: &HashSet<NodeId>, _filter: &IpFilter,
    ) ->  HashSet<NodeId> {
        // TODO: with_in_group!!!!

        // Here we do not consider the ip_limit!!!!
        let mut cnt = 0;
        let mut nodes: HashSet<NodeId> = HashSet::new();
        for node in self.cluster_group[group_id].iter(){
            if self.trusted_nodes.contains(node) && !existed_nodes.contains(node) {
                nodes.insert(node.clone());
                cnt += 1;
                if cnt >= count {
                    break;
                }
            }
        }
        
        nodes
    }

    pub fn sample_trusted_node_ids(
        &self, count: u32, filter: &IpFilter,
    ) -> HashSet<NodeId> {
        if self.ip_limit.is_enabled() {
            self.ip_limit.sample_trusted(count)
        } else {
            self.trusted_nodes.sample_node_ids(count, filter)
        }
    }

    pub fn sample_trusted_node_ids_with_tag(
        &self, count: u32, key: &String, value: &String,
    ) -> HashSet<NodeId> {
        // todo always enable ip_limit and remove the legacy sampling methods in
        // node table
        self.trusted_node_tag_index
            .sample(count, key, value)
            .unwrap_or_else(HashSet::new)
    }

    pub fn get_nodes(
        &self, ids: HashSet<NodeId>, trusted_only: bool,
    ) -> Vec<NodeEntry> {
        ids.iter()
            .filter_map(|id| self.get(id, trusted_only))
            .map(|n| NodeEntry {
                id: n.id.clone(),
                endpoint: n.endpoint.clone(),
            })
            .collect()
    }

    // if id does not exist, insert to the hashmap
    // if id exists, update the coordinate
    pub fn update_node_coordinate(
        &mut self, id: NodeId, coord: &vivaldi::Coordinate<Dimension2>,
    ) {
        let map = &mut self.node_coordinate;
        if map.contains_key(&id) == false {
            map.insert(id, coord.clone());
            debug!("Inserting ID = {:?} Coord = {:?}", id, coord);
        } else {
            debug!("Updating ID = {:?} Coord = {:?}", id, coord);
            if let Some(x) = map.get_mut(&id) {
                *x = coord.clone();
            }
        }
    }

    pub fn print_all_coordinate(
        &self,
    ) {
        for (id, coord) in self.node_coordinate.iter() {
            println!("NodeId = {:?} Coord = {:?}", id, coord);
        }
    }
    
    pub fn cluster_all_node(
        &mut self,
        self_id: NodeId,
        self_coord: vivaldi::Coordinate<Dimension2>,
    ) {
        self.update_node_coordinate(self_id, &self_coord);

        // at most 8 clustering!
        let (cluster_result, centers) = 
        //(self.cluster_result, self.centers) = 
            self.cluster(&self.node_coordinate, MAX_CLUSTER_NUM);
        self.cluster_result = cluster_result;
        self.centers = centers;

        let n = self.centers.len();
        self.cluster_group = vec![Default::default(); n];
        for (id, group_id) in self.cluster_result.iter() {
            self.cluster_group[*group_id].insert(id.clone());
        }

        let mut i = 0;
        for group in self.cluster_group.iter() {
            let mut group_coord = Vec::new();
            for id in group.iter() {
                let coord = self.node_coordinate.get(id).unwrap();
                group_coord.push(coord.vector().clone());
            }
            debug!("cluster group {} : {:?}", i, group_coord);
            i += 1;
        }
    }

    // K-mean++ algorithm
    // K clusters

    // return 
    // 1. map from NodeId -> group number
    // 2. the center of every group
    pub fn cluster(
        &self, 
        coordinate: &HashMap<NodeId, vivaldi::Coordinate<Dimension2>>, 
        k: usize
    ) -> (HashMap<NodeId, usize>, Vec<vivaldi::vector::Dimension2>) {
        let max_round = 10;
        let mut results: HashMap<NodeId, usize> = HashMap::new();
        let mut centers = Vec::new();
        let mut node_array = Vec::new();
        let mut rng = thread_rng();

        // clone all those coordinates
        for (id, coord) in coordinate.iter() {
            node_array.push(coord.vector().clone());
            results.insert(id.clone(), 0);
        }


        if self.centers.len() == k + 1 {
            // if history cluster results exists, set up the initial centers as the history centers.
            centers = self.centers.clone();
        } else {
            // K means ++
            // Firstly randomly select a center
            // Then, calculates the distance to the center D(x) for every nodes
            // Select the new center based on the weighted distribution [D(x_1)^2...D(x_n)^2]
            // Repeat this procedure until select K centers.

            let n = node_array.len();
            debug!("clustering k = {:?}", k);
            debug!("clustering: array {:?}", &node_array);
            let cluster_num = min(k, n);
            centers.push(node_array[0]);
            for _i in 1..cluster_num {
                let mut weight = Vec::new();
                for j in 0..n {
                    let mut min_dist: f64 = 1e100;
                    for c in centers.iter() {
                        let v = node_array[j as usize].clone() - c.clone();
                        if v.magnitude().0 < min_dist {
                            min_dist = v.magnitude().0;
                        }
                    }
                    weight.push(min_dist * min_dist);
                }
                let d = WeightedIndex::new(&weight);
                if d.is_err() {
                    break;
                }
                let new_center_index = d.unwrap().sample(&mut rng);
                centers.push(node_array[new_center_index as usize]);
            }
        }

        let cluster_num = centers.len();

        for _r in 0..max_round {

            // find the closest center
            for (id, coord) in coordinate.iter() {
                let mut min_dist = 1e10;
                let mut closest_center_index = 0;
                for i in 0..cluster_num {
                    let v = coord.vector().clone() - centers[i as usize].clone();
                    let dist = v.magnitude().0;
                    if dist < min_dist {
                        min_dist = dist;
                        closest_center_index = i;
                    }
                }
                // update the results
                if let Some(x) = results.get_mut(&id) {
                    *x = closest_center_index;
                }
            }

            // re-calculate the center
            let mut new_centers: Vec<Dimension2> = vec![Default::default(); cluster_num];
            let mut cluster_count = vec![0; cluster_num];
            for (id, coord) in coordinate.iter() {
                if let Some(index) = results.get(id) {
                    new_centers[*index] = new_centers[*index] + coord.vector().clone();
                    cluster_count[*index] += 1;
                }
            }
            for i in 0..cluster_num {
                centers[i as usize] = new_centers[i as usize].clone() / (cluster_count[i as usize] as f64);
            }

            println!("{:?}", centers);
        }

        (results, centers)
    }

    /// Persist trust and untrusted node tables and clear all useless nodes.
    pub fn save(&mut self) {
        self.trusted_nodes.save();
        self.trusted_nodes.clear_useless();

        self.untrusted_nodes.save();
        self.untrusted_nodes.clear_useless();

        self.blacklisted_nodes.save();
    }

    /// Promote untrusted nodes to trusted with the given duration.
    pub fn promote(&mut self, node_ids: Vec<NodeId>, due: Duration) {
        for id in node_ids.iter() {
            if self.trusted_nodes.contains(id) {
                continue;
            }

            if let Some(node) = self.untrusted_nodes.get(id) {
                if let Some(lc) = node.last_connected {
                    if lc.success_for_duration(due) {
                        if let Some(mut removed_node) =
                            self.untrusted_nodes.remove_with_id(id)
                        {
                            removed_node.last_contact =
                                removed_node.last_connected;
                            self.promote_with_untrusted(
                                id,
                                removed_node.endpoint.address.ip(),
                            );
                            // IP address not changed and always allow to add.
                            self.trusted_node_tag_index.add_node(&removed_node);
                            self.trusted_nodes.add_node(
                                removed_node,
                                false, /* preserve_last_contact */
                            );
                        }
                    }
                }
            }
        }
    }

    /// Demote the specified node to untrusted if it is trusted.
    pub fn demote(&mut self, node_id: &NodeId) {
        self.ip_limit.demote(node_id);
        if let Some(removed_trusted_node) =
            self.trusted_nodes.remove_with_id(node_id)
        {
            self.trusted_node_tag_index
                .remove_node(&removed_trusted_node);
            self.untrusted_nodes.add_node(
                removed_trusted_node,
                false, /* preserve_last_contact */
            );
        }
    }

    /// Remove node from database for the specified id
    pub fn remove(&mut self, id: &NodeId) -> Option<Node> {
        if let Some(node) = self.trusted_nodes.remove_with_id(id) {
            self.trusted_node_tag_index.remove_node(&node);
            self.ip_limit.remove(id);
            Some(node)
        } else if let Some(node) = self.untrusted_nodes.remove_with_id(id) {
            self.ip_limit.remove(id);
            Some(node)
        } else if let Some(node) = self.blacklisted_nodes.remove_with_id(id) {
            Some(node)
        } else {
            None
        }
    }

    fn init(&mut self, trusted: bool) {
        let nodes = if trusted {
            self.trusted_nodes.all()
        } else {
            self.untrusted_nodes.all()
        };

        for id in nodes {
            let ip = if trusted {
                self.trusted_nodes
                    .get(&id)
                    .expect("node not found in trusted table")
                    .endpoint
                    .address
                    .ip()
            } else {
                self.untrusted_nodes
                    .get(&id)
                    .expect("node not found in untrusted table")
                    .endpoint
                    .address
                    .ip()
            };

            let mut allowed = true;
            let mut evictee = None;

            match self.ip_limit.validate_insertion(&id, &ip, self) {
                ValidateInsertResult::AlreadyExists => {
                    panic!("node id is not unique in database")
                }
                ValidateInsertResult::QuotaNotEnough => allowed = false,
                ValidateInsertResult::QuotaEnough => {}
                ValidateInsertResult::OccupyIp(id) => evictee = Some(id),
                ValidateInsertResult::Evict(id) => evictee = Some(id),
            }

            if allowed {
                if let Some(evictee_id) = &evictee {
                    if trusted {
                        self.trusted_nodes.remove_with_id(&evictee_id);
                    } else {
                        self.untrusted_nodes.remove_with_id(&evictee_id);
                    }
                }

                assert!(self.ip_limit.insert(id, ip, trusted, evictee));
            } else if trusted {
                self.trusted_nodes.remove_with_id(&id);
            } else {
                self.untrusted_nodes.remove_with_id(&id);
            }
        }
    }

    pub fn set_tag(&mut self, id: NodeId, key: &str, value: &str) {
        let (trusted, node) =
            if let Some(node) = self.trusted_nodes.get_mut(&id) {
                (true, node)
            } else if let Some(node) = self.untrusted_nodes.get_mut(&id) {
                (false, node)
            } else {
                return;
            };

        // add or update tag for node
        let removed = node.tags.insert(key.into(), value.into());

        // do not update tag index for untrusted node
        if !trusted {
            return;
        }

        if !self.ip_limit.is_enabled() {
            return;
        }

        let subnet = self
            .ip_limit
            .subnet(&id)
            .expect("node index should always exist");

        // remove the old tag index
        if let Some(removed) = removed {
            self.trusted_node_tag_index.remove(
                &id,
                subnet,
                &key.into(),
                &removed,
            );
        }

        // add new tag index
        self.trusted_node_tag_index.insert(
            id,
            subnet,
            key.into(),
            value.into(),
        );
    }

    /// Set the specified node to blacklisted.
    pub fn set_blacklisted(&mut self, id: &NodeId) {
        // update the last failure time
        self.note_failure(
            id, true,  /* by_connection */
            false, /* trusted_only */
        );

        // move to blacklisted node table
        if let Some(node) = self.remove(id) {
            self.blacklisted_nodes
                .add_node(node, false /* preserve_last_contact */);
        }
    }

    /// Check if the specified node is blacklisted.
    /// If blacklisted for a long time, it will be removed from blacklisted node
    /// table.
    pub fn evaluate_blacklisted(&mut self, id: &NodeId) -> bool {
        let node = match self.blacklisted_nodes.get_mut(id) {
            Some(node) => node,
            None => return false,
        };

        let last_contact = match node.last_contact {
            Some(contact) => contact.time(),
            None => {
                // By default, the last_contact should not be empty.
                // If changed to None (e.g. manually), just treat
                // the node as non-blacklisted.
                self.blacklisted_nodes.remove_with_id(id);
                return false;
            }
        };

        if let Ok(elapsed) = last_contact.elapsed() {
            if elapsed > self.blacklisted_lifetime {
                self.blacklisted_nodes.remove_with_id(id);
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::NodeDatabase;
    use crate::node_table::{NodeEndpoint, NodeEntry, NodeId};
    use std::{str::FromStr, time::Duration};
    use vivaldi::{
        Coordinate, vector::Dimension2, 
    };

    fn new_entry(addr: &str) -> NodeEntry {
        NodeEntry {
            id: NodeId::random(),
            endpoint: NodeEndpoint::from_str(addr).unwrap(),
        }
    }

    #[test]
    fn test_insert_with_token_added() {
        let mut db = NodeDatabase::new(None, 2);

        // add a new node
        let entry = new_entry("127.0.0.1:999");
        db.insert_with_token(entry.clone(), 5);

        // should be untrusted with stream token 5
        assert_eq!(db.get(&entry.id, true /* trusted_only */), None);
        assert_eq!(
            db.get(&entry.id, false /* trusted_only */)
                .unwrap()
                .stream_token,
            Some(5)
        );
    }

    #[test]
    fn test_insert_with_token_updated_trusted() {
        let mut db = NodeDatabase::new(None, 2);

        // add trusted node, whose token is None
        let entry = new_entry("127.0.0.1:999");
        db.insert_trusted(entry.clone());
        assert_eq!(
            db.get(&entry.id, true /* trusted_only */)
                .unwrap()
                .stream_token,
            None
        );

        // update node with token 3
        db.insert_with_token(entry.clone(), 3);
        assert_eq!(
            db.get(&entry.id, true /* trusted_only */)
                .unwrap()
                .stream_token,
            Some(3)
        );
    }

    #[test]
    fn test_insert_with_token_updated_untrusted() {
        let mut db = NodeDatabase::new(None, 2);

        let entry = new_entry("127.0.0.1:999");
        db.insert_with_token(entry.clone(), 5);

        // update node with new token
        db.insert_with_token(entry.clone(), 8);
        assert_eq!(db.get(&entry.id, true /* trusted_only */), None);
        assert_eq!(
            db.get(&entry.id, false /* trusted_only */)
                .unwrap()
                .stream_token,
            Some(8)
        );
    }

    #[test]
    fn test_insert_with_token_updated_new_ip() {
        let mut db = NodeDatabase::new(None, 2);

        let entry1 = new_entry("127.0.0.1:999");
        db.insert_with_token(entry1.clone(), 5);

        // update node with new ip and token
        let mut entry2 = new_entry("127.0.0.2:999");
        entry2.id = entry1.id;
        db.insert_with_token(entry2.clone(), 8);
        let node = db.get(&entry1.id, false /* trusted_only */).unwrap();
        assert_eq!(node.endpoint, entry2.endpoint);
        assert_eq!(node.stream_token, Some(8));
    }

    #[test]
    fn test_insert_with_token_updated_ip_exists() {
        let mut db = NodeDatabase::new(None, 2);

        // add node1
        let entry1 = new_entry("127.0.0.1:999");
        db.insert_with_token(entry1.clone(), 3);

        // add node2
        let entry2 = new_entry("127.0.0.2:999");
        db.insert_with_token(entry2.clone(), 4);

        // update node2's IP address to ip1, node1 will be removed
        let mut entry = new_entry("127.0.0.1:999");
        entry.id = entry2.id.clone();
        db.insert_with_token(entry.clone(), 5);

        // node1 removed
        assert_eq!(db.get(&entry1.id, false /* trusted_only */), None);

        // node2 updated
        let node = db.get(&entry.id, false /* trusted_only */).unwrap();
        assert_eq!(node.endpoint, entry.endpoint);
        assert_eq!(node.stream_token, Some(5));
    }

    #[test]
    fn test_demote() {
        let mut db = NodeDatabase::new(None, 2);

        // add a trusted node
        let entry = new_entry("127.0.0.1:999");
        db.insert_trusted(entry.clone());
        assert_eq!(db.get(&entry.id, true /* trusted_only */).is_some(), true);

        // demote the trusted node to untrusted
        db.demote(&entry.id);
        assert_eq!(db.get(&entry.id, true /* trusted_only */), None);
        assert!(db.get(&entry.id, false /* trusted_only */).is_some());
    }

    #[test]
    fn test_remove() {
        let mut db = NodeDatabase::new(None, 2);

        // add trusted node
        let entry1 = new_entry("127.0.0.1:999");
        db.insert_trusted(entry1.clone());
        assert_eq!(db.get(&entry1.id, true /* trusted_only */).is_some(), true);

        // add untrusted node
        let entry2 = new_entry("127.0.0.2:999");
        db.insert_with_token(entry2.clone(), 9);
        assert_eq!(
            db.get(&entry2.id, false /* trusted_only */).is_some(),
            true
        );

        // delete nodes
        assert_eq!(db.remove(&NodeId::random()), None);
        assert_eq!(db.remove(&entry1.id).unwrap().endpoint, entry1.endpoint);
        assert_eq!(db.remove(&entry2.id).unwrap().endpoint, entry2.endpoint);

        assert_eq!(db.get(&entry1.id, true /* trusted_only */), None);
        assert_eq!(db.get(&entry2.id, false /* trusted_only */), None);
    }

    #[test]
    fn test_blacklisted() {
        let mut db = NodeDatabase::new(None, 2);

        let n = new_entry("127.0.0.1:999");
        db.insert_trusted(n.clone());
        assert_eq!(db.get(&n.id, true /* trusted_only */).unwrap().id, n.id);
        assert_eq!(db.evaluate_blacklisted(&n.id), false);

        // set to blacklisted
        db.set_blacklisted(&n.id);
        assert_eq!(db.evaluate_blacklisted(&n.id), true);
        assert_eq!(db.get(&n.id, false), None);
    }

    #[test]
    fn test_blacklisted_lifetime() {
        let mut db = NodeDatabase::new(None, 2);

        let n = new_entry("127.0.0.1:999");
        db.insert_trusted(n.clone());
        db.set_blacklisted(&n.id);

        db.blacklisted_lifetime = Duration::from_millis(1);
        std::thread::sleep(Duration::from_millis(2));

        assert_eq!(db.evaluate_blacklisted(&n.id), false);
        assert_eq!(db.get(&n.id, false), None);
    }

    #[test]
    fn test_cluster() {
        let mut db = NodeDatabase::new(None, 100);

        let n1 = new_entry("127.0.0.1:1");
        let n2 = new_entry("127.0.0.1:2");
        let n3 = new_entry("127.0.0.1:3");
        let n4 = new_entry("127.0.0.1:4");
        let n5 = new_entry("127.0.0.1:5");
        let n6 = new_entry("127.0.0.1:6");
        let n7 = new_entry("127.0.0.1:7"); 
        let n8 = new_entry("127.0.0.1:8");
        let n9 = new_entry("127.0.0.1:9"); 
        let n10 = new_entry("127.0.0.1:10");

        db.insert_trusted(n1.clone());
        db.insert_trusted(n2.clone());
        db.insert_trusted(n3.clone());
        db.insert_trusted(n4.clone());
        db.insert_trusted(n5.clone());
        db.insert_trusted(n6.clone());
        db.insert_trusted(n7.clone());
        db.insert_trusted(n8.clone());
        db.insert_trusted(n9.clone());
        db.insert_trusted(n10.clone());

        db.update_node_coordinate(n1.id.clone(), &Coordinate::new(Dimension2([-3.0, 3.0]), 0.0, 1.0));
        db.update_node_coordinate(n2.id.clone(), &Coordinate::new(Dimension2([-2.0, 3.0]), 0.0, 1.0));
        db.update_node_coordinate(n3.id.clone(), &Coordinate::new(Dimension2([2.0, 2.0]), 0.0, 1.0));
        db.update_node_coordinate(n4.id.clone(), &Coordinate::new(Dimension2([3.0, 2.0]), 0.0, 1.0));
        db.update_node_coordinate(n5.id.clone(), &Coordinate::new(Dimension2([3.0, 1.0]), 0.0, 1.0));
        db.update_node_coordinate(n6.id.clone(), &Coordinate::new(Dimension2([-3.0, -2.0]), 0.0, 1.0));
        db.update_node_coordinate(n7.id.clone(), &Coordinate::new(Dimension2([-2.0, -2.0]), 0.0, 1.0));
        db.update_node_coordinate(n8.id.clone(), &Coordinate::new(Dimension2([-3.0, -3.0]), 0.0, 1.0));
        db.update_node_coordinate(n9.id.clone(), &Coordinate::new(Dimension2([2.0, -3.0]), 0.0, 1.0));
        db.update_node_coordinate(n10.id.clone(), &Coordinate::new(Dimension2([3.0, -3.0]), 0.0, 1.0));

        let (result, _center) = db.cluster(&db.node_coordinate, 4);
        let c1 = result.get(&n1.id);
        let c2 = result.get(&n2.id);
        let c3 = result.get(&n3.id);
        let c4 = result.get(&n4.id);
        let c5 = result.get(&n5.id);
        let c6 = result.get(&n6.id);
        let c7 = result.get(&n7.id);
        let c8 = result.get(&n8.id);
        let c9 = result.get(&n9.id);
        let c10 = result.get(&n10.id);

        println!("c1 = {:?}", c1);
        println!("c2 = {:?}", c2);
        println!("c3 = {:?}", c3);
        println!("c4 = {:?}", c4);
        println!("c5 = {:?}", c5);
        println!("c6 = {:?}", c6);
        println!("c7 = {:?}", c7);
        println!("c8 = {:?}", c8);
        println!("c9 = {:?}", c9);
        println!("c10 = {:?}", c10);

        assert_eq!(c1, c2);
        assert_eq!(c3, c4);
        assert_eq!(c3, c5);
        assert_eq!(c6, c7);
        assert_eq!(c6, c8);
        assert_eq!(c9, c10);


        //db.update_node_coordinate(n1.id, Coordinate::new(Dimension2([-3, 3]), 0.0, 1.0));
        

        //assert_eq!(db.evaluate_blacklisted(&n.id), false);
        //assert_eq!(db.get(&n.id, false), None);
    }
}
