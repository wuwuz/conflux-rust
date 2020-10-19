// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::handleable::{Context, Handleable},
    Error,
};
use cfx_types::H256;
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use vivaldi::{
    vector::Dimension2, vector::Dimension3,
    Coordinate,
};

#[derive(Debug, RlpDecodable, RlpEncodable)]
pub struct CoordinatePing {
    pub coord: vivaldi::Coordinate<Dimension2>,
    pub send_time_milli: u64, // millisecond since UNIX_EPOCH
}

#[derive(Debug, RlpDecodable, RlpEncodable)]
pub struct CoordinatePong {
    pub recv_coord: vivaldi::Coordinate<Dimension2>, 
    pub send_coord: vivaldi::Coordinate<Dimension2>,
    pub send_time_milli: u64, // millisecond since UNIX_EPOCH
}

impl Handleable for CoordinatePing {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        debug!("on_coodinate_ping, msg=:{:?}", self);
        //ctx.manager.insert_coordinate(ctx.node_id(), &self.coord);
        let response = CoordinatePong {
            recv_coord: self.coord.clone(),
            send_coord: ctx.manager.get_coordinate(),
            send_time_milli: self.send_time_milli,
        };
        ctx.send_response(&response)
    }
}

impl Handleable for CoordinatePong {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        debug!("on_coodinate_pong, msg=:{:?}, from {}", self, ctx.node_id());
        ctx.manager.insert_coordinate(ctx.node_id(), &self.send_coord);
        ctx.manager.print_all_coordinate();
        let send_time = UNIX_EPOCH.checked_add(Duration::from_millis(self.send_time_milli));
        if let Some(send_time) = send_time {

            let now = SystemTime::now();
            let elapsed_time = now.duration_since(send_time).expect("clock may have gone backwards");
            debug!("RTT is {:?}", elapsed_time);

            ctx.manager.update_coordinate(&self.send_coord, elapsed_time);
            debug!("My new coordinate is {:?}", ctx.manager.get_coordinate());
        }

        Ok(())
    }
}

