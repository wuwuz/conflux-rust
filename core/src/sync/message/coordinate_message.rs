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

#[derive(Debug, PartialEq, RlpDecodable, RlpEncodable)]
pub struct CoordinatePing {
    pub x: u32,
    pub y: u32,
    pub send_time_milli: u64, // millisecond since UNIX_EPOCH
}

#[derive(Debug, PartialEq, RlpDecodable, RlpEncodable)]
pub struct CoordinatePong {
    pub x: u32,
    pub y: u32,
    pub send_time_milli: u64, // millisecond since UNIX_EPOCH
}

impl Handleable for CoordinatePing {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        debug!("on_coodinate_ping, msg=:{:?}", self);
        let response = CoordinatePong {
            x: self.x, 
            y: self.y,
            send_time_milli: self.send_time_milli,
        };
        ctx.send_response(&response)
    }
}

impl Handleable for CoordinatePong {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        debug!("on_coodinate_pong, msg=:{:?}", self);
        let send_time = UNIX_EPOCH.checked_add(Duration::from_millis(self.send_time_milli));
        if let Some(send_time) = send_time {

            let now = SystemTime::now();
            let elapsed_time = now.duration_since(send_time).expect("clock may have gone backwards");
            debug!("RTT is {:?}", elapsed_time);
        }

        Ok(())
    }
}

