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
pub struct CoordinateMessage {
    pub x: u32,
    pub y: u32,
    pub send_time_milli: u64, // millisecond since UNIX_EPOCH
}

impl Handleable for CoordinateMessage {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        debug!("on_coodinate, msg=:{:?}", self);
        let send_time = UNIX_EPOCH.checked_add(Duration::from_millis(self.send_time_milli));
        if let Some(send_time) = send_time {

            let now = SystemTime::now();
            let elapsed_time = now.duration_since(send_time).expect("clock may have gone backwards");
            debug!("time difference is {:?}", elapsed_time);
        }

        Ok(())
    }
}
