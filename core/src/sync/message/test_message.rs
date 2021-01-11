// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::handleable::{Context, Handleable},
    Error,
};
//use cfx_types::H256;
use rlp_derive::{RlpDecodable, RlpEncodable};
//use std::collections::HashSet;
//use std::time::{Instant};

#[derive(Debug, RlpDecodable, RlpEncodable)]
pub struct TestDelayModelMessage {
    pub seq_num: u32,
    pub load: Vec<u8>,
}

impl Handleable for TestDelayModelMessage {
    fn handle(self, _ctx: &Context) -> Result<(), Error> {
        //debug!("DelayTest: Receive package from {}", ctx.node_id());
        //debug!("DelayTest: Sequence Number = {}, time = {:?}", self.seq_num, Instant::now());
        Ok(())
    }
}

