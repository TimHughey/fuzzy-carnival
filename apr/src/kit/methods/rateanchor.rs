// Rusty Pierre
//
// Copyright 2023 Tim Hughey
//
// Licensed under the Apache License, Version 2.0 (the "License")
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{
    kit::{Frame, Response},
    Result,
};
use anyhow::anyhow;
use serde::Deserialize;

#[allow(unused)]
#[derive(Default, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Data {
    rate: u64,
    #[serde(alias = "networkTimeTimelineID")]
    network_time_timeline_id: Option<i64>,
    network_time_secs: Option<i64>,
    network_time_frac: Option<i64>,
    network_time_flags: Option<u8>,
    rtp_time: Option<u32>,
}

#[derive(Debug, Default)]
pub struct Set {
    data: Option<Data>,
}

impl Set {
    pub fn response(&mut self, frame: Frame) -> Result<Response> {
        let cseq = frame.cseq;
        let routing = frame.routing;
        let content = frame
            .content
            .ok_or_else(|| anyhow!("{routing} requires content"))?;

        self.data = plist::from_bytes(&content.data)?;

        tracing::info!("{routing}\nCONTENT {:#?}", self.data);

        Ok(Response::ok_simple(cseq))
    }
}
