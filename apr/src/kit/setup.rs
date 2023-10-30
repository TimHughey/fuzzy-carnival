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

use super::{
    msg::{Frame, Response},
    ListenerPorts,
};
use crate::{HostInfo, Result};
use anyhow::anyhow;

#[derive(Debug, Default)]
#[allow(unused)]
pub struct Method {
    group_uuid: Option<String>,
    has_group_leader: Option<bool>,
    listener_ports: ListenerPorts,
}

impl Method {
    pub fn build(listener_ports: ListenerPorts) -> Self {
        Self {
            group_uuid: None,
            has_group_leader: None,
            listener_ports,
        }
    }

    pub fn make_response(&mut self, frame: Frame) -> Result<Response> {
        use plist::{Dictionary as Dict, Value as Val};

        if let Some(content) = frame.content {
            const STREAMS: &str = "streams";
            const TIMING_PROTO: &str = "timingProtocol";

            let dict_in: Dict = plist::from_bytes(&content.data)?;

            let mut rdict = plist::Dictionary::new();

            // initial setup request does not contain the key streams
            if dict_in.contains_key(STREAMS) {
                tracing::info!("{STREAMS} present");
            } else {
                const ADDRESSES: &str = "Addresses";
                const EVENT_PORT: &str = "eventPort";
                const GROUP_UUID: &str = "groupUUID";
                const GROUP_LEADER: &str = "groupContainsGroupLeader";
                const ID: &str = "ID";
                const TIMING_PEER_INFO: &str = "timingPeerInfo";
                const TIMING_PORT: &str = "timingPort";

                match dict_in
                    .get(TIMING_PROTO)
                    .and_then(plist::Value::as_string)
                    .ok_or_else(|| anyhow!("{TIMING_PROTO} not found or invalid"))?
                {
                    "PTP" => tracing::debug!("PTP timing requested"),
                    "NTP" => return Err(anyhow!("NTP timing not supported")),
                    timing => tracing::warn!("unhandled {TIMING_PROTO}: {timing}"),
                }

                let group_uuid = dict_in
                    .get(GROUP_UUID)
                    .ok_or_else(|| anyhow!("group_uuid missing"))?
                    .as_string()
                    .ok_or_else(|| anyhow!("group uuid is not a string"))?
                    .to_string();

                self.group_uuid = Some(group_uuid);
                self.has_group_leader =
                    dict_in.get(GROUP_LEADER).and_then(plist::Value::as_boolean);

                // get timing peer list

                // CREATE REPLY
                //
                //  1. timing peer info (our IP address(es)
                //  3. event tcp port (with listener active)
                //  3. flip service status to active

                let ip_addr = HostInfo::ip_as_str();

                let mut timing_peers = Dict::new();
                timing_peers.insert(
                    ADDRESSES.into(),
                    Val::Array(vec![Val::String(ip_addr.into())]),
                );
                timing_peers.insert(ID.into(), Val::String(ip_addr.into()));

                rdict.insert(
                    TIMING_PEER_INFO.into(),
                    Val::Array(vec![Val::Dictionary(timing_peers)]),
                );

                rdict.insert(
                    EVENT_PORT.into(),
                    Val::Integer(self.listener_ports.event.unwrap_or(0).into()),
                );
                rdict.insert(TIMING_PORT.into(), Val::Integer(0u16.into()));

                return Response::ok_plist_dict(frame.cseq, &rdict);
            }
        }

        Ok(Response::internal_server_error(frame.cseq))
    }
}
