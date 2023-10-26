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
    rtsp::{Body, Frame, Response},
    Result,
};
use anyhow::anyhow;
use bstr::ByteSlice;
use bytes::{BufMut, BytesMut};

#[derive(Debug, Default)]
#[allow(unused)]
pub struct Setup {
    group_uuid: String,
    has_group_leader: bool,
}

pub fn make_response(frame: Frame) -> Result<Response> {
    use plist::{Dictionary as Dict, Value as Val};

    let mut setup = Setup::default();

    if let Body::Dict(dict) = frame.body {
        const STREAMS: &str = "streams";
        const TIMING_PROTO: &str = "timingProtocol";

        let mut out = BytesMut::with_capacity(4096);
        let writer = (&mut out).writer();

        plist::to_writer_xml(writer, &dict)?;

        tracing::debug!("\nSETUP DICT\n{}", out.to_str()?);

        let mut rdict = plist::Dictionary::new();

        // initial setup request does not contain the key streams
        if dict.contains_key(STREAMS) {
            tracing::info!("{STREAMS} present");
        } else {
            const ADDRESSES: &str = "Addresses";
            const EVENT_PORT: &str = "eventPort";
            const GROUP_UUID: &str = "groupUUID";
            const GROUP_LEADER: &str = "groupContainsGroupLeader";
            const ID: &str = "ID";
            const TIMING_PEER_INFO: &str = "timingPeerInfo";
            const TIMING_PORT: &str = "timingPort";

            match dict
                .get(TIMING_PROTO)
                .and_then(plist::Value::as_string)
                .ok_or_else(|| anyhow!("{TIMING_PROTO} not found or invalid"))?
            {
                "PTP" => tracing::debug!("PTP timing requested"),
                "NTP" => return Err(anyhow!("NTP timing not supported")),
                timing => tracing::warn!("unhandled {TIMING_PROTO}: {timing}"),
            }

            setup.group_uuid = dict
                .get(GROUP_UUID)
                .and_then(plist::Value::as_string)
                .ok_or_else(|| anyhow!("{GROUP_UUID} not found or invalid"))?
                .into();

            setup.has_group_leader = dict
                .get(GROUP_LEADER)
                .and_then(plist::Value::as_boolean)
                .ok_or_else(|| anyhow!("{GROUP_LEADER} not found or invalid"))?;

            // get timing peer list

            // CREATE REPLY
            //
            //  1. timing peer info (our IP address(es)
            //  3. event tcp port (with listener active)
            //  3. flip service status to active

            let mut timing_peers = Dict::new();
            timing_peers.insert(
                ADDRESSES.into(),
                Val::Array(vec![Val::String("192.168.2.4".into())]),
            );
            timing_peers.insert(ID.into(), Val::String("192.168.2.4".into()));

            rdict.insert(
                TIMING_PEER_INFO.into(),
                Val::Array(vec![Val::Dictionary(timing_peers)]),
            );

            rdict.insert(EVENT_PORT.into(), Val::Integer(31_876u32.into()));
            rdict.insert(TIMING_PORT.into(), Val::Integer(0u16.into()));

            return Response::ok_with_body(frame.headers, Body::from(rdict));
        }
    }

    Response::internal_server_error(frame.headers)
}
