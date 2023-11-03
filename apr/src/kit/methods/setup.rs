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
    kit::{
        msg::{Frame, Response},
        Ports,
    },
    HostInfo, Result,
};
use anyhow::anyhow;
use bytes::BytesMut;
// use bytes::BytesMut;
// use pretty_hex::PrettyHex;
use serde::Deserialize;

pub const TIMING_PORT: &str = "timingPort";
// pub const TIMING_PROTO: &str = "timingProtocol";
pub const STREAMS: &str = "streams";
pub const ADDRESSES: &str = "Addresses";
pub const EVENT_PORT: &str = "eventPort";
// pub const GROUP_UUID: &str = "groupUUID";
// pub const GROUP_LEADER: &str = "groupContainsGroupLeader";
pub const ID: &str = "ID";
pub const TIMING_PEER_INFO: &str = "timingPeerInfo";

#[derive(Debug, Default)]
pub struct Stream {
    pub audio_format: u64,
    pub compression: u8,
    pub conn_id: [u8; 8],
    pub dynamic_stream_id_support: bool,
    pub stream_type: u8,
    pub shared_key: Vec<u8>,
    pub sample_frames_per_packet: u64,
}

impl TryFrom<&plist::Dictionary> for Stream {
    type Error = anyhow::Error;

    fn try_from(dict: &plist::Dictionary) -> std::result::Result<Self, Self::Error> {
        use plist::Value as Val;

        Ok(Self {
            // "audioFormat": Integer(4194304,),
            audio_format: dict
                .get("audioFormat")
                .and_then(Val::as_unsigned_integer)
                .ok_or_else(|| anyhow!("error: audio format"))?,
            // "ct": Integer(4,),
            compression: dict
                .get("ct")
                .and_then(Val::as_unsigned_integer)
                .ok_or_else(|| anyhow!("error: compression"))?
                .try_into()?,
            // "streamConnectionID": Integer(-7961538597027756049,),
            // because I don't like big negative numbers we'll store
            // the connection id as regular ole bytes
            conn_id: {
                dict.get("streamConnectionID")
                    .and_then(Val::as_signed_integer)
                    .ok_or_else(|| anyhow!("error: conn id"))?
                    .to_ne_bytes()
            },
            // "supportsDynamicStreamID": Boolean(true,),
            dynamic_stream_id_support: dict
                .get("supportsDynamicStreamID")
                .and_then(Val::as_boolean)
                .ok_or_else(|| anyhow!("error: dynamic stream"))?,
            // "type": Integer(103,),
            stream_type: dict
                .get("type")
                .and_then(Val::as_unsigned_integer)
                .ok_or_else(|| anyhow!("error: stream type"))?
                .try_into()?,
            // "shk": Data([202,205,126,201,161,252],),
            shared_key: dict
                .get("shk")
                .and_then(Val::as_data)
                .ok_or_else(|| anyhow!("error: shared key"))?
                .try_into()?,
            // "spf"
            sample_frames_per_packet: dict
                .get("spf")
                .and_then(Val::as_unsigned_integer)
                .ok_or_else(|| anyhow!("error: spf"))?,
            // "audioMode": String("default",),
            // "clientID": String("com.apple.Music",),
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TimingPeer {
    #[serde(alias = "ID")]
    pub id: String,
    pub addresses: Vec<String>,
    pub device_type: u8,
    pub supports_clock_port_matching_override: bool,
}

#[allow(unused, clippy::struct_excessive_bools)]
#[derive(Default, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Base {
    pub timing_protocol: String,
    pub stats_collection_enabled: bool,
    #[serde(alias = "sessionUUID")]
    pub session_uuid: String,
    pub os_name: String,
    pub os_build_version: String,
    pub source_version: String,
    pub sender_supports_relay: bool,
    pub os_version: String,
    pub timing_peer_info: Option<TimingPeer>,
    pub is_multi_select_air_play: bool,
    #[serde(skip)]
    pub timing_peer_list: Vec<TimingPeer>,
    #[serde(alias = "sessionCorrelationUUID")]
    pub session_correlation_uuid: String,
    pub group_contains_group_leader: bool,
    #[serde(alias = "groupUUID")]
    pub group_uuid: String,
    #[serde(alias = "deviceID")]
    pub device_id: String,
    pub model: String,
    pub name: String,
    pub mac_address: String,
}

#[derive(Debug, Default)]
pub struct Setup {
    ports: Ports,
    base: Base,
    streams: Vec<Stream>,
}

impl Setup {
    pub fn response(&mut self, frame: Frame, ports: Option<Ports>) -> Result<Response> {
        use plist::Dictionary as Dict;

        let Frame {
            routing,
            cseq,
            content,
            ..
        } = frame;

        self.ports = ports.ok_or_else(|| anyhow!("ports are None"))?;

        if let Some(content) = content {
            let dict_in: Dict = plist::from_bytes(&content.data)?;

            // NOTE: the prsence of a streams array indicates step2
            if dict_in.contains_key(STREAMS) {
                tracing::debug!("{} WITH STREAMS\n{dict_in:#?}", routing);
                self.step2_with_streams(cseq, &dict_in)
            } else {
                self.step1_no_streams(cseq, &content.data)
            }
        } else {
            let error = format!("{routing} requires content");
            tracing::error!(error);
            Ok(Response::internal_server_error(cseq))
        }
    }

    fn step1_no_streams(&mut self, cseq: u32, data: &BytesMut) -> Result<Response> {
        use plist::{Dictionary as Dict, Value as Val};

        // tracing::info!("\nSETUP {dict_in:#?}");

        self.base = plist::from_bytes(data)?;

        /*  match dict_in
            .get(TIMING_PROTO)
            .and_then(plist::Value::as_string)
            .ok_or_else(|| anyhow!("{} not found or invalid", TIMING_PROTO))?
        {
            "PTP" => tracing::debug!("PTP timing requested"),
            "NTP" => return Err(anyhow!("NTP timing not supported")),
            timing => tracing::warn!("unhandled {}: {timing}", TIMING_PROTO),
        }

        let group_uuid = dict_in
            .get(GROUP_UUID)
            .ok_or_else(|| anyhow!("group_uuid missing"))?
            .as_string()
            .ok_or_else(|| anyhow!("group uuid is not a string"))?
            .to_string();

        self.group_uuid = Some(group_uuid);
        self.has_group_leader = dict_in.get(GROUP_LEADER).and_then(plist::Value::as_boolean); */

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

        let mut rdict = plist::Dictionary::new();

        rdict.insert(
            TIMING_PEER_INFO.into(),
            Val::Array(vec![Val::Dictionary(timing_peers)]),
        );

        rdict.insert(EVENT_PORT.into(), Val::Integer(self.ports.event.into()));
        rdict.insert(TIMING_PORT.into(), Val::Integer(0u16.into()));

        Response::ok_plist_dict(cseq, &rdict)
    }

    fn step2_with_streams(&mut self, cseq: u32, dict_in: &plist::Dictionary) -> Result<Response> {
        use plist::Value as Val;

        // "streams": Array
        if let Some(streams) = dict_in.get("streams").and_then(Val::as_array) {
            for stream_dict in streams {
                if let Some(dict) = stream_dict.as_dictionary() {
                    self.streams.push(Stream::try_from(dict)?);
                }
            }

            let stream0 = self.streams.get(0).ok_or_else(|| anyhow!("whoa"))?;
            let mut rdict_stream0 = plist::Dictionary::new();

            rdict_stream0.insert("type".into(), stream0.stream_type.try_into()?);
            rdict_stream0.insert("dataPort".into(), self.ports.data.into());
            rdict_stream0.insert("audioBufferSize".into(), 0x80_000u64.into());
            rdict_stream0.insert("controlPort".into(), self.ports.control.into());

            let array = plist::Value::Array(vec![plist::Value::from(rdict_stream0)]);
            let mut rdict = plist::Dictionary::new();

            rdict.insert("streams".into(), array);

            tracing::debug!("SETUP RDICT\n{rdict:#?}");

            Response::ok_plist_dict(cseq, &rdict)
        } else {
            Ok(Response::internal_server_error(cseq))
        }
    }
}
