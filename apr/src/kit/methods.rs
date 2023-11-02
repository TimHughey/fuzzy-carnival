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
        ListenerPorts,
    },
    BytesWrite, FlagsCalc, HostInfo, Result,
};
use anyhow::anyhow;
use bytes::BytesMut;
use pretty_hex::PrettyHex;

mod static_data {
    use once_cell::sync::Lazy;

    pub static FP_HEADER: Lazy<Vec<u8>> = Lazy::new(|| {
        let data: &[u8] = include_bytes!("static/fp_header.bin");
        data.to_vec()
    });

    pub static FP_REPLY1: Lazy<Vec<u8>> = Lazy::new(|| {
        let data: &[u8] = include_bytes!("static/fp_reply1.bin");
        data.to_vec()
    });

    pub static FP_REPLY2: Lazy<Vec<u8>> = Lazy::new(|| {
        let data: &[u8] = include_bytes!("static/fp_reply2.bin");
        data.to_vec()
    });

    pub static FP_SETUP2_MSG_SEQ: Lazy<Vec<u8>> = Lazy::new(|| {
        let data: &[u8] = include_bytes!("static/fp_setup2_msg_seq.bin");
        data.to_vec()
    });

    pub static INFO_RESP: Lazy<Vec<u8>> = Lazy::new(|| {
        let data: &[u8] = include_bytes!("static/info_resp.xml");
        data.to_vec()
    });
}

pub(crate) mod consts {
    pub(crate) const FP_MODE_IDX: usize = 14;
    pub(crate) const FP_SEQ_IDX: usize = 6;
    // const TYPE_IDX: usize = 5;
    pub(crate) const FP_SETUP2_SUFFIX_LEN: usize = 20;

    pub(crate) const FP_SETUP1_SEQ: u8 = 1;
    pub(crate) const FP_SETUP2_SEQ: u8 = 3;

    pub(crate) const GET_PARAMETER: &str = "GET_PARAMETER";
    pub(crate) const GET: &str = "GET";
    pub(crate) const POST: &str = "POST";
    pub(crate) const RECORD: &str = "RECORD";
    pub(crate) const SET_PARAMETER: &str = "SET_PARAMETER";
    pub(crate) const SET_PEERS: &str = "SETPEERS";
    pub(crate) const SET_PEERSX: &str = "SETPEERSX";
    pub(crate) const SETUP: &str = "SETUP";
    pub(crate) const TEARDOWN: &str = "TEARDOWN";
}

#[derive(Debug, Default)]
pub(crate) struct Command {
    _priv: (),
}

impl Command {
    pub fn make_response(frame: Frame) -> Result<Response> {
        let cseq = frame.cseq;

        if let Some(content) = frame.content {
            use plist::Value as Val;
            let pval: plist::Value = plist::from_bytes(&content.data)?;

            if let Some(arr) = pval
                .as_dictionary()
                .and_then(|dict| dict.get("params").and_then(Val::as_dictionary))
                .and_then(|dict| dict.get("mrSupportedCommandsFromSender"))
                .and_then(Val::as_array)
            {
                for a in arr {
                    if let Some(data) = a.as_data() {
                        let sub_val: Val = plist::from_bytes(data)?;

                        tracing::debug!("\n{sub_val:?}");
                    }
                }
            }
        }

        Ok(Response::ok_simple(cseq))
    }
}

#[derive(Debug, Default)]
pub(crate) struct FairPlay {
    _priv: (),
}

impl FairPlay {
    #[allow(clippy::similar_names)]
    pub fn make_response(frame: Frame) -> Result<Response> {
        use consts::{FP_MODE_IDX, FP_SEQ_IDX, FP_SETUP1_SEQ, FP_SETUP2_SEQ, FP_SETUP2_SUFFIX_LEN};
        use static_data::{FP_HEADER, FP_REPLY1, FP_REPLY2, FP_SETUP2_MSG_SEQ};

        if let Some(content) = frame.content {
            tracing::debug!("\nBODY {:?}", content.hex_dump());

            let cseq = frame.cseq;
            let seq = content.data[FP_SEQ_IDX];
            // let _type = content.data[TYPE_IDX];
            let mode = content.data[FP_MODE_IDX];

            let response = match (seq, mode) {
                (FP_SETUP1_SEQ, 0) => Response::ok_octet_stream(cseq, &FP_REPLY1),
                (FP_SETUP1_SEQ, 1 | 2 | 3) => Response::ok_octet_stream(cseq, &FP_REPLY2),

                (FP_SETUP2_SEQ, _mode) => {
                    let data_in = content.into_data();
                    let capacity = FP_HEADER.len() + FP_SETUP2_SUFFIX_LEN + FP_SETUP2_MSG_SEQ.len();
                    let mut buf = Vec::<u8>::with_capacity(capacity);
                    buf.extend_from_slice(&FP_HEADER);

                    let at = data_in.len() - FP_SETUP2_SUFFIX_LEN;
                    let (_discard, sliver) = data_in.split_at(at);

                    buf.extend_from_slice(sliver);
                    buf.extend_from_slice(&FP_SETUP2_MSG_SEQ[..]);

                    Response::ok_octet_stream(cseq, &buf)
                }
                (_seq, _mode) => Response::internal_server_error(cseq),
            };

            return Ok(response);
        }

        Err(anyhow!("content must be present"))
    }
}

#[derive(Debug, Default)]
pub(crate) struct Info {
    _priv: (),
}

impl Info {
    #[allow(clippy::no_effect_underscore_binding)]
    pub fn make_response(frame: Frame) -> Result<Response> {
        use plist::Value;

        let cseq = frame.cseq;
        let routing = frame.routing;
        if let Some(content) = frame.content {
            // apparently the client is OK with a 500 for the qualifier GET /info request.
            //
            // later in the initial connection sequence GET /info is requested again
            // without content and we can send the typical response
            if let Some(dict) = content.get_dict()? {
                if let Some(arr) = dict.get("qualifier").and_then(Value::as_array) {
                    if let Some("txtAirPlay") = arr.get(0).and_then(Value::as_string) {
                        tracing::debug!("{routing} qualifier=txtAirPlay");
                        return Ok(Response::internal_server_error(cseq));
                    }
                }

                // in the event we did get content that was not the qualifier log it
                tracing::warn!("\n{routing} CONTENT {:?}", content.data.hex_dump());
            }
        } else {
            tracing::debug!("{routing} EMPTY CONTENT");
            return Self::handle_qualifier(cseq);
        }

        Ok(Response::internal_server_error(cseq))
    }

    fn handle_qualifier(cseq: u32) -> Result<Response> {
        use plist::{
            Dictionary as Dict,
            Value::{Integer as ValInt, String as ValString},
        };

        let mut dict: Dict = plist::from_bytes(static_data::INFO_RESP.as_slice())?;

        for (k, v) in [
            ("features", ValInt(FlagsCalc::features_as_u64().into())),
            ("statusFlags", ValInt(FlagsCalc::status_as_u32().into())),
            ("deviceID", ValString(HostInfo::id_as_str().into())),
            ("pi", ValString(HostInfo::id_as_str().into())),
            ("name", ValString(HostInfo::receiver_as_str().into())),
            ("model", ValString("Hughey".into())),
        ] {
            dict.insert(k.into(), v);
        }

        let mut binary = BytesMut::with_capacity(1024);
        plist::to_writer_binary(BytesWrite(&mut binary), &dict)?;

        Ok(Response::ok_octet_stream(cseq, &binary))
    }
}

#[derive(Debug, Default)]
pub struct SetPeers {
    peers: Vec<plist::Dictionary>,
}

impl SetPeers {
    pub fn make_response(&mut self, frame: Frame) -> Result<Response> {
        use plist::Value as Val;

        let cseq = frame.cseq;

        if let Some(content) = frame.content {
            let val: Val = content.try_into()?;

            match val {
                Val::Array(array) => {
                    self.peers = array
                        .iter()
                        .filter_map(|v| v.as_dictionary().cloned())
                        .collect();
                }
                val => {
                    let error = "invalid plist variant";
                    tracing::error!("{error}\n{val:?}");
                    return Err(anyhow!(error));
                }
            }
        }

        Ok(Response::ok_simple(cseq))
    }
}

#[allow(unused)]
mod setup {
    use anyhow::anyhow;

    pub const TIMING_PORT: &str = "timingPort";
    pub const TIMING_PROTO: &str = "timingProtocol";
    pub const STREAMS: &str = "streams";
    pub const ADDRESSES: &str = "Addresses";
    pub const EVENT_PORT: &str = "eventPort";
    pub const GROUP_UUID: &str = "groupUUID";
    pub const GROUP_LEADER: &str = "groupContainsGroupLeader";
    pub const ID: &str = "ID";
    pub const TIMING_PEER_INFO: &str = "timingPeerInfo";

    #[derive(Debug, Default)]
    pub struct Stream {
        audio_format: u64,
        compression: u8,
        conn_id: [u8; 8],
        dynamic_stream_id_support: bool,
        stream_type: u8,
        shared_key: Vec<u8>,
        sample_frames_per_packet: u64,
    }

    impl TryFrom<&plist::Dictionary> for Stream {
        type Error = anyhow::Error;

        fn try_from(dict: &plist::Dictionary) -> Result<Self, Self::Error> {
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
}

#[derive(Debug, Default)]
pub struct Setup {
    group_uuid: Option<String>,
    has_group_leader: Option<bool>,
    listener_ports: ListenerPorts,
    streams: Vec<setup::Stream>,
}

impl Setup {
    pub fn build(listener_ports: ListenerPorts) -> Self {
        Self {
            group_uuid: None,
            has_group_leader: None,
            listener_ports,
            streams: Vec::new(),
        }
    }

    pub fn make_response(&mut self, frame: Frame) -> Result<Response> {
        use plist::Dictionary as Dict;

        let cseq = frame.cseq;

        if let Some(content) = frame.content {
            let dict_in: Dict = plist::from_bytes(&content.data)?;

            #[allow(clippy::if_not_else)]
            if !dict_in.contains_key(setup::STREAMS) {
                self.step1_no_streams(cseq, &dict_in)
            } else {
                tracing::info!("{} WITH STREAMS\n{dict_in:#?}", frame.routing);
                self.step2_with_streams(cseq, &dict_in)
            }
        } else {
            let error = format!("{} requires content", frame.routing);
            tracing::error!(error);
            Ok(Response::internal_server_error(frame.cseq))
        }
    }

    fn step1_no_streams(&mut self, cseq: u32, dict_in: &plist::Dictionary) -> Result<Response> {
        use plist::{Dictionary as Dict, Value as Val};

        let mut rdict = plist::Dictionary::new();

        match dict_in
            .get(setup::TIMING_PROTO)
            .and_then(plist::Value::as_string)
            .ok_or_else(|| anyhow!("{} not found or invalid", setup::TIMING_PROTO))?
        {
            "PTP" => tracing::debug!("PTP timing requested"),
            "NTP" => return Err(anyhow!("NTP timing not supported")),
            timing => tracing::warn!("unhandled {}: {timing}", setup::TIMING_PROTO),
        }

        let group_uuid = dict_in
            .get(setup::GROUP_UUID)
            .ok_or_else(|| anyhow!("group_uuid missing"))?
            .as_string()
            .ok_or_else(|| anyhow!("group uuid is not a string"))?
            .to_string();

        self.group_uuid = Some(group_uuid);
        self.has_group_leader = dict_in
            .get(setup::GROUP_LEADER)
            .and_then(plist::Value::as_boolean);

        // get timing peer list

        // CREATE REPLY
        //
        //  1. timing peer info (our IP address(es)
        //  3. event tcp port (with listener active)
        //  3. flip service status to active

        let ip_addr = HostInfo::ip_as_str();

        let mut timing_peers = Dict::new();
        timing_peers.insert(
            setup::ADDRESSES.into(),
            Val::Array(vec![Val::String(ip_addr.into())]),
        );
        timing_peers.insert(setup::ID.into(), Val::String(ip_addr.into()));

        rdict.insert(
            setup::TIMING_PEER_INFO.into(),
            Val::Array(vec![Val::Dictionary(timing_peers)]),
        );

        rdict.insert(
            setup::EVENT_PORT.into(),
            Val::Integer(self.listener_ports.event.unwrap_or(0).into()),
        );
        rdict.insert(setup::TIMING_PORT.into(), Val::Integer(0u16.into()));

        Response::ok_plist_dict(cseq, &rdict)
    }

    fn step2_with_streams(&mut self, cseq: u32, dict_in: &plist::Dictionary) -> Result<Response> {
        use plist::Value as Val;
        use setup::Stream;

        // "streams": Array
        if let Some(streams) = dict_in.get("streams").and_then(Val::as_array) {
            for stream_dict in streams {
                if let Some(dict) = stream_dict.as_dictionary() {
                    self.streams.push(Stream::try_from(dict)?);
                }
            }
        }

        if !self.streams.is_empty() {}

        //

        Ok(Response::internal_server_error(cseq))
    }
}
