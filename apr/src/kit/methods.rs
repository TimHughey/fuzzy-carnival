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

mod consts {
    pub(crate) const FP_MODE_IDX: usize = 14;
    pub(crate) const FP_SEQ_IDX: usize = 6;
    // const TYPE_IDX: usize = 5;
    pub(crate) const FP_SETUP2_SUFFIX_LEN: usize = 20;

    pub(crate) const FP_SETUP1_SEQ: u8 = 1;
    pub(crate) const FP_SETUP2_SEQ: u8 = 3;
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
    peers: Vec<String>,
    clock_id: i64,
}

#[allow(clippy::unnecessary_wraps)]
impl SetPeers {
    pub fn make_response(&mut self, frame: Frame) -> Result<Response> {
        use plist::Value as Val;

        let cseq = frame.cseq;

        if let Some(content) = frame.content {
            let val: plist::Value = content.try_into()?;

            match val {
                Val::Array(arr) => {
                    // the array provided appears to only contain a single row
                    // so let's warn if different
                    if arr.len() > 1 {
                        tracing::warn!("peers array suspect: len > 1");
                    }

                    if let Val::Dictionary(dict) = &arr[0] {
                        tracing::debug!("\nSETPEERS {dict:#?}");

                        if let Some(Val::Array(addrs)) = dict.get("Addresses") {
                            for addr in addrs.iter() {
                                if let Val::String(addr) = addr {
                                    self.peers.push(addr.clone());
                                }
                            }
                        }

                        if let Some(Val::Integer(clock_id)) = dict.get("ClockID") {
                            if let Some(clock_id) = clock_id.as_signed() {
                                self.clock_id = clock_id;
                            } else {
                                tracing::error!("failed to convert {clock_id:?}");
                            }
                        }
                    }
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

#[derive(Debug, Default)]
pub struct Setup {
    group_uuid: Option<String>,
    has_group_leader: Option<bool>,
    listener_ports: ListenerPorts,
}

impl Setup {
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
