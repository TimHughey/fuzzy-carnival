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
    kit::msg::{Frame, Response},
    BytesWrite, FlagsCalc, HostInfo, Result,
};
use anyhow::anyhow;
use bytes::BytesMut;
use pretty_hex::PrettyHex;

// Method
pub(crate) mod rateanchor;
pub(crate) use rateanchor::Set as SetRateAnchorTime;
// Method: SETPEERS(X)
pub(crate) mod peers;
pub(crate) use peers::Set as SetPeers;
// Method: SETUP
pub(crate) mod setup;
pub(crate) use setup::Setup;

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
    pub(crate) const SETRATEANCHORTIME: &str = "SETRATEANCHORTIME";
}

#[derive(Debug, Default)]
pub(crate) struct Command {
    _priv: (),
}

impl Command {
    pub fn response(frame: Frame) -> Result<Response> {
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
    pub fn response(frame: Frame) -> Result<Response> {
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
    pub fn response(frame: Frame) -> Result<Response> {
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
