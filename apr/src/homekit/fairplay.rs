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

use anyhow::anyhow;
use once_cell::sync::Lazy;

use crate::{
    rtsp::{Body, Frame, Response},
    Result,
};

const MODE_IDX: usize = 14;
const SEQ_IDX: usize = 6;
const TYPE_IDX: usize = 5;
const SETUP2_SUFFIX_LEN: usize = 20;

const SETUP1_SEQ: u8 = 1;
const SETUP2_SEQ: u8 = 3;

static HEADER_BIN: Lazy<Vec<u8>> = Lazy::new(|| include_bytes!("fairplay/header.bin").to_vec());
static REPLY1: Lazy<Vec<u8>> = Lazy::new(|| include_bytes!("fairplay/reply1.bin").to_vec());
static REPLY2: Lazy<Vec<u8>> = Lazy::new(|| include_bytes!("fairplay/reply2.bin").to_vec());
static SETUP2_MSG_SEQ: Lazy<Vec<u8>> =
    Lazy::new(|| include_bytes!("fairplay/setup2_msg_seq.bin").to_vec());

pub fn make_response(frame: Frame) -> Result<Response> {
    if let Body::Bulk(body_in) = frame.body {
        use pretty_hex::PrettyHex;
        tracing::debug!("\nBODY {:?}", body_in.hex_dump());

        let seq = body_in[SEQ_IDX];
        let _type = body_in[TYPE_IDX];
        let mode = body_in[MODE_IDX];

        match (seq, mode) {
            (SETUP1_SEQ, 0) => {
                Response::ok_with_body(frame.headers, Body::OctetStream(REPLY1.clone()))
            }
            (SETUP1_SEQ, mode) if [1, 2, 3].contains(&mode) => {
                Response::ok_with_body(frame.headers, Body::OctetStream(REPLY2.clone()))
            }

            (SETUP2_SEQ, _mode) => {
                let capacity = HEADER_BIN.len() + SETUP2_SUFFIX_LEN + SETUP2_MSG_SEQ.len();
                let mut buf = Vec::<u8>::with_capacity(capacity);
                buf.extend_from_slice(&HEADER_BIN);

                let at = body_in.len() - SETUP2_SUFFIX_LEN;
                let (_discard, sliver) = body_in.split_at(at);

                buf.extend_from_slice(sliver);
                buf.extend_from_slice(&SETUP2_MSG_SEQ[..]);

                Response::ok_with_body(frame.headers, Body::OctetStream(buf))
            }
            (_seq, _mode) => Response::internal_server_error(frame.headers),
        }
    } else {
        Err(anyhow!("body should be bulk"))
    }
}
