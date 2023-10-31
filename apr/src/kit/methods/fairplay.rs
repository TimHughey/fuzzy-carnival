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

use super::super::msg::{Frame, Response};
use crate::Result;
use anyhow::anyhow;
use once_cell::sync::Lazy;
use pretty_hex::PrettyHex;

const MODE_IDX: usize = 14;
const SEQ_IDX: usize = 6;
// const TYPE_IDX: usize = 5;
const SETUP2_SUFFIX_LEN: usize = 20;

const SETUP1_SEQ: u8 = 1;
const SETUP2_SEQ: u8 = 3;

static HEADER_BIN: Lazy<Vec<u8>> = Lazy::new(|| include_bytes!("fairplay_bin/header.bin").to_vec());
static REPLY1: Lazy<Vec<u8>> = Lazy::new(|| include_bytes!("fairplay_bin/reply1.bin").to_vec());
static REPLY2: Lazy<Vec<u8>> = Lazy::new(|| include_bytes!("fairplay_bin/reply2.bin").to_vec());
static SETUP2_MSG_SEQ: Lazy<Vec<u8>> =
    Lazy::new(|| include_bytes!("fairplay_bin/setup2_msg_seq.bin").to_vec());

#[allow(clippy::similar_names)]
pub fn make_response(frame: Frame) -> Result<Response> {
    if let Some(content) = frame.content {
        tracing::debug!("\nBODY {:?}", content.hex_dump());

        let cseq = frame.cseq;
        let seq = content.data[SEQ_IDX];
        // let _type = content.data[TYPE_IDX];
        let mode = content.data[MODE_IDX];

        let is_123 = |mode: u8| [1, 2, 3].contains(&mode);

        let response = match (seq, mode) {
            (SETUP1_SEQ, 0) => Response::ok_octet_stream(cseq, &REPLY1),
            (SETUP1_SEQ, mode) if is_123(mode) => Response::ok_octet_stream(cseq, &REPLY2),

            (SETUP2_SEQ, _mode) => {
                let data_in = content.into_data();
                let capacity = HEADER_BIN.len() + SETUP2_SUFFIX_LEN + SETUP2_MSG_SEQ.len();
                let mut buf = Vec::<u8>::with_capacity(capacity);
                buf.extend_from_slice(&HEADER_BIN);

                let at = data_in.len() - SETUP2_SUFFIX_LEN;
                let (_discard, sliver) = data_in.split_at(at);

                buf.extend_from_slice(sliver);
                buf.extend_from_slice(&SETUP2_MSG_SEQ[..]);

                Response::ok_octet_stream(cseq, &buf)
            }
            (_seq, _mode) => Response::internal_server_error(cseq),
        };

        return Ok(response);
    }

    Err(anyhow!("content must be present"))
}
