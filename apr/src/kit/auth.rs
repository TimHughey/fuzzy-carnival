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
    cipher,
    tags::{Map as Tags, Val as TagVal},
    Frame, Response, Result,
};
use once_cell::sync::Lazy;

pub mod setup;
pub mod srp;
pub mod verify;

const M1: TagVal = TagVal::State(1);
const M3: TagVal = TagVal::State(3);

pub struct Pair {
    setup: Lazy<setup::Context>,
    verify: Lazy<verify::Context>,
}

impl Default for Pair {
    fn default() -> Self {
        Self {
            setup: Lazy::new(setup::Context::build),
            verify: Lazy::new(verify::Context::build),
        }
    }
}

impl Pair {
    pub fn cipher_take(&mut self) -> Option<cipher::Context> {
        self.setup.cipher.take()
    }

    pub fn response(&mut self, path: &str, frame: Frame) -> Result<Response> {
        let Frame { cseq, content, .. } = frame;

        let tags_in = Tags::try_from(content)?;

        let tags_out = match (path, tags_in.get_state()?) {
            ("/pair-setup", M1) => self.setup.m1_m2(&tags_in),
            ("/pair-setup", M3) => self.setup.m3_m4(&tags_in)?,
            ("/pair-verify", M1) => {
                let accessory_client_pub = tags_in.get_public_key()?;
                self.verify.m1_m2(accessory_client_pub)?
            }
            (path, state) => {
                tracing::warn!("{path}: UNKNOWN {state}\n{tags_in:?}");
                return Ok(Response::internal_server_error(cseq));
            }
        };

        Ok(Response::ok_octet_stream(cseq, &tags_out.encode()))
    }
}
