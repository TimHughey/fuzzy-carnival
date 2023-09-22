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

use super::{Tag, TagList, TagVal, TagVariant, VerifyState};
use crate::HostInfo;
use alkali::{asymmetric::cipher, asymmetric::sign, mem};
use anyhow::anyhow;
use pretty_hex::PrettyHex;
use std::fmt;

pub struct Context {
    device_id: sign::Seed<mem::FullAccess>,

    // Same keys as used for pair-setup, derived from device_id
    #[allow(unused)]
    server_keys: sign::Keypair,

    #[allow(unused)]
    verify_client_signature: bool,

    // For establishing the shared secret for encrypted communication
    #[allow(unused)]
    server_eph_keys: cipher::Keypair,

    #[allow(unused)]
    client_eph_pk: Option<cipher::PublicKey>,

    shared_secret: Option<[u8; 32]>,
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ss = if let Some(ss) = &self.shared_secret {
            ss.hex_dump().to_string()
        } else {
            "None".to_string()
        };

        f.debug_struct("VerifyCtx")
            .field("device_id", &self.device_id.hex_dump())
            .field("shared_secret", &ss)
            .finish()
    }
}

impl Context {
    pub fn build() -> crate::Result<Self> {
        type Seed = sign::Seed<mem::FullAccess>;

        let seed = Seed::try_from(HostInfo::seed().as_slice())?;

        Ok(Self {
            server_keys: sign::Keypair::from_seed(&seed)?,
            device_id: seed,
            verify_client_signature: false,
            server_eph_keys: cipher::Keypair::generate()?,
            client_eph_pk: None,
            shared_secret: None,
        })
    }

    pub fn push_client_pub_key(&mut self, client_pub_key: cipher::PublicKey) {
        self.client_eph_pk = Some(client_pub_key);
    }

    fn request(self, tlv_list: &TagList) -> crate::Result<Self> {
        use VerifyState::{Msg01, Msg02, Msg03, Msg04};
        let state = VerifyState::try_from(tlv_list.get(&TagVariant::State)?.clone())?;

        match state {
            Msg01 => {
                let Tag { val: pub_key, .. } = tlv_list.get(&TagVariant::PublicKey)?;
                if let TagVal::PublicKey(key_src) = pub_key {
                    Ok(Self {
                        client_eph_pk: Some(key_src),
                        ..self
                    })
                } else {
                    Err(anyhow!("verify msg01 does not contain client pub key"))
                }
            }
            Msg02 => Ok(self),
            Msg03 => Ok(self),
            Msg04 => Ok(self),
        }
    }
}
