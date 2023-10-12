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

use crate::Result;
#[allow(unused_imports)]
use alkali::{
    asymmetric::{cipher, sign},
    mem,
    symmetric::auth,
};
use anyhow::anyhow;
#[allow(unused_imports)]
use bytes::{Bytes, BytesMut};
use once_cell::sync::Lazy;

pub struct Ephemeral {
    pub server: cipher::Keypair,
}

#[allow(unused)]
static mut KEYS: Lazy<Ephemeral> = Lazy::new(Ephemeral::default);

impl Ephemeral {
    #[allow(dead_code)]
    pub fn server_pk(&self) -> &[u8] {
        self.server.public_key.as_slice()
    }

    #[allow(dead_code)]
    pub fn server_sk(&self) -> &[u8] {
        self.server.private_key.as_slice()
    }

    #[allow(dead_code)]
    pub fn zero() -> Result<()> {
        unsafe {
            let sk = cipher::PrivateKey::new_empty()?;

            if let Some(keys) = Lazy::get_mut(&mut KEYS) {
                keys.server = cipher::Keypair {
                    public_key: [0u8; cipher::PUBLIC_KEY_LENGTH],
                    private_key: sk.try_clone()?,
                };
            } else {
                return Err(anyhow!("failed to put client public key"));
            }
        }

        Ok(())
    }
}

impl Default for Ephemeral {
    fn default() -> Self {
        let msg = "failed to generate server keys";

        Self {
            server: cipher::Keypair::generate().expect(msg),
        }
    }
}
