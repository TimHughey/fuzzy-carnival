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

use crate::{kit::Tags, HostInfo, Result};
use anyhow::anyhow;
use once_cell::sync::OnceCell;
use std::fmt;

#[derive(Default)]
pub struct Context {
    pub accessory: OnceCell<Accessory>,
}

impl Context {
    pub fn build() -> Self {
        Self {
            accessory: OnceCell::new(),
        }
    }

    pub fn m1_m2(&self, accessory_client_pub: &[u8]) -> Result<Tags> {
        use crate::kit::TagVal;
        use bytes::BytesMut;
        #[allow(unused)]
        use chacha20poly1305::{
            aead::{Aead, AeadCore, KeyInit},
            AeadInPlace, ChaCha20Poly1305, Nonce,
        };

        use ed25519_dalek::Signer;
        use hmac_sha256::HKDF;

        let sign_key = &HostInfo::get().accessory_sign_key;
        let id = HostInfo::id_as_slice();

        let accessory = self
            .accessory
            .get_or_init(|| Accessory::build(accessory_client_pub));

        let mut info = BytesMut::with_capacity(64 * 3);
        info.extend_from_slice(accessory.public.as_bytes());
        info.extend_from_slice(id);
        info.extend_from_slice(accessory.client_pub.as_bytes());

        let info = info.freeze();

        let signature = sign_key.try_sign(&info)?;

        let mut tags = Tags::default();

        tags.push(TagVal::Identifier(id.into()));
        tags.push(TagVal::Signature(signature.to_vec()));

        let prk = HKDF::extract(b"Pair-Verify-Encrypt-Salt", &accessory.shared);
        let mut session_key = BytesMut::zeroed(32);
        HKDF::expand(&mut session_key, &prk[..], b"Pair-Verify-Encrypt-Info\x01");

        let mut data = tags.encode();
        let nonce = Nonce::from_slice(b"\0\0\0\0PV-Msg02");
        let cipher = ChaCha20Poly1305::new_from_slice(&session_key[..])?;

        let tag = cipher
            .encrypt_in_place_detached(nonce, &[], &mut data)
            .map_err(|e| anyhow!("{e}"))?;

        data.extend_from_slice(&tag);

        let mut tags = Tags::default();

        tags.push(TagVal::State(0x02));
        tags.push(TagVal::PublicKey(accessory.public.as_bytes().to_vec()));
        tags.push(TagVal::EncryptedData(data.to_vec()));

        Ok(tags)
    }
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\nVerify Context\n")?;
        writeln!(f, "{:?}", self.accessory)
    }
}

pub struct Accessory {
    pub public: x25519_dalek::PublicKey,
    pub client_pub: x25519_dalek::PublicKey,
    pub shared: x25519_dalek::SharedSecret,
}

impl Accessory {
    pub fn build(accessory_client_pub: &[u8]) -> Self {
        let mut client_pub_buf = [0u8; 32];
        client_pub_buf.copy_from_slice(&accessory_client_pub[0..32]);
        let accessory_client_pub: x25519_dalek::PublicKey = client_pub_buf.into();

        let random = x25519_dalek::EphemeralSecret::random();
        let public = x25519_dalek::PublicKey::from(&random);

        Self {
            shared: random.diffie_hellman(&accessory_client_pub),
            client_pub: accessory_client_pub,
            public,
        }
    }
}

impl fmt::Debug for Accessory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use pretty_hex::PrettyHex;

        f.write_str("\nAccessory\n")?;

        writeln!(f, "PUBLIC {:?}\n", self.public.hex_dump())?;
        writeln!(f, "CLIENT PUB {:?}\n", self.client_pub.hex_dump())?;
        writeln!(f, "SHARED {:?}", self.shared.hex_dump())
    }
}
