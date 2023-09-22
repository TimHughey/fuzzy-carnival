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

use super::GenericState;
use alkali::asymmetric::cipher;
use anyhow::anyhow;
use bytes::{Buf, Bytes, BytesMut};
use pretty_hex::PrettyHex;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Variant {
    Method,
    Identifier,
    Salt,
    PublicKey,
    Proof,
    EncryptedData,
    State,
}

#[derive(Debug, Default, Clone)]
pub enum Val {
    Method(u8),
    Identifier(Vec<u8>),
    Salt(Vec<u8>),
    PublicKey(cipher::PublicKey),
    Proof(Vec<u8>),
    EncryptedData(Vec<u8>),
    State(GenericState),
    // Error(u8),
    // RetryDelay(u32),
    // Certificate(Vec<u8>),
    // Signature(Vec<u8>),
    // Permission(u32),
    // FragmentData(Vec<u8>),
    // FragmentLast(Vec<u8>),
    // Flags(u64),
    // Separator,
    #[default]
    Unknown,
}

impl Val {
    pub fn build(variant: &Variant, bytes: Bytes) -> crate::Result<Val> {
        use Variant::{EncryptedData, Identifier, Method, Proof, PublicKey, Salt, State};

        let val = match variant {
            Identifier => Self::Identifier(bytes.into()),
            Proof => Self::Proof(bytes.into()),
            PublicKey if bytes.len() == cipher::PUBLIC_KEY_LENGTH => {
                let pub_key = cipher::PublicKey::try_from(&bytes[..])?;

                Self::PublicKey(pub_key)
            }
            Salt => Self::Salt(bytes.into()),
            EncryptedData => Self::EncryptedData(bytes.into()),
            Method => Val::Method(bytes[0]),
            State => Val::State(GenericState::try_from(bytes[0])?),
            PublicKey => Err(anyhow!(
                "unable to create tag val from {:?}",
                bytes.hex_dump()
            ))?,
        };

        Ok(val)
    }
}

#[derive(Debug, Clone)]
pub struct Tag {
    pub variant: Variant,
    pub val: Val,
}

impl Tag {
    const METHOD: u8 = 0;
    const IDENTIFIER: u8 = 1;
    const SALT: u8 = 2;
    const PUBLIC_KEY: u8 = 3;
    const PROOF: u8 = 4;
    const ENCRYPTED_DATA: u8 = 5;
    const STATE: u8 = 6;

    pub fn build(variant: Variant, bytes: Bytes) -> crate::Result<Self> {
        Ok(Self {
            val: Val::build(&variant, bytes)?,
            variant,
        })
    }

    pub fn from_tag_and_bytes(tag: u8, buf: Bytes) -> crate::Result<Self> {
        use Variant::{EncryptedData, Identifier, Method, Proof, PublicKey, Salt, State};
        const SINGLE_BYTE: usize = 1;

        let variant = match (tag, buf.len()) {
            (Self::METHOD, SINGLE_BYTE) => Method,
            (Self::STATE, SINGLE_BYTE) => State,
            (Self::IDENTIFIER, _len) => Identifier,
            (Self::SALT, _len) => Salt,
            (Self::PUBLIC_KEY, _len) => PublicKey,
            (Self::PROOF, _len) => Proof,
            (Self::ENCRYPTED_DATA, _len) => EncryptedData,
            (tag, SINGLE_BYTE) => Err(anyhow!("unknown tag {tag}"))?,
            (tag, _len) => Err(anyhow!("unknown tag {tag} for {:?}", buf.hex_dump()))?,
        };

        Self::build(variant, buf)
    }
}

impl TryFrom<Val> for Tag {
    type Error = anyhow::Error;

    fn try_from(val: Val) -> crate::Result<Self> {
        let variant = match &val {
            Val::Method(_) => Variant::Method,
            Val::Identifier(_) => Variant::Identifier,
            Val::Salt(_) => Variant::Salt,
            Val::PublicKey(_) => Variant::PublicKey,
            Val::Proof(_) => Variant::Proof,
            Val::EncryptedData(_) => Variant::EncryptedData,
            Val::State(_) => Variant::State,
            Val::Unknown => Err(anyhow!("unknown tlv value"))?,
        };

        Ok(Self { variant, val })
    }
}

#[derive(Debug, Default, Clone)]
pub struct TagList(Vec<Tag>);

impl TagList {
    #[must_use]
    pub fn len_ne(&self, want_len: usize) -> bool {
        self.0.len() != want_len
    }

    #[allow(dead_code)]
    pub fn get(&self, variant: &Variant) -> crate::Result<Tag> {
        self.0
            .iter()
            .find(|tlv| tlv.variant == *variant)
            .ok_or(anyhow!("variant {variant:#?} not found"))
            .cloned()
    }

    pub fn get_state(&self) -> crate::Result<GenericState> {
        if let Tag {
            val: Val::State(state),
            ..
        } = self.get(&Variant::State)?
        {
            Ok(state)
        } else {
            Err(anyhow!("fatal error"))
        }
    }
}

impl TryFrom<BytesMut> for TagList {
    type Error = anyhow::Error;

    fn try_from(mut buf: BytesMut) -> crate::Result<Self> {
        let mut inner = Vec::<Tag>::new();

        while !buf.is_empty() {
            // first byte is the tag, second byte is the num of value bytes
            let tag = buf.get_u8();
            let len = buf.get_u8() as usize;

            let tlv = if buf.len() >= len {
                Tag::from_tag_and_bytes(tag, buf.copy_to_bytes(len))?
            } else {
                Err(anyhow!("tag expected {len} bytes while buffer is empty"))?
            };

            inner.push(tlv);
        }

        Ok(TagList(inner))
    }
}
