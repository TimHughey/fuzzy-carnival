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

use super::msg::Content;
use crate::Result;
use anyhow::anyhow;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use indexmap::IndexMap;
use pretty_hex::PrettyHex;
use std::{
    fmt::{self, Write},
    mem,
};
use tracing::{debug, error, warn};
pub use x25519_dalek::PublicKey as CipherPubKey;
use Val::{
    Certificate, EncryptedData, Error, Flags, FragmentData, FragmentLast, Identifier, Method,
    Permissions, Proof, PublicKey, RetryDelay, Salt, Separator, Signature, State,
};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Idx {
    Method = 0,        // (integer) Method to use for pairing. See PairMethod
    Identifier = 1,    // (UTF-8) Identifier for authentication
    Salt = 2,          // (bytes) 16+ bytes of random salt
    PublicKey = 3,     // (bytes) Curve25519, SRP public key or signed Ed25519 key
    Proof = 4,         // (bytes) Ed25519 or SRP proof
    EncryptedData = 5, // (bytes) Encrypted data with auth tag at end
    State = 6,         // (integer) State of the pairing process. 1=M1, 2=M2, etc.
    Error = 7,         // (integer) Error code, only present when error
    RetryDelay = 8,    // (integer) Seconds to delay until retrying a setup code
    Certificate = 9,   // (bytes) X.509 Certificate
    Signature = 10,    // (bytes) Ed25519
    Permissions = 11,  // (integer) Bit value describing permissions of the controller
    // being added.
    // None (0x00): Regular user
    // Bit 1 (0x01): Admin that is able to add and remove
    // pairings against the accessory
    FragmentData = 12, // (bytes) Non-last fragment of data. If length is 0,
    // it's an ACK.
    FragmentLast = 13, // (bytes) Last fragment of data
    Flags = 19,        // Added from airplay2_receiver
    Separator = 0xffu8,
}

#[derive(Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum Val {
    Method(u8) = 0,
    Identifier(Vec<u8>) = 1,
    Salt(Vec<u8>) = 2,
    PublicKey(Vec<u8>) = 3,
    Proof(Vec<u8>) = 4,
    EncryptedData(Vec<u8>) = 5,
    State(u8) = 6,
    Error(u8) = 7,
    RetryDelay(u32) = 8,
    Certificate(Vec<u8>) = 9,
    Signature(Vec<u8>) = 10,
    Permissions(u32) = 11,
    FragmentData(Vec<u8>) = 12,
    FragmentLast(Vec<u8>) = 13,
    Flags(u8) = 19,
    Separator = 0xffu8,
}

impl Idx {
    pub const CERTIFICATE: u8 = Self::Certificate as u8;
    pub const ENCRYPTED_DATA: u8 = Self::EncryptedData as u8;
    pub const ERROR: u8 = Self::Error as u8;
    pub const FLAGS: u8 = Self::Flags as u8;
    pub const FRAGMENT_DATA: u8 = Self::FragmentData as u8;
    pub const FRAGMENT_LAST: u8 = Self::FragmentLast as u8;
    pub const PERMISSIONS: u8 = Self::Permissions as u8;
    pub const PROOF: u8 = Self::Proof as u8;
    pub const RETRY_DELAY: u8 = Self::RetryDelay as u8;
    pub const SEPERATOR: u8 = Self::Separator as u8;
    pub const SIGNATURE: u8 = Self::Signature as u8;
    pub const STATE: u8 = Self::State as u8;

    fn discriminant(&self) -> u8 {
        let ptr: *const Self = self;

        unsafe { *ptr.cast::<u8>() }
    }
}

/// Encoding helpers
fn tsb(id: u8, val: u8) -> Bytes {
    Bytes::copy_from_slice(&[id, 1, val])
}

fn tvb(id: u8, data: Vec<u8>) -> Bytes {
    const MAX_CHUNK: usize = u8::MAX as usize;

    let calc = |bytes: &Vec<u8>| {
        const OVERHEAD: usize = 2;

        match bytes.len() {
            len if len > MAX_CHUNK => ((len / MAX_CHUNK) + 1) * OVERHEAD + len,
            len => OVERHEAD + len,
        }
    };

    let mut out = BytesMut::with_capacity(calc(&data));

    Bytes::from(data).chunks(MAX_CHUNK).for_each(|c| {
        if let Ok(len) = u8::try_from(c.len()) {
            out.put_u8(id);
            out.put_u8(len);
            out.extend_from_slice(c);
        } else {
            error!("chunk size > 255");
        }
    });

    out.into()
}

impl Val {
    pub const METHOD: u8 = Idx::Method as u8;
    pub const IDENTIFER: u8 = Idx::Identifier as u8;
    pub const SALT: u8 = Idx::Salt as u8;
    pub const PUBLIC_KEY: u8 = Idx::PublicKey as u8;

    pub fn desc(&self) -> &'static str {
        match self {
            Method(_) => "Method",
            Identifier(_) => "Identifier",
            Salt(_) => "Salt",
            PublicKey(_) => "PublicKey",
            Proof(_) => "Proof",
            EncryptedData(_) => "EncryptedData",
            State(_) => "State",
            Error(_) => "Error",
            RetryDelay(_) => "RetryDelay",
            Certificate(_) => "Certificate",
            Signature(_) => "Signature",
            Permissions(_) => "Permission",
            FragmentData(_) => "FragmentData",
            FragmentLast(_) => "FragmentLast",
            Flags(_) => "Flags",
            Separator => "Seperator",
        }
    }

    fn id(&self) -> u8 {
        let s: *const Self = self;
        unsafe { *s.cast::<u8>() }
    }

    pub fn idx(&self) -> u8 {
        let s: *const Self = self;
        unsafe { *s.cast::<u8>() }
    }

    pub fn encode(self) -> Bytes {
        let tag_id = self.tag_id();
        let tag_len = self.len();

        match self {
            Method(n) | State(n) if tag_len == 1 => tsb(tag_id, n),
            EncryptedData(data) | Signature(data) | Identifier(data) | PublicKey(data)
            | Salt(data) | Proof(data) => tvb(tag_id, data),

            val => {
                error!("encode failure: {val:?}");
                panic!("coding error");
            }
        }
    }

    pub fn extend(&mut self, more: Val) {
        let self_id = self.id();

        if self_id == more.id() {
            debug!("attempting extend {self:?}");

            if let (
                Identifier(a) | Salt(a) | Proof(a) | Signature(a) | EncryptedData(a)
                | Certificate(a) | FragmentData(a) | FragmentLast(a) | PublicKey(a),
                Identifier(b) | Salt(b) | Proof(b) | Signature(b) | EncryptedData(b)
                | Certificate(b) | FragmentData(b) | FragmentLast(b) | PublicKey(b),
            ) = (self, more)
            {
                a.extend_from_slice(&b);

                debug!("\nextending {self_id}, new len {}", b.len());
            }
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Identifier(v) | Salt(v) | Proof(v) | EncryptedData(v) | FragmentData(v)
            | FragmentLast(v) | Certificate(v) | Signature(v) | PublicKey(v) => v.len(),
            State(_) => 1,
            Method(x) | Error(x) | Flags(x) => mem::size_of_val(x),
            RetryDelay(x) | Permissions(x) => mem::size_of_val(x),
            Separator => 0,
        }
    }

    pub fn make_state(val: u8) -> Val {
        Val::State(val)
    }

    /// Returns the tag id of this [`Val`].
    #[inline]
    pub fn tag_id(&self) -> u8 {
        self.idx()
    }
}

impl fmt::Debug for Val {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let desc = self.desc();

        write!(f, "{desc}")?;

        match self {
            Identifier(x) | Signature(x) | Salt(x) | Proof(x) | EncryptedData(x)
            | FragmentData(x) | FragmentLast(x) | Certificate(x) => {
                write!(f, " {:?}", x.hex_dump())
            }
            RetryDelay(x) | Permissions(x) => write!(f, " {x}"),
            Method(x) | Error(x) | State(x) | Flags(x) => write!(f, " {x}"),
            PublicKey(pk) => write!(f, " {:?}", pk.hex_dump()),
            Separator => Ok(()),
        }
    }
}

impl fmt::Display for Val {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let desc = self.desc();

        write!(f, "{desc}")?;

        match self {
            Identifier(x) | Signature(x) | Salt(x) | Proof(x) | EncryptedData(x)
            | FragmentData(x) | FragmentLast(x) | Certificate(x) => {
                write!(f, " {:?}", x.hex_dump())
            }
            RetryDelay(x) | Permissions(x) => write!(f, " {x}"),
            Method(x) | Error(x) | State(x) | Flags(x) => write!(f, " {x}"),
            PublicKey(pk) => write!(f, " {:?}", pk.hex_dump()),
            Separator => Ok(()),
        }
    }
}

#[derive(Default, Clone)]
pub struct Map(IndexMap<u8, Val>);

impl Map {
    pub fn encode(self) -> BytesMut {
        self.0
            .into_values()
            .map(Val::encode)
            .collect::<Vec<Bytes>>()
            .concat()
            .as_slice()
            .into()
    }

    pub fn push(&mut self, val: Val) {
        use indexmap::map::Entry;
        let idx = Val::idx(&val);

        match self.0.entry(idx) {
            Entry::Vacant(vacant) => {
                debug!("pushing {idx} {val:?}");
                vacant.insert(val);
            }
            Entry::Occupied(mut occupied) => {
                let v = occupied.insert(val);
                warn!("replaced {v:?}");
            }
        }
    }

    pub fn get_cloned(&self, idx: Idx) -> Result<Val> {
        let val = self
            .0
            .get(&idx.discriminant())
            .ok_or(anyhow!("{idx:?} not available"));

        Ok(val?.clone())
    }

    pub fn get_state(&self) -> Result<Val> {
        self.0
            .get(&Idx::STATE)
            .cloned()
            .ok_or_else(|| anyhow!("state not found"))
    }

    pub fn get_public_key(&self) -> Result<&Vec<u8>> {
        if let Some(Val::PublicKey(s)) = self.0.get(&Val::PUBLIC_KEY) {
            return Ok(s);
        }

        Err(anyhow!("public key not present"))
    }
}

impl TryFrom<Bytes> for Map {
    type Error = anyhow::Error;

    fn try_from(bytes: Bytes) -> Result<Self> {
        Map::try_from(BytesMut::from(&bytes[..]))
    }
}

impl TryFrom<Option<Content>> for Map {
    type Error = anyhow::Error;

    fn try_from(maybe_content: Option<Content>) -> std::result::Result<Self, Self::Error> {
        if let Some(content) = maybe_content {
            return Self::try_from(content.data);
        }

        let error = "content data is requied to create tags map";
        tracing::error!(error);
        Err(anyhow!(error))
    }
}

impl TryFrom<BytesMut> for Map {
    type Error = anyhow::Error;

    fn try_from(mut buf: BytesMut) -> Result<Self> {
        let mut map: IndexMap<u8, Val> = IndexMap::new();

        while !buf.is_empty() {
            let tag = buf.get_u8();
            let tag_len = buf.get_u8() as usize;

            if buf.len() < tag_len {
                return Err(anyhow!("buffer exhausted"));
            }

            let val = match (tag, tag_len) {
                (Val::METHOD, 1) => Val::Method(buf.get_u8()),

                (Val::SALT, len) => Val::Salt(buf.copy_to_bytes(len).to_vec()),

                (Val::IDENTIFER, len) => {
                    let bytes = &buf.copy_to_bytes(len);
                    Val::Identifier(bytes.to_vec())
                }

                (Val::PUBLIC_KEY, len) => Val::PublicKey(buf.copy_to_bytes(len).to_vec()),

                (Idx::ENCRYPTED_DATA, len) => {
                    let bytes = &buf.copy_to_bytes(len);
                    Val::EncryptedData(bytes.to_vec())
                }

                (Idx::PROOF, len) => {
                    let bytes = &buf.copy_to_bytes(len);
                    Val::Proof(bytes.to_vec())
                }

                (Idx::STATE, 1) => Val::State(buf.get_u8()),

                (Idx::ERROR, 1) => Val::Error(buf.get_u8()),

                (Idx::RETRY_DELAY, 4) => Val::RetryDelay(buf.get_u32()),

                (Idx::SIGNATURE, len) => {
                    let bytes = &buf.copy_to_bytes(len);
                    Val::Signature(bytes.to_vec())
                }

                (Idx::PERMISSIONS, 4) => Val::Permissions(buf.get_u32()),

                (Idx::CERTIFICATE, len) => {
                    let bytes = &buf.copy_to_bytes(len);
                    Val::Certificate(bytes.to_vec())
                }

                (Idx::FRAGMENT_DATA, len) => {
                    let bytes = &buf.copy_to_bytes(len);
                    Val::FragmentData(bytes.to_vec())
                }

                (Idx::FRAGMENT_LAST, len) => {
                    let bytes = &buf.copy_to_bytes(len);
                    Val::FragmentLast(bytes.to_vec())
                }

                (Idx::FLAGS, 1) => Val::Flags(buf.get_u8()),

                (Idx::SEPERATOR, 0) => Val::Separator,

                (tag, len) => {
                    error!("UNHANDLED {tag} len {len} {:?}", buf.hex_dump());
                    Err(anyhow!("unhandled tag"))?
                }
            };

            let idx = val.idx();

            if let Some(existing) = map.get_mut(&idx) {
                debug!("found existing {existing:?}");
                existing.extend(val);
            } else {
                debug!("inserting new tag {idx} {val:?}");
                map.insert(idx, val);
            }
        }

        Ok(Map(map))
    }
}

impl fmt::Debug for Map {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Tag List\n")?;

        for item in self.0.values() {
            f.write_str(item.desc())?;
            f.write_str(": ")?;

            match item {
                Method(x) | Error(x) => {
                    f.write_fmt(format_args!("{x}"))?;
                }

                Identifier(x) | Signature(x) | Salt(x) | Proof(x) | EncryptedData(x)
                | FragmentData(x) | FragmentLast(x) | Certificate(x) => {
                    f.write_fmt(format_args!("{:?}", x.hex_dump()))?;
                }

                PublicKey(pk) => {
                    f.write_fmt(format_args!("{:?}", pk.hex_dump()))?;
                }

                State(s) => f.write_fmt(format_args!("{s:?}"))?,

                Separator => (),

                RetryDelay(x) | Permissions(x) => {
                    f.write_fmt(format_args!("{x}"))?;
                }

                Flags(x) => f.write_fmt(format_args!("{x}"))?,
            }

            f.write_char('\n')?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::Map;
    use bytes::BytesMut;

    #[test]
    fn can_parse_state_and_public_key() {
        let bytes = [
            0x06, 0x01, 0x01, 0x03, 0x20, 0xf0, 0x0B, 0x71, 0x42, 0x70, 0x26, 0xe1, 0x7e, 0x23,
            0xed, 0x0a, 0x8b, 0x71, 0x17, 0x87, 0xa6, 0x79, 0x3d, 0x50, 0xd3, 0x21, 0x48, 0x4a,
            0xa6, 0x49, 0xac, 0xaa, 0x44, 0x26, 0x81, 0x9f, 0x38,
        ];

        let mut buf: BytesMut = BytesMut::with_capacity(bytes.len());
        buf.extend_from_slice(&bytes);

        let list = Map::try_from(buf);

        assert!(list.is_ok());

        let list = list.unwrap();

        println!("{list:?}");
    }

    #[test]
    fn can_encode_list() {
        use super::Val::{EncryptedData, Identifier, State};
        let mut list = Map::default();

        let mut ident = BytesMut::zeroed(511);
        ident.fill(0xa0u8);

        let mut data = BytesMut::zeroed(512);
        data.fill(0xb0u8);

        list.push(State(0x10u8));
        list.push(Identifier(ident.into()));
        list.push(EncryptedData(data.into()));

        let bytes = list.encode();

        assert!(!bytes.is_empty());
        assert_eq!(bytes.len(), 1038);

        let x = Map::try_from(bytes).ok();

        println!("{x:?}");
    }
}
