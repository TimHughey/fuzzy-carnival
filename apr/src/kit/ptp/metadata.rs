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

use super::consts;
use crate::Result;
use anyhow::anyhow;
use bytes::{Buf, BytesMut};
use std::ops::Shr;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(unused)]
pub enum Id {
    Sync,
    DelayReq,
    PdelayReq,
    PdelayResp,
    Reserved4,
    Reserved5,
    Reserved6,
    Reserved7,
    FollowUp,
    DelayResp,
    PdelayRespFollowUp,
    Announce,
    Signaling,
    Management,
    ReservedE,
    ReservedF,
    #[default]
    NotInterested,
}

impl TryFrom<u8> for Id {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        let value = value & consts::MASK_LOW;

        Ok(match value {
            0 => Self::Sync,
            1 => Self::DelayReq,
            2 => Self::PdelayReq,
            3 => Self::PdelayResp,
            4 => Self::Reserved4,
            5 => Self::Reserved5,
            6 => Self::Reserved6,
            7 => Self::Reserved7,
            8 => Self::FollowUp,
            9 => Self::DelayResp,
            10 => Self::PdelayRespFollowUp,
            11 => Self::Announce,
            12 => Self::Management,
            13 => Self::ReservedE,
            14 => Self::ReservedF,
            _ => Err(anyhow!("unknown msg type: 0x{value:x}"))?,
        })
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Data {
    pub(super) transport_specific: u8, // high four bits of byte 0
    pub(super) msg_id: Id,             // low four bits of byte 0
    pub(super) reserved: u8,           // high four bits of byte 1
    pub(super) version: u8,            // low four bits of byte 1
    pub(super) len: u16,               // entire message length (header, body, suffix)
}

#[allow(unused)]
impl Data {
    #[inline]
    pub fn buf_size_of() -> usize {
        use std::mem::size_of;

        size_of::<u8>() * 2 + size_of::<u16>()
    }

    #[inline]
    fn check_version(self) -> bool {
        self.version == 2u8
    }

    #[inline]
    pub fn is_src_ready(self, src: &BytesMut) -> bool {
        src.len() >= (self.len as usize)
    }

    /// Attempt to create [Data] from an immutable slice.
    ///
    /// Return Ok(None) to signal additional bytes are required.
    ///
    /// # Errors
    ///
    /// This function will return an error if the message id (aka type)
    /// isn't recognized.
    pub fn new_from_slice(src: &[u8]) -> Result<Option<Self>> {
        use std::io::Cursor;

        // insufficient number of bytes to create metadata
        if src.len() < Self::buf_size_of() {
            return Ok(None);
        }

        // make a copy of the first four bytes to peek at
        let mut cursor = Cursor::new(src);
        let byte_0 = cursor.get_u8();
        let byte_1 = cursor.get_u8();
        let len = cursor.get_u16();

        // construct Self with a possible Err for unknown msg_id (aka type)
        let md = Self {
            transport_specific: (byte_0 & consts::MASK_HIGH).shr(4),
            msg_id: Id::try_from(byte_0)?,
            reserved: (byte_1 & consts::MASK_HIGH).shr(4),
            version: (byte_1 & consts::MASK_LOW),
            len,
        };

        // return the created metadata if the version is correct
        if md.check_version() {
            // consume the bytes we used to create the metadata
            return Ok(Some(md));
        }

        // version check failed, return Err
        let error = "incorrect message version";
        tracing::error!("{error}: {} != 0x02", md.version);
        Err(anyhow!(error))
    }

    #[inline]
    pub fn split_bytes(self) -> usize {
        self.len as usize
    }
}

impl std::fmt::Debug for Data {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#?} len={}", self.msg_id, self.len)?;

        if !self.check_version() {
            write!(f, " [INVALID VERSION={}]", self.version)?;
        }

        Ok(())
    }
}
