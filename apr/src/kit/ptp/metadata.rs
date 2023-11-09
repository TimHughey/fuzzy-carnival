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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(unused)]
pub enum Id {
    Sync,
    DelayReq,
    PdelayReq,
    PdelayResp,
    FollowUp,
    DelayResp,
    PdelayRespFollowUp,
    Announce,
    Signaling,
    Management,
    Reserved(u8),
}

impl Id {
    pub fn new(id: u8) -> Self {
        match id & consts::MASK_LOW {
            0x0 => Id::Sync,
            0x1 => Id::DelayReq,
            0x2 => Id::PdelayReq,
            0x3 => Id::PdelayResp,
            0x8 => Id::FollowUp,
            0x9 => Id::DelayResp,
            0xa => Id::PdelayRespFollowUp,
            0xb => Id::Announce,
            0xc => Id::Signaling,
            0xd => Id::Management,
            id => Id::Reserved(id),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Data {
    pub(super) transport_specific: u8, // high nibble of byte 0
    pub(super) msg_id: Id,             // low nibble of byte 0
    pub(super) reserved: u8,           // high nibble of byte 1
    pub(super) version: u8,            // low nibble of byte 1
    pub(super) len: u16,               // entire message length (header, payload, suffix)
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
    /// This function will not consume bytes from the buffer
    /// so it may be used to determine if the complete message
    /// is available.
    ///
    /// Return Ok(None) to signal additional bytes are required.
    ///
    /// # Errors
    ///
    /// This function will return an error if the message version
    /// is not v2
    pub fn new_from_slice(src: &[u8]) -> Result<Option<Self>> {
        use std::io::Cursor;

        // insufficient number of bytes to create metadata
        if src.len() < Self::buf_size_of() {
            return Ok(None);
        }

        // use a basic Cursor to get values without consuming
        let mut cursor = Cursor::new(src);
        let byte_0 = cursor.get_u8();
        let byte_1 = cursor.get_u8();
        let len = cursor.get_u16();

        // construct Self with a possible Err for unknown msg_id (aka type)
        let md = Self {
            transport_specific: (byte_0 & consts::MASK_HIGH).shr(4),
            msg_id: Id::new(byte_0),
            reserved: (byte_1 & consts::MASK_HIGH).shr(4),
            version: (byte_1 & consts::MASK_LOW),
            len,
        };

        // return the created metadata if the version is correct
        if md.check_version() {
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
