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

use super::{clock, util};
use crate::Result;
use anyhow::anyhow;
use bytes::{Buf, BytesMut};
use std::time;

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
        match util::nibble_low(id) {
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
pub struct Data {
    pub reception_time: time::Duration,
    pub transport_specific: u8, // high nibble of byte 0
    pub msg_id: Id,             // low nibble of byte 0
    pub _reserved: u8,          // high nibble of byte 1
    pub version: u8,            // low nibble of byte 1
    pub len: u16,               // entire message length (header, payload, suffix)
}

impl Data {
    #[inline]
    pub fn buf_size_of() -> usize {
        std::mem::size_of::<u8>() * 2 + std::mem::size_of::<u16>()
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
            reception_time: clock::Epoch::reception_time(),
            transport_specific: util::nibble_high(byte_0),
            msg_id: Id::new(byte_0),
            _reserved: util::nibble_high(byte_1),
            version: util::nibble_low(byte_1),
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
        f.debug_struct("Data")
            .field("type", &self.msg_id)
            .field("reception_time", &self.reception_time)
            .finish()
    }
}
