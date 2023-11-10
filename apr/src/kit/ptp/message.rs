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
    header::Common,
    protocol::{Payload, Suffix},
    MetaData, MsgId,
};
use bytes::{Buf, BytesMut};
use pretty_hex::PrettyHex;
use std::net::SocketAddr;

pub struct Core {
    header: Common,
    payload: Payload,
    _suffix: Option<Suffix>, // captured for potential future needs
    sock_addr: Option<SocketAddr>,
}

impl Core {
    /// Creates [Core] from a [``MetaData``] and a [``BytesMut``] containing
    /// sufficient available bytes.

    pub fn new_from_buf(metadata: MetaData, mut buf: BytesMut) -> Self {
        // NOTE: metadata previously created, skip those bytes
        buf.advance(MetaData::buf_size_of());

        let header = Common::new_with_metadata(metadata, &mut buf);
        let payload = Payload::new(metadata.msg_id, &mut buf);
        let suffix = Suffix::new_from_buf(&mut buf);

        if !buf.is_empty() {
            tracing::warn!(
                "{:?} incomplete buffer consumption\nUNUSED BUF {:?}",
                metadata.msg_id,
                buf.hex_dump()
            );
        }

        Self {
            header,
            payload,
            _suffix: suffix,
            sock_addr: None,
        }
    }

    #[allow(unused)]
    pub fn get_type(&self) -> super::metadata::Id {
        self.header.metadata.msg_id
    }

    pub fn match_msg_id(&self, msg_id: MsgId) -> bool {
        self.header.metadata.msg_id == msg_id
    }

    pub fn save_sockaddr(&mut self, addr: SocketAddr) {
        self.sock_addr.get_or_insert(addr);
    }
}

impl std::fmt::Debug for Core {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("PTP")
            .field("header", &self.header)
            .field("payload", &self.payload)
            //.field("SUFFIX", &self.suffix)
            .field("from_addr", &self.sock_addr)
            .finish_non_exhaustive()
    }
}
