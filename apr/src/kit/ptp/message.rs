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

pub(super) use super::{header::Common, protocol::Payload, MetaData};
use bytes::{Buf, BytesMut};

#[derive(Default)]
pub struct Core {
    header: Common,
    payload: Payload,
}

impl Core {
    /// Creates [Core] from a [``MetaData``] and a [``BytesMut``] containing previously
    /// confirmed available bytes.
    ///
    /// # Errors
    ///
    /// This function will return an error if [Payload] creation fails.
    pub(super) fn new_from_buf(metadata: MetaData, mut buf: BytesMut) -> Self {
        // NOTE: metadata previously created, skip those bytes
        buf.advance(MetaData::buf_size_of());

        Self {
            header: Common::new_with_metadata(metadata, &mut buf),
            // consume the remaining bytes via split() and pass a
            // BytesMut to Payload to avoid additional splits downstream
            payload: Payload::new(metadata.msg_id, buf.split()),
        }
    }

    #[allow(unused)]
    pub fn get_type(&self) -> super::metadata::Id {
        self.header.metadata.msg_id
    }
}

impl std::fmt::Debug for Core {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("PTP MESSAGE")
            .field("HEADER", &self.header)
            .field("PAYLOAD", &self.payload)
            .finish()
    }
}
