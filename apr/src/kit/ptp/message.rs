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
use bytes::BytesMut;

pub(super) use super::{header::Common, protocol::Payload};

#[allow(unused)]
#[derive(Default, Debug)]
pub struct Inflight {
    header: Option<Common>,
    payload: Option<Payload>,
}

#[allow(unused)]
#[derive(Default)]
pub struct Core {
    header: Common,
    payload: Payload,
}

impl Core {
    #[allow(unused)]
    pub fn new(src: &mut BytesMut) -> Result<Self> {
        let mut buf = src.split();

        let header = Common::new(&mut buf)?;
        let payload = Payload::new2(header.metadata.msg_id, &mut buf)?;

        src.unsplit(buf);

        Ok(Self { header, payload })
    }

    #[allow(unused)]
    pub fn get_type(&self) -> super::metadata::Id {
        self.header.metadata.msg_id
    }

    #[cfg(test)]
    pub fn min_bytes() -> usize {
        Common::size_of()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.header.metadata.len as usize
    }
}

impl std::fmt::Display for Core {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MESSAGE ")?;

        write!(f, "\n{:#?}", self.header)?;

        write!(f, "\n{}", self.payload)?;

        Ok(())
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
