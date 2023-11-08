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

use super::{consts, metadata::Data as MetaData, Buf, BytesMut, ClockIdentity};
use crate::Result;
use anyhow::anyhow;

#[allow(unused)]
#[derive(Default)]
pub(super) struct Common {
    pub metadata: MetaData,
    pub domain_num: u8,
    pub reserved_b: u8,
    pub flags: u16,
    pub correction_field: u64,
    pub reserved_l: u32,
    pub clock_identity: ClockIdentity,
    pub source_port_id: u16,
    pub sequence_id: u16,
    pub control_field: u8,
    pub log_message_period: u8,
}

impl Common {
    #[allow(unused)]
    pub fn new(src: &mut BytesMut) -> Result<Self> {
        let mut buf = src.split();

        if buf.len() >= Self::size_of() {
            // we have enough bytes to build the header without an error

            let item = Self {
                metadata: MetaData::new2(&mut buf)?,
                domain_num: buf.get_u8(),
                reserved_b: buf.get_u8(),
                flags: buf.get_u16(),
                correction_field: buf.get_u64(),
                reserved_l: buf.get_u32(),
                clock_identity: ClockIdentity::new(&mut buf.split_to(ClockIdentity::size_of()))?,
                source_port_id: buf.get_u16(),
                sequence_id: buf.get_u16(),
                control_field: buf.get_u8(),
                log_message_period: buf.get_u8(),
            };

            src.unsplit(buf);

            return Ok(item);
        }

        Err(anyhow!("failed to build header"))
    }

    pub fn size_of() -> usize {
        *consts::HEADER_LEN
    }
}

impl std::fmt::Debug for Common {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // use super::consts::{MASK_HIGH, MASK_LOW};

        let flags = self.flags.to_be_bytes();

        fmt.debug_struct("Common")
            .field("kind", &self.metadata)
            .field("sequence_id", &self.sequence_id)
            .field("clock_identity", &self.clock_identity)
            .field("source_port", &self.source_port_id)
            .field("flags", &format_args!("{:08b} {:08b}", flags[0], flags[1]))
            .field(
                "control_field",
                &format_args!("{:#04x?}", &self.control_field),
            )
            .field("log_message_period", &self.log_message_period)
            .field("correction_field", &self.correction_field)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum Channel {
    Event,
    General,
}

impl std::fmt::Display for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Channel::Event => write!(f, "EVENT")?,
            Channel::General => write!(f, "GENERAL")?,
        }

        if f.alternate() {
            match self {
                Channel::Event => write!(f, "  ")?,
                Channel::General => (),
            }
        }

        Ok(())
    }
}
