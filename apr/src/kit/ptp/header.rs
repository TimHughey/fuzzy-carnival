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

use super::{ClockIdentity, MetaData};
use bitflags::bitflags;
use bytes::{Buf, BytesMut};
use std::time;

bitflags! {
    // NOTE: the bit order below is deliberately different
    //       than the spec.  flags u16 is sent big-endian
    //
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Flags: u16 {
        // bit ordering exactly matches IEEE 1588-2019 (Table 37)
        // MSB
        const ALTERNATE_MASTER = 0b01 << 0;
        const TWO_STEP = 0b01 << 1;
        const UNICAST = 0b01 << 2;
        const PROFILE_SPECIFIC_1 = 0b01 << 3;
        const PROFILE_SPECIFIC_2 = 0b01 << 4;
        const RESERVED = 0b01 << 5;

        // LSB
        const LEAP_61 = 0b01 << 8;
        const LEAP_59 = 0b01 << 9;
        const CURRENT_OFFSET_VALID =  0b01 << 10;
        const PTP_TIMESCALE = 0b01 << 11;
        const TIME_TRACEABLE = 0b01 << 12;
        const FREQUENCY_TRACEABLE = 0b01 << 13;
        const SYNCRONIZATON_UNCERTAIN = 0b01 << 14;
        const UNASSIGNED = 0b01 << 15;

        const _ = !0; // allow all bits to be set
    }
}

pub struct Common {
    pub metadata: MetaData,
    pub _domain_num: u8,
    pub _reserved_b: u8,
    pub flags: Flags,
    pub correction_field: Option<time::Duration>,
    pub _reserved_l: u32,
    pub clock_identity: ClockIdentity,
    pub source_port_id: u16,
    pub sequence_id: u16,
    pub control_field: u8,
    pub log_message_period: u8,
}

impl Common {
    #[allow(unused)]
    pub fn new_with_metadata(metadata: MetaData, buf: &mut BytesMut) -> Self {
        // NOTE:  this function assumes the buf has available bytes to create the header

        Self {
            metadata,
            _domain_num: buf.get_u8(),
            _reserved_b: buf.get_u8(),
            // NOTE: must get as native-endian to match bitflags
            //       haven't taken the time to decipher why... someday...
            flags: Flags::from_bits_retain(buf.get_u16_ne()),
            // NOTE: PTP value is multiplied by 2^16 (65536)
            correction_field: {
                let d = time::Duration::from_nanos(buf.get_u64() / 65536);

                if d > time::Duration::ZERO {
                    Some(d)
                } else {
                    None
                }
            },
            _reserved_l: buf.get_u32(),
            clock_identity: ClockIdentity::new_from_buf(buf),
            source_port_id: buf.get_u16(),
            sequence_id: buf.get_u16(),
            control_field: buf.get_u8(),
            log_message_period: buf.get_u8(),
        }
    }
}

impl std::fmt::Debug for Common {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("Common")
            .field("metadata", &self.metadata)
            .field("sequence_id", &self.sequence_id)
            .field("clock_identity", &self.clock_identity)
            .field("source_port", &self.source_port_id)
            .field("flags", &self.flags)
            .field(
                "control_field",
                &format_args!("{:#04x?}", &self.control_field),
            )
            .field(
                "log_message_period",
                &format_args!("0x{:02x}", &self.log_message_period),
            )
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
