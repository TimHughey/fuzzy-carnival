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
    clock::{GrandMaster, Timestamp},
    tlv, util, ClockIdentity, Epoch,
};
use crate::Result;
use bitflags::bitflags;
use bytes::{Buf, BufMut, BytesMut};
use pretty_hex::{HexConfig, PrettyHex};
use std::hash::{Hash, Hasher};
use time::{Duration, Instant};

#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum Channel {
    Event,
    General,
}

impl From<Channel> for u16 {
    fn from(value: Channel) -> Self {
        match value {
            Channel::Event => 319,
            Channel::General => 320,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MsgType {
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

impl MsgType {
    pub fn new(id: u8) -> Self {
        match util::nibble_low(id) {
            0x0 => MsgType::Sync,
            0x1 => MsgType::DelayReq,
            0x2 => MsgType::PdelayReq,
            0x3 => MsgType::PdelayResp,
            0x8 => MsgType::FollowUp,
            0x9 => MsgType::DelayResp,
            0xa => MsgType::PdelayRespFollowUp,
            0xb => MsgType::Announce,
            0xc => MsgType::Signaling,
            0xd => MsgType::Management,
            id => MsgType::Reserved(id),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MetaData {
    pub reception_time: Instant,
    pub transport_specific: u8, // high nibble of byte 0
    pub msg_type: MsgType,      // low nibble of byte 0
    pub _reserved: u8,          // high nibble of byte 1
    pub version: u8,            // low nibble of byte 1
    pub len: u16,               // entire message length (header, payload, suffix)
}

impl MetaData {
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

    /// Attempt to create [``MetaData``] from an immutable slice.
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
            reception_time: Epoch::reception_time(),
            transport_specific: util::nibble_high(byte_0),
            msg_type: MsgType::new(byte_0),
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
        Err(anyhow::anyhow!(error))
    }

    #[inline]
    pub fn split_bytes(self) -> usize {
        self.len as usize
    }
}

impl Hash for MetaData {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.msg_type.hash(state);
    }
}

bitflags! { // Message Flags
    // NOTE: the bit order below is deliberately different
    //       than the spec.  flags u16 is sent big-endian
    //
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MsgFlags: u16 {
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

impl MsgFlags {
    pub fn is_good_sync(self) -> bool {
        self == MsgFlags::UNICAST | MsgFlags::TWO_STEP | MsgFlags::PTP_TIMESCALE
    }
}

#[derive(Clone)]
pub struct Header {
    pub _domain_num: u8,
    pub _minor_sdo_id: u8,
    pub flags: MsgFlags,
    pub correction_field: Option<Duration>,
    pub _msg_type_specific: u32,
    pub source_port_identity: PortIdentity,
    pub sequence_id: u16,
    pub control_field: u8,
    pub log_message_interval: u8,
}

impl Header {
    #[allow(unused)]
    pub fn new(buf: &mut BytesMut) -> Self {
        // NOTE:  this function assumes the buf has available bytes to create the header

        Self {
            _domain_num: buf.get_u8(),
            _minor_sdo_id: buf.get_u8(),
            // NOTE: must get as native-endian to match bitflags
            //       haven't taken the time to decipher why... someday...
            flags: MsgFlags::from_bits_retain(buf.get_u16_ne()),
            // NOTE: PTP value is multiplied by 2^16 (65536)
            correction_field: {
                let nanoseconds: i32 = (buf.get_u64() / 65536).try_into().unwrap();
                let d = Duration::new(0, nanoseconds);
                // let d = Duration::from_nanos();

                if d > Duration::ZERO {
                    Some(d)
                } else {
                    None
                }
            },
            _msg_type_specific: buf.get_u32(),
            source_port_identity: PortIdentity::new_from_buf(buf),
            sequence_id: buf.get_u16(),
            control_field: buf.get_u8(),
            log_message_interval: buf.get_u8(),
        }
    }
}

#[derive(Clone)]
pub struct Message {
    pub metadata: MetaData,
    pub header: Header,
    pub payload: Payload,
    pub suffix: Option<Suffix>, // captured for potential future needs
}

impl Message {
    /// Creates [Core] from a [``MetaData``] and a [``BytesMut``] containing
    /// sufficient available bytes.
    pub fn new_from_buf(metadata: MetaData, mut buf: BytesMut) -> Self {
        // NOTE: metadata previously created, skip those bytes
        buf.advance(MetaData::buf_size_of());

        let header = Header::new(&mut buf);
        let payload = Payload::new(metadata.msg_type, &mut buf);
        let suffix = Suffix::new_from_buf(&mut buf);

        if !buf.is_empty() {
            tracing::warn!(
                "{:?} incomplete buffer consumption\nUNUSED BUF {:?}",
                metadata.msg_type,
                buf.hex_dump()
            );
        }

        Self {
            metadata,
            header,
            payload,
            suffix,
        }
    }

    #[allow(unused)]
    pub fn get_type(&self) -> MsgType {
        self.metadata.msg_type
    }

    #[allow(unused)]
    pub fn match_msg_type(&self, msg_type: MsgType) -> bool {
        self.metadata.msg_type == msg_type
    }
}

#[derive(Default, Clone, Copy, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct PortIdentity {
    pub clock_identity: ClockIdentity,
    pub port: u16,
}

impl PortIdentity {
    pub fn new_from_buf(buf: &mut BytesMut) -> Self {
        Self {
            clock_identity: ClockIdentity::new_from_buf(buf),
            port: buf.get_u16(),
        }
    }

    pub fn new_from_buf_maybe(buf: &mut BytesMut) -> Option<Self> {
        let item = Self {
            clock_identity: ClockIdentity::new_from_buf(buf),
            port: buf.get_u16(),
        };

        if item > Self::default() {
            return Some(item);
        }

        None
    }

    pub fn new_local(id: &[u8], port: Option<u16>) -> Self {
        let mut buf = BytesMut::with_capacity(std::mem::size_of::<ClockIdentity>());

        buf.put(id); // this only represents six of the eight identity bytes
        buf.put_u16(0x11aa); // pad to create our "uniqueness"

        Self {
            clock_identity: ClockIdentity::new_from_buf(&mut buf),
            port: port.unwrap_or(0x90a1),
        }
    }
}

impl AsRef<PortIdentity> for PortIdentity {
    fn as_ref(&self) -> &PortIdentity {
        self
    }
}

#[derive(Default, Clone)]
pub enum Payload {
    Announce {
        origin_timestamp: Option<Timestamp>,
        current_utc_offset: u16,
        _reserved: u8,
        grandmaster: GrandMaster,
        steps_removed: u16,
        time_source: u8,
    },
    Sync {
        origin_timestamp: Option<Timestamp>,
    },
    FollowUp {
        precise_origin_timestamp: Option<Timestamp>,
    },
    Signaling {
        target_port_identity: Option<PortIdentity>,
    },
    Management {
        target_port_identity: PortIdentity,
        starting_boundary_hops: u8,
        boundary_hops: u8,
        action_field: u8,
        _reserved: u8,
    },
    #[default]
    Empty,
}

impl Payload {
    pub fn new(msg_type: MsgType, buf: &mut BytesMut) -> Self {
        match msg_type {
            MsgType::Announce => Payload::Announce {
                origin_timestamp: Timestamp::new_from_buf(buf),
                current_utc_offset: buf.get_u16(),
                _reserved: buf.get_u8(),
                grandmaster: GrandMaster::new_from_buf(buf),
                steps_removed: buf.get_u16(),
                time_source: buf.get_u8(),
            },
            MsgType::Sync => Payload::Sync {
                origin_timestamp: Timestamp::new_from_buf(buf),
            },
            MsgType::FollowUp => Payload::FollowUp {
                precise_origin_timestamp: Timestamp::new_from_buf(buf),
            },
            MsgType::Signaling => Payload::Signaling {
                target_port_identity: PortIdentity::new_from_buf_maybe(buf),
            },
            MsgType::Management => Payload::Management {
                target_port_identity: PortIdentity::new_from_buf(buf),
                starting_boundary_hops: buf.get_u8(),
                boundary_hops: buf.get_u8(),
                action_field: buf.get_u8(),
                _reserved: buf.get_u8(),
            },

            _id => Payload::Empty,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Suffix {
    _tlvs: Vec<tlv::Value>,
}

impl Suffix {
    pub fn new_from_buf(buf: &mut BytesMut) -> Option<Self> {
        if buf.len() <= 4 {
            return None;
        }

        let mut tlvs: Vec<tlv::Value> = Vec::new();
        while buf.len() >= 5 {
            tlvs.push(tlv::Value::new_from_buf(buf));
        }

        Some(Suffix { _tlvs: tlvs })
    }
}

impl std::fmt::Debug for Header {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("Header")
            .field("sequence_id", &self.sequence_id)
            .field("source_port_identity", &self.source_port_identity)
            .field("flags", &self.flags)
            .field(
                "control_field",
                &format_args!("{:#04x?}", &self.control_field),
            )
            .field(
                "log_message_interval",
                &format_args!("0x{:02x}", &self.log_message_interval),
            )
            .field("correction_field", &self.correction_field)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Message {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = format!("PTP {:?}", self.metadata.msg_type);

        if matches!(
            self.metadata.msg_type,
            MsgType::Announce | MsgType::Signaling | MsgType::Sync | MsgType::FollowUp
        ) {
            fmt.debug_struct(name.as_str())
                .field("metadata", &self.metadata)
                .field("header", &self.header)
                .field("payload", &self.payload)
                .field("suffix", &self.suffix)
                .finish()
        } else {
            fmt.debug_struct("PTP")
                .field("metadata", &self.metadata)
                .field("header", &self.header)
                .field("payload", &self.payload)
                .finish_non_exhaustive()
        }
    }
}

impl std::fmt::Debug for MetaData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetaData")
            .field("msg_type", &self.msg_type)
            .field("len", &self.len)
            .field(
                "reception_time",
                &format_args!("{:?}", Epoch::local_time(&self.reception_time)),
            )
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for PortIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cfg = HexConfig {
            title: false,
            ascii: false,
            width: 2,
            group: 0,
            ..HexConfig::default()
        };

        f.debug_struct("PortIdentity")
            .field("clock_identity", &self.clock_identity)
            .field(
                "port",
                &format_args!("{}", self.port.to_be_bytes().hex_conf(cfg)),
            )
            .finish()
    }
}

impl std::fmt::Debug for Payload {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Payload::Announce {
                origin_timestamp,
                current_utc_offset,
                grandmaster,
                steps_removed,
                time_source,
                ..
            } => fmt
                .debug_struct("Announce")
                .field("origin_timestamp", origin_timestamp)
                .field("current_utc_offset", current_utc_offset)
                .field("grandmaster", grandmaster)
                .field("steps_removed", steps_removed)
                .field("time_source", &format_args!("0x{time_source:x}"))
                .finish(),

            Payload::Sync { origin_timestamp } => fmt
                .debug_struct("Sync")
                .field("origin_timestamp", origin_timestamp)
                .finish(),

            Payload::FollowUp {
                precise_origin_timestamp,
            } => fmt
                .debug_struct("FollowUp")
                .field("precise_origin_timestamp", precise_origin_timestamp)
                .finish(),

            Payload::Signaling {
                target_port_identity,
            } => fmt
                .debug_struct("Signaling")
                .field("target_port_identity", target_port_identity)
                .finish(),
            Self::Management {
                target_port_identity,
                starting_boundary_hops,
                boundary_hops,
                action_field,
                _reserved,
            } => fmt
                .debug_struct("Management")
                .field("target_port", target_port_identity)
                .field("starting_boundary_hops", starting_boundary_hops)
                .field("boundary_hops", boundary_hops)
                .field("action_field", action_field)
                .finish(),

            Self::Empty => fmt.debug_struct("Empty").finish(),
        }
    }
}
