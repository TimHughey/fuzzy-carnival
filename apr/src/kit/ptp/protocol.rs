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
    tlv, util, ClockIdentity, ClockTimestamp,
};
use bitflags::bitflags;
use bytes::{Buf, BytesMut};
use pretty_hex::{HexConfig, PrettyHex};
use std::hash::{Hash, Hasher};
use thiserror::Error;
use time::{Duration, Instant};

#[derive(Error, Debug)]
pub enum Error {
    #[error("version check failed")]
    WrongVersion { version: u8 },
    #[error("invalid flags: {flags:?}")]
    InvalidFlags { flags: MsgFlags },
    #[error("seq_id mismatch: {want} != {have}")]
    SeqIdMismatch { want: u16, have: u16 },
    #[error("unhandled msg_id: {msg_id:?}")]
    UnhandledMsg { msg_id: MsgType },
    #[error("unreasonable log_message_interval: {log_message_interval}")]
    UnreasonableLogMessageInterval { log_message_interval: i8 },
    #[error("net clock peer failed: {addr} {port}")]
    InvalidClockNetPeer { addr: String, port: u64 },
}

type MetaDataResult = std::result::Result<Option<MetaData>, Error>;

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
    pub channel: Channel,
    pub reception_timestamp: ClockTimestamp,
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
    pub fn is_src_ready(self, src: &BytesMut) -> bool {
        src.len() >= (self.len as usize)
    }

    /// Attempt to create [``MetaData2``] from an immutable slice.
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
    pub fn new_from_slice(src: &[u8], channel: Channel) -> MetaDataResult {
        use std::io::Cursor;

        // insufficient number of bytes to create metadata
        if src.len() < Self::buf_size_of() {
            return Ok(None);
        }

        // use a basic Cursor to get values without consuming
        let mut cursor = Cursor::new(src);
        let byte_0 = cursor.get_u8();
        let byte_1 = cursor.get_u8();

        // have byte_1 so we can check version early and return Error on mismatch
        let version = check_version(byte_1)?;

        let len = cursor.get_u16();

        // construct Self with a possible Err for unknown msg_id (aka type)
        Ok(Some(Self {
            channel,
            reception_timestamp: ClockTimestamp::now(),
            transport_specific: util::nibble_high(byte_0),
            msg_type: MsgType::new(byte_0),
            _reserved: util::nibble_high(byte_1),
            version,
            len,
        }))
    }

    #[inline]
    pub fn split_bytes(self) -> usize {
        self.len as usize
    }
}

#[inline]
fn check_version(byte: u8) -> std::result::Result<u8, Error> {
    let version = util::nibble_low(byte);

    match version {
        0x02 => Ok(version),
        version => Err(Error::WrongVersion { version }),
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
    pub fn is_good_sync(mut self) -> bool {
        self.remove(MsgFlags::PTP_TIMESCALE);

        self == MsgFlags::UNICAST | MsgFlags::TWO_STEP
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
    pub log_message_interval: i8,
}

impl Header {
    #[allow(unused)]
    pub fn new(buf: &mut BytesMut) -> Self {
        /// NOTE:  this function assumes the buf has available bytes to create the header
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
            log_message_interval: buf.get_i8(),
        }
    }

    pub fn correction_field(&self) -> Option<Duration> {
        self.correction_field
    }

    pub fn flags(&self) -> MsgFlags {
        self.flags
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Common {
    pub channel: Channel,
    pub ingress_at: Instant,
    pub ingress_timestamp: ClockTimestamp,
    pub seq_id: u16,
    pub msg_id: MsgType,
    pub source_port_identity: PortIdentity,
}

impl Common {
    pub fn new(metadata: &MetaData, header: &Header) -> Self {
        Self {
            ingress_at: Instant::now(),
            channel: metadata.channel,
            ingress_timestamp: metadata.reception_timestamp,
            seq_id: header.sequence_id,
            msg_id: metadata.msg_type,
            source_port_identity: header.source_port_identity,
        }
    }

    pub fn interval(&self, latest: &Self) -> Duration {
        let e_latest = latest.ingress_timestamp.into_inner();
        let e_arrival = self.ingress_timestamp.into_inner();

        e_arrival - e_latest
    }

    #[inline]
    pub fn msg_id(&self) -> MsgType {
        self.msg_id
    }

    #[inline]
    pub fn offset(&self, precise: ClockTimestamp, correction: Duration) -> Duration {
        self.ingress_timestamp.into_inner() - precise.into_inner() - correction
    }

    #[inline]
    pub fn seq_variance(&self, latest: &Self) -> Option<u16> {
        latest.seq_id.checked_sub(self.seq_id)
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
}

impl AsRef<PortIdentity> for PortIdentity {
    fn as_ref(&self) -> &PortIdentity {
        self
    }
}

#[derive(Debug, Clone)]
pub struct AnnounceData {
    pub common: Common,
    pub origin_timestamp: Option<Timestamp>,
    pub steps_removed: u16,
    pub time_source: u8,
    pub log_message_interval: Duration,
    pub grandmaster: GrandMaster,
}

#[derive(Debug, Clone)]
pub struct FollowUpData {
    pub common: Common,
    pub correction: Option<Duration>,
    pub origin_timestamp: Option<Timestamp>,
}

#[derive(Debug, Clone)]
pub struct SyncData {
    pub common: Common,
    pub flags: MsgFlags,
    pub correction: Option<Duration>,
    pub origin_timestamp: Option<Timestamp>,
}

type PayloadResult = std::result::Result<Payload, Error>;

#[derive(Debug, Clone)]
pub enum Payload {
    Announce(AnnounceData),
    FollowUp(FollowUpData),
    Sync(SyncData),
    Discard(Common),
}

impl Payload {
    pub fn get_common(&self) -> &Common {
        match self {
            Payload::Announce(data) => &data.common,
            Payload::Sync(data) => &data.common,
            Payload::FollowUp(data) => &data.common,
            Payload::Discard(common) => common,
        }
    }

    pub fn port_identity(&self) -> PortIdentity {
        self.get_common().source_port_identity
    }

    pub fn try_new(metadata: MetaData, mut buf: BytesMut) -> PayloadResult {
        // NOTE: metadata previously created, skip those bytes
        buf.advance(MetaData::buf_size_of());

        // build the header (from buf)
        let header = Header::new(&mut buf);

        // build Common from header
        let common = Common::new(&metadata, &header);

        // build payload from buf
        let payload = match common.msg_id() {
            MsgType::Announce => {
                // pluck all bytes from the buffer then validate to ensure
                // we only hand-off Announce payloads that can be processed
                let origin_timestamp = Timestamp::new_from_buf(&mut buf);
                let _current_utc_offset = buf.get_u16();
                let _reserved = buf.get_u8();
                let grandmaster = GrandMaster::new_from_buf(&mut buf);
                let steps_removed = buf.get_u16();
                let time_source = buf.get_u8();
                let log_message_interval = header.log_message_interval;

                // interval is represented as log2 of seconds.  here we convert that
                // representation to millseconds
                let log_message_interval =
                    Duration::milliseconds(match header.log_message_interval {
                        n if (..-4).contains(&n) => {
                            return Err(Error::UnreasonableLogMessageInterval {
                                log_message_interval,
                            });
                        }
                        n if n < 0 => 1000 >> n.abs(),
                        n if n > 0 => 1000 << n.abs(),
                        _n => 1000,
                    });

                Ok(Payload::Announce(AnnounceData {
                    common,
                    origin_timestamp,
                    steps_removed,
                    time_source,
                    log_message_interval,
                    grandmaster,
                }))
            }
            MsgType::FollowUp => {
                // the body is the same as IEEE 1588-2019 (just the preciseOriginTimestamp)
                let origin_timestamp = Timestamp::new_from_buf(&mut buf);

                // now parse the suffix
                //
                // IEEE 8021AS-2020 spec alters the definition of FollowUp
                // messages and includes specific TLVs.
                //
                // NOTE: as of 2023-11-23 it is unclear if the above is relevant. a specialized
                //       TLV is included however all components are zeroed
                //
                // called for side effects
                let _suffix = Suffix::new_from_buf(&mut buf);

                Ok(Payload::FollowUp(FollowUpData {
                    common,
                    correction: header.correction_field(),
                    origin_timestamp,
                }))
            }
            MsgType::Sync => Ok(Payload::Sync(SyncData {
                common,
                flags: header.flags(),
                correction: header.correction_field(),
                origin_timestamp: Timestamp::new_from_buf(&mut buf),
            })),

            MsgType::Management => {
                let _target_port_identity = PortIdentity::new_from_buf(&mut buf);
                let _starting_boundary_hops = buf.get_u8();
                let _boundary_hops = buf.get_u8();
                let _action_fiel = buf.get_u8();
                let _reserved = buf.get_u8();

                Ok(Payload::Discard(common))
            }
            MsgType::Signaling => {
                let target_port_identity = PortIdentity::new_from_buf_maybe(&mut buf);

                if let Some(tpi) = target_port_identity {
                    let suffix = Suffix::new_from_buf(&mut buf);

                    tracing::info!("signaling: {tpi}\n{suffix:#?}");
                }

                Ok(Payload::Discard(common))
            }

            MsgType::DelayReq
            | MsgType::DelayResp
            | MsgType::PdelayReq
            | MsgType::PdelayResp
            | MsgType::PdelayRespFollowUp
            | MsgType::Reserved(_) => Err(Error::UnhandledMsg {
                msg_id: common.msg_id,
            }),
        }?;

        if !buf.is_empty() {
            let _suffix = Suffix::new_from_buf(&mut buf);
        }

        Ok(payload)
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

impl std::fmt::Display for PortIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let port = self.port.to_be_bytes();

        write!(f, "{}-{:02x}-{:02x}", self.clock_identity, port[0], port[1])
    }
}
