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

use bytes::{Buf, Bytes, BytesMut};
use pretty_hex::{HexConfig, PrettyHex};

pub mod ieee8021_as {
    use bytes::{Buf, BytesMut};

    #[derive(Default, Debug, Clone)]
    pub struct FollowUpInfo {
        // The value of cumulativeScaledRateOffset is equal to (rateRatio – 1.0) * (2^41),
        // truncated to the next smaller signed integer, where rateRatio is the
        // ratio of the frequency of the Grandmaster Clock to the frequency of the
        // LocalClock entity in the PTP Instance that sends the message.
        //
        // NOTE: The above scaling allows the representation of fractional frequency offsets
        // in the range [–(2^–10 – 2^–41), 2^–10 –2^–41], with granularity of 2^41.
        // This range is approximately [–9.766 * 10^–4, 9.766 * 10^–4].
        pub cumulative_scaled_rate_offset: i32,

        // The value of gmTimeBaseIndicator is the timeBaseIndicator of
        // the ClockSource entity for the current Grandmaster PTP Instance (see 9.2.2.3).
        pub gm_time_base_indicator: u16,

        // The value of lastGmPhaseChange is the time of the current
        // Grandmaster Clock minus the time of the previous Grandmaster
        // Clock, at the time that the current Grandmaster PTP Instance became the
        // Grandmaster PTP Instance. The value is copied from the
        // lastGmPhaseChange member of the MDSyncSend structure whose receipt
        // causes the MD entity to send the Follow_Up message (see 11.2.11).
        pub last_gm_phase_change: [u8; 12],

        // The value of scaledLastGmFreqChange is the fractional frequency offset of the
        // current Grandmaster Clock relative to the previous Grandmaster Clock, at the
        // time that the current Grandmaster PTP Instance became the Grandmaster PTP Instance,
        // or relative to itself prior to the last change in gmTimeBaseIndicator,
        // multiplied by 241 and truncated to the next smaller signed integer.
        // The value is obtained by multiplying the lastGmFreqChange member of
        // MDSyncSend whose receipt causes the MD entity to send the
        // Follow_Up message (see 11.2.11) by 241, and truncating to the
        // next smaller signed integer.
        //
        // NOTE The above scaling allows the representation of fractional frequency offsets
        // in the range [–(2^–10 – 2^–41), 2^–10 – 2^–41], with granularity of 2^-41.
        // This range is approximately [–9.766 * 10^–4, 9.766 * 10^–4].
        pub scaled_last_gm_freq_change: i32,
    }

    impl FollowUpInfo {
        pub fn new_from_buf(buf: &mut BytesMut) -> Self {
            Self {
                cumulative_scaled_rate_offset: buf.get_i32(),
                gm_time_base_indicator: buf.get_u16(),
                last_gm_phase_change: {
                    let mut dst = [0u8; 12];
                    let src = buf.split_to(dst.len());
                    dst.copy_from_slice(&src);
                    dst
                },
                scaled_last_gm_freq_change: buf.get_i32(),
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Reserved(u16),
    // Standard TLVs
    Management,
    ManagementErrorStatus,
    OrganizationExtension,
    OrganizationExtensionPropagate,
    OrganizationExtensionDoNotPropagate,
    EnhancedAccuracyMetrics,
    RequestUnicastTransmission,
    GrantUnicastTransmission,
    CancelUnicastTransmission,
    AcknowledgeCancelUnicastTransmission,
    PathTrace,
    AlternateTimeOffsetIndicator,
    L1Sync,
    PortCommunicationAvailable,
    ProtocolAddress,
    SlaveRxSyncTimingData,
    SlaveRxSyncComputedData,
    SlaveTxEventTimestamps,
    CumulativeRateRatio,
    Pad,
    Authentication,
    Deprecated(u16),
    Experimental(u16),
}

impl Type {
    pub fn new_from_buf(buf: &mut BytesMut) -> Self {
        match buf.get_u16() {
            0x0001 => Type::Management,
            0x0002 => Type::ManagementErrorStatus,
            0x0003 => Type::OrganizationExtension,
            0x0004 => Type::RequestUnicastTransmission,
            0x0005 => Type::GrantUnicastTransmission,
            0x0006 => Type::CancelUnicastTransmission,
            0x0007 => Type::AcknowledgeCancelUnicastTransmission,
            0x0008 => Type::PathTrace,
            0x0009 => Type::AlternateTimeOffsetIndicator,
            0x4000 => Type::OrganizationExtensionPropagate,
            0x4001 => Type::EnhancedAccuracyMetrics,
            0x8000 => Type::OrganizationExtensionDoNotPropagate,
            0x8001 => Type::L1Sync,
            0x8002 => Type::PortCommunicationAvailable,
            0x8003 => Type::ProtocolAddress,
            0x8004 => Type::SlaveRxSyncTimingData,
            0x8005 => Type::SlaveRxSyncComputedData,
            0x8006 => Type::SlaveTxEventTimestamps,
            0x8007 => Type::CumulativeRateRatio,
            0x8008 => Type::Pad,
            0x8009 => Type::Authentication,
            v if (0x2000..0x2003).contains(&v) => Type::Deprecated(v),
            v if (0x2004..0x202f).contains(&v) => Type::Experimental(v),
            v if (0x7000..0x7fff).contains(&v) => Type::Experimental(v),
            v => Type::Reserved(v),
        }
    }
}

impl std::default::Default for Type {
    fn default() -> Self {
        Self::Reserved(0)
    }
}

impl std::fmt::Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone)]
pub enum Value {
    NoData {
        id: Type,
    },
    PathTrace {
        sequence: Bytes,
    },
    OrganizationExtension {
        id: Bytes,
        sub_type: Bytes,
        data: Bytes,
    },
    FollowUpInfo(ieee8021_as::FollowUpInfo),
}

impl Value {
    pub fn new_from_buf(buf: &mut BytesMut) -> Self {
        let id = Type::new_from_buf(buf);
        let len = buf.get_u16() as usize;

        match id {
            Type::PathTrace => Value::PathTrace {
                sequence: buf.copy_to_bytes(len),
            },
            Type::OrganizationExtension => {
                let org_id = buf.split_to(3);
                let sub_type = buf.split_to(3);
                let mut data = buf.split_to(len - org_id.len() - sub_type.len());

                match (&org_id[..], &sub_type[..]) {
                    ([0x00, 0x80, 0xc2], [0x00, 0x00, 0x01]) => {
                        Value::FollowUpInfo(ieee8021_as::FollowUpInfo::new_from_buf(&mut data))
                    }
                    (_, _) => Value::OrganizationExtension {
                        id: org_id.freeze(),
                        sub_type: sub_type.freeze(),
                        data: data.freeze(),
                    },
                }
            }

            _ => {
                // discard bytes
                buf.advance(len);
                Value::NoData { id }
            }
        }
    }
}

impl std::fmt::Debug for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cfg = HexConfig {
            title: false,
            ascii: false,
            width: 8,
            group: 0,
            ..HexConfig::default()
        };

        match self {
            Value::NoData { id } => f.debug_struct("NoData").field("id", id).finish(),
            Value::PathTrace { sequence } => f
                .debug_struct("PathTrace")
                .field("sequence", &format_args!("{}", sequence.hex_conf(cfg)))
                .finish(),
            Value::OrganizationExtension { id, sub_type, data } => f
                .debug_struct("OrgaanizationExtension")
                .field("id", &format_args!("{}", id.hex_conf(cfg)))
                .field("sub_type", &format_args!("{}", sub_type.hex_conf(cfg)))
                .field("data", &format_args!("{}", data.hex_conf(cfg)))
                .finish(),
            Value::FollowUpInfo(info) => {
                f.debug_struct("FollowUpInfo").field("data", info).finish()
            }
        }
    }
}
