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
}

impl Value {
    pub fn new_from_buf(buf: &mut BytesMut) -> Self {
        let id = Type::new_from_buf(buf);
        let len = buf.get_u16() as usize;

        match id {
            Type::PathTrace => Value::PathTrace {
                sequence: buf.copy_to_bytes(len),
            },
            Type::OrganizationExtension => Value::OrganizationExtension {
                id: buf.copy_to_bytes(3),
                sub_type: buf.copy_to_bytes(3),
                data: buf.copy_to_bytes(len - 6),
            },

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
        }
    }
}
