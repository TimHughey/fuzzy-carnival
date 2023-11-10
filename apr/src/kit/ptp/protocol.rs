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
    clock::{self, GrandMaster, Timestamp},
    metadata::Id,
    tlv,
};
use bytes::{Buf, BytesMut};

#[derive(Default)]
pub struct PortIdentity {
    clock_identity: clock::Identity,
    port: u16,
}

impl PortIdentity {
    pub fn new(buf: &mut BytesMut) -> Self {
        Self {
            clock_identity: clock::Identity::new_from_buf(buf),
            port: buf.get_u16(),
        }
    }
}

impl std::fmt::Debug for PortIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortIdentity")
            .field("clock_identity", &self.clock_identity)
            .field("port", &self.port)
            .finish()
    }
}

#[derive(Default)]
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
        target_port_identity: PortIdentity,
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
    pub fn new(id: Id, buf: &mut BytesMut) -> Self {
        match id {
            Id::Announce => Payload::Announce {
                origin_timestamp: Timestamp::new_from_buf(buf),
                current_utc_offset: buf.get_u16(),
                _reserved: buf.get_u8(),
                grandmaster: GrandMaster::new_from_buf(buf),
                steps_removed: buf.get_u16(),
                time_source: buf.get_u8(),
            },
            Id::Sync => Payload::Sync {
                origin_timestamp: Timestamp::new_from_buf(buf),
            },
            Id::FollowUp => Payload::FollowUp {
                precise_origin_timestamp: Timestamp::new_from_buf(buf),
            },
            Id::Signaling => Payload::Signaling {
                target_port_identity: PortIdentity::new(buf),
            },
            Id::Management => Payload::Management {
                target_port_identity: PortIdentity::new(buf),
                starting_boundary_hops: buf.get_u8(),
                boundary_hops: buf.get_u8(),
                action_field: buf.get_u8(),
                _reserved: buf.get_u8(),
            },

            _id => Payload::Empty,
        }
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
                .field("time_source", time_source)
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

#[derive(Debug, Default)]
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
