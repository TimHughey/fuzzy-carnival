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
    enums::tlv::TypeValue as TlvTypeVal,
    metadata::Id,
    Buf, Bytes, BytesMut,
};

use pretty_hex::{HexConfig, PrettyHex};

#[derive(Default)]
pub(super) struct PathTrace {
    tlv_type: TlvTypeVal,
    len: u16,
    sequence: Bytes,
}

impl std::fmt::Debug for PathTrace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cfg = HexConfig {
            title: false,
            ascii: false,
            width: 8,
            group: 0,
            ..HexConfig::default()
        };

        f.debug_struct("PathTrace")
            .field("type", &self.tlv_type)
            .field("len", &self.len)
            .field(
                "sequence",
                &format_args!("{}", &self.sequence.hex_conf(cfg)),
            )
            .finish()
    }
}

#[allow(unused)]
#[derive(Debug, Default)]
pub(super) struct Tlv {
    tlv_type: u16,
    len: u16,
    organization_id: [u8; 3],
    organization_sub_type: [u8; 3],
    data: Bytes,
}

#[derive(Default)]
pub(super) enum Payload {
    Announce {
        origin_timestamp: Timestamp,
        current_utc_offset: u16,
        _reserved1: u8,
        grandmaster: GrandMaster,
        steps_removed: u16,
        time_source: u8,
        path_trace: PathTrace,
    },
    Sync {
        origin_timestamp: Timestamp,
    },
    FollowUp {
        precise_origin_timestamp: Timestamp,
    },

    #[default]
    Empty,
}

impl Payload {
    pub fn new(id: Id, mut buf: BytesMut) -> Self {
        use super::enums::tlv::TypeValue;
        use super::metadata::Id::{Announce, FollowUp, Sync};

        // by splitting src we are able to pass buf mutable references
        // to the creators of the various struct members. once the entire
        // struct is built (wihtout errors) we then merge (unsplit) buf
        // back to src to advance the cursor.
        // let mut buf = src.split();

        match id {
            Announce => Payload::Announce {
                // origin_timestamp: BigUint::from_bytes_be(&buf.split_to(10)),
                origin_timestamp: Timestamp::new(&mut buf),
                current_utc_offset: buf.get_u16(),
                _reserved1: buf.get_u8(),
                grandmaster: GrandMaster::new_from_buf(&mut buf),
                steps_removed: buf.get_u16(),
                time_source: buf.get_u8(),
                path_trace: {
                    let tlv_type = buf.get_u16();
                    let len = buf.get_u16();

                    if let Ok(ttv) = TypeValue::try_from(tlv_type) {
                        let sequence = buf.copy_to_bytes(len as usize);

                        PathTrace {
                            tlv_type: ttv,
                            len,
                            sequence,
                        }
                    } else {
                        PathTrace::default()
                    }
                },
            },
            Sync => Payload::Sync {
                origin_timestamp: Timestamp::new(&mut buf),
            },
            FollowUp => Payload::FollowUp {
                precise_origin_timestamp: Timestamp::new(&mut buf),
            },

            _id => Payload::Empty,
        }
    }
}

impl std::fmt::Display for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Announce {
                origin_timestamp,
                current_utc_offset,
                grandmaster,
                steps_removed,
                time_source,
                path_trace,
                ..
            } => {
                write!(f, "\n{grandmaster:#?}\norigin_ts={origin_timestamp:?} utc_offset={current_utc_offset} steps_removed={steps_removed} time_source={time_source} {path_trace:?}")?;
            }
            Self::Sync { origin_timestamp } => {
                write!(f, "origin_timestamp={origin_timestamp:?}")?;
            }
            Self::FollowUp {
                precise_origin_timestamp,
            } => {
                write!(f, "precise_origin_timestamp={precise_origin_timestamp:?}")?;
            }
            Self::Empty => write!(f, "<< EMPTY >>")?,
        }

        Ok(())
    }
}

impl std::fmt::Debug for Payload {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Announce {
                origin_timestamp,
                current_utc_offset,
                grandmaster,
                steps_removed,
                time_source,
                path_trace,
                ..
            } => fmt
                .debug_struct("Announce")
                .field("origin_timestamp", origin_timestamp)
                .field("current_utc_offset", current_utc_offset)
                .field("grandmaster", grandmaster)
                .field("steps_removed", steps_removed)
                .field("time_source", time_source)
                .field("path_trace", path_trace)
                .finish(),

            Self::Sync { origin_timestamp } => fmt
                .debug_struct("Sync")
                .field("origin_timestamp", origin_timestamp)
                .finish(),

            Self::FollowUp {
                precise_origin_timestamp,
            } => fmt
                .debug_struct("FollowUp")
                .field("precise_origin_timestamp", precise_origin_timestamp)
                .finish(),

            Self::Empty => fmt.debug_struct("Empty").finish(),
        }
    }
}
