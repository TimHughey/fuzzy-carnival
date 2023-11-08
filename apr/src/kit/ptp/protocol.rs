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
    clock::GrandMaster, enums::tlv::TypeValue as TlvTypeVal, metadata::Id, Buf, Bytes, BytesMut,
};
use crate::Result;
use hex::ToHex;
use num_bigint::BigUint;
use pretty_hex::{HexConfig, PrettyHex};

#[allow(unused)]
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

impl std::fmt::Display for PathTrace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PathTrace {}\n{:?}",
            self.tlv_type,
            self.sequence.encode_hex::<String>().hex_dump()
        )
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
#[allow(unused)]
pub(super) enum Payload {
    Announce {
        origin_timestamp: BigUint,
        current_utc_offset: u16,
        reserved1: u8,
        grandmaster: GrandMaster,
        steps_removed: u16,
        time_source: u8,
        path_trace: PathTrace,
    },
    Sync {
        origin_timestamp: BigUint,
    },
    FollowUp {
        precise_origin_timestamp: BigUint,
    },

    #[default]
    Empty,
}

impl Payload {
    pub fn new2(id: Id, buf: &mut BytesMut) -> Result<Self> {
        use super::enums::tlv::TypeValue;
        use super::metadata::Id::{Announce, FollowUp, Sync};

        Ok(match id {
            Announce => Payload::Announce {
                origin_timestamp: BigUint::from_bytes_be(&buf.split_to(10)),
                current_utc_offset: buf.get_u16(),
                reserved1: buf.get_u8(),
                grandmaster: {
                    let mut gm_buf = buf.split();

                    let gm = GrandMaster::new(&mut gm_buf)?;

                    buf.unsplit(gm_buf);

                    gm
                },
                //  grandmaster: GrandMaster::new(&mut buf)?,
                steps_removed: buf.get_u16(),
                time_source: buf.get_u8(),
                path_trace: {
                    let tlv_type = buf.get_u16();
                    let len = buf.get_u16();

                    // tracing::debug!("found tlv_type={tlv_type} len={len}");

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
                origin_timestamp: BigUint::from_bytes_be(&buf.copy_to_bytes(10)),
            },
            FollowUp => Payload::FollowUp {
                precise_origin_timestamp: BigUint::from_bytes_be(&buf.copy_to_bytes(10)),
            },

            id => todo!("implement {id:#?}"),
        })
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
                write!(f, "\n{grandmaster:#?}\norigin_ts={origin_timestamp} utc_offset={current_utc_offset} steps_removed={steps_removed} time_source={time_source} {path_trace}")?;
            }
            Self::Sync { origin_timestamp } => {
                write!(f, "origin_timestamp={origin_timestamp}")?;
            }
            Self::FollowUp {
                precise_origin_timestamp,
            } => {
                write!(f, "precise_origin_timestamp={precise_origin_timestamp}")?;
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
