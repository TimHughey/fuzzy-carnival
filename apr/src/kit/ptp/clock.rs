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

use super::{util, Buf, Bytes, BytesMut};
use num_bigint::BigUint;
use pretty_hex::{HexConfig, PrettyHex};

const IDENTITY_LEN: usize = 8;

#[derive(Default)]
pub(super) struct Identity {
    inner: [u8; IDENTITY_LEN],
}

impl Identity {
    pub fn new(mut buf: Bytes) -> Self {
        Self {
            inner: util::make_array_n::<8>(buf.copy_to_bytes(8)),
        }
    }

    pub fn size_of() -> usize {
        IDENTITY_LEN
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cfg = HexConfig {
            title: false,
            ascii: false,
            width: 8,
            group: 0,
            ..HexConfig::default()
        };

        write!(f, "{}", self.inner.hex_conf(cfg))
    }
}

#[allow(unused)]
#[derive(Default)]
pub(super) struct Quality {
    class: u8,
    accuracy: u8,
    offset_scaled_log_variance: u16,
}

impl Quality {
    pub fn new(buf: &mut BytesMut) -> Self {
        Self {
            class: buf.get_u8(),
            accuracy: buf.get_u8(),
            offset_scaled_log_variance: buf.get_u16(),
        }
    }
}

impl std::fmt::Debug for Quality {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("Quality")
            .field("class", &self.class)
            .field("accuracy", &self.accuracy)
            .field(
                "offset_scaled_log_variance",
                &self.offset_scaled_log_variance,
            )
            .finish()
    }
}

#[derive(Default)]
pub(super) struct GrandMaster {
    priority_one: u8,
    quality: Quality,
    priority_two: u8,
    identity: Identity,
}

impl GrandMaster {
    pub fn new_from_buf(buf: &mut BytesMut) -> Self {
        Self {
            priority_one: buf.get_u8(),
            quality: Quality::new(buf),
            priority_two: buf.get_u8(),
            identity: Identity::new(buf.copy_to_bytes(8)),
        }
    }
}

impl std::fmt::Debug for GrandMaster {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("GrandMaster")
            .field("identity", &self.identity)
            .field("pri_1", &self.priority_one)
            .field("pri_2", &self.priority_two)
            .field("quality", &self.quality)
            .finish()
    }
}

#[derive(Default)]
pub(super) struct Timestamp {
    pub seconds_field: BigUint,
    pub nanos_field: BigUint,
}

impl Timestamp {
    pub fn new(buf: &mut BytesMut) -> Self {
        // combination of:
        //  - seconds (48 bits)
        //  - nanoseconds (32 bits)
        // is guaranteed to fit within an 80 bit number
        //
        // nanos will never exceed a 2^9 value

        Self {
            seconds_field: BigUint::from_bytes_be(&buf.split_to(6)), // 48 bits
            nanos_field: BigUint::from_bytes_be(&buf.split_to(4)),   // 32 bits
        }
    }
}

impl std::fmt::Debug for Timestamp {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("Timestamp")
            .field("secs", &self.seconds_field)
            .field("nanos", &self.nanos_field)
            .finish()
    }
}
