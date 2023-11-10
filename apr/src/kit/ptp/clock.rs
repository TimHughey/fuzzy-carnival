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

use super::util;
use bytes::{Buf, BytesMut};
use once_cell::sync::Lazy;
use pretty_hex::{HexConfig, PrettyHex};
use std::time;

const IDENTITY_LEN: usize = 8;

pub struct Epoch {
    inner: time::Instant,
}

impl Epoch {
    pub fn reception_time() -> time::Duration {
        EPOCH.inner.elapsed()
    }
}

static EPOCH: Lazy<Epoch> = Lazy::new(|| Epoch {
    inner: time::Instant::now(),
});

#[derive(Default, PartialEq, Eq, Hash)]
pub struct Identity {
    inner: [u8; IDENTITY_LEN],
}

impl Identity {
    pub fn new_from_buf(buf: &mut BytesMut) -> Self {
        Self {
            inner: util::make_array_n::<IDENTITY_LEN>(buf),
        }
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
pub struct Quality {
    class: u8,
    accuracy: u8,
    offset_scaled_log_variance: u16,
}

impl Quality {
    pub fn new_from_buf(buf: &mut BytesMut) -> Self {
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
pub struct GrandMaster {
    priority_one: u8,
    quality: Quality,
    priority_two: u8,
    identity: Identity,
}

impl GrandMaster {
    pub fn new_from_buf(buf: &mut BytesMut) -> Self {
        Self {
            priority_one: buf.get_u8(),
            quality: Quality::new_from_buf(buf),
            priority_two: buf.get_u8(),
            identity: Identity::new_from_buf(buf),
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
pub struct Timestamp {
    pub val: time::Duration,
    // pub nanos_field: time::Duration,
}

impl Timestamp {
    pub fn new_from_buf(buf: &mut BytesMut) -> Option<Self> {
        use std::time::Duration;
        use util::make_array_nlo;
        // combination of:
        //  - seconds (48 bits)
        //  - nanoseconds (32 bits)
        // is guaranteed to fit within an 80 bit number
        //
        // nanos will never exceed a 2^9 value

        // consume the vals from the buffer regardless of if this a non-zero timestamp
        // the field sizing for PTP doesn't fit "cleanly" into a Duration so we do
        // some hand rolled buf work
        let secs = u64::from_be_bytes(make_array_nlo::<8, 6, 2>(buf));
        let nanos = buf.get_u32();

        let val = Duration::new(secs, nanos);

        if val > Duration::ZERO {
            return Some(Self { val });
        }

        None
    }
}

impl std::fmt::Debug for Timestamp {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("Timestamp")
            .field("val", &self.val)
            // .field("nanos", &self.nanos_field)
            .finish()
    }
}
