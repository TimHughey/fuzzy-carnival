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

use super::{util, PortIdentity};
use bytes::{Buf, BytesMut};
use once_cell::sync::Lazy;
use pretty_hex::{HexConfig, PrettyHex};
use std::hash::Hash;
use tokio::time::{Duration, Instant};

const IDENTITY_LEN: usize = 8;
#[derive(Copy, Clone)]
pub struct Epoch {
    inner: Instant,
}

impl Epoch {
    #[inline]
    pub fn reception_time() -> Instant {
        Instant::now()
    }

    #[inline]
    pub fn local_time(reception_time: &Instant) -> Duration {
        reception_time.duration_since(EPOCH.inner)
    }

    #[inline]
    #[allow(unused)]
    pub fn now() -> Instant {
        Instant::now()
    }
}

static EPOCH: Lazy<Epoch> = Lazy::new(|| Epoch {
    inner: Instant::now(),
});

pub mod local {
    use crate::{kit::ptp::PortIdentity, HostInfo};
    use once_cell::sync::Lazy;

    #[allow(unused)]
    pub(super) static PORT_IDENTITY: Lazy<PortIdentity> = Lazy::new(|| {
        let id = HostInfo::mac_as_byte_slice();

        PortIdentity::new_local(id, None)
    });
}

#[allow(unused)]
pub fn get_local_port_identity() -> &'static PortIdentity {
    &local::PORT_IDENTITY
}

#[derive(Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

impl AsRef<[u8]> for Identity {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_slice()
    }
}

pub mod quality {
    use bytes::{Buf, BytesMut};

    #[derive(Debug, Default, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
    pub enum Accuracy {
        LessThan100ns(u8),
        #[default]
        Within100ns,
        GreaterThan100ns(u8),
        AlternateProfiles(u8),
        Reserved(u8),
        Unknown(u8),
    }

    impl Accuracy {
        pub fn new(v: u8) -> Self {
            const LESS_THAN_100_NS: std::ops::Range<u8> = 0x17..0x21;
            const WITHIN_100_NS: u8 = 0x21;
            const GREATER_THAN_100_NS: std::ops::Range<u8> = 0x22..0x32;
            const ALT_PROFILES: std::ops::Range<u8> = 0x80..0xfe;
            const UNKNOWN: std::ops::RangeInclusive<u8> = 0xfe..=0xff;

            match v {
                WITHIN_100_NS => Accuracy::Within100ns,
                v if LESS_THAN_100_NS.contains(&v) => Accuracy::LessThan100ns(v),
                v if GREATER_THAN_100_NS.contains(&v) => Accuracy::GreaterThan100ns(v),
                v if ALT_PROFILES.contains(&v) => Accuracy::AlternateProfiles(v),
                v if UNKNOWN.contains(&v) => Accuracy::Unknown(v),
                v => Accuracy::Reserved(v),
            }
        }

        pub fn new_from_buf(buf: &mut BytesMut) -> Self {
            Accuracy::new(buf.get_u8())
        }
    }

    #[derive(Debug, Default, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
    pub enum Class {
        #[default]
        Default, // low discriminat for sorting
        Reserved(u8),
        Shall(u8),
        DegradationAlternative(u8),
        AlternateProfiles(u8),
    }

    impl Class {
        pub fn new_from_buf(buf: &mut BytesMut) -> Self {
            const SHALL: &[u8] = &[6, 7, 13, 14];
            const DEGRADATION: &[u8] = &[52, 58, 187, 193];
            const ALT_PROFILES: std::ops::RangeInclusive<u8> = 133..=170;

            match buf.get_u8() {
                248 => Class::Default,
                v if SHALL.contains(&v) => Class::Shall(v),
                v if DEGRADATION.contains(&v) => Class::DegradationAlternative(v),
                v if ALT_PROFILES.contains(&v) => Class::AlternateProfiles(v),
                v => Class::Reserved(v),
            }
        }
    }
}

#[allow(unused)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct Quality {
    pub class: quality::Class,
    pub accuracy: quality::Accuracy,
    pub offset_scaled_log_variance: u16,
}

impl Quality {
    pub fn new_from_buf(buf: &mut BytesMut) -> Self {
        Self {
            class: quality::Class::new_from_buf(buf),
            accuracy: quality::Accuracy::new_from_buf(buf),
            offset_scaled_log_variance: buf.get_u16(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(unused)]
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

    pub fn identity(&self) -> Identity {
        self.identity
    }
}

#[derive(Default, Clone, Copy)]
pub struct Timestamp {
    pub val: Duration,
}

impl Timestamp {
    pub fn new_from_buf(buf: &mut BytesMut) -> Option<Self> {
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

impl std::fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Timestamp")
            .field("val", &format_args!("{:8.2?}", &self.val))
            .finish()
    }
}
