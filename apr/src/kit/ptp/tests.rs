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
// See the License for the specific

use super::{protocol::MsgType, Message, MetaData};
use crate::{kit::tests::Data, Result};
use anyhow::anyhow;
use tracing_test::traced_test;

#[test]
#[traced_test]
fn can_replay_messages() -> Result<()> {
    const MAX_MSGS: usize = 50;

    let mut src = Data::get().ptp;
    let mut cnt: usize = 0;

    while !src.is_empty() && cnt < MAX_MSGS {
        cnt += 1;

        match MetaData::new_from_slice(&src)? {
            Some(metadata) if metadata.is_src_ready(&src) => {
                // creation of the metadata successful and src contains enough bytes
                // to continue with message creation

                // any error during message creation is considered a hard-failure
                // so we can use split_to() to consume the bytes from src
                let buf = src.split_to(metadata.split_bytes());

                // pass the newly split BytesMut to Message
                let message = Message::new_from_buf(metadata, buf);

                println!("{message:#?}\n");
            }
            Some(_) | None => {
                return Err(anyhow!("failed to create metadata"));
            }
        }
    }

    println!("msgs_replayed: {cnt}");

    Ok(())
}

#[test]
#[traced_test]
fn can_replay_follow_up_messages() -> Result<()> {
    const MAX_MSGS: usize = 50;

    let mut src = Data::get().ptp;
    let mut cnt: usize = 0;

    while !src.is_empty() && cnt < MAX_MSGS {
        cnt += 1;

        match MetaData::new_from_slice(&src)? {
            Some(metadata) if metadata.is_src_ready(&src) => {
                // creation of the metadata successful and src contains enough bytes
                // to continue with message creation

                // any error during message creation is considered a hard-failure
                // so we can use split_to() to consume the bytes from src
                let buf = src.split_to(metadata.split_bytes());

                // pass the newly split BytesMut to Message
                let message = Message::new_from_buf(metadata, buf);

                if message.match_msg_type(MsgType::FollowUp) {
                    println!("{message:#?}\n");
                }
            }
            Some(_) | None => {
                return Err(anyhow!("failed to create metadata"));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod clock {
    use crate::kit::ptp::{
        clock::{
            quality::{Accuracy, Class},
            Quality,
        },
        PortIdentity,
    };

    type SomeClockQualityClass = Option<Class>;
    type SomeClockAccuracyClass = Option<Accuracy>;

    fn make_clock_quality(
        class: SomeClockQualityClass,
        accuracy: SomeClockAccuracyClass,
        variance: Option<u16>,
    ) -> Quality {
        Quality {
            class: class.unwrap_or(Class::default()),
            accuracy: accuracy.unwrap_or(Accuracy::Within100ns),
            offset_scaled_log_variance: variance.unwrap_or(0x0001),
        }
    }

    #[test]
    fn can_order_and_compare_clock_quality() {
        let good = make_clock_quality(None, None, None);
        let bad = make_clock_quality(
            Some(Class::DegradationAlternative(52)),
            Some(Accuracy::GreaterThan100ns(0x23)),
            None,
        );

        // good quality compares as less than bad quality
        assert!(good < bad);

        // now let's check that the clock class is better (less)
        // while the accuracy is better
        let good = make_clock_quality(None, None, Some(0xa000));
        let bad = make_clock_quality(None, Some(Accuracy::GreaterThan100ns(0x31)), Some(0x1000));

        // clock class should overrule other fields
        // NOTE: we need to confirm this statement
        assert!(good < bad);
    }

    #[test]
    fn can_hash_clock_quality() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // check all fields are better (lower)
        let quality_good = Quality {
            class: Class::Default,
            accuracy: Accuracy::Within100ns,
            offset_scaled_log_variance: 0x0001,
        };

        let quality_bad = Quality {
            class: Class::Reserved(12),
            accuracy: Accuracy::GreaterThan100ns(13),
            offset_scaled_log_variance: 0x0001,
        };

        // let's also confirm they hash to different values
        let mut hasher = DefaultHasher::new();

        quality_good.hash(&mut hasher);
        let hash_val_good = hasher.finish();

        quality_bad.hash(&mut hasher);
        let hash_val_bad = hasher.finish();

        assert_ne!(hash_val_good, hash_val_bad);
    }

    #[test]

    fn can_create_local_port_identity() {
        use crate::kit::ptp::clock;

        let local_identity = clock::get_local_port_identity();

        assert!(*local_identity > PortIdentity::default());
        assert_ne!(*local_identity, PortIdentity::default());
    }

    #[test]
    fn can_create_local_port_identity_alt() {
        use crate::kit::ptp::{
            clock::{quality::Accuracy, Quality},
            PortIdentity,
        };
        use crate::HostInfo;
        use bytes::{BufMut, BytesMut};

        const BYTE_6: u8 = 0x11;
        const BYTE_7: u8 = 0xaa;

        let id = HostInfo::mac_as_byte_slice();
        let port_identity = PortIdentity::new_local(id, None);

        // println!("{port_identity:?}");

        let clock_identity = port_identity.clock_identity.as_ref();

        assert_eq!(clock_identity[6], BYTE_6);
        assert_eq!(clock_identity[7], BYTE_7);
        assert_eq!(port_identity.port, 0x90a1);

        let qval: u32 = 0xf8fe_436a; // from shairport

        let mut buf = BytesMut::with_capacity(8);
        buf.put(&qval.to_be_bytes()[..]);

        let quality = Quality::new_from_buf(&mut buf);

        // NOTE: not clear why shairport uses this accuracy
        //       possiblity to ensure it's clock is never chosen
        //       as grand master
        assert_eq!(quality.accuracy, Accuracy::Unknown(254));

        // println!("{quality:#?}");
    }
}
