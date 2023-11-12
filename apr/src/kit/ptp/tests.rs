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

use super::{clock, protocol::MsgType, Message, MetaData};
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
fn can_create_local_port_identity() {
    println!("{:#?}", clock::get_local_port_identity());
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
