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

use super::{message::Core as Message, MetaData};
use crate::{kit::tests::Data, Result};
use anyhow::anyhow;
use bstr::ByteSlice;
// use bytes::BytesMut;
use tracing_test::traced_test;

#[test]
#[traced_test]
fn can_replay_messages() -> Result<()> {
    const EOM: &[u8] = b"\x00!*!*!*\x00";
    const MAX_MSGS: usize = 50;

    let mut msgs = Data::get().ptp;
    let mut cnt: usize = 0;

    while cnt < MAX_MSGS {
        cnt += 1;

        if let Some(eom_at) = msgs.find(EOM) {
            // found the EOM, split into a buffer including EOM
            let mut buf_with_eom = msgs.split_to(eom_at + EOM.len());

            // now get just the actual message
            let mut src = buf_with_eom.split_to(eom_at);

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

        if msgs.is_empty() {
            return Ok(());
        }
    }

    Ok(())
}
