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

use super::message::Core as Message;
use crate::{kit::tests::Data, Result};
use anyhow::anyhow;
use bstr::ByteSlice;
use bytes::Buf;
// use bytes::BytesMut;
use pretty_hex::PrettyHex;
use tracing_test::traced_test;

#[test]
fn can_split_all_msgs() -> Result<()> {
    const EOM: &[u8] = b"\x00!*!*!*\x00";
    const MAX_MSGS: usize = 10;

    let mut msgs = Data::get().ptp;
    let mut cnt: usize = 0;

    loop {
        if cnt > MAX_MSGS {
            return Ok(());
        }

        cnt += 1;

        if let Some(eom_at) = msgs.find(EOM) {
            let mut buf_with_eom = msgs.split_to(eom_at + EOM.len());
            let mut buf = buf_with_eom.split_to(eom_at);

            let buf_len = buf.len();

            let message = Message::new(&mut buf)?;

            println!("{message:#?}\n");

            {
                // confirm raw message len is equivalent to parsed len
                let message_len = message.len();

                if message_len != buf_len {
                    println!("** MESSAGE raw={buf_len} parsed={message_len}");
                }
            }
        }

        if msgs.is_empty() {
            return Ok(());
        }
    }
}

#[test]
#[traced_test]
fn can_create_metadata() -> Result<()> {
    // use super::MetaData;

    let mut msgs = Data::get().ptp;
    let before_msg_len = msgs.len();

    let mut buf = msgs.split();

    let message = Message::new(&mut buf)?;

    msgs.unsplit(buf);

    let after_msg_len = msgs.len();

    tracing::info!("\n MESSAGE {message:#?}");

    tracing::info!("consumed={}", before_msg_len - after_msg_len);

    Ok(())
}

#[test]
#[traced_test]
fn can_replay_ptp_messages() -> Result<()> {
    // use super::metadata::Id;

    const EOM: &[u8] = b"\x00!*!*!*\x00";
    const MAX: usize = 10;
    let mut count = 0;

    let mut msgs = Data::get().ptp;

    loop {
        if count >= MAX {
            break;
        }

        count += 1;

        // let msg_len = msgs.len();
        let mut buf = msgs.split();

        match Message::new(&mut buf) {
            Ok(message) => {
                msgs.unsplit(buf);

                tracing::info!("\n{message:#?}");
            }
            Err(e) => {
                tracing::error!("{e}");
                return Err(e);
            }
        }

        if let Some(eom_start_at) = msgs.find(EOM) {
            let discard = msgs.split_to(eom_start_at);

            if !discard.is_empty() {
                tracing::info!("\nDISCARDING {:#?}", discard.hex_dump());
            }

            // skip EOM
            msgs.advance(EOM.len());
        } else {
            tracing::info!("\nBUF {:#?}", msgs[..128].hex_dump());

            return Err(anyhow!("EOM not found"));
        }

        if msgs.len() < Message::min_bytes() {
            break;
        }
    }

    Ok(())
}
