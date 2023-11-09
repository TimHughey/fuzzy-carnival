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

use super::{header::Channel, Message, MetaData};
use crate::{
    util::{BinSave, BinSaveCat},
    Result,
};
use bytes::{BufMut, BytesMut};
use once_cell::sync::Lazy;
use std::net::SocketAddr;
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, Default)]
pub struct FrameIn {
    _priv: (),
}

#[derive(Debug, Default)]
pub struct FrameOut {
    _priv: (),
}

#[derive(Debug)]
pub struct Context {
    channel: Channel,
    #[allow(unused)]
    binsave: Lazy<BinSave>,
    _priv: (),
}

impl Context {
    pub fn new_for_channel(channel: Channel) -> Self {
        Self {
            channel,
            binsave: Lazy::new(|| BinSave::new(BinSaveCat::Ptp).expect("binsave init falure")),
            _priv: (),
        }
    }

    pub fn maybe_got_frame(&mut self, res: Option<Result<(Message, SocketAddr)>>) -> Result<()> {
        if let Some(res) = res {
            match res {
                Ok((_message, addr)) => {
                    tracing::info!("{:#} SRC={addr} MESSAGE", self.channel);

                    return Ok(());
                }
                Err(e) => {
                    tracing::error!("{:#} framing error: {e}", self.channel);
                    return Err(e);
                }
            }
        }

        Ok(())
    }
}

impl Decoder for Context {
    type Item = Message;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        // attempt to create metadata from an immutable slice of source buffer
        match MetaData::new_from_slice(src)? {
            Some(metadata) if metadata.is_src_ready(src) => {
                // creation of the metadata successful and src contains enough bytes
                // to continue with message creation

                // any error during message creation is considered a hard-failure
                // we use split_to() to consume the message from src and pass
                // the buffer to Message
                let buf = src.split_to(metadata.split_bytes());

                // for debug purposes persist the complete message
                self.binsave.persist(&buf, "all", None)?;

                let message = Message::new_from_buf(metadata, buf);
                Ok(Some(message))
            }
            Some(_) | None => Ok(None),
        }
    }
}

impl Encoder<FrameOut> for Context {
    type Error = anyhow::Error;

    fn encode(&mut self, _item: FrameOut, dst: &mut BytesMut) -> Result<()> {
        dst.put_u8(0xAE);

        Ok(())
    }
}
