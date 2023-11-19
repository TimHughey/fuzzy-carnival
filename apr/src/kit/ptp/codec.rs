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

use super::{Channel, MetaData, Payload};
use crate::{
    util::{BinSave, BinSaveCat},
    HostInfo, Result,
};
use bytes::{BufMut, BytesMut};
use once_cell::sync::Lazy;
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;
use tokio_util::{
    codec::{Decoder, Encoder},
    udp::UdpFramed,
};

#[derive(Debug, Default)]
pub struct FrameOut {
    _priv: (),
}

static BIN_SAVE: Lazy<Option<BinSave>> = Lazy::new(|| BinSave::new(BinSaveCat::Ptp).ok());

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Context {
    #[allow(unused)]
    channel: Channel,
    addr: SocketAddr,
}

impl Context {
    pub async fn new(channel: Channel) -> Result<UdpFramed<Context>> {
        let addr = make_bind_addr(channel)?;
        let socket = UdpSocket::bind(addr).await?;
        let codec = Self { channel, addr };

        Ok(UdpFramed::new(socket, codec))
    }

    #[allow(unused)]
    pub fn auth_sender_port(&self, port: u16) -> bool {
        self.addr.port() == port
    }
}

// Stand-alone function, no need to host it in Context
fn make_bind_addr(channel: Channel) -> Result<SocketAddr> {
    let ip_addr: IpAddr = HostInfo::ip_as_str().parse()?;

    Ok(SocketAddr::new(ip_addr, channel.into()))
}

impl Decoder for Context {
    type Item = Payload;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        // attempt to create metadata from an immutable slice of source buffer
        Ok(match MetaData::new_from_slice(src)? {
            Some(metadata) if metadata.is_src_ready(src) => {
                // creation of the metadata successful and src contains enough bytes
                // to continue with message creation

                // any error during message creation is considered a hard-failure
                // we use split_to() to consume the message from src and pass
                // the buffer to Message
                let buf = src.split_to(metadata.split_bytes());

                // for debug purposes persist the complete message, allow to quietly fail
                BIN_SAVE
                    .as_ref()
                    .and_then(|bin_save| bin_save.persist(&buf, "all", None).ok());

                match Payload::try_new(metadata, buf) {
                    Ok(payload) => Some(payload),
                    Err(e) => {
                        tracing::error!("Payload::try_new(): {e}");
                        None
                    }
                }
            }
            Some(_) | None => None,
        })
    }
}

impl Encoder<FrameOut> for Context {
    type Error = anyhow::Error;

    fn encode(&mut self, _item: FrameOut, dst: &mut BytesMut) -> Result<()> {
        dst.put_u8(0xAE);

        Ok(())
    }
}
