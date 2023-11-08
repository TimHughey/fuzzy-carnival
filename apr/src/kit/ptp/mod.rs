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

use crate::{HostInfo, Result};
use tokio::net::UdpSocket;
use tokio_stream::StreamExt;
use tokio_util::{sync::CancellationToken, udp::UdpFramed};

pub(super) mod clock;
pub(super) mod codec;
pub(super) mod consts;
pub(super) mod enums;
pub(super) mod header;
pub(super) mod message;
pub(super) mod metadata;
pub(super) mod protocol;
pub(self) mod util;

#[cfg(test)]
pub(super) mod tests;

pub(self) use clock::Identity as ClockIdentity;
pub(super) use codec::Context as Codec;
pub(super) use header::Channel;
pub(self) use metadata::Data as MetaData;

pub(self) use anyhow::anyhow;
pub(self) use bytes::{Buf, Bytes, BytesMut};

pub async fn run_loop(cancel_token: CancellationToken) -> Result<()> {
    let addr = format!("{}:319", HostInfo::ip_as_str());
    let event_socket = UdpSocket::bind(&addr).await?;

    let mut event_framed = UdpFramed::new(event_socket, Codec::new_for_channel(Channel::Event));

    let addr = format!("{}:320", HostInfo::ip_as_str());
    let gen_socket = UdpSocket::bind(&addr).await?;
    let mut gen_framed = UdpFramed::new(gen_socket, Codec::new_for_channel(Channel::General));

    tokio::pin!(cancel_token);

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                tracing::warn!("received cancel request");
                break;

            },
            res = event_framed.next() => {
                event_framed.codec_mut().maybe_got_frame(res)


            },
            res = gen_framed.next() => {
                gen_framed.codec_mut().maybe_got_frame(res)

            }
        }?; // break from loop on Err
    }
    Ok(())
}
