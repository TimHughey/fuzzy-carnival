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

use crate::Result;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

#[cfg(test)]
pub(super) mod tests;

pub(super) mod clock;
pub(super) mod codec;
pub(super) mod protocol;
pub(super) mod tlv;

mod util;

pub(super) use clock::{Epoch, Identity as ClockIdentity};
pub(super) use codec::Context as Codec;
pub(super) use protocol::{Channel, Message, MetaData, PortIdentity};

pub async fn run_loop(cancel_token: CancellationToken) -> Result<()> {
    // create the two codecs
    let mut event_codec = Codec::new(Channel::Event).await?;
    let mut gen_codec = Codec::new(Channel::General).await?;

    loop {
        let maybe_frame = tokio::select! {
            // event frames should be processed as quickly as possible
            // so we run 'biased' (prioritized by implementation order)
            biased;

            // always process cancellations
            _ = cancel_token.cancelled() => break,
            // process event frames as they arrive, deprioritizing general frames
            Some(res) = event_codec.next() => res,
            // when no event frames are available proceed with general frames
            Some(res) = gen_codec.next() => res,

            //
            // NOTE: if either of the codecs return None the select! is restarted
            //
        };

        match maybe_frame {
            Ok((message, sock_addr)) => {
                tracing::info!("{sock_addr:?} {message:#?}");
            }
            Err(e) => {
                tracing::error!("framing error: {e}");
                return Err(anyhow::anyhow!(e));
            }
        }
    }

    // the only way we reach this point is when canceled.
    tracing::warn!("received cancel request");
    Ok(())
}
