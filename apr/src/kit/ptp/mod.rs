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
use std::net::SocketAddr;
use tokio::time::{self, Duration, Instant};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

#[cfg(test)]
pub(super) mod tests;

pub(super) mod clock;
pub(super) mod codec;
pub(super) mod protocol;
pub(super) mod state;
pub(super) mod tlv;

mod util;

pub(super) use clock::{Epoch, Identity as ClockIdentity, Known as KnownClock};
pub(super) use codec::Context as Codec;
pub(super) use protocol::{Channel, Message, MetaData, MsgType, Payload, PortIdentity};
pub(super) use state::{Context as State, Count as StateCount};

pub(super) enum Selected {
    MaybeMessage { res: Result<(Message, SocketAddr)> },
    Cancel,
    Broadcast { tick_at: Instant },
    Report { tick_at: Instant },
}

pub async fn run_loop(cancel_token: CancellationToken) -> Result<()> {
    // create Stats
    let mut state = State::new();

    // create the two codecs
    let mut event_codec = Codec::new(Channel::Event).await?;
    let mut gen_codec = Codec::new(Channel::General).await?;

    // create the broadcast and reporting intervals:
    //  1. wrap it in a block so they survive select invocations
    //  2. pin for use in select
    let broadcast = make_broadcast_interval(None);
    let report = make_report_interval(None);
    tokio::pin!(broadcast);
    tokio::pin!(report);

    loop {
        // invoke [``tokio::select!``] and return [``Selected``]
        let selected = tokio::select! {
            // event frames should be processed as quickly as possible
            // so we run 'biased' (prioritized by implementation order)
            biased;

            // 0. always process cancellations
            _ = cancel_token.cancelled() => Selected::Cancel,

            // 1. process event frames as they arrive, deprioritizing general frames
            Some(res) = event_codec.next() => Selected::MaybeMessage { res },

            // 2. broadcasting our ticks is higher priority then receipt of general frames
            tick_at = broadcast.tick() => Selected::Broadcast { tick_at },

            // 3. process general frames after 0, 1, 2
            Some(res) = gen_codec.next() => Selected::MaybeMessage{res},

            // 4. lowest priority is reporting stats
            tick_at = report.tick() => Selected::Report { tick_at },

            // NOTE: if either of the codecs return None the select! is restarted
        };

        match selected {
            Selected::MaybeMessage { res } => match res {
                Ok((message, sock_addr)) => {
                    state.inc_count(StateCount::Message);
                    state.handle_message(sock_addr, message);
                }
                Err(e) => {
                    tracing::error!("{e}");
                    tracing::error!("message framing error: {e}");

                    return Err(anyhow::anyhow!(e));
                }
            },

            Selected::Cancel => {
                tracing::warn!("received cancel request");
                break;
            }
            Selected::Broadcast { tick_at: _tick_at } => state.inc_count(StateCount::Broadcast),
            Selected::Report { tick_at: _tick_at } => {
                if let Some(metrics) = state.freq_metrics() {
                    tracing::info!("{metrics:?}");
                }

                tracing::debug!("{state:#?}");
            }
        }
    } // forever loop: Err and cancel (via break) are the only way out

    Ok(())
}

fn make_broadcast_interval(interval: Option<Duration>) -> time::Interval {
    // create the broadcast interval
    let interval = interval.unwrap_or_else(|| Duration::from_millis(130));
    let start = Instant::now() + interval;
    time::interval_at(start, interval)
}

fn make_report_interval(interval: Option<Duration>) -> time::Interval {
    // create the reporting interval
    let interval = interval.unwrap_or_else(|| Duration::from_secs(10));
    let start = Instant::now() + interval;
    time::interval_at(start, interval)
}
