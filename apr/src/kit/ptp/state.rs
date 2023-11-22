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

pub(super) use super::{foreign::Port, protocol::Error, Payload, PortIdentity};
use crate::kit::ptp::foreign::Syncs;
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    ops::Div,
};
use tokio::time::{Duration, Instant};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Count {
    Broadcast,
    Message,
}

#[derive(Default, Debug)]
pub struct Counters {
    pub broadcasts: u128,
    pub messages: u128,
}

impl Counters {
    pub fn inc(&mut self, count: Count) {
        match count {
            Count::Broadcast => self.broadcasts += 1,
            Count::Message => self.messages += 1,
        }
    }
}

pub struct Context {
    pub last_at: Option<Instant>,
    pub message_freq: VecDeque<Duration>,
    pub counters: Counters,
    pub foreign_ports: HashMap<PortIdentity, Port>,
}

#[derive(Copy, Clone)]
pub struct FreqMetrics {
    pub min: Duration,
    pub avg: Duration,
    pub max: Duration,
    pub cnt: usize,
}

impl Context {
    pub fn new() -> Self {
        Self {
            last_at: None,
            message_freq: VecDeque::with_capacity(20),
            counters: Counters::default(),
            foreign_ports: HashMap::with_capacity(10),
        }
    }

    #[allow(unused)]
    pub fn average_msg_frequency(&self) -> Option<Duration> {
        let sum: Duration = self.message_freq.iter().sum();

        if let Ok(len) = u32::try_from(self.message_freq.len()) {
            return Some(sum.div(len));
        }

        None
    }

    #[allow(unused)]
    pub fn freq_metrics(&self) -> Option<FreqMetrics> {
        let fm = &self.message_freq;
        let min = fm.iter().min();
        let avg = self.average_msg_frequency();
        let max = fm.iter().max();

        let all = [min, avg.as_ref(), max];

        if let [Some(min), Some(avg), Some(max)] = all {
            return Some(FreqMetrics {
                min: *min,
                avg: *avg,
                max: *max,
                cnt: fm.len(),
            });
        }

        None
    }

    pub fn got_message(&mut self) {
        let now = Instant::now();

        if let Some(last_at) = self.last_at.as_mut() {
            let since_last = now.duration_since(*last_at);

            if self.message_freq.len() == self.message_freq.capacity() {
                let _discard = self.message_freq.pop_front();
            }

            self.message_freq.push_back(since_last);
            *last_at = now;
        } else {
            self.last_at.get_or_insert(now);
        }
    }

    pub fn inbound(
        &mut self,
        _sock_addr: SocketAddr,
        payload: Payload,
    ) -> std::result::Result<(), Error> {
        use std::collections::hash_map::Entry;
        self.got_message();

        // can not use a reference here since HashMap::entry() consumes the key
        let key = payload.port_identity();

        // get the record for this source port identity (aka clock id).
        // in the code below we will only create a new entry upon receipt of
        // an Announce message.  all other messages are ignored until the clock is
        // announved.
        let entry = self.foreign_ports.entry(key);

        let msg_id = payload.get_common().msg_id;

        match (payload, entry) {
            // we know this clock
            (Payload::Announce(data), Entry::Occupied(mut o)) => {
                let port = o.get_mut();
                port.announces_mut().apply(data);
                Ok(())
            }
            // we don't recognize this clock port and we have announce message
            (Payload::Announce(data), Entry::Vacant(v)) => {
                let port = v.insert(Port::default());
                port.announces_mut().apply(data);

                Ok(())
            }
            // sync messages are sent to initiate the two-step sync + follow_up
            // process to yield the precise source port timestamp
            (Payload::Sync(data), Entry::Occupied(mut o)) => {
                let port = o.get_mut();

                if port.have_announces() {
                    if let Some(syncs) = port.syncs.as_mut() {
                        match syncs.try_apply(&data) {
                            Ok(()) => (),
                            Err(e) => {
                                // sync try_apply only fails if the sync message
                                // does not match the expected contents.  if it doesn't
                                // match something is very wrong and all sync tracking is removed.
                                //
                                // this approach is OK because syncs arrive very quickly
                                tracing::error!("sync apply failed: {e}");
                                o.remove_entry();
                                return Err(e);
                            }
                        }
                    } else {
                        port.syncs = Some(Syncs::new(&data));
                    }
                }

                Ok(())
            }
            // attempt to handle FollowUp messages only if we've previously seen this
            // source port identity (aka received Announce).  see foreign mod for
            // additional constraints (e.g. we've received a two-step sync message)
            (Payload::FollowUp(data), Entry::Occupied(mut o)) => {
                let port = o.get_mut();

                // confirm FollowUp is for the last Sync
                if let Some(sync_seq_id) = port.last_sync_seq_id() {
                    let seq_id = data.common.seq_id;

                    if sync_seq_id != seq_id {
                        return Err(Error::SeqIdMismatch {
                            want: seq_id,
                            have: sync_seq_id,
                        });
                    }

                    port.follow_ups_mut().apply(&data);
                }

                Ok(())
            }
            (Payload::FollowUp(_) | Payload::Sync(_), Entry::Vacant(_)) => {
                tracing::info!("ignoring {msg_id:?} before announce");
                Ok(())
            }
            (Payload::Discard(_data), _) => Ok(()),
        }
    }

    pub fn inc_count(&mut self, count: Count) {
        self.counters.inc(count);
    }
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State")
            .field("foreign_masters", &self.foreign_ports)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State")
            .field(
                "foreign_masters",
                &format_args!("{:#?}", &self.foreign_ports),
            )
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for FreqMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FreqMetrics")
            .field("min", &format_args!("{:3.2?}", self.min))
            .field("avg", &format_args!("{:3.2?}", self.avg))
            .field("max", &format_args!("{:3.2?}", self.max))
            .finish()
    }
}
