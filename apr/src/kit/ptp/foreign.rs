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

use crate::kit::ptp::Epoch;

pub(self) use super::{clock::GrandMaster, protocol::Payload, Message, MsgFlags, PortIdentity};

use std::collections::{HashMap, VecDeque};
pub(self) use tokio::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Base {
    pub arrival_time: Instant,
    pub seq_id: u16,
}

impl Base {
    pub fn new(msg: &Message) -> Self {
        Self {
            arrival_time: msg.metadata.reception_time,
            seq_id: msg.header.sequence_id,
        }
    }

    pub fn confirm_seq_id(&self, other_seq_id: u16) -> bool {
        let expected_seq_id = other_seq_id + 1;

        if self.seq_id == expected_seq_id {
            return true;
        }

        tracing::warn!("sequence number mismatch: {expected_seq_id} != {other_seq_id}",);

        false
    }

    pub fn interval(&self, earlier: &Instant) -> Duration {
        self.arrival_time.duration_since(*earlier)
    }
}

pub(super) mod track {
    use super::{update, Base, Duration, GrandMaster, Instant, Payload};
    use crate::Result;
    use std::collections::VecDeque;

    #[allow(unused)]
    #[derive(Debug, Default, Clone)]
    pub(super) struct Announces {
        pub last: Option<Base>,
        pub master_at: Option<Instant>,
        pub grandmaster: Option<GrandMaster>,
        pub intervals: Option<VecDeque<Duration>>,
    }

    impl Announces {
        pub fn new(update: update::Announce) -> Self {
            Self {
                last: Some(update.base),
                grandmaster: Some(update.grandmaster),
                ..Default::default()
            }
        }
    }

    #[derive(Debug, Default, Clone)]
    pub(super) struct FollowUps {
        pub arrival_time: Option<Instant>,
        pub seq_id: u16,
        pub count: u64,
        pub payload: Payload,
    }

    impl FollowUps {
        pub fn apply(&mut self, update: update::FollowUp) {
            self.arrival_time = Some(update.arrival_time());
            self.seq_id = update.seq_id();
            self.count += 1;
            self.payload = update.payload.unwrap();
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct Syncs {
        pub count: u64,
        pub seq_id: u16,
        pub last_at: Instant,
    }

    impl Syncs {
        pub fn new(update: &update::Sync) -> Self {
            Self {
                count: 1,
                seq_id: update.seq_id(),
                last_at: update.arrival_time(),
            }
        }

        pub fn apply(&mut self, update: &update::Sync) -> Result<()> {
            if update.flags.is_good_sync() && update.confirm_seq_id(self.seq_id) {
                self.seq_id = update.seq_id();
                self.count += 1;
                self.last_at = update.arrival_time();

                return Ok(());
            }

            let error = "invalid flags or seq_id mismatch";
            tracing::warn!("{error}: flags={:#?}", update.flags);
            Err(anyhow::anyhow!(error))
        }
    }
}

pub(super) mod update {
    use crate::kit::ptp::protocol::Header;

    use super::{Base, Duration, GrandMaster, Instant, Message, MsgFlags, Payload};

    pub struct Announce {
        pub base: Base,
        pub log_messsage_interval: Duration,
        pub grandmaster: GrandMaster,
    }

    impl TryFrom<Message> for Announce {
        type Error = anyhow::Error;

        fn try_from(msg: Message) -> Result<Self, Self::Error> {
            let base = Base::new(&msg);

            if let Message {
                header:
                    Header {
                        log_message_interval: msg_interval,
                        ..
                    },
                payload:
                    Payload::Announce {
                        grandmaster,
                        steps_removed: 0,
                        time_source: 0xa0,
                        ..
                    },
                ..
            } = msg
            {
                return Ok(Self {
                    base,
                    log_messsage_interval: Duration::from_millis(u64::from(msg_interval)),
                    grandmaster,
                });
            }

            let error = "Announce payload validation failed";
            tracing::error!("{error}: {msg:#?}");
            Err(anyhow::anyhow!(error))
        }
    }

    pub struct FollowUp {
        pub base: Base,
        pub payload: Option<Payload>,
    }

    impl FollowUp {
        pub fn arrival_time(&self) -> Instant {
            self.base.arrival_time
        }

        pub fn seq_id(&self) -> u16 {
            self.base.seq_id
        }
    }

    impl From<Message> for FollowUp {
        fn from(msg: Message) -> Self {
            Self {
                base: Base::new(&msg),
                payload: Some(msg.payload),
            }
        }
    }

    pub struct Sync {
        pub base: Base,
        pub flags: MsgFlags,
    }

    impl Sync {
        pub fn arrival_time(&self) -> Instant {
            self.base.arrival_time
        }

        pub fn confirm_seq_id(&self, other_seq_id: u16) -> bool {
            let expected_seq_id = other_seq_id + 1;

            self.base.seq_id == expected_seq_id
        }

        pub fn seq_id(&self) -> u16 {
            self.base.seq_id
        }
    }

    impl From<Message> for Sync {
        fn from(msg: Message) -> Self {
            Self {
                base: Base::new(&msg),
                flags: msg.header.flags,
            }
        }
    }
}

#[allow(unused)]
#[derive(Default)]
pub struct Master {
    seen_at: Option<Instant>,
    // master_at: Option<Instant>,
    announces: Option<track::Announces>,
    syncs: Option<track::Syncs>,
    follow_ups: Option<track::FollowUps>,
}

impl Master {
    pub fn got_announce(&mut self, update: update::Announce) {
        let max_interval = update.log_messsage_interval;
        let base = update.base;

        // if there isn't a last yet just store what we got
        let announces = self
            .announces
            .get_or_insert_with(|| track::Announces::new(update));

        let last = announces.last.get_or_insert(base);

        let intervals = announces
            .intervals
            .get_or_insert_with(|| VecDeque::with_capacity(5));

        // the code above may have just created Announces so we confirm the
        // update is a different arrival time.  if the arrival time is different
        // we can proceed with calculating an interval
        if last != &base && base.confirm_seq_id(last.seq_id) {
            // good, this data is expected
            let interval = base.interval(&last.arrival_time);

            // did this data arrive on time?
            if interval > max_interval {
                let d = Instant::now().duration_since(base.arrival_time);
                tracing::warn!("late announce: {interval:8.2?} {max_interval:?} {d:?}");
            }

            self.seen_at = Some(base.arrival_time);
            intervals.push_back(interval);

            // finally, update last to be whet we just examined
            *last = base;
        }

        // now, check if we have enough interval data points to allow
        // this to become master
        if intervals.len() >= 4 {
            let sum: Duration = intervals.iter().sum();
            let range = Duration::from_millis(100)..(max_interval * 5);

            match announces.master_at {
                Some(_) if !range.contains(&sum) => {
                    tracing::warn!("no longer master");
                    *self = Self::default();
                    return;
                }
                None if range.contains(&sum) => {
                    tracing::info!("now master");

                    announces.master_at = Some(Epoch::reception_time());
                }
                None => {
                    tracing::warn!("sum={sum:0.3?} range={range:#?}");
                }
                Some(_) => (),
            }
        }

        // lastly, only track the last four intervals
        while intervals.len() > 4 {
            intervals.pop_front();
        }
    }

    pub fn got_follow_up(&mut self, update: update::FollowUp) {
        // the spec states a sync must arrive before processing a followup, here we do just that
        if let Some(syncs) = self.syncs.as_mut() {
            if let Some(count) = syncs.count.checked_sub(1) {
                // good, we had at least one pending sync, store the reduced count
                syncs.count = count;

                // we've confirmed a sync was seen previously.  now process the follow up
                let follow_ups = self.follow_ups.get_or_insert(track::FollowUps::default());

                follow_ups.apply(update);

                return;
            }

            tracing::warn!("ignoring follow up before sync");
        }

        //
    }

    pub fn got_sync(&mut self, update: &update::Sync) {
        // only process the sync message if this source port id was announced
        if self.announces.is_some() {
            let syncs = self.syncs.as_mut();

            match syncs {
                Some(syncs) => {
                    if syncs.apply(update).is_err() {
                        // NOTE: tracing log entry produced by syncs.update()
                        self.syncs = None;
                    }
                }
                None => self.syncs = Some(track::Syncs::new(update)),
            }
        }
    }
}

#[derive(Default)]
pub struct MasterMap {
    pub inner: HashMap<PortIdentity, Master>,
}

impl MasterMap {
    pub fn new() -> Self {
        Self {
            inner: HashMap::with_capacity(10),
        }
    }
}

impl std::fmt::Debug for Master {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Master")
            .field("seen_at", &format_args!("{:?}", self.seen_at))
            // .field("master_at", &format_args!("{:?}", self.announcesmaster_at))
            .field("announces", &self.announces)
            // .field("have_announce_last", &self.announce_last.is_some())
            .field("Syncs", &self.syncs)
            .field("follow_ups", &self.follow_ups)
            .finish()
    }
}

impl std::fmt::Display for Master {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Master")
            // .field("seen_at", &format_args!("{:?}", self.seen_at))
            // .field("master_at", &format_args!("{:?}", self.master_at))
            // .field(
            //     "announce_history",
            //     &format_args!("len={}", self.announce_intervals.len()),
            // )
            // .field("have_announce_last", &self.announce_last.is_some())
            .field("Syncs", &self.syncs)
            .field("follow_ups", &self.follow_ups)
            .finish()
    }
}

impl std::fmt::Debug for MasterMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterMap")
            .field("inner", &self.inner)
            .finish()
    }
}
