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

pub(self) use super::{clock::GrandMaster, protocol::Payload, Message, MsgFlags, PortIdentity};

use std::collections::{HashMap, VecDeque};
pub(self) use tokio::time::{Duration, Instant};

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
}

pub(super) mod track {
    // use std::collections::VecDeque;

    use super::{update, GrandMaster, Instant, Payload};
    use crate::Result;
    use std::collections::VecDeque;

    #[derive(Debug, Clone)]
    pub(super) struct Announces {
        pub seq_id: u16,
        pub last_at: Instant,
        pub master_at: Option<Instant>,
        pub grandmaster: Option<GrandMaster>,
        pub intervals: VecDeque<Instant>,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub(super) struct Announce {
        pub arrival_time: Instant,
        pub seq_id: u16,
        pub grandmaster: GrandMaster,
    }

    impl Announce {
        pub fn is_different_arrival_time(&self, arrival_time: &Instant) -> bool {
            self.arrival_time != *arrival_time
        }

        pub fn new(update: &update::Announce, grandmaster: GrandMaster) -> Self {
            Self {
                arrival_time: update.arrival_time(),
                seq_id: update.seq_id(),
                grandmaster,
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

        pub fn update(&mut self, update: &update::Sync) -> Result<()> {
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
    use super::{Base, Duration, Instant, Message, MsgFlags, Payload};
    pub struct Announce {
        pub base: Base,
        pub log_messsage_interval: Duration,
        pub payload: Option<Payload>,
    }

    impl Announce {
        pub fn arrival_time(&self) -> Instant {
            self.base.arrival_time
        }

        pub fn confirm_seq_id(&self, other_seq_id: u16) -> bool {
            let expected_seq_id = other_seq_id + 1;

            self.base.seq_id == expected_seq_id
        }

        pub fn interval(&self, earlier: &Instant) -> Duration {
            self.base.arrival_time.duration_since(*earlier)
        }

        pub fn seq_id(&self) -> u16 {
            self.base.seq_id
        }
    }

    impl From<Message> for Announce {
        fn from(msg: Message) -> Self {
            Self {
                base: Base::new(&msg),
                log_messsage_interval: Duration::from_millis(u64::from(
                    msg.header.log_message_interval,
                )),
                payload: Some(msg.payload),
            }
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

        // pub fn confirm_seq_id(&self, other_seq_id: u16) -> bool {
        //     let expected_seq_id = other_seq_id + 1;

        //     self.base.seq_id == expected_seq_id
        // }

        // pub fn interval(&self, earlier: &Instant) -> Duration {
        //     self.base.arrival_time.duration_since(*earlier)
        // }

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

        // pub fn interval(&self, earlier: &Instant) -> Duration {
        //     self.base.arrival_time.duration_since(*earlier)
        // }

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

pub struct Master {
    seen_at: Option<Instant>,
    master_at: Option<Instant>,
    // announces: Option<track::Announces>,
    announce_intervals: VecDeque<Duration>,
    announce_last: Option<track::Announce>,
    syncs: Option<track::Syncs>,
    follow_ups: Option<track::FollowUps>,
}

impl Master {
    pub fn clear(&mut self) {
        tracing::warn!("clearing foreign master");

        self.seen_at = None;
        self.master_at = None;
        self.announce_intervals.clear();
        self.announce_last = None;
        self.syncs = None;
        self.follow_ups = None;
    }

    pub fn got_announce(&mut self, mut update: update::Announce) {
        let max_interval = update.log_messsage_interval;

        if let Some(Payload::Announce {
            origin_timestamp: None,
            grandmaster,
            steps_removed: 0,
            time_source: 0xa0,
            ..
        }) = update.payload.take()
        {
            // if there isn't a last yet just store what we got
            let last = self
                .announce_last
                .get_or_insert_with(|| track::Announce::new(&update, grandmaster.clone()));

            // now, let's confirm the data needs to be processed (wasn't just placed into
            // the Option)
            if last.is_different_arrival_time(&update.arrival_time())
                && update.confirm_seq_id(last.seq_id)
            {
                // good, this data is expected
                let interval = update.interval(&last.arrival_time);

                // did this data arrive on time?
                if interval > max_interval {
                    tracing::warn!("late announce: {interval:8.2?} {max_interval:?}");
                }

                // it did, let's track this interval
                self.seen_at = Some(update.arrival_time());
                self.announce_intervals.push_back(interval);

                // and update the latest Announce
                self.announce_last = Some(track::Announce::new(&update, grandmaster));
            }

            // now, check if we have enough interval data points to allow
            // this to become master
            if self.announce_intervals.len() >= 4 {
                let sum: Duration = self.announce_intervals.iter().sum();
                let range = Duration::from_millis(100)..(max_interval * 5);

                match self.master_at {
                    Some(_) if !range.contains(&sum) => {
                        tracing::warn!("no longer master");
                        self.clear();
                    }
                    None if range.contains(&sum) => {
                        tracing::info!("now master");
                        self.master_at = Some(update.arrival_time());
                    }
                    None => {
                        tracing::warn!("sum={sum:0.3?} range={range:#?}");
                    }
                    Some(_) => (),
                }
            }

            // lastly, only track the last four intervals
            if self.announce_intervals.len() > 4 {
                self.announce_intervals.pop_front();
            }
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
        match self {
            Master {
                announce_last: Some(_),
                syncs: Some(syncs),
                ..
            } => {
                if syncs.update(update).is_err() {
                    self.syncs = None;
                }
            }
            Master {
                announce_last: Some(_),
                syncs: None,
                ..
            } => {
                self.syncs = Some(track::Syncs::new(update));
            }
            Master {
                announce_last: None,
                ..
            } => (),
        }
    }
}

impl std::default::Default for Master {
    fn default() -> Self {
        Self {
            seen_at: None,
            master_at: None,
            announce_intervals: VecDeque::with_capacity(5),
            announce_last: None,
            syncs: None,
            follow_ups: None,
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
            .field("master_at", &format_args!("{:?}", self.master_at))
            .field(
                "announce_history",
                &format_args!("len={}", self.announce_intervals.len()),
            )
            .field("have_announce_last", &self.announce_last.is_some())
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
