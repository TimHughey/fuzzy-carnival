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

pub(self) use super::{
    foreign::track::{
        Announces as AnnouncesTrack, FollowUps as FollowUpsTrack, Syncs as SyncsTrack,
    },
    protocol::Payload,
    ClockTimestamp, Epoch, GrandMaster, Header, Message, MsgFlags,
};

pub(self) use time::{Duration, Instant};

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

    pub fn interval(&self, latest: &Base) -> Duration {
        let e_latest = latest.arrival_time.elapsed();
        let e_arrival = self.arrival_time.elapsed();

        e_arrival - e_latest
    }

    pub fn local_time(&self) -> Duration {
        Epoch::local_time(&self.arrival_time)
    }

    pub fn seq_variance(&self, latest: &Self) -> Option<u16> {
        latest.seq_id.checked_sub(self.seq_id)
    }
}

pub(super) mod track {
    use super::{update, Base, ClockTimestamp, Duration, GrandMaster, Instant};
    use crate::Result;
    use std::collections::VecDeque;

    #[derive(Debug)]
    pub(super) struct Intervals {
        last: Option<Base>,
        durations: VecDeque<Duration>,
    }

    impl std::default::Default for Intervals {
        fn default() -> Self {
            Self {
                last: None,
                durations: VecDeque::with_capacity(5),
            }
        }
    }

    impl Intervals {
        pub fn check_if_master(&mut self, latest: Base, max_interval: Duration) -> Option<Instant> {
            // ensure we're considering four intervals
            while self.durations.len() > 4 {
                self.durations.pop_front();
            }

            if let Some(last) = self.last.as_mut() {
                // calc the duration since the previous and latest
                let interval = last.interval(&latest);

                if interval > max_interval {
                    tracing::warn!("late announce: diff={:5.2?}", interval - max_interval);
                }

                match last.seq_variance(&latest) {
                    Some(1) => (), // sequence id is good
                    Some(variance) => {
                        tracing::warn!("sequence variance: {variance}");
                    }
                    None => {
                        tracing::info!("sequence id underflow");
                    }
                }

                // add the calculated interval to the list for consideration
                self.durations.push_back(interval);

                *last = latest;

                if self.durations.len() >= 4 {
                    // now sum all the known intervals
                    let sum: Duration = self.durations.iter().sum();
                    let sum_max: Duration =
                        max_interval * u32::try_from(self.durations.len()).unwrap();

                    if sum <= sum_max {
                        return Some(latest.arrival_time);
                    }
                }
            }

            self.last = Some(latest);
            None
        }
    }

    #[allow(unused)]
    #[derive(Default, Debug)]
    pub(super) struct Announces {
        pub last: Option<Base>,
        pub master_at: Option<Instant>,
        pub grandmaster: Option<GrandMaster>,
        pub intervals: Intervals,
    }

    impl Announces {
        pub fn apply(&mut self, update: update::Announce) {
            let max_interval = update.log_messsage_interval;
            let base = update.base;

            match self.intervals.check_if_master(base, max_interval) {
                None => {
                    tracing::warn!("master not ready");
                }
                Some(master_at) => {
                    if self.master_at.is_none() {
                        tracing::info!("master now");
                        self.master_at = Some(master_at);
                    }

                    // take grandmaster from update. update the stored grandmaster
                    // if anything has changed or simply store it if we don't yet
                    // have grandmaster data
                    let grandmaster = update.grandmaster;

                    match self.grandmaster.as_mut() {
                        None => {
                            tracing::info!("grandmaster: {:?}", grandmaster.identity());

                            self.grandmaster = Some(grandmaster);
                        }
                        Some(last_gm) if last_gm != &grandmaster => {
                            tracing::info!("updating:\n{grandmaster:#?}");
                            *last_gm = grandmaster;
                        }
                        Some(_last_gm) => (),
                    }
                }
            }
        }
    }

    #[derive(Debug, Default, Clone)]
    pub(super) struct FollowUps {
        pub last: Option<Base>,
        pub count: u64,
        pub correction_field: Option<Duration>,
        pub precise_origin_timestamp: Option<ClockTimestamp>,
        pub offset_from_master: Option<Duration>,
    }

    impl FollowUps {
        pub fn apply(&mut self, update: &update::FollowUp) {
            let base = update.base;
            let correction_field = update.correction_field;
            let precise_origin_timestamp = update.precise_origin_timestamp;

            self.last = Some(base);
            self.count += 1;
            self.correction_field = correction_field;
            self.precise_origin_timestamp = precise_origin_timestamp;

            let ingress_timestamp = base.local_time();
            // assume this is two-step for now
            let offset = ingress_timestamp
                - precise_origin_timestamp.unwrap_or_default().into_inner()
                - correction_field.unwrap_or_default();

            self.offset_from_master = Some(offset);

            // let offset_from_master = tracing::info!("\n{self:?}");
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub(super) struct Syncs {
        pub last: Option<Base>,
        pub count: u64,
    }

    impl Syncs {
        pub fn new(update: &update::Sync) -> Self {
            Self {
                last: Some(update.base),
                count: 1,
            }
        }

        pub fn apply(&mut self, update: &update::Sync) -> Result<()> {
            let latest = update.base;
            if update.flags.is_good_sync() {
                if let Some(last) = self.last.as_mut() {
                    match last.seq_variance(&latest) {
                        Some(1) => (),
                        Some(variance) => tracing::warn!("syncs: sequence variance={variance}"),
                        None => {
                            tracing::info!("sequence num wrap: {} {}", last.seq_id, latest.seq_id);
                        }
                    }

                    self.count += 1;
                    *last = latest;

                    return Ok(());
                }
            }

            let error = "invalid flags";
            tracing::warn!("{error}: flags={:#?}", update.flags);
            Err(anyhow::anyhow!(error))
        }

        pub fn take_one(&mut self) -> Option<u64> {
            if let Some(reduced_cnt) = self.count.checked_sub(1) {
                self.count = reduced_cnt;

                return Some(reduced_cnt);
            }

            None
        }
    }
}

pub(super) mod update {
    use super::{Base, Duration, GrandMaster, Header, Message, MsgFlags, Payload};
    use crate::kit::ptp::clock::Timestamp;

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
                    log_messsage_interval: Duration::milliseconds(i64::from(msg_interval)),
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
        pub correction_field: Option<Duration>,
        pub precise_origin_timestamp: Option<Timestamp>,
    }

    impl TryFrom<Message> for FollowUp {
        type Error = anyhow::Error;

        fn try_from(msg: Message) -> Result<Self, Self::Error> {
            let base = Base::new(&msg);

            if let Message {
                header: Header {
                    correction_field, ..
                },
                payload:
                    Payload::FollowUp {
                        precise_origin_timestamp,
                    },
                ..
            } = msg
            {
                return Ok(Self {
                    base,
                    correction_field,
                    precise_origin_timestamp,
                });
            }

            let error = "payload type mismatch";
            tracing::error!(error);
            Err(anyhow::anyhow!(error))
        }
    }

    pub struct Sync {
        pub base: Base,
        pub flags: MsgFlags,
    }

    impl From<Message> for Sync {
        fn from(msg: Message) -> Self {
            if let Some(correction) = msg.header.correction_field {
                tracing::info!("sync correction field: {correction:3.3?}");
            }

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
    announces: Option<track::Announces>,
    syncs: Option<track::Syncs>,
    follow_ups: Option<track::FollowUps>,
}

impl Master {
    pub fn got_announce(&mut self, update: update::Announce) {
        self.announces_mut().apply(update);
    }

    pub fn got_follow_up(&mut self, update: &update::FollowUp) {
        // the spec states a sync must arrive before processing a followup
        if self.syncs_mut().and_then(SyncsTrack::take_one).is_some() {
            // we've confirmed a sync proceeded this follow-up
            return self.follow_ups_mut().apply(update);
        }

        tracing::warn!("ignoring follow up before sync");
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

    fn announces_mut(&mut self) -> &mut AnnouncesTrack {
        self.announces.get_or_insert(AnnouncesTrack::default())
    }

    fn follow_ups_mut(&mut self) -> &mut FollowUpsTrack {
        self.follow_ups.get_or_insert(FollowUpsTrack::default())
    }

    fn syncs_mut(&mut self) -> Option<&mut SyncsTrack> {
        self.syncs.as_mut()
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
