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
        Announces as TrackAnnounces, FollowUps as TrackFollowUps, Syncs as TrackSyncs,
    },
    protocol::Payload,
    ClockTimestamp, GrandMaster, Header, Message, Result,
};

pub(self) use time::{Duration, Instant};

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Base {
    pub ingress_timestamp: ClockTimestamp,
    pub seq_id: u16,
}

impl Base {
    pub fn new(msg: &Message) -> Self {
        Self {
            ingress_timestamp: msg.metadata.reception_timestamp,
            seq_id: msg.header.sequence_id,
        }
    }

    pub fn ingress_timestamp(&self) -> ClockTimestamp {
        self.ingress_timestamp
    }

    pub fn interval(&self, latest: &Base) -> Duration {
        let e_latest = latest.ingress_timestamp.into_inner();
        let e_arrival = self.ingress_timestamp.into_inner();

        e_arrival - e_latest
    }

    pub fn seq_variance(&self, latest: &Self) -> Option<u16> {
        latest.seq_id.checked_sub(self.seq_id)
    }
}

pub mod track {
    use super::{update, Base, ClockTimestamp, Duration, GrandMaster, Message, Payload};
    use crate::Result;
    use std::collections::VecDeque;

    #[derive(Default, Debug)]
    pub(super) struct Intervals {
        last: Option<Base>,
        durations: Option<VecDeque<Duration>>,
    }

    impl Intervals {
        pub fn check_if_master(
            &mut self,
            latest: Base,
            max_interval: Duration,
        ) -> Option<ClockTimestamp> {
            let intervals = self
                .durations
                .get_or_insert_with(|| VecDeque::with_capacity(5));

            // ensure we're considering four intervals
            while intervals.len() > 4 {
                intervals.pop_front();
            }

            let last = self.last.as_mut();

            if let Some(last) = last {
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
                intervals.push_back(interval);

                *last = latest;

                if intervals.len() >= 4 {
                    // now sum all the known intervals
                    let sum: Duration = intervals.iter().sum();

                    if sum <= u32::try_from(intervals.len()).unwrap() * max_interval {
                        return Some(latest.ingress_timestamp);
                    }
                }
            }

            self.last.get_or_insert(latest);

            // self.last = Some(latest);
            None
        }
    }

    #[allow(unused)]
    #[derive(Default, Debug)]
    pub(super) struct Announces {
        pub last: Option<Base>,
        pub master_at: Option<ClockTimestamp>,
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

    #[derive(Default, Clone, Hash)]
    pub struct FollowUps {
        pub last: Base,
        pub count: u64,
        pub correction_field: Duration,
        pub precise_origin_timestamp: ClockTimestamp,
        pub offset_from_master: Duration,
    }

    impl FollowUps {
        pub fn try_apply(&mut self, msg: &Message) -> Result<()> {
            let base = Base::new(msg);
            let correction_field = msg.correction_field();

            if let Message {
                payload:
                    Payload::FollowUp {
                        precise_origin_timestamp,
                    },
                ..
            } = msg
            {
                let precise = precise_origin_timestamp.unwrap_or_default();

                self.last = base;
                self.count += 1;
                self.correction_field = correction_field.unwrap_or_default();
                self.precise_origin_timestamp = precise_origin_timestamp.unwrap_or_default();

                // assume this is two-step for now
                let offset = base.ingress_timestamp().into_inner()
                    - precise.into_inner()
                    - self.correction_field;

                self.offset_from_master = offset;

                return Ok(());
            }

            let error = "payload mismatch";
            tracing::error!("{error}: {:#?}", msg.payload);
            Err(anyhow::anyhow!(error))
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct Syncs {
        pub last: Option<Base>,
        pub count: u64,
    }

    impl Syncs {
        pub fn new(msg: &Message) -> Self {
            Self {
                last: Some(Base::new(msg)),
                count: 1,
            }
        }

        pub fn try_apply(&mut self, msg: &Message) -> Result<()> {
            let latest = Base::new(msg);
            let flags = msg.header.flags;

            if flags.is_good_sync() {
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
            tracing::warn!("{error}: flags={:#?}", flags);
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
    use super::{Base, Duration, GrandMaster, Header, Message, Payload};

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
}

#[allow(unused)]
#[derive(Default)]

/// Representation of a Foreign Port Identity
///
/// Foreign ports are announced by the PTP instance which hosts the clock,
/// send sync messages and followups to provide precise time information.
pub struct Port {
    seen_at: Option<Instant>,
    announces: Option<track::Announces>,
    pub(super) syncs: Option<track::Syncs>,
    pub(super) follow_ups: Option<track::FollowUps>,
}

impl Port {
    pub fn got_announce(&mut self, update: update::Announce) {
        self.announces_mut().apply(update);
    }

    pub fn got_follow_up(&mut self, msg: &Message) -> Result<()> {
        // the spec states a sync must arrive before processing a followup
        if self.syncs_mut().and_then(TrackSyncs::take_one).is_some() {
            // we've confirmed a sync proceeded this follow-up

            return self.follow_ups_mut().try_apply(msg);

            // return self.follow_ups_mut().apply(update);
        }

        tracing::warn!("ignoring follow up before sync");

        Ok(())
    }

    fn announces_mut(&mut self) -> &mut TrackAnnounces {
        self.announces.get_or_insert(TrackAnnounces::default())
    }

    fn follow_ups_mut(&mut self) -> &mut TrackFollowUps {
        self.follow_ups.get_or_insert(TrackFollowUps::default())
    }

    fn syncs_mut(&mut self) -> Option<&mut TrackSyncs> {
        self.syncs.as_mut()
    }

    pub fn have_announces(&self) -> bool {
        self.announces.is_some()
    }
}

impl std::fmt::Debug for track::FollowUps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            f.debug_struct("FollowUps")
                .field(
                    "correction_field",
                    &format_args!("{:0.3}", self.correction_field),
                )
                .field("offset", &format_args!("{}", self.offset_from_master))
                .finish_non_exhaustive()
        } else {
            f.debug_struct("FollowUps")
                .field("last", &self.last)
                .field("count", &self.count)
                .field("correction_field", &self.correction_field)
                .field("precise_origin_timestamp", &self.precise_origin_timestamp)
                .field("offset_from_mester", &self.offset_from_master)
                .finish()
        }
    }
}

impl std::fmt::Debug for Port {
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

impl std::fmt::Display for Port {
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
