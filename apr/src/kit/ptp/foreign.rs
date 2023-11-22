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

use std::collections::VecDeque;

pub(self) use super::{
    protocol::{AnnounceData, Common, Error, FollowUpData, SyncData},
    ClockTimestamp, GrandMaster,
};
pub(self) use time::{Duration, Instant};

pub mod track {
    use super::{ClockTimestamp, Common, Duration};
    use std::collections::VecDeque;

    #[derive(Default, Debug)]
    pub struct Intervals {
        last: Option<Common>,
        durations: Option<VecDeque<Duration>>,
    }

    impl Intervals {
        pub fn check_if_master(
            &mut self,
            latest: Common,
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

            None
        }
    }
}

#[allow(unused)]
#[derive(Default, Debug)]
pub struct Announces {
    pub last: Option<Common>,
    pub master_at: Option<ClockTimestamp>,
    pub grandmaster: Option<GrandMaster>,
    pub intervals: track::Intervals,
}

impl Announces {
    pub fn apply(&mut self, data: AnnounceData) {
        let max_interval = data.log_message_interval;
        let common = data.common;

        match self.intervals.check_if_master(common, max_interval) {
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
                let grandmaster = data.grandmaster;

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

#[derive(Clone, Hash)]
pub struct Jitter {
    at: Instant,
    val: Duration,
}

#[allow(unused)]
impl Jitter {
    pub fn elapsed(&self, other: &Self) -> std::time::Duration {
        self.at.0.duration_since(other.at.0)
    }
}

#[derive(Default, Clone, Hash)]
pub struct FollowUps {
    pub last: Option<Common>,
    pub count: u64,
    pub correction_field: Duration,
    pub precise_origin_timestamp: ClockTimestamp,
    pub offset_from_master: Option<Duration>,
    pub jitter: VecDeque<Jitter>,
}

impl FollowUps {
    pub fn apply(&mut self, data: &FollowUpData) {
        let common = data.common;
        let correction = data.correction.unwrap_or_default();
        let precise = data.origin_timestamp.unwrap_or_default();

        // NOTE: two-step mode is validated when the Sync is received
        let offset = common.offset(precise, correction);

        if let Some(prev_offset) = self.offset_from_master {
            self.jitter.push_back(Jitter {
                at: common.ingress_at,
                val: offset - prev_offset,
            });

            while self.jitter.len() > 30 {
                self.jitter.pop_front();
            }
        }

        self.last = Some(common);
        self.count += 1;
        self.correction_field = correction;
        self.precise_origin_timestamp = precise;
        self.offset_from_master = Some(offset);

        // let offset =
        //     common.ingress_timestamp().into_inner() - precise.into_inner() - self.correction_field;

        //  let _jitter = self.offset_from_master.map(|prev| prev - offset);

        // if let Some(jitter) = jitter {
        //     tracing::info!("jitter={jitter:.3}");
        // }

        // self.offset_from_master = Some(offset);
    }
}

impl<'a> std::iter::Sum<&'a Self> for Jitter {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a Self>,
    {
        Self {
            at: Instant::now(),
            val: iter.map(|Jitter { at: _, val }| *val).sum(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Syncs {
    pub last: Option<Common>,
    pub count: u64,
}

impl Syncs {
    pub fn new(data: &SyncData) -> Self {
        Self {
            last: Some(data.common),
            count: 1,
        }
    }

    pub fn last_seq_id(&self) -> Option<u16> {
        self.last.map(|last| last.seq_id)
    }

    pub fn try_apply(&mut self, data: &SyncData) -> std::result::Result<(), Error> {
        let latest = data.common;
        let flags = data.flags;

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
        Err(Error::InvalidFlags { flags })
    }

    #[allow(unused)]
    pub fn take_one(&mut self) -> Option<u64> {
        if let Some(reduced_cnt) = self.count.checked_sub(1) {
            self.count = reduced_cnt;

            return Some(reduced_cnt);
        }

        None
    }
}

#[allow(unused)]
#[derive(Default)]

/// Representation of a Foreign Port Identity
///
/// Foreign ports are announced by the PTP instance which hosts the clock.
/// [``Syncs``] and [``FollowUps``] messages are sent by the foreign port
/// to provide precision time.
pub struct Port {
    seen_at: Option<Instant>,
    pub announces: Option<Announces>,
    pub(super) syncs: Option<Syncs>,
    pub(super) follow_ups: Option<FollowUps>,
}

impl Port {
    #[allow(unused)]
    pub fn new(data: AnnounceData) -> Self {
        let mut announces = Announces::default();
        announces.apply(data);

        Self {
            seen_at: Some(Instant::now()),
            announces: Some(announces),
            ..Default::default()
        }
    }

    pub fn announces_mut(&mut self) -> &mut Announces {
        self.announces.get_or_insert(Announces::default())
    }

    pub fn follow_ups_mut(&mut self) -> &mut FollowUps {
        self.follow_ups.get_or_insert(FollowUps::default())
    }

    pub fn jitter_mean(&self) -> Option<Duration> {
        self.follow_ups
            .as_ref()
            .and_then(|fup| match u32::try_from(fup.jitter.len()) {
                Ok(cnt) if cnt > 0 => {
                    let sum: Jitter = fup.jitter.iter().sum();

                    Some(sum.val / cnt)
                }
                Ok(_) | Err(_) => None,
            })
    }

    pub fn last_sync_seq_id(&self) -> Option<u16> {
        self.syncs.as_ref().and_then(Syncs::last_seq_id)
    }

    #[allow(unused)]
    pub fn syncs_mut(&mut self) -> Option<&mut Syncs> {
        self.syncs.as_mut()
    }

    pub fn have_announces(&self) -> bool {
        self.announces.is_some()
    }
}

impl std::fmt::Debug for FollowUps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let offset = if let Some(offset) = self.offset_from_master {
            format!("{offset}")
        } else {
            "None".into()
        };

        if f.alternate() {
            let jitter_sum: Jitter = self.jitter.iter().sum();
            let cnt = self.jitter.len();

            let mean = match u32::try_from(cnt) {
                Ok(len) => jitter_sum.val / len,
                Err(_) => Duration::default(),
            };

            f.debug_struct("FollowUps")
                .field(
                    "correction_field",
                    &format_args!("{:0.3}", self.correction_field),
                )
                .field("offset", &offset)
                .field("jitter_mean", &format_args!("{mean:.3}"))
                .finish_non_exhaustive()
        } else {
            f.debug_struct("FollowUps")
                .field("last", &self.last)
                .field("count", &self.count)
                .field("correction_field", &self.correction_field)
                .field("precise_origin_timestamp", &self.precise_origin_timestamp)
                .field("offset_from_mester", &offset)
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

impl std::fmt::Debug for Jitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Jitter")
            .field("ago", &format_args!("{:.3}", self.at.elapsed()))
            .field("val", &format_args!("{:.3}", self.val))
            .finish()
    }
}
