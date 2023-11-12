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

use std::{collections::VecDeque, ops::Div};
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

#[derive(Debug)]
pub struct Context {
    pub last_at: Option<Instant>,
    pub message_freq: VecDeque<Duration>,
    pub counters: Counters,
}

#[derive(Copy, Clone)]
pub struct FreqMetrics {
    pub min: Duration,
    pub avg: Duration,
    pub max: Duration,
    pub cnt: usize,
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

impl Context {
    pub fn new() -> Self {
        Self {
            last_at: None,
            message_freq: VecDeque::with_capacity(20),
            counters: Counters::default(),
        }
    }

    pub fn average_freq(&self) -> Option<Duration> {
        let sum: Duration = self.message_freq.iter().sum();

        if let Ok(len) = u32::try_from(self.message_freq.len()) {
            return Some(sum.div(len));
        }

        None
    }

    pub fn freq_metrics(&self) -> Option<FreqMetrics> {
        let fm = &self.message_freq;
        let min = fm.iter().min();
        let avg = self.average_freq();
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
        let last_at = self.last_at.get_or_insert(Instant::now());
        let now = Instant::now();
        let since_last = now.duration_since(*last_at);

        if since_last >= Duration::from_nanos(500) {
            if self.message_freq.len() == self.message_freq.capacity() {
                let _discard = self.message_freq.pop_front();
            }

            self.message_freq.push_back(since_last);
            *last_at = now;
        }
    }

    pub fn inc_count(&mut self, count: Count) {
        self.counters.inc(count);
    }
}
