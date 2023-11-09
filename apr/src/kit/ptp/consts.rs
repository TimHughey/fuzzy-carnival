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

// use super::MetaData;
// use once_cell::sync::Lazy;

// pub(super) const CLOCK_IDENTITY_BYTES: usize = 8;
// pub(super) const IDENTITY_LEN: usize = 8;
pub(super) const MASK_HIGH: u8 = 0xf0;
pub(super) const MASK_LOW: u8 = 0x0f;

// pub(super) static HEADER_LEN: Lazy<usize> = Lazy::new(|| {
//     [
//         MetaData::buf_size_of(), // metadata (transport specific, msg id, version)
//         size_of::<u8>(),         // domain num
//         size_of::<u8>(),         // reserved_b
//         size_of::<u16>(),        // flags
//         size_of::<u64>(),        // correction field
//         size_of::<u32>(),        // reserved_l
//         CLOCK_IDENTITY_BYTES,    // clock identity bytes
//         size_of::<u16>(),        // source port id
//         size_of::<u16>(),        // sequence num
//         size_of::<u8>(),         // control field
//         size_of::<u8>(),         // log message period
//     ]
//     .iter()
//     .sum()
// });

// pub(super) static GRANDMASTER_SIZEOF: Lazy<usize> = Lazy::new(|| {
//     [
//         size_of::<u8>(),  // priority one
//         size_of::<u32>(), // quality
//         size_of::<u8>(),  // priority two
//         IDENTITY_LEN,     // clock identity bytes
//     ]
//     .iter()
//     .sum()
// });
