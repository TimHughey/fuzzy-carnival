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

use bytes::{Buf, BytesMut};
use std::ops::Shr;

pub const MASK_HIGH: u8 = 0xf0;
pub const MASK_LOW: u8 = 0x0f;

pub fn make_array_n<const N: usize>(src: &mut BytesMut) -> [u8; N] {
    let mut array = [0u8; N];
    src.copy_to_bytes(N).copy_to_slice(array.as_mut());

    array
}

pub fn make_array_nlo<const N: usize, const L: usize, const O: usize>(
    src: &mut BytesMut,
) -> [u8; N] {
    let mut array = [0u8; N];
    src.copy_to_bytes(L).copy_to_slice(&mut array[O..]);

    array
}

pub fn nibble_high(byte: u8) -> u8 {
    (byte & MASK_HIGH).shr(4)
}

pub fn nibble_low(byte: u8) -> u8 {
    byte & MASK_LOW
}
