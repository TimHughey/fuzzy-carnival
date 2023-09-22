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

use super::{Tag, TagVal, TagVariant};
use anyhow::anyhow;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Generic(u8);

impl From<u8> for Generic {
    fn from(val: u8) -> Self {
        Self(val)
    }
}

#[derive(Debug, Clone)]
pub enum Verify {
    Msg01 = 1,
    Msg02 = 2,
    Msg03 = 3,
    Msg04 = 4,
}

impl TryFrom<Tag> for Verify {
    type Error = anyhow::Error;

    fn try_from(tlv: Tag) -> crate::Result<Self> {
        match tlv {
            Tag {
                variant: TagVariant::State,
                val: TagVal::State(s),
            } => Self::try_from(s),
            tlv => Err(anyhow!("conversion from generic state failed: {tlv:?}")),
        }
    }
}

impl TryFrom<Generic> for Verify {
    type Error = anyhow::Error;

    fn try_from(val: Generic) -> crate::Result<Self> {
        match val.0 {
            1 => Ok(Self::Msg01),
            2 => Ok(Self::Msg02),
            3 => Ok(Self::Msg03),
            4 => Ok(Self::Msg04),
            n => Err(anyhow!("unknown verify state: {n}")),
        }
    }
}
