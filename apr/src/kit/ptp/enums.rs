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

pub(super) mod tlv {
    use crate::kit::ptp::anyhow;

    #[repr(u16)]
    #[derive(Debug, Default)]
    pub enum TypeValue {
        #[default]
        Reserved = 0,
        // Standard TLVs
        Management = 1,
        ManagementErrorstatus = 2,
        OrganizationExtension = 3,
        // Optional unicast message negotiation TLVs
        RequestUnicastTransmission = 4,
        GrantUnicastTransmission = 5,
        CancelUnicastTransmission = 6,
        AcknowledgeCancelUnicastTransmission = 7,
        // Optional path trace mechanism TLV
        PathTrace = 8,
        // Optional alternate timescale TLV
        AlternateTimeOffsetIndicator = 9,
        // there are more, but not needed yet
    }

    impl TypeValue {
        #[allow(unused)]
        fn discriminant(&self) -> *const u16 {
            (self as *const Self).cast::<u16>()
        }
    }

    impl TryFrom<u16> for TypeValue {
        type Error = anyhow::Error;
        fn try_from(value: u16) -> Result<Self, Self::Error> {
            Ok(match value {
                0 => Self::Reserved,
                1 => Self::Management,
                2 => Self::ManagementErrorstatus,
                3 => Self::OrganizationExtension,
                4 => Self::RequestUnicastTransmission,
                5 => Self::GrantUnicastTransmission,
                6 => Self::CancelUnicastTransmission,
                7 => Self::AcknowledgeCancelUnicastTransmission,
                8 => Self::PathTrace,
                9 => Self::AlternateTimeOffsetIndicator,
                v if (0x000a..0x1fff).contains(&v) => {
                    // tracing::debug!("found reserved value: {v}");
                    Self::Reserved
                }
                v => {
                    let error = "unknown tlv type";
                    tracing::error!("{error}: 0x{v:x}");
                    Err(anyhow!(error))?
                }
            })
        }
    }

    impl std::fmt::Display for TypeValue {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{self:?}")
        }
    }
}
