// Rusty Pierre
//
// Copyright 2023 Tim Hughey
//
// Licensed under the Apache License, Version 2.0 (the "License");
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

// This is defined as a convenience.
pub type Result<T> = anyhow::Result<T>;

pub(crate) mod flags;
pub(crate) use flags::Calculated as FlagsCalc;

pub(crate) mod host;
pub use host::Info as HostInfo;
pub mod server; // AirPlay Server (receiver)

pub(crate) mod homekit;
pub use homekit::HomeKit;

pub mod asym;
pub mod rtsp;
pub mod serdis;

pub(crate) mod shutdown;
use shutdown::Shutdown;
