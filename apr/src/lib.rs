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

pub(crate) mod flags;
pub use flags::FeatureFlags;

pub mod server; // AirPlay Server (receiver)

pub(crate) mod session;
pub use session::Session;

pub(crate) mod frame;
pub use frame::ContentType;
pub use frame::Frame;
pub use frame::FrameError;

pub(crate) mod particulars;
pub use particulars::Particulars;

pub(crate) mod serdis;

pub(crate) mod shutdown;
use shutdown::Shutdown;

// This is defined as a convenience.
pub type Result<T> = anyhow::Result<T>;
