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

pub mod codec;
pub(crate) mod header;
pub(crate) mod method;
pub(crate) mod msgs;
pub(crate) mod status;

pub use header::ContType as HeaderContType;
pub use header::List as HeaderList;
pub use method::Method;
pub use msgs::Body;
pub use msgs::Frame;
pub use msgs::Inflight as InflightFrame;
pub use msgs::Response;
pub use status::Code as StatusCode;

#[cfg(test)]
mod tests;
