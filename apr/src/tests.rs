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

// #[test]
// fn can_create_host_info() {
//     use crate::HostInfo;
// }

use tracing_test::traced_test;

#[cfg(test)]
use crate::HostInfo;

#[traced_test]
#[test]
fn can_lazy_create_host_info() {
    let info = HostInfo::get();
    let name = HostInfo::name_as_str();

    println!("{info:#?}");

    assert!(name.is_ascii());
    assert!(!HostInfo::id_as_str().contains(':'));

    assert_eq!(info.sign_seed.len(), 32);
}
