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

use crate::{kit::tests::Data, Result};
use tracing_test::traced_test;

#[test]
#[traced_test]
fn can_create_inflight_for_setpeers() -> Result<()> {
    use crate::kit::msg::Inflight;

    // for creating lines iterator
    let mut msg = Data::get_msg("SETPEERS")?;

    let inflight = Inflight::try_from(&mut msg)?;

    tracing::info!("\n{inflight}");

    Ok(())
}

#[test]
fn can_create_inflight_for_setpeersx() -> Result<()> {
    use crate::kit::msg::{Frame, Inflight};
    // use pretty_hex::PrettyHex;

    // for creating lines iterator
    let mut msg = Data::get_setpeersx();

    let inflight = Inflight::try_from(&mut msg)?;

    println!("\n{inflight}");

    let frame = Frame::try_from(inflight)?;

    println!("\n{frame:#}");

    // tracing::info!("\nBUF {:?}", msg.hex_dump());

    Ok(())
}
