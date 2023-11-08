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

use crate::{
    kit::{methods::SetPeers, msg::Frame, tests::Data},
    Result,
};
use tracing_test::traced_test;

#[test]
fn can_create_inflight_for_setpeersx() -> Result<()> {
    let inflight = Data::get_inflight("SETPEERSX", None)?;

    assert_eq!(inflight.block_len, None);
    assert!(inflight.cseq.is_some_and(|cseq| cseq == 10));
    assert!(inflight.content.is_some());
    assert!(inflight.metadata.is_some());

    let frame = Frame::try_from(inflight)?;

    assert_eq!(frame.cseq, 10);
    assert!(frame.content.is_some());

    assert!(frame.content.is_some_and(|content| content.len == 448
        && content.kind.as_str() == "/peer-list-changed-x"
        && content.data.starts_with(b"bplist00")));

    let metadata = frame.metadata;

    assert!(metadata.active_remote.is_some_and(|v| v > 1));
    assert!(metadata
        .dacpd_id
        .is_some_and(|v| { v.as_bytes().iter().all(u8::is_ascii_hexdigit) }));

    Ok(())
}

#[test]
#[traced_test]
fn can_respond_to_setpeers_msg() -> Result<()> {
    let mut setpeers = SetPeers::default();

    let frame = Data::get_frame("SETPEERSX", None)?;
    let response = setpeers.response(frame)?;

    assert_eq!(response.status_code, 200);

    tracing::info!("{setpeers:#?}");

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn can_create_setup_step1_from_frame() -> Result<()> {
    use crate::kit::{methods::Setup, ListenersAndPorts};

    let frame = Data::get_frame("SETUP", Some(6))?;
    let mut listener_ports = ListenersAndPorts::new().await?;

    println!("{listener_ports:#?}");

    let ports = listener_ports.take_ports();

    let mut setup = Setup::default();
    let _response = setup.response(frame, ports)?;

    println!("{setup:#?}");

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn can_create_setup_step2_from_frame() -> Result<()> {
    use crate::kit::{methods::Setup, ListenersAndPorts};

    let frame1 = Data::get_frame("SETUP", Some(6))?;
    let frame2 = Data::get_frame("SETUP", Some(14))?;

    let mut listener_ports = ListenersAndPorts::new().await?;
    let ports = listener_ports.take_ports();

    let mut setup = Setup::default();

    let _response = setup.response(frame1, ports)?;
    let _response = setup.response(frame2, ports)?;
    println!("{setup:#?}");

    Ok(())
}

#[test]
fn can_handle_set_rate_and_anchor() -> Result<()> {
    let frame = Data::get_frame("SETRATEANCHORTIME", None)?;

    if let Frame {
        content: Some(content),
        ..
    } = frame
    {
        let val: plist::Value = content.try_into()?;

        println!("{val:#?}");
    }

    Ok(())
}
