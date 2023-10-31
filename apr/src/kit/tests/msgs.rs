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
    kit::{
        methods::SetPeers,
        msg::{Frame, Inflight},
        tests::Data,
    },
    Result,
};
use tracing_test::traced_test;

#[test]
#[traced_test]
fn can_create_inflight_for_setpeers() -> Result<()> {
    use crate::kit::msg::Inflight;

    let mut msg = Data::get_msg("SETPEERS")?;
    let mut inflight = Inflight::default();
    inflight.absorb_buf(&mut msg)?;
    inflight.absorb_content(&mut msg);

    assert!(inflight.cseq.is_some_and(|cseq| cseq == 10));
    assert!(inflight.routing.is_some_and(|routing| {
        let (method, _path) = routing.parts_tuple();

        method.as_str() == "SETPEERS" && routing.is_rtsp()
    }));
    assert!(inflight.content.is_some_and(|content| {
        content.len == 86
            && content.kind.as_str() == "/peer-list-changed"
            && content.data.starts_with(b"bplist00\xA2\x01")
    }));

    const DACPD_ID_SAMPLE: &str = "4DEBD3E0FEF928B";

    assert!(inflight.metadata.is_some_and(|metadata| {
        metadata
            .active_remote
            .is_some_and(|active_remote| active_remote > 0)
            && metadata
                .dacpd_id
                .is_some_and(|dacpd_id| dacpd_id.len() == DACPD_ID_SAMPLE.len())
            && metadata
                .user_agent
                .is_some_and(|user_agent| user_agent.starts_with("AirPlay"))
    }));

    Ok(())
}

#[test]
fn can_create_inflight_for_setpeersx() -> Result<()> {
    use crate::kit::msg::{Frame, Inflight};

    let mut msg = Data::get_msg("SETPEERSX")?;
    let mut inflight = Inflight::default();
    inflight.absorb_buf(&mut msg)?;
    inflight.absorb_content(&mut msg);

    assert_eq!(inflight.block_len, None);
    assert!(inflight.cseq.is_some_and(|cseq| cseq == 10));
    assert!(inflight.content.is_some());
    assert!(inflight.metadata.is_some());

    let frame = Frame::try_from(inflight)?;

    assert_eq!(frame.cseq, 10);
    assert!(frame.content.is_some());

    if let Some(content) = frame.content.as_ref() {
        let plist_val: plist::Value = plist::from_bytes(&content.data)?;

        if let plist::Value::Array(arr) = plist_val {
            // let row0 = &arr[0];

            println!("{:#?}", arr[0]);
        }
    }

    assert!(frame.content.is_some_and(|content| content.len == 264
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
    let mut msg = Data::get_msg("SETPEERSX")?;
    let mut setpeers = SetPeers::default();

    let mut inflight = Inflight::default();

    inflight.absorb_buf(&mut msg)?;
    inflight.absorb_content(&mut msg);

    if let Ok(frame) = Frame::try_from(inflight) {
        let _response = setpeers.make_response(frame)?;

        tracing::info!("{setpeers:?}");
    }

    Ok(())
}
