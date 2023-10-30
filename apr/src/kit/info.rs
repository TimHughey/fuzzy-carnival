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

use super::msg::{Frame, Response};
use crate::{BytesWrite, FlagsCalc, HostInfo, Result};
use bytes::BytesMut;
use once_cell::sync::OnceCell;
use plist::Dictionary;
use std::path::Path;

struct Xml {
    cell: OnceCell<Vec<u8>>,
}

impl Xml {
    const XML_FILE: &str = "plists/get_info_resp.plist";

    pub const fn new() -> Self {
        Self {
            cell: OnceCell::new(),
        }
    }
    pub fn bytes(&self) -> &[u8] {
        self.cell
            .get_or_init(|| {
                let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
                let path = Path::new(dir.as_str()).join(Self::XML_FILE);
                std::fs::read(&path)
                    .unwrap_or_else(|_err| panic!("failed to info response: {}", path.display()))
            })
            .as_slice()
    }
}

static XML: Xml = Xml::new();

#[allow(clippy::no_effect_underscore_binding)]
pub fn make_response(frame: Frame) -> Result<Response> {
    use plist::Value::{Integer as ValInt, String as ValString};

    let cseq = frame.cseq;
    let _content = frame.content;

    let mut dict: Dictionary = plist::from_bytes(XML.bytes())?;

    for (k, v) in [
        ("features", ValInt(FlagsCalc::features_as_u64().into())),
        ("statusFlags", ValInt(FlagsCalc::status_as_u32().into())),
        ("deviceID", ValString(HostInfo::id_as_str().into())),
        ("pi", ValString(HostInfo::id_as_str().into())),
        ("name", ValString(HostInfo::receiver_as_str().into())),
        ("model", ValString("Hughey".into())),
    ] {
        dict.insert(k.into(), v);
    }

    let mut binary = BytesMut::with_capacity(1024);
    plist::to_writer_binary(BytesWrite(&mut binary), &dict)?;

    Ok(Response::ok_octet_stream(cseq, &binary))
}
