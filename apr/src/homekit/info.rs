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
    rtsp::{Body, Frame, Response},
    FlagsCalc, HostInfo, Result,
};
use bytes::BytesMut;
use once_cell::sync::OnceCell;
use plist::Dictionary;
use std::{io, path::Path};

pub struct Xml {
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

fn body() -> Result<Body> {
    use plist::Value::{Integer as ValInt, String as ValString};

    // Right now `write!` on `Vec<u8>` goes through io::Write and is not
    // super speedy, so inline a less-crufty implementation here which
    // doesn't go through io::Error.
    struct BytesWrite<'a>(&'a mut BytesMut);

    impl io::Write for BytesWrite<'_> {
        fn write(&mut self, s: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(s);
            Ok(s.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

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

    Ok(Body::OctetStream(binary.into()))
}

pub fn response(frame: Frame) -> Result<Response> {
    use crate::rtsp::{HeaderContType::AppAppleBinaryPlist as Plist, StatusCode};

    let body = body()?;

    Ok(Response {
        status_code: StatusCode::OK,
        headers: frame.headers.make_response(Plist, body.len()),
        body,
        homekit: frame.homekit,
    })
}

#[cfg(test)]
mod tests {

    #[test]
    pub fn can_create_body() -> crate::Result<()> {
        let body = super::body()?;

        println!("{body}");

        assert_eq!(body.len(), 512);

        Ok(())
    }
}
