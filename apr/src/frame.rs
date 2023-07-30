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

// use std::convert::TryInto;

use std::{collections::HashMap, fmt, fmt::Display, io::Cursor};

extern crate plist;
use plist::Dictionary;

extern crate serde_derive;

use anyhow::Result;
use arrayvec::ArrayVec;
use bstr::ByteSlice;
use bytes::Buf;
use derive_new::new;
use thiserror::Error;
#[allow(unused_imports)]
use tracing::{debug, error, info};

#[derive(Error, Debug, Default)]
pub enum FrameError {
    #[error("should be complete frame, continue reading")]
    Incomplete,
    #[error("line {0} should be a method line")]
    Method(String),
    #[error("{0} should be a handled method")]
    MethodUnknown(String),
    #[error("{found:?} should be a header line")]
    InvalidHeader { found: String },
    #[error("content length should be convertable to numeric")]
    InvalidContentLength(#[from] std::num::ParseIntError),
    #[error("should be valid binary plist")]
    InvalidPlist(#[from] plist::Error),
    #[error("message should be convertible to UTF8")]
    ProtocolError(#[from] bstr::Utf8Error),
    #[error("message body contain content body for {0}")]
    ContentBody(String),
    #[default]
    #[error("unknown error")]
    Default,
}

#[derive(Debug)]
pub enum ContentType {
    Plist(Dictionary),
    Raw(Vec<u8>),
}

const CONTENT_LENGTH: &str = "Content-Length";
const CONTENT_TYPE: &str = "Content-Type";

const APP_PLIST: &str = "application/x-apple-binary-plist";
const RTSP_VER: &str = "RTSP/1.0";

#[derive(Debug, Default, PartialEq)]
pub enum Method {
    Get(String),
    #[default]
    Unknown,
}

impl Method {
    pub fn new(src: &str) -> Result<Method, FrameError> {
        const KIND_IDX: usize = 0;
        const PATH_IDX: usize = 1;
        const PROTOCOL_IDX: usize = 2;

        const MAX_PARTS: usize = 3;
        let p = src
            .split_ascii_whitespace()
            .map(|s| s.to_string())
            .take(MAX_PARTS)
            .collect::<ArrayVec<String, MAX_PARTS>>();

        if p[PROTOCOL_IDX] != RTSP_VER {
            return Err(FrameError::Method(src.to_string()));
        }

        let path = || p[PATH_IDX].to_owned();

        match &p[KIND_IDX] {
            k if k == "GET" => Ok(Method::Get(path())),
            k => Err(FrameError::MethodUnknown(k.to_string())),
        }
    }
}

#[derive(Debug, new)]
#[allow(dead_code)]
pub struct Frame {
    pub method: Method,
    headers: HashMap<String, String>,
    content: Option<ContentType>,
    consumed: u64,
}

impl Frame {
    pub fn content_ref(&self) -> &Option<ContentType> {
        &self.content
    }

    pub fn parse(src: &mut Cursor<&[u8]>) -> Result<Frame, FrameError> {
        use bstr::B;

        let needle = B("\r\n\r\n");

        match src.chunk().find(needle) {
            Some(dpos) if dpos > 0 => {
                // convert the first block to str for easy extraction
                // of relevant data.  return Err if conversion to str
                // fails (indicating bad data)
                let hdr_block = src.get_ref()[0..dpos].to_str()?;

                // establish destinations for the data we'll extract
                let mut method: Method = Method::default();
                let mut headers: HashMap<String, String> = HashMap::new();

                for (n, line) in hdr_block.lines().enumerate() {
                    match n {
                        // line=0 is the method, url and protocol
                        n if n == 0 => method = Method::new(line)?,

                        // line=1.. are headers
                        _n if line.contains(':') => {
                            const MAX_PARTS: usize = 2;

                            let p = line
                                .split_ascii_whitespace()
                                .map(|s| s.trim_end_matches(':'))
                                .take(MAX_PARTS)
                                .collect::<ArrayVec<&str, MAX_PARTS>>();

                            headers.insert(p[0].to_string(), p[1].to_string());
                        }
                        _n => Err(FrameError::InvalidHeader {
                            found: line.to_string(),
                        })?,
                    }
                }

                // done processing the prelude and headers block, move cursor
                src.advance(dpos + needle.len());

                let content = consume_body(src, &headers)?;
                let consumed = src.position();

                // NOTE
                // the cursor position at the end of this function is used as the
                // length of the src data processed for comsumption by the caller

                Ok(Frame::new(method, headers, content, consumed))
            }
            Some(_) => Err(FrameError::Incomplete),
            None => Err(FrameError::Incomplete),
        }
    }
}

impl Display for Method {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Method::Get(path) => write!(fmt, "GET {}", path),
            Method::Unknown => write!(fmt, "UNKNOWN"),
        }
    }
}

impl Display for Frame {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        write!(fmt, "{} {}\n{:#?}", self.method, RTSP_VER, self.headers)
    }
}

///
/// Frame module utilities
///

///
/// Consume Message Body
///

fn consume_body(
    src: &mut Cursor<&[u8]>,
    headers: &HashMap<String, String>,
) -> Result<Option<ContentType>, FrameError> {
    if src.remaining() == 0
        || !headers.contains_key(CONTENT_TYPE)
        || !headers.contains_key(CONTENT_LENGTH)
    {
        return Ok(None);
    }

    // we've confirmed the key exists so safe to unwrap
    let cnt = headers.get(CONTENT_LENGTH).unwrap().parse::<usize>()?;
    let raw = src.chunk()[0..cnt].as_bstr();

    match headers.get(CONTENT_TYPE) {
        // handle binary plists
        Some(t) if t == APP_PLIST => {
            let plist = plist::from_bytes::<Dictionary>(raw)?;
            src.advance(cnt);
            Ok(Some(ContentType::Plist(plist)))
        }

        // default if unknown content type
        Some(_) => {
            let raw = raw.to_vec();
            src.advance(cnt);

            Ok(Some(ContentType::Raw(raw)))
        }
        None => Ok(None),
    }
}

#[test]
fn can_create_method_for_get() -> Result<()> {
    let src: &str = r#"GET /info RTSP/1.0"#;

    let method = Method::new(src)?;

    assert!(matches!(method, Method::Get { .. }));

    Ok(())
}
