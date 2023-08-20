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

use std::{collections::BTreeMap, fmt, fmt::Display, io::Cursor};

extern crate plist;
use plist::Dictionary;

extern crate serde_derive;

use anyhow::{anyhow, Result};
use arrayvec::ArrayVec;
use bstr::ByteSlice;
use bytes::Buf;
use thiserror::Error;

#[allow(unused_imports)]
use tracing::{debug, error, info};

use crate::cmd::RespCode;

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
    #[error("message body contains content body for {0}")]
    ContentBody(String),
    #[error("invalid request")]
    Request(String),
    #[default]
    #[error("unknown error")]
    Default,
}

#[derive(Default, Debug)]
pub enum ContentType {
    Plist(Dictionary),
    Bulk(Vec<u8>),
    #[default]
    Empty,
}

const CONTENT_LENGTH: &str = "Content-Length";
const CONTENT_TYPE: &str = "Content-Type";

const APP_PLIST: &str = "application/x-apple-binary-plist";
const RTSP_VER: &str = "RTSP/1.0";

#[derive(Debug, Default, PartialEq)]
pub struct Request {
    pub method: String,
    pub path: String,
}

impl Request {
    pub fn new(src: &str) -> Result<Request, FrameError> {
        use tinyvec::ArrayVec;

        const KIND_IDX: usize = 0;
        const PATH_IDX: usize = 1;
        const PROTOCOL_IDX: usize = 2;
        const MAX_PARTS: usize = 3;

        let p = src
            .split_ascii_whitespace()
            .take(MAX_PARTS)
            .collect::<ArrayVec<[&str; MAX_PARTS]>>();

        if (p.len() != MAX_PARTS) || (p[PROTOCOL_IDX] != RTSP_VER) {
            return Err(FrameError::Request(src.to_string()));
        }

        Ok(Request {
            method: p[KIND_IDX].into(),
            path: p[PATH_IDX].into(),
        })
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Reply {
    headers: tinyvec::ArrayVec<[(String, String); 10]>,
    content: Option<ContentType>,
    resp_code: RespCode,
}

#[derive(Debug)]

pub struct Frame {
    pub request: Request,
    pub headers: BTreeMap<String, String>,
    pub content: ContentType,
    pub reply: Option<Reply>,
}

impl Frame {
    pub fn content_ref(&self) -> &ContentType {
        &self.content
    }

    pub fn path(&self) -> &str {
        self.request.path.as_str()
    }

    pub fn path_and_content(&self) -> (&str, &ContentType) {
        (self.request.path.as_str(), &self.content)
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
                let mut request = Request::default();
                let mut headers = BTreeMap::<String, String>::new();

                for (n, line) in hdr_block.lines().enumerate() {
                    match n {
                        // line=0 is the method, url and protocol
                        n if n == 0 => {
                            request = Request::new(line)?;
                        }

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

                // NOTE
                // consume_body moves the cursor position forward, as needed
                let content = consume_body(src, &headers)?;

                // NOTE
                // the cursor position at the end of this function is used as the
                // length of the src data processed for comsumption by the caller

                Ok(Frame {
                    request,
                    headers,
                    content,
                    reply: None,
                })
            }
            Some(_) => Err(FrameError::Incomplete),
            None => Err(FrameError::Incomplete),
        }
    }

    pub fn seq_num(&self) -> Result<u32> {
        if let Some(sn) = self.headers.get("CSeq") {
            let sn: u32 = sn.parse()?;
            return Ok(sn);
        }

        Err(anyhow!("CSeq header not available"))
    }
}

impl Display for Request {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{} {} RTSP/1.0", self.method, self.path)
    }
}

impl Display for Frame {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        let content = || match self.content_ref() {
            ContentType::Plist(plist) => format!("\n{:?}", plist),
            _ => String::new(),
        };

        write!(
            fmt,
            "frame\n{}\n{:#?}\n{}",
            self.request,
            self.headers,
            content()
        )
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
    headers: &BTreeMap<String, String>,
) -> Result<ContentType, FrameError> {
    if src.remaining() == 0
        || !headers.contains_key(CONTENT_TYPE)
        || !headers.contains_key(CONTENT_LENGTH)
    {
        return Ok(ContentType::Empty);
    }

    // we've confirmed the key exists so safe to unwrap
    let cnt = headers.get(CONTENT_LENGTH).unwrap().parse::<usize>()?;
    let raw = src.chunk()[0..cnt].as_bstr();

    match headers.get(CONTENT_TYPE) {
        // handle binary plists
        Some(t) if t == APP_PLIST => {
            let plist = plist::from_bytes::<Dictionary>(raw)?;
            src.advance(cnt);
            Ok(ContentType::Plist(plist))
        }

        // default if unknown content type
        Some(_) => {
            let raw = raw.to_vec();
            src.advance(cnt);

            Ok(ContentType::Bulk(raw))
        }
        None => Ok(ContentType::Empty),
    }
}

#[test]
fn can_create_request() -> Result<()> {
    let src: &str = r#"GET /info RTSP/1.0"#;

    let r = Request::new(src)?;

    assert!(r.method == "GET");
    assert!(r.path == "/info");

    Ok(())
}
