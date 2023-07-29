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

use std::{collections::HashMap, convert::From, fmt, fmt::Display, io::Cursor};

extern crate plist;
use plist::Dictionary;

extern crate serde_derive;

use arrayvec::ArrayVec;
use bstr::ByteSlice;
use bytes::Buf;
use derive_new::new;
#[allow(unused_imports)]
use tracing::{debug, error, info};

#[derive(Debug)]
pub enum ContentType {
    Plist(Dictionary),
    Raw(Vec<u8>),
}

const CONTENT_LENGTH: &str = "Content-Length";
const CONTENT_TYPE: &str = "Content-Type";

const APP_PLIST: &str = "application/x-apple-binary-plist";
const PLIST_PREFIX: &str = "bplist";
const RTSP_VER: &str = "RTSP/1.0";

#[derive(Debug, PartialEq)]
pub enum Method {
    Get(String),
    Unknown,
}

impl Method {
    pub fn new(src: &str) -> Result<Method, Error> {
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
            return Err(Error::ProtocolError);
        }

        let path = || p[PATH_IDX].to_owned();

        match &p[KIND_IDX] {
            k if k == "GET" => Ok(Method::Get(path())),
            _ => Err(Error::ProtocolError),
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

    pub fn parse(src: &mut Cursor<&[u8]>) -> Result<Frame, Error> {
        use bstr::B;
        use Error::Incomplete;

        let needle = B("\r\n\r\n");

        match src.chunk().find(needle) {
            Some(dpos) if dpos > 0 => {
                // convert the first block to str for easy extraction
                // of relevant data.  return Err if conversion to str
                // fails (indicating bad data)
                let hdr_block = src.get_ref()[0..dpos].to_str()?;

                // establish destinations for the data we'll extract
                let mut method: Option<Method> = None;
                let mut headers: HashMap<String, String> = HashMap::new();

                for (n, line) in hdr_block.lines().enumerate() {
                    match n {
                        // line=0 is the method, url and protocol
                        n if n == 0 => method = Some(Method::new(line)?),

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
                        _ => Err(Error::ProtocolError)?,
                    }
                }

                // done processing the prelude and headers block, move cursor
                src.advance(dpos + needle.len());

                let content = consume_body(src, &headers)?;
                let consumed = src.position();

                // NOTE
                // the cursor position at the end of this function is used as the
                // length of the src data processed for comsumption by the caller

                match method {
                    Some(method) => Ok(Frame::new(method, headers, content, consumed)),
                    None => Err(Error::ProtocolError),
                }
            }
            Some(_) => Err(Incomplete),
            None => Err(Incomplete),
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
) -> Result<Option<ContentType>, Error> {
    use plist::from_bytes;

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
            let prefix = raw[0..PLIST_PREFIX.len()].to_str()?;

            if prefix == PLIST_PREFIX {
                let plist = from_bytes::<Dictionary>(raw)?;
                src.advance(cnt);
                return Ok(Some(ContentType::Plist(plist)));
            }

            Err(Error::InvalidPlist)
        }

        // default if unknown content type
        Some(_) => {
            let raw = raw.to_vec();
            src.advance(cnt);

            Ok(Some(ContentType::Raw(raw)))
        }
        None => Err(Error::ProtocolError),
    }
}

#[test]
fn can_create_method_for_get() -> Result<(), Error> {
    let src: &str = r#"GET /info RTSP/1.0"#;

    let method = Method::new(src)?;

    assert!(matches!(method, Method::Get { .. }));

    Ok(())
}

#[derive(Debug)]
pub enum Error {
    Incomplete,
    ProtocolError,
    InvalidPlist,
    /// Invalid message encoding
    Other(crate::Error),
}

impl From<String> for Error {
    fn from(src: String) -> Error {
        Error::Other(src.into())
    }
}

impl From<&str> for Error {
    fn from(src: &str) -> Error {
        src.to_string().into()
    }
}

impl From<bstr::Utf8Error> for Error {
    fn from(_src: bstr::Utf8Error) -> Error {
        "protocol error; invalid frame format".into()
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(_src: std::num::ParseIntError) -> Error {
        "protocol error; invalid frame format".into()
    }
}

impl From<plist::Error> for Error {
    fn from(src: plist::Error) -> Error {
        src.into()
    }
}

// impl From<TryFromIntError> for Error {
//     fn from(_src: TryFromIntError) -> Error {
//         "protocol error; invalid frame format".into()
//     }
// }

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Incomplete => "stream ended early".fmt(fmt),
            Error::ProtocolError => "protocol error".fmt(fmt),
            Error::InvalidPlist => "invalid plist".fmt(fmt),
            Error::Other(err) => err.fmt(fmt),
        }
    }
}
