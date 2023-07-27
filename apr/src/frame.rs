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

use std::{collections::HashMap, convert::From, fmt, io::Cursor};

extern crate plist;
use plist::Dictionary;

extern crate serde_derive;

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

#[derive(Debug, new)]
#[allow(dead_code)]
pub struct Frame {
    method: Option<String>,
    path: Option<String>,
    headers: HashMap<String, String>,
    content: Option<Vec<u8>>,
}

impl Frame {
    pub fn get_content(&self) -> Result<ContentType, Error> {
        use plist::from_bytes;

        // has_content() allows safe unwrapping
        if self.has_content() {
            match self.headers.get(CONTENT_TYPE) {
                Some(t) if t == APP_PLIST => {
                    if let Some(content) = &self.content {
                        if let Ok(prefix) = content[0..PLIST_PREFIX.len()].to_str() {
                            if prefix == PLIST_PREFIX {
                                let plist = from_bytes::<Dictionary>(content);
                                return Ok(ContentType::Plist(plist.ok().unwrap()));
                            }
                        }

                        Err(Error::InvalidPlist)
                    } else {
                        Err(Error::ProtocolError)
                    }
                }
                Some(_) => Ok(ContentType::Raw(self.content.to_owned().unwrap())),
                None => Err(Error::ProtocolError),
            }
        } else {
            Err(Error::ProtocolError)
        }
    }

    pub fn check(src: &mut Cursor<&[u8]>) -> Result<(), Error> {
        use bstr::B;
        use Error::Incomplete;

        let splitter = B("\r\n\r\n");

        match src.get_ref().split_str(splitter).count() {
            // complete message contains two separators
            parts if parts < 2 => Err(Incomplete),
            parts if parts == 2 => {
                let needle = splitter;

                match src.get_ref().rfind(needle) {
                    Some(delim) if delim != 0 => {
                        {
                            let msg = src.chunk()[0..delim].to_str()?;
                            debug!("complete message:\n{}", msg);
                        }

                        // if there is content be sure to include it
                        if let Some(cnt) = get_content_len(src.chunk()) {
                            src.advance(cnt);
                        }

                        src.advance(delim + needle.len());

                        debug!(
                            "cursor_pos={} remaining={}",
                            src.position(),
                            src.remaining()
                        );

                        Ok(())
                    }
                    _ => Err(Incomplete),
                }
            }

            parts => {
                error!("parts found={}", parts);
                Err("invalid number of separators".into())
            }
        }
    }

    pub fn has_content(&self) -> bool {
        self.headers.contains_key(CONTENT_LENGTH)
            && self.headers.contains_key(CONTENT_TYPE)
            && self.content.is_some()
    }

    pub fn parse(src: &mut Cursor<&[u8]>) -> Result<Frame, Error> {
        use bstr::B;
        use Error::Incomplete;

        const CONTENT_LENGTH: &str = "Content-Length";
        let needle = B("\r\n\r\n");

        match src.chunk().find(needle) {
            Some(dpos) if dpos > 0 => {
                // convert the first block to str for easy extraction
                // of relevant data.  return Err if conversion to str
                // fails (indicating bad data)
                let hdr_block = src.get_ref()[0..dpos].to_str()?;

                // establish destinations for the data we'll extract
                let mut method: Option<String> = None;
                let mut path: Option<String> = None;
                let mut headers: HashMap<String, String> = HashMap::new();
                let mut content: Option<Vec<u8>> = None;

                let lines = hdr_block.lines();

                lines.enumerate().for_each(|e| match e {
                    // we use enumerate here to handle the first line differently
                    // than the rest.  the first line is the method, path and protocol
                    (n, u) if n == 0 => {
                        let mut prelude = u.split_ascii_whitespace();
                        if let (Some(m), Some(p)) = (prelude.next(), prelude.next()) {
                            method = Some(m.to_string());
                            path = Some(p.to_string());
                        }
                    }
                    // subsequent lines are headers
                    (_n, u) => {
                        let mut p = u.split(": ");

                        if let (Some(k), Some(v)) = (p.next(), p.next()) {
                            headers.insert(k.to_string(), v.to_string());
                        }
                    }
                });

                // done processing the prelude and headers block, move cursor
                src.advance(dpos + needle.len());

                // extract content, if present
                if let Some(content_len) = headers.get(CONTENT_LENGTH) {
                    let cnt: usize = content_len.parse()?;

                    if src.remaining() >= cnt {
                        content = Some(src.chunk()[0..cnt].to_vec());

                        // done extracting content, move cursor
                        src.advance(cnt);
                    } else {
                        return Err(Incomplete);
                    }
                }

                // NOTE
                // the cursor position at the end of this function is used as the
                // length of the src data processed so it can be consumed

                Ok(Frame::new(method, path, headers, content))
            }
            Some(_) => Err(Incomplete),
            None => Err(Incomplete),
        }
    }
}

#[allow(dead_code)]
fn get_content_len(src: &[u8]) -> Option<usize> {
    debug!("src={:?}", src.to_str());

    let mut src = Cursor::new(src);
    let needle = CONTENT_LENGTH;

    if let Some(cnt) = src.chunk().find(needle) {
        debug!("needle at pos={}", cnt);
        src.advance(cnt + CONTENT_LENGTH.len());

        if let Some(val) = src.chunk().words().next() {
            debug!("found word={}", val);
            if let Ok(len) = val.parse::<usize>() {
                return Some(len);
            }
        }
    }

    None
}
#[test]
fn can_get_content_len_from_cursor() {
    let inner: &[u8] = r#"Content-Type: application/x-apple-binary-plist
    Content-Length: 80"#
        .as_bytes();

    let src = Cursor::new(inner);

    let maybe_val = get_content_len(src.chunk());

    assert!(maybe_val.is_some());
    assert!(maybe_val.unwrap() == 80);
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
