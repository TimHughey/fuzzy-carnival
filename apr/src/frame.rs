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

use bytes::Buf;
use derive_new::new;
use tracing::{error, info};

#[derive(Debug, new)]
#[allow(dead_code)]
pub struct Frame {
    method: Option<String>,
    url: Option<String>,
    headers: HashMap<String, String>,
    content: Option<Vec<u8>>,
}

impl Frame {
    pub fn check(src: &mut Cursor<&[u8]>) -> Result<(), Error> {
        use bstr::{ByteSlice, B};
        use Error::Incomplete;

        let splitter = B("\r\n\r\n");

        // let len = src.get_ref().len();

        match src.get_ref().split_str(splitter).count() {
            // complete message contains two separators
            parts if parts < 2 => Err(Incomplete),
            parts if parts == 2 => {
                let needle = splitter;

                match src.get_ref().rfind(needle) {
                    Some(delim) if delim != 0 => {
                        let msg = src.get_ref()[0..delim].to_str()?;
                        src.advance(msg.len() + needle.len());

                        // let body_start = delim + needle.len();
                        let body = &src.get_ref()[0..];
                        // let body_len = body.len();

                        let body_prefix = body[0..4].to_str()?;

                        info!("{}", msg);

                        info!("cursor_pos={} prefix={}", src.position(), body_prefix);

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

    pub fn parse(src: &mut Cursor<&[u8]>) -> Result<Frame, Error> {
        use bstr::{ByteSlice, B};
        use Error::Incomplete;

        let needle = B("\r\n\r\n");

        match src.get_ref().find(needle) {
            Some(dpos) if dpos > 0 => {
                let mut method: Option<String> = None;
                let mut url: Option<String> = None;
                let mut headers: HashMap<String, String> = HashMap::new();
                let mut content: Option<Vec<u8>> = None;

                let lines = src.get_ref()[0..dpos].lines();

                lines.enumerate().for_each(|e| match e {
                    (n, u) if n == 0 && u.is_utf8() => {
                        let mut p = u.split_str(B(" "));
                        if let Some(Ok(s)) = p.next().map(|x| x.to_str()) {
                            method = Some(s.to_string());
                        }

                        if let Some(Ok(s)) = p.next().map(|s| s.to_str()) {
                            url = Some(s.to_string());
                        }
                    }
                    (_n, u) if u.is_utf8() => {
                        let mut p = e.1.split_str(B(": "));

                        if let (Some(Ok(k)), Some(Ok(v))) =
                            (p.next().map(|x| x.to_str()), p.next().map(|x| x.to_str()))
                        {
                            headers.insert(k.to_string(), v.to_string());
                        }
                    }
                    (_, _) => (),
                });

                src.advance(dpos + needle.len());

                if let Some(Ok(cnt)) = headers.get("Content-Length").map(|x| x.parse::<usize>()) {
                    content = Some(src.get_ref()[0..cnt].to_vec());

                    src.advance(cnt);
                }

                Ok(Frame::new(method, url, headers, content))
            }
            Some(_) => Err(Incomplete),
            None => Err(Incomplete),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Incomplete,
    ProtocolError,
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
            Error::Other(err) => err.fmt(fmt),
        }
    }
}
