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

pub(crate) mod status;
use bstr::ByteSlice;
pub use status::StatusCode;

pub(crate) mod method;
pub use method::Method;

pub(crate) mod header;
pub use header::Map;

pub mod codec;

use crate::Result;
use anyhow::anyhow;
use pretty_hex::PrettyHex;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct Frame {
    method: Method,
    path: String,
    headers: Map,
    body: Option<Vec<u8>>,
}

impl Frame {
    const MIN_BYTES: usize = 80;
    const SPACE: char = ' ';
    const PROTOCOL: &str = "RTSP/1.0";

    /// # Errors
    ///
    /// Will return `Err` if content length value can not
    /// be parsed into a usize
    pub fn content_len(&self) -> Result<Option<usize>> {
        self.headers.content_len()
    }

    #[must_use]
    pub fn min_bytes(cnt: usize) -> bool {
        cnt >= Self::MIN_BYTES
    }

    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn include_body(&mut self, src: &[u8]) {
        if let Ok(Some(len)) = self.headers.content_len() {
            self.body = Some(src[0..len].into());
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for Frame {
    type Error = anyhow::Error;

    #[inline]
    fn try_from(buf: &'a [u8]) -> Result<Self> {
        let src = buf.to_str()?.trim_end();

        // split on the protocol to validate the version and remove the protocol
        // text from further comparisons
        let chunks = src.split_once(Self::PROTOCOL);

        let maybe_frame = match chunks {
            Some((request, rest)) => {
                // the first line is the request: METHOD PATH RTSP/1.0
                let line = request.split_once(Self::SPACE);

                if let Some((method, path)) = line {
                    // get the header line slice and prepare the header map
                    let headers = rest.trim_start();
                    let mut header_map = Map::new();

                    for line in headers.lines() {
                        header_map.append(line)?;
                    }

                    if !header_map.is_empty() {
                        return Ok(Self {
                            method: Method::from_str(method)?,
                            path: path.to_owned(),
                            headers: header_map,
                            ..Self::default()
                        });
                    }
                }

                Ok(Self::default())
            }
            None => Err(anyhow!("protocol version not found")),
        };

        // match maybe_frame {
        //     Ok(frame) if frame.content_len()
        // }

        // if let frame = maybe_frame? && frame.content_len() {}

        maybe_frame
    }
}

impl fmt::Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "\n{} {} ", self.method, self.path)?;

        for (key, val) in self.headers.headers() {
            writeln!(f, "{key}: {val}")?;
        }

        if let Some(body) = &self.body {
            writeln!(f, "CONTENT {:?}", body.hex_dump())?;
        }

        Ok(())
    }
}
