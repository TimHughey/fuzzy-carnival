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

use super::{header, HeaderList, Method, StatusCode};
use crate::{homekit::BlockLen, Result};
use anyhow::anyhow;
use bstr::ByteSlice;
use bytes::{BufMut, BytesMut};
use pretty_hex::PrettyHex;
use std::{fmt, path::PathBuf, str::FromStr};

#[derive(Debug, Default)]
#[allow(unused)]
pub struct Routing {
    method: Method,
    path: String,
}

impl TryFrom<BytesMut> for Routing {
    type Error = anyhow::Error;

    fn try_from(buf: BytesMut) -> Result<Self> {
        let idx = buf.find_char(' ').ok_or_else(|| {
            tracing::warn!("space delimiter not found in {:?}", buf.hex_dump());

            anyhow!("method, path not found")
        })?;

        let (method, path) = buf.split_at(idx);

        Ok(Self {
            method: Method::try_from(method.to_str()?)?,
            path: path.to_str()?.into(),
        })
    }
}

#[derive(Debug, Default)]
pub struct Inflight {
    pub routing: Option<Routing>,
    pub headers: Option<HeaderList>,
    pub body: Option<Body>,
    pub residual: Option<BytesMut>,
    pub block_len: Option<BlockLen>,
    pub content_len: Option<usize>,
}

impl Inflight {
    //
}

#[derive(Default)]
pub struct Frame {
    pub method: Method,
    pub path: String,
    pub headers: HeaderList,
    pub body: Body,
    pub consumed: usize,
    pub pending: Option<Pending>,
}

impl Frame {
    const SPACE: char = ' ';
    const PROTOCOL: &str = "RTSP/1.0";

    #[must_use]
    pub fn content_len(&self) -> Option<usize> {
        self.headers.content_length
    }

    #[must_use]
    pub fn find_head_body_separator(src: &[u8]) -> Option<usize> {
        // delimiter for end of RTSP message, content (if any) follows
        const NEEDLE: &[u8; 4] = b"\r\n\r\n";
        const MIN_BYTES: usize = 80;

        if src.len() > MIN_BYTES {
            return src.find(NEEDLE);
        }

        None
    }

    /// # Errors
    ///
    /// May return error if body is not recognized
    ///
    #[inline]
    pub fn include_body(&mut self, src: &[u8]) -> Result<()> {
        if let Some(len) = self.headers.content_length {
            self.body = Body::try_from(&src[0..len])?;
        }

        Ok(())
    }

    #[must_use]
    pub fn method_path(&self) -> (Method, String) {
        // must return actual objects to avoid borrow checker
        (self.method, self.path.clone())
    }
}

impl TryFrom<BytesMut> for Frame {
    type Error = anyhow::Error;

    fn try_from(buf: BytesMut) -> Result<Self> {
        // delimiter for end of RTSP message, content (if any) follows
        const NEEDLE: &[u8; 4] = b"\r\n\r\n";

        // clone the original buf for persisting to disk, this is a cheap operation
        // and is also used to calculate the bytes consumed
        let file_buf = buf.clone();

        // locate the delim between head and body (aka needle)
        if let Some(needle_pos) = buf.find(NEEDLE) {
            // grab the head and tail slice, noting tail contains the needle and
            // potentially the body (depending on content len header)
            let mid = needle_pos + NEEDLE.len();
            let (head, body) = buf.split_at(mid);

            let mut frame = Frame::try_from(head)?;

            let path = frame.headers.debug_file_path("in")?;

            match frame.content_len() {
                // has content length header and all content is in buffer
                Some(len) if body.len() >= len => {
                    let body = &body[0..len];

                    frame.include_body(body)?;
                    frame.consumed = head.len() + body.len();

                    persist_buf(&file_buf, Some(path))?;

                    Ok(frame)
                }

                // content header exists but full content check failed
                // incomplete, need more bytes to proceed
                Some(len) => Ok(Self {
                    pending: Some(Pending::new(head.len(), len)),
                    ..frame
                }),
                // no content header, frame is complete
                _ => {
                    frame.consumed = head.len();

                    persist_buf(head, Some(path))?;

                    Ok(frame)
                }
            }
        } else {
            persist_buf(&buf, None)?;

            Err(anyhow!("unable to find request end"))
        }
    }
}

fn persist_buf(buf: &[u8], path: Option<PathBuf>) -> Result<()> {
    use std::{env::var, fs::OpenOptions, io::Write};

    let path = path.unwrap_or_else(|| {
        const KEY: &str = "CARGO_MANIFEST_DIR";
        let path: PathBuf = var(KEY).unwrap().into();
        let mut path = path.parent().unwrap().to_path_buf();

        path.push("extra/ref/v2/error/frame.bin");

        path
    });

    Ok(OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(path)?
        .write_all(buf)?)
}

impl<'a> TryFrom<&'a [u8]> for Frame {
    type Error = anyhow::Error;

    #[inline]
    fn try_from(buf: &'a [u8]) -> Result<Self> {
        let src = buf.to_str()?.trim_end();

        // split on the protocol to validate the version and remove the protocol
        // text from further comparisons
        let (request, rest) = src
            .split_once(Self::PROTOCOL)
            .ok_or_else(|| anyhow!("protocol version not found"))?;

        // the first line is the request: METHOD PATH RTSP/1.0
        let line = request.split_once(Self::SPACE);

        // get the method and path
        if let Some((method, path)) = line {
            return Ok(Self {
                method: Method::from_str(method)?,
                path: path.trim_end().to_owned(),
                headers: header::List::try_from(rest)?,
                ..Self::default()
            });
        }

        Ok(Self::default())
    }
}

impl fmt::Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FRAME {} {}", self.method, self.path)?;

        if f.alternate() {
            write!(f, "\n{}\n{}", self.headers, self.body)?;
        }

        Ok(())
    }
}

#[derive(Default, Debug, PartialEq)]
pub enum Body {
    Dict(plist::Dictionary),
    Bulk(Vec<u8>),
    OctetStream(Vec<u8>),
    Text(String),
    #[default]
    Empty,
}

use Body::{Bulk, Dict, Empty, OctetStream, Text};

impl Body {
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        const EMPTY: [u8; 1] = [0u8];

        match self {
            Bulk(v) | OctetStream(v) => v.as_slice(),
            Text(s) => s.as_bytes(),
            Dict(_) | Empty => EMPTY.as_slice(),
        }
    }

    /// Returns the length of this [`Body`].
    ///
    /// # Errors
    ///
    /// This function will return an error if detemination of length fails.
    pub fn len(&self) -> Result<usize> {
        Ok(match self {
            Dict(plist) => {
                struct BytesWrite<'a>(&'a mut BytesMut);

                impl std::io::Write for BytesWrite<'_> {
                    fn write(&mut self, s: &[u8]) -> std::io::Result<usize> {
                        self.0.extend_from_slice(s);
                        Ok(s.len())
                    }

                    fn flush(&mut self) -> std::io::Result<()> {
                        Ok(())
                    }
                }

                let mut buf = BytesMut::with_capacity(1024);
                plist::to_writer_binary(BytesWrite(&mut buf), plist)?;

                buf.len()
            }
            Bulk(v) | OctetStream(v) => v.len(),
            Text(text) => text.len(),
            Empty => 0,
        })
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self {
            Dict(plist) => plist.is_empty(),
            Bulk(v) | OctetStream(v) => v.is_empty(),
            Text(text) => text.is_empty(),
            Empty => true,
        }
    }
}

impl From<plist::Dictionary> for Body {
    fn from(dict: plist::Dictionary) -> Self {
        Self::Dict(dict)
    }
}

impl fmt::Display for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bulk(v) | OctetStream(v) => f.write_fmt(format_args!("{:?}", v.hex_dump())),
            Dict(dict) => f.write_fmt(format_args!("{dict:#?}")),
            Text(text) => f.write_fmt(format_args!("{text}")),
            Empty => f.write_str("<<EMPTY>>"),
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for Body {
    type Error = anyhow::Error;

    ///
    /// Errors:
    ///
    #[inline]
    fn try_from(raw: &'a [u8]) -> Result<Self> {
        const PLIST_HDR: &[u8; 6] = b"bplist";

        match raw {
            // detect and parse Apple Property List
            r if r.starts_with(PLIST_HDR) => Ok(Dict(plist::from_bytes(r)?)),

            r if r[0] < 20 => Ok(Bulk(r.into())),

            // detect and copy plain ascii text
            r if r.is_ascii() => Ok(Text(r.to_str()?.into())),

            // detect and handle empty body
            r if r.is_empty() => Ok(Empty),

            // unknown or unhandled body
            r => Ok(Bulk(r.into())),
        }
    }
}

impl TryInto<BytesMut> for Body {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<BytesMut> {
        let mut buf = BytesMut::with_capacity(4096);

        match self {
            OctetStream(v) | Bulk(v) if !v.is_empty() => buf.extend_from_slice(&v),
            Text(t) if !t.is_empty() => buf.extend_from_slice(t.as_bytes()),
            Dict(dict) => plist::to_writer_binary((&mut buf).writer(), &dict)?,
            OctetStream(_) | Bulk(_) | Text(_) | Empty => (),
        };

        tracing::debug!("\nDICT {:?}", buf.hex_dump());

        Ok(buf)
    }
}

pub struct Response {
    pub status_code: StatusCode,
    pub headers: header::List,
    pub body: Body,
}

impl Response {
    #[inline]
    #[must_use]
    pub fn has_body(&self) -> bool {
        !matches!(self.body, Body::Empty)
    }

    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    pub fn ok_with_body(headers: HeaderList, body: Body) -> Result<Self> {
        Ok(Self {
            status_code: StatusCode::OK,
            headers: headers.make_response2(&body)?,
            body,
        })
    }

    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    pub fn ok_without_body(headers: HeaderList) -> Result<Self> {
        Ok(Self {
            status_code: StatusCode::OK,
            headers: headers.make_response_no_body(),
            body: Body::Empty,
        })
    }

    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    pub fn internal_server_error(headers: HeaderList) -> Result<Self> {
        Ok(Self {
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            headers: headers.make_response_no_body(),
            body: Body::Empty,
        })
    }

    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    pub fn bad_request(headers: HeaderList) -> Result<Self> {
        Ok(Self {
            status_code: StatusCode::BAD_REQUEST,
            headers: headers.make_response_no_body(),
            body: Body::Empty,
        })
    }

    /// # Errors
    ///
    #[inline]
    pub fn extend_with_content_info(&self, dst: &mut BytesMut) -> Result<()> {
        use std::fmt::Write;

        let ctype = self.headers.content_type.as_ref();
        let clen = self.headers.content_length.as_ref();

        if let (Some(ctype), Some(clen)) = (ctype, clen) {
            let avail = dst.capacity();
            tracing::debug!("buf avail: {avail}");

            let ctype_key = header::Key2::ContentType.as_str();
            let ctype_val = ctype.as_str();
            let clen_key = header::Key2::ContentLength.as_str();

            let res = write!(
                dst,
                "\
                {ctype_key}: {ctype_val}\r\n\
                {clen_key}: {clen}\r\n\
                \r\n\
                "
            );

            return Ok(res?);
        }

        Err(anyhow!("no content type or length"))
    }
}

impl Default for Response {
    fn default() -> Self {
        Self {
            status_code: StatusCode::OK,
            headers: HeaderList::default(),
            body: Body::Empty,
        }
    }
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status_code = &self.status_code;
        let headers = &self.headers;
        let body = &self.body;

        write!(f, "{status_code}\n{headers}{body}")
    }
}

impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RESPONSE {}", self.status_code)?;

        if f.alternate() {
            write!(f, "\n{}\n{}", self.headers, self.body)?;
        }

        Ok(())
    }
}

#[allow(unused)]
#[derive(Debug, Clone)]
pub struct Pending {
    head: usize,
    body: usize,
    attempts: usize,
}

impl Pending {
    pub fn new(head: usize, body: usize) -> Pending {
        Self {
            head,
            body,
            attempts: 1,
        }
    }
}

impl Default for Pending {
    fn default() -> Self {
        Self {
            head: 0,
            body: 0,
            attempts: 1,
        }
    }
}
