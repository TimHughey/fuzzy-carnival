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
use crate::{kit::BlockLen, Result};
use anyhow::anyhow;
use bstr::{ByteSlice, B};
use bytes::{Buf, BufMut, BytesMut};
use pretty_hex::PrettyHex;
use std::fmt;

#[derive(Debug, Default)]
pub struct Inflight {
    pub routing: Option<Routing>,
    pub headers: Option<HeaderList>,
    pub content_len: Option<usize>,
    pub body: Option<Body>,
    pub residual: Option<BytesMut>,
    pub block_len: Option<BlockLen>,
}

impl TryFrom<&mut BytesMut> for Inflight {
    type Error = anyhow::Error;

    fn try_from(buf: &mut BytesMut) -> std::result::Result<Self, Self::Error> {
        const SEP: &[u8; 2] = b"\x0a\x0d";
        const PROTO: &[u8] = b"RTSP/1.0";

        // for advancing the cursor
        let msg = buf.clone();

        let mut inflight = Self::default();

        for (_n, line) in msg.lines_with_terminator().enumerate() {
            // tracing::debug!("\nLINE {:?}\n", line.hex_dump());

            let line_len = line.len();

            // delimiter between headers and body
            if line_len <= 2 && line.iter().all(|b| SEP.contains(b)) {
                buf.advance(line_len);
                break;
            }

            let line = line.as_bstr().trim();

            if !line.is_empty() && line.is_ascii() {
                // first pass of loop, handle the routing (method and path)
                if inflight.routing.is_none() && line.ends_with(PROTO) {
                    inflight.routing = Some(Routing::try_from(line)?);
                    buf.advance(line_len);
                    continue;
                }

                // subsequent lines are either headers or body
                let headers = inflight.headers.get_or_insert(HeaderList::default());

                headers.push_from_slice(line)?;
                buf.advance(line_len);
            }
        }

        tracing::info!("\nREMAINING BUF FOR BODY {:?}", buf.hex_dump());

        if let Some(len) = inflight.headers.as_ref().and_then(|h| h.content_length) {
            // trim spurious seperators
            for sep in SEP {
                if buf[0] == *sep {
                    buf.advance(1);
                }
            }

            if buf.len() >= len {
                inflight.body = Some(Body::try_from(buf.split_to(len))?);
            }

            if !buf.is_empty() {
                inflight.residual = Some(buf.clone());
            }
        }

        Ok(inflight)
    }
}

impl fmt::Display for Inflight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("INFLIGHT FRAME")?;

        self.content_len
            .as_ref()
            .and_then(|len| write!(f, "CONTENT LEN={len}").ok());

        self.block_len
            .as_ref()
            .and_then(|len| write!(f, " {len:?}").ok());

        f.write_str("\n")?;

        self.routing
            .as_ref()
            .and_then(|routing| write!(f, "{routing} ").ok());

        self.headers
            .as_ref()
            .and_then(|headers| write!(f, "\n{headers}").ok());

        self.body
            .as_ref()
            .and_then(|body| write!(f, "\n{body}").ok());

        self.residual
            .as_ref()
            .and_then(|buf| write!(f, "\nRESIDUAL {:?}", buf.hex_dump()).ok());

        f.write_str("\n")
    }
}

#[derive(Default)]
pub struct Frame {
    pub routing: Routing,
    pub headers: HeaderList,
    pub body: Body,
}

impl Frame {
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
    pub fn routing(&self) -> &Routing {
        // must return actual objects to avoid borrow checker
        &self.routing
    }
}

impl TryFrom<Inflight> for Frame {
    type Error = anyhow::Error;

    fn try_from(mut inflight: Inflight) -> Result<Self> {
        Ok(Self {
            routing: inflight
                .routing
                .take()
                .ok_or_else(|| anyhow!("routing missing"))?,
            headers: inflight
                .headers
                .take()
                .ok_or_else(|| anyhow!("headers missing"))?,
            body: inflight.body.take().unwrap_or(Body::Empty),
        })
    }
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
        // let line = request.split_once(Self::SPACE);

        // get the method and path

        Ok(Self {
            routing: Routing::try_from(request.as_bytes())?,
            // method: Method::from_str(method)?,
            // path: path.trim_end().into(),
            headers: header::List::try_from(rest)?,
            ..Self::default()
        })
    }
}

impl fmt::Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FRAME {}", self.routing)?;

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
        const FPLY_HDR: &[u8; 4] = b"FPLY";

        Ok(match raw {
            // detect and handle empty body
            r if r.is_empty() => Empty,

            // detect and parse Apple Property List
            r if r.starts_with(PLIST_HDR) => Dict(plist::from_bytes(r)?),

            // detect and copy plain ascii text
            r if r.is_ascii() => Text(r.to_str()?.into()),

            r if r.starts_with(FPLY_HDR) => Bulk(r.into()),

            // if the first byte is not ascii dump into Bulk
            r if !r[0].is_ascii() => Bulk(r.into()),

            // unknown or unhandled body
            r => {
                tracing::warn!("unable to detect body type:\nRAW {:?}", raw.hex_dump());
                Bulk(r.into())
            }
        })
    }
}

impl TryFrom<BytesMut> for Body {
    type Error = anyhow::Error;

    ///
    /// Errors:
    ///
    #[inline]
    fn try_from(raw: BytesMut) -> Result<Self> {
        const PLIST_HDR: &[u8; 6] = b"bplist";

        Ok(match raw {
            // detect and parse Apple Property List
            r if r.starts_with(PLIST_HDR) => Dict(plist::from_bytes(&r)?),

            r if r[0] < 20 => Bulk(r.into()),

            // detect and copy plain ascii text
            r if r.is_ascii() => Text(r.to_str()?.into()),

            // detect and handle empty body
            r if r.is_empty() => Empty,

            // unknown or unhandled body
            r => {
                tracing::warn!("unable to detect body type:\nRAW {:?}", r.hex_dump());
                Bulk(r.into())
            }
        })
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

#[derive(Debug, Default)]
#[allow(unused)]
pub struct Routing {
    method: Method,
    path: String,
}

impl Routing {
    pub fn as_tuple(&self) -> (Method, String) {
        (self.method, self.path.clone())
    }
}

#[allow(non_snake_case)]
impl TryFrom<&[u8]> for Routing {
    type Error = anyhow::Error;

    fn try_from(buf: &[u8]) -> Result<Self> {
        let PROTO: &[u8] = B("RTSP/1.0");

        let idx = buf.find_char(' ').ok_or_else(|| {
            tracing::warn!("space delimiter not found:\nBUF {:?}", buf.hex_dump());

            anyhow!("method and/or path not found")
        })?;

        let (method, path) = buf.split_at(idx);
        let path = path
            .strip_suffix(PROTO)
            .ok_or_else(|| anyhow!("PROTOCOL not found"))?
            .trim();

        Ok(Self {
            method: Method::try_from(method.to_str()?)?,
            path: path.to_str()?.into(),
        })
    }
}

impl fmt::Display for Routing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.method.as_str(), self.path)
    }
}
