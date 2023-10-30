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

use super::cipher::BlockLen;
use crate::Result;
use anyhow::anyhow;
use bstr::ByteSlice;
use bytes::{Buf, BytesMut};
use plist::Dictionary;
use pretty_hex::PrettyHex;

pub mod parts;
pub use parts::{Content, ContentMatch, MetaData, Routing};

const CSEQ: &[u8] = b"CSeq";
const STATUS_OK: u16 = 200;
const STATUS_BAD_REQUEST: u16 = 400;
const STATUS_INTERNAL_SERVER_ERROR: u16 = 500;

#[derive(Debug, Default)]
pub struct Inflight {
    pub block_len: Option<BlockLen>,
    pub routing: Option<Routing>,
    pub cseq: Option<u32>,
    pub content: Option<Content>,
    pub metadata: Option<MetaData>,
}

impl Inflight {
    fn absorb_content_data(mut self, buf: &mut BytesMut) -> Result<Self> {
        if buf.is_empty() {
            return Ok(self);
        } else if let Some(content) = self.content.as_mut() {
            // trim spurious seperators
            for sep in b"\r\n" {
                if buf[0] == *sep {
                    buf.advance(1);
                }
            }
            let len = content.len;

            if buf.len() >= len {
                content.data = buf.split_to(len);
            }

            if !buf.is_empty() {
                tracing::warn!("\nBUF RESIDUAL: {:?}", buf.hex_dump());
            }

            return Ok(self);
        }

        Err(anyhow!("data available however content metadata unknown"))
    }

    fn absorb_desc_and_field(&mut self, line: &[u8], delim_at: usize) -> Result<()> {
        let cm = ContentMatch::get();

        let (desc, field) = line.split_at(delim_at);

        // lines 1.. are headers Key: Val pairs
        match (desc, field[1..].trim()) {
            // handle three special cases.  we intentionally deviate from the
            // incoming message format and store CSeq and Content in self since
            // they are essential for downstream processes.
            (CSEQ, field) => self.store_cseq(field)?,

            (desc, field) if cm.is_kind(desc) => {
                self.get_content_mut().kind = field.to_str()?.into();
            }
            (desc, field) if cm.is_len(desc) => {
                self.get_content_mut().len = field.to_str()?.parse()?;
            }
            // all other header values are treated as captured metadata
            (desc, field) => {
                self.metadata
                    .get_or_insert(MetaData::default())
                    .push_from_slice(desc, field)?;
            }
        }

        Ok(())
    }

    fn absorb_routing(&mut self, src: &[u8]) -> Result<()> {
        self.routing
            .get_or_insert(Routing::try_from(src.as_bytes())?);

        Ok(())
    }

    pub fn build_frame(mut self) -> Result<Option<Frame>> {
        if self.block_len.is_none()
            && self.routing.is_some()
            && self.cseq.is_some()
            && self.metadata.is_some()
        {
            Content::confirm_valid(&self.content)?;

            let frame = Some(Frame {
                routing: self.routing.unwrap(),
                cseq: self.cseq.unwrap(),
                content: self.content.take(),
                metadata: self.metadata.unwrap(),
            });

            return Ok(frame);
        }

        Ok(None)
    }

    fn get_content_mut(&mut self) -> &mut Content {
        self.content.get_or_insert(Content::default())
    }

    fn store_cseq(&mut self, cseq: &[u8]) -> Result<()> {
        let cseq: u32 = cseq.to_str()?.parse()?;

        self.cseq.get_or_insert(cseq);

        if let Some(content) = self.content.as_mut() {
            content.cseq = cseq;
        }

        Ok(())
    }
}

impl TryFrom<&mut BytesMut> for Inflight {
    type Error = anyhow::Error;

    fn try_from(buf: &mut BytesMut) -> std::result::Result<Self, Self::Error> {
        const SEP: &[u8] = b"\x0a\x0d";

        // for advancing the cursor
        let msg = buf.clone();

        let mut inflight = Self::default();

        // part 1:
        // handle the prelude, headers (meta data)
        for (line_num, line) in msg.lines_with_terminator().enumerate() {
            // tracing::info!("\nLINE {line_num:03} {:?}\n", line.hex_dump());

            // capture the line length before modifications for use advancing
            // buf cursor
            let line_len = line.len();

            // delimiter between headers and body
            if line_len <= SEP.len() && line.iter().all(|b| SEP.contains(b)) {
                buf.advance(line_len);
                break;
            }

            if line.is_empty() || !line.is_ascii() {
                tracing::info!("\nSKIPPED LINE {line_num:03} {:?}\n", line.hex_dump());

                continue; // NOTE: do not advance the cursor
            }

            let line = line.trim();

            // line 0 is always method, path and protocol
            if line_num == 0 {
                inflight.absorb_routing(line)?;
                buf.advance(line_len);
                continue;
            }

            if let Some(mid) = line.find_byte(b':') {
                inflight.absorb_desc_and_field(line, mid)?;

                buf.advance(line_len); // the line is consumed, move the cursor
            }
        }

        inflight.absorb_content_data(buf)
    }
}

impl std::fmt::Display for Inflight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("INFLIGHT")?;
        self.routing
            .as_ref()
            .and_then(|routing| write!(f, " {routing}").ok());

        self.block_len
            .as_ref()
            .and_then(|len| write!(f, " [BLOCK LEN={len:?}]").ok());

        f.write_str("\n")?;

        self.cseq
            .as_ref()
            .and_then(|cseq| writeln!(f, "CSeq: {cseq}").ok());

        self.content.as_ref().and_then(|c| {
            writeln!(f, "Content-Type: {}", c.kind).ok();
            writeln!(f, "Content-Length: {}", c.len).ok()
        });

        self.metadata.as_ref().and_then(|m| writeln!(f, "{m}").ok());

        self.content
            .as_ref()
            .and_then(|c| writeln!(f, "CONTENT {:?}", c.data.hex_dump()).ok());

        Ok(())
    }
}

pub struct Frame {
    pub routing: Routing,
    pub cseq: u32,
    pub content: Option<Content>,
    pub metadata: MetaData,
}

impl TryFrom<Inflight> for Frame {
    type Error = anyhow::Error;

    fn try_from(mut inflight: Inflight) -> std::result::Result<Self, Self::Error> {
        if let Some(len) = inflight.block_len.as_ref() {
            tracing::warn!("pending block_len={len}");
            return Err(anyhow!("pending block_len"));
        }

        Content::confirm_valid(&inflight.content)?;

        let routing = inflight.routing.ok_or_else(|| anyhow!("routing missing"))?;
        let cseq = inflight.cseq.ok_or_else(|| anyhow!("cseq missing"))?;
        let metadata = inflight
            .metadata
            .ok_or_else(|| anyhow!("metadata missing"))?;

        Ok(Self {
            routing,
            cseq,
            content: inflight.content.take(),
            metadata,
        })
    }
}

impl std::fmt::Display for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FRAME {}", self.routing)?;

        if f.alternate() {
            f.write_str("\n")?;
            let content = self.content.as_ref();

            writeln!(f, "CSeq: {}", self.cseq)?;

            if let Some(content) = content {
                writeln!(f, "Content-Type: {}", content.kind)?;
                writeln!(f, "Content-Length: {}", content.len)?;
            }

            write!(f, "{}", self.metadata)?;

            if let Some(content) = self.content.as_ref() {
                write!(f, "\nCONTENT DATA {:?}", content.data.hex_dump())?;
            }
        }

        Ok(())
    }
}

pub mod method {
    pub const GET: &str = "GET";
    pub const POST: &str = "POST";
    pub const SETUP: &str = "SETUP";
    pub const GET_PARAMETER: &str = "GET_PARAMETER";
    pub const RECORD: &str = "RECORD";
    pub const SET_PEERS: &str = "SETPEERS";
    pub const SET_PEERSX: &str = "SETPEERSX";
}

pub struct Response {
    pub status_code: u16,
    pub cseq: u32,
    pub content: Option<Content>,
}

#[allow(unused)]
impl Response {
    pub fn bad_request(cseq: u32, content: Content) -> Self {
        Self {
            status_code: STATUS_BAD_REQUEST,
            content: Some(content),
            cseq,
        }
    }

    pub fn encode_to(mut self, dst: &mut BytesMut) -> Result<()> {
        use std::fmt::Write;

        write!(dst, "RTSP/1.0 {}\r\n", self.status_code)?;
        write!(dst, "CSeq: {}\r\n", self.cseq)?;
        write!(dst, "Server: AirPierre/366.0\r\n")?;

        if let Some(content) = self.content {
            write!(dst, "{content:#}")?;
        } else {
            write!(dst, "\r\n")?;
        }

        Ok(())
    }

    pub fn internal_server_error(cseq: u32) -> Self {
        Self {
            status_code: STATUS_INTERNAL_SERVER_ERROR,
            content: None,
            cseq,
        }
    }

    pub fn ok_plist_dict(cseq: u32, dict: &Dictionary) -> Result<Self> {
        Ok(Self {
            status_code: STATUS_OK,
            content: Some(Content::new_binary_plist(cseq, dict)?),
            cseq,
        })
    }

    pub fn ok_octet_stream(cseq: u32, src: &[u8]) -> Self {
        Self {
            status_code: STATUS_OK,
            content: Some(Content::new_octet_stream(cseq, src)),
            cseq,
        }
    }

    pub fn ok_simple(cseq: u32) -> Self {
        Self {
            status_code: STATUS_OK,
            content: None,
            cseq,
        }
    }

    pub fn ok_text(cseq: u32, src: &str) -> Self {
        Self {
            status_code: STATUS_OK,
            content: Some(Content::new_text(cseq, src)),
            cseq,
        }
    }

    pub fn ok_with_content(cseq: u32, content: Content) -> Self {
        Self {
            status_code: STATUS_OK,
            content: Some(content),
            cseq,
        }
    }

    pub fn ok_without_content(cseq: u32) -> Self {
        Self {
            status_code: STATUS_OK,
            content: None,
            cseq,
        }
    }

    // / # Errors
    // /
    // #[inline]
    // pub fn extend_with_content_info(&self, dst: &mut BytesMut) -> Result<()> {
    //     use std::fmt::Write;

    //     let ctype = self.headers.content_type.as_ref();
    //     let clen = self.headers.content_length.as_ref();

    //     if let (Some(ctype), Some(clen)) = (ctype, clen) {
    //         let avail = dst.capacity();
    //         tracing::debug!("buf avail: {avail}");

    //         let ctype_key = header::Key2::ContentType.as_str();
    //         let ctype_val = ctype.as_str();
    //         let clen_key = header::Key2::ContentLength.as_str();

    //         let res = write!(
    //             dst,
    //             "\
    //             {ctype_key}: {ctype_val}\r\n\
    //             {clen_key}: {clen}\r\n\
    //             \r\n\
    //             "
    //         );

    //         return Ok(res?);
    //     }

    //     Err(anyhow!("no content type or length"))
    // }
}

impl Default for Response {
    fn default() -> Self {
        Self::ok_without_content(0)
    }
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let status_code = &self.status_code;
        let cseq = &self.cseq;

        writeln!(f, "{status_code}\nCSeq: {cseq}\n")
    }
}

impl std::fmt::Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RESPONSE {} cseq={}", self.status_code, self.cseq)?;

        // if f.alternate() {
        //     write!(f, "\n{}\n{}", self.status_code, self.body)?;
        // }

        Ok(())
    }
}
