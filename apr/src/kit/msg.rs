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
use pretty_hex::PrettyHex;

pub mod parts;
pub use parts::{Content, ContentMatch, MetaData, Routing};

const CSEQ: &[u8] = b"CSeq";

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
        if let Some(content) = self.content.as_mut() {
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
        let content = self.content.get_or_insert(Content::default());

        let (desc, field) = line.split_at(delim_at);

        // lines 1.. are headers Key: Val pairs
        match (desc, field[1..].trim()) {
            // handle three special cases.  we intentionally deviate from the
            // incoming message format and store CSeq and Content in self since
            // they are essential for downstream processes.
            (CSEQ, field) => {
                self.cseq.get_or_insert(field.to_str()?.parse()?);
            }
            (desc, field) if cm.is_kind(desc) => {
                content.kind = field.to_str()?.into();
            }
            (desc, field) if cm.is_len(desc) => {
                content.len = field.to_str()?.parse()?;
            }
            // all other header values are treated as captured metadata
            (desc, field) => {
                let metadata = self.metadata.get_or_insert(MetaData::default());

                metadata.push_from_slice(desc, field)?;
            }
        }

        Ok(())
    }

    fn absorb_routing(&mut self, src: &[u8]) -> Result<()> {
        self.routing
            .get_or_insert(Routing::try_from(src.as_bytes())?);

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
