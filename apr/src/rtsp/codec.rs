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

use crate::rtsp::Frame;
use crate::Result;
use anyhow::anyhow;
use bstr::ByteSlice;
use bytes::{Buf, BytesMut};
use pretty_hex::PrettyHex;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tracing::{debug, error, info};

/// A simple [`Decoder`] and [`Encoder`] implementation that splits up data into lines.
///
/// [`Decoder`]: crate::codec::Decoder
/// [`Encoder`]: crate::codec::Encoder
#[derive(Default, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Rtsp {
    // incomplete body tracking
    pending: Option<Pending>,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct Pending {
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

    pub fn new_or_update(src: &mut Option<Pending>, head: usize, body: usize) -> Option<Pending> {
        match src.as_ref() {
            Some(p) => Some(Pending {
                attempts: p.attempts.saturating_add_signed(1),
                ..p.to_owned()
            }),
            None => Some(Pending::new(head, body)),
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

impl Rtsp {
    /// Returns a `RtspCode` for splitting creating Rtsp Frames from buffered bytes
    pub fn new() -> Self {
        Self::default()
    }
}

impl Decoder for Rtsp {
    type Item = Frame;
    type Error = anyhow::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>> {
        // delimiter for end of RTSP message, content (if any) follows
        const NEEDLE: &[u8; 4] = b"\r\n\r\n";

        match buf.len() {
            // enough bytes in buffer for a potential frame
            cnt if Frame::min_bytes(cnt) => {
                debug!("\nDECODE BUFFER {:?}", buf.hex_dump());

                // Division of Concerns:
                //   Rtsp Codec:
                //      - finds needle (delimiter) representing the RTSP message
                //      - ensures content (if any) is in the buffer if frame creation
                //        signals content is incomplete
                //
                //   Rtsp Frame:
                //      - parses raw buffer based on codec needle
                //      - determines content (if any) is in the buffer
                //      - if content is available, creates Frame and returns bytes consumed
                //      - it content is incomplete, returns bytes required

                // locate the delim between head and body (aka needle)
                if let Some(needle_pos) = buf.as_bstr().find(NEEDLE) {
                    // grab the head and tail slice, noting tail contains the needle and
                    // potentially the body (depending on content len header)
                    let mid = needle_pos + NEEDLE.len();
                    let (head, body) = buf.split_at(mid);

                    let mut frame = Frame::try_from(head)?;

                    match frame.content_len()? {
                        // has content length header and all content is in buffer
                        Some(content_len) if body.len() >= content_len => {
                            frame.include_body(body);
                            buf.advance(head.len() + content_len);

                            self.pending = None;

                            Ok(Some(frame))
                        }

                        // no content header, frame is complete
                        None => {
                            buf.advance(head.len());

                            self.pending = None;

                            Ok(Some(frame))
                        }

                        // content header exists but full content check failed
                        // incomplete, need more bytes to proceed
                        Some(content_len) => {
                            Pending::new_or_update(&mut self.pending, head.len(), content_len);

                            info!("{:?}", self.pending);

                            Ok(None)
                        }
                    }
                } else {
                    error!("unable to find request end");
                    Err(anyhow!("unable to find request end"))
                }
            }

            // not enough bytes in buffer for a minimal frame
            _cnt => Ok(None),
        }
    }
}

// fn parse_buffer()

impl<T> Encoder<T> for Rtsp
where
    T: Buf + bstr::ByteSlice,
{
    type Error = anyhow::Error;

    fn encode(&mut self, msg: T, buf: &mut BytesMut) -> Result<()> {
        info!("msg:\n{:?}", &msg.as_bytes().hex_dump());
        info!("buf:\n{:?}", buf.hex_dump());
        // let line = line.as_ref();
        // buf.reserve(line.len() + 1);
        // buf.put(line.as_bytes());
        // buf.put_u8(b'\n');
        Ok(())
    }
}
