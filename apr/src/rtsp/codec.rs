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

use crate::{
    rtsp::{Body, Frame, Response},
    Result,
};
use anyhow::anyhow;
use bstr::ByteSlice;
use bytes::{Buf, BytesMut};
use pretty_hex::PrettyHex;
use std::{fmt, fs::OpenOptions};
use tokio_util::codec::{Decoder, Encoder};
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

impl Rtsp {
    /// Returns a `RtspCode` for creating Rtsp frames from buffered bytes
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Implementation of encoding an HTTP response into a `BytesMut`, basically
/// just writing out an HTTP/1.1 response.
impl Encoder<Response> for Rtsp {
    type Error = anyhow::Error;

    fn encode(&mut self, item: Response, dst: &mut BytesMut) -> Result<()> {
        use std::fmt::Write;
        use Body::{Bulk, Dict, Empty, OctetStream, Text};

        // Right now `write!` on `Vec<u8>` goes through io::Write and is not
        // super speedy, so inline a less-crufty implementation here which
        // doesn't go through io::Error.
        struct BytesWrite<'a>(&'a mut BytesMut);

        impl fmt::Write for BytesWrite<'_> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                self.0.extend_from_slice(s.as_bytes());
                Ok(())
            }

            fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> fmt::Result {
                fmt::write(self, args)
            }
        }

        let status = item.status_code;
        let path = item.headers.debug_file_path("out")?;
        let cseq = item.headers.cseq.unwrap();

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .append(true)
            .open(path)?;

        dst.write_fmt(format_args!(
            "\
             RTSP/1.0 {status}\r\n\
             CSeq: {cseq}\r\n\
             Server: AirPierre/366.0\r\n\
             ",
        ))
        .map_err(|e| anyhow!("write response failed: {e}"))?;

        match &item.body {
            Bulk(extend) | OctetStream(extend) => {
                item.extend_with_content_info(dst)?;
                dst.extend_from_slice(extend.as_slice());
            }

            Text(extend) => {
                item.extend_with_content_info(dst)?;
                dst.extend_from_slice(extend.as_bytes());
            }

            Dict(_) => Err(anyhow!("Dict not supported"))?,
            Empty => (),
        }

        info!("\nENCODED: {:?}", dst.hex_dump());

        {
            use std::io::Write;
            file.write_all(dst.as_ref())?;
        }

        Ok(())
    }
}

impl Decoder for Rtsp {
    type Item = Frame;
    type Error = anyhow::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>> {
        use std::io::Write;

        // delimiter for end of RTSP message, content (if any) follows
        const NEEDLE: &[u8; 4] = b"\r\n\r\n";

        let file_buf = buf.clone();

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
                if let Some(needle_pos) = buf.find(NEEDLE) {
                    // grab the head and tail slice, noting tail contains the needle and
                    // potentially the body (depending on content len header)
                    let mid = needle_pos + NEEDLE.len();
                    let (head, body) = buf.split_at(mid);

                    let mut frame = Frame::try_from(head)?;

                    let path = frame.headers.debug_file_path("in")?;

                    let mut file = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .append(true)
                        .open(path)?;

                    match frame.content_len() {
                        // has content length header and all content is in buffer
                        Some(len) if body.len() >= len => {
                            file.write_all(file_buf.as_ref())?;

                            let body = &body[0..len];

                            frame.include_body(body)?;

                            buf.advance(head.len() + body.len());

                            self.pending = None;

                            Ok(Some(frame))
                        }

                        // content header exists but full content check failed
                        // incomplete, need more bytes to proceed
                        Some(len) => {
                            Pending::new_or_update(&mut self.pending, head.len(), len);

                            info!("{:?}", self.pending);

                            Ok(None)
                        }
                        // no content header, frame is complete
                        _ => {
                            file.write_all(head)?;
                            buf.advance(head.len());

                            self.pending = None;

                            Ok(Some(frame))
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

    pub fn new_or_update(src: &mut Option<Pending>, head: usize, body: usize) -> Pending {
        match src.as_ref() {
            Some(p) => Pending {
                attempts: p.attempts.saturating_add_signed(1),
                ..p.clone()
            },
            None => Pending::new(head, body),
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
