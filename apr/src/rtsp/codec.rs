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
    rtsp::{msgs::Pending, Body, Frame, Response},
    Result,
};
use anyhow::anyhow;
use bytes::{Buf, BytesMut};
use pretty_hex::PrettyHex;
use std::{fmt, fs::OpenOptions};
use tokio_util::codec::{Decoder, Encoder};
use tracing::debug;

/// A simple [`Decoder`] and [`Encoder`] implementation that splits up data into lines.
///
/// [`Decoder`]: crate::codec::Decoder
/// [`Encoder`]: crate::codec::Encoder
#[derive(Default, Clone, Debug)]
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

        debug!("\nENCODED: {:?}", dst.hex_dump());

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
        let cnt = buf.len();

        if Frame::min_bytes(cnt) {
            // enough bytes in buffer for a potential frame

            debug!("\nDECODE BUFFER {:?}", buf.hex_dump());

            match Frame::try_from(buf.clone()) {
                Ok(mut frame) => {
                    if frame.pending.is_none() {
                        buf.advance(frame.consumed);

                        Ok(Some(frame))
                    } else {
                        self.pending = frame.pending.take();
                        Ok(None)
                    }
                }
                Err(e) => Err(e),
            }
        } else {
            // not enough bytes in buffer for a minimal frame
            Ok(None)
        }
    }
}
