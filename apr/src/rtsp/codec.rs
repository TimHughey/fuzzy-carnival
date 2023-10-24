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
    homekit::{CipherCtx, CipherLock},
    rtsp::{msgs::Pending, Body, Frame, HeaderList, Response},
    Result,
};
use anyhow::anyhow;
use bytes::{Buf, BytesMut};
use pretty_hex::PrettyHex;
use std::{
    // io::Write,
    path::PathBuf,
    sync::{Arc, RwLock},
};
use tokio_util::codec::{Decoder, Encoder};
use tracing::debug;

/// A simple [`Decoder`] and [`Encoder`] implementation that splits up data into lines.
///
/// [`Decoder`]: crate::codec::Decoder
/// [`Encoder`]: crate::codec::Encoder
#[derive(Default, Debug)]
pub struct Rtsp {
    // incomplete body tracking
    pending: Option<Pending>,
    block_len: Option<u16>,
    cipher: CipherLock,
}

impl Rtsp {
    /// Returns a `RtspCode` for creating Rtsp frames from buffered bytes
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn install_cipher(&mut self, ctx: CipherCtx) {
        self.cipher = Some(Arc::new(RwLock::new(ctx)));
    }
}

// Right now `write!` on `Vec<u8>` goes through io::Write and is not
// super speedy, so inline a less-crufty implementation here which
// doesn't go through io::Error.
// struct BytesWrite<'a>(&'a mut BytesMut);
//
// impl fmt::Write for BytesWrite<'_> {
//     fn write_str(&mut self, s: &str) -> fmt::Result {
//         self.0.extend_from_slice(s.as_bytes());
//         Ok(())
//     }
//
//     fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> fmt::Result {
//         fmt::write(self, args)
//     }
// }

impl Decoder for Rtsp {
    type Item = Frame;
    type Error = anyhow::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>> {
        // const U16_SIZE: usize = std::mem::size_of::<u16>();

        if buf.len() < 3 {
            return Ok(None);
        }

        if let Some(cipher) = self.cipher.as_ref() {
            // since this is an encrypted message we have the luxury of determining
            // if the buffer contains enough bytes to proceed with decryption by
            // examining the header (u16 value)

            // enough bytes in buffer for a potential frame
            let block_len = self.block_len.get_or_insert_with(|| buf.get_u16_le());

            let buf_len = buf.len();
            let block_needed_len = (*block_len as usize) + 16;

            if buf_len < block_needed_len {
                tracing::warn!("incomplete block, buf {buf_len} < {block_needed_len}");

                return Ok(None);
            }

            let data = buf.split_to(block_needed_len);

            tracing::info!("\nINBOUND DATA (raw) {:?}", data.hex_dump());

            if !buf.is_empty() {
                tracing::warn!("spurious data in buf\nBUF (SUPRIOUS) {:?}", buf.hex_dump());
            }

            // decrypt the data.
            // returns:
            //   Ok(Some) => the clear text buffer
            //   Err => handle immediately with question mark
            let plaintext = cipher.write().unwrap().decrypt(data, *block_len)?;

            buf.unsplit(plaintext);

            self.block_len = None;

            tracing::info!("\nDECODED CLEAR TEXT {:?}", buf.hex_dump());
        }

        // we now have a clear text buffer that we can parse into a frame
        match Frame::try_from(buf.clone()) {
            Ok(mut frame) => {
                if frame.pending.is_none() {
                    buf.advance(frame.consumed);

                    if !buf.is_empty() {
                        tracing::warn!("additional bytes in buffer len={}", buf.len());
                    }

                    Ok(Some(frame))
                } else {
                    // TODO: do something with pending
                    self.pending = frame.pending.take();
                    Ok(None)
                }
            }
            Err(e) => Err(e),
        }
    }
}

/// Implementation of encoding an RTSP response into a `BytesMut`, basically
/// just writing out an RTSP/1.0 response.
impl Encoder<Response> for Rtsp {
    type Error = anyhow::Error;

    fn encode(&mut self, item: Response, dst: &mut BytesMut) -> Result<()> {
        use std::fmt::Write;
        use Body::{Bulk, Dict, Empty, OctetStream, Text};

        let mut bin_save = BinSave::new(&item.headers)?;

        let status = item.status_code;
        let cseq = item.headers.cseq.unwrap();

        dst.write_fmt(format_args!("RTSP/1.0 {status}\r\n"))?;
        dst.write_fmt(format_args!("CSeq: {cseq}\r\n"))?;
        dst.write_str("Server: AirPierre/366.0\r\n")?;

        match &item.body {
            Bulk(extend) | OctetStream(extend) => {
                item.extend_with_content_info(dst)?;
                dst.extend_from_slice(extend.as_slice());
            }

            Text(extend) => {
                item.extend_with_content_info(dst)?;
                dst.extend_from_slice(extend.as_bytes());
            }

            Dict(_) => Err(anyhow!("Dict not implemented yet"))?,
            Empty => (),
        }

        debug!("\nOUTBOUND CLEAR TEXT {:?}", dst.hex_dump());

        bin_save.persist(dst.as_ref())?;

        if let Some(cipher) = self.cipher.as_ref() {
            let cleartext = dst.split();
            let encrypted = cipher.write().unwrap().encrypt(cleartext)?;

            tracing::debug!("\nENCRYPTED (before unsplit) {:?}", encrypted.hex_dump());

            dst.unsplit(encrypted);
        }

        tracing::info!("\nOUTBOUND BUF {:?}", dst.hex_dump());

        bin_save.persist_last(dst.as_ref())?;

        Ok(())
    }
}

struct BinSave {
    file: std::fs::File,
    dump_path: Option<PathBuf>,
}

impl BinSave {
    pub fn new(headers: &HeaderList) -> Result<Self> {
        let path = headers.debug_file_path("out")?;

        Ok(Self {
            file: std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .append(true)
                .open(path)?,
            dump_path: headers.dump_path(),
        })
    }

    pub fn persist(&mut self, buf: &[u8]) -> Result<()> {
        use std::io::Write;
        Ok(self.file.write_all(buf)?)
    }

    pub fn persist_last(&mut self, buf: &[u8]) -> Result<()> {
        use std::io::Write;

        if let Some(base) = &self.dump_path {
            let mut path = base.clone();
            path.push("all.bin");

            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .append(true)
                .open(path)?;

            file.write_all(buf)?;

            let sep = b"\x00!*!*!*\x00";
            file.write_all(sep)?;
        }

        Ok(())
    }
}
