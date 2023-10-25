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
    homekit::{BlockLen, CipherCtx, CipherLock},
    rtsp::{Body, Frame, HeaderList, Inflight, Response},
    Result,
};
use anyhow::anyhow;
// use bstr::ByteSlice;
use bytes::BytesMut;
use pretty_hex::PrettyHex;
use std::{
    // io::Write,
    path::PathBuf,
    sync::{Arc, RwLock},
};
use tokio_util::codec::{Decoder, Encoder};

/// A simple [`Decoder`] and [`Encoder`] implementation that splits up data into lines.
///
/// [`Decoder`]: crate::codec::Decoder
/// [`Encoder`]: crate::codec::Encoder
#[derive(Debug, Default)]
pub struct Rtsp {
    cipher: CipherLock,
    plaintext: Option<BytesMut>,
    inflight: Option<Inflight>,
}

impl Rtsp {
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
        const U16_SIZE: usize = std::mem::size_of::<u16>();
        // const BLOCK_MIN_LEN: usize = U16_SIZE + 1 + 16;
        const PLAINTEXT_MIN_LEN: usize = 80;
        const ENCRYPTED_LEN_MAX: usize = 0x400;

        if let Some(cipher) = self.cipher.as_ref() {
            let buf_len = buf.len();
            let n_blocks = num_traits::clamp_min(buf_len / ENCRYPTED_LEN_MAX, 1);
            tracing::debug!("buf len={buf_len} n_blocks={n_blocks}");

            loop {
                // must get mut reference inside loop to make borrow checker happy
                let inflight = self.inflight.get_or_insert(Inflight::default());

                // if this is a new block then create a BlockLen, otherwise get the existing one
                let block_len = inflight.block_len.get_or_insert(BlockLen::default());

                // when this is a new block consume the block length bytes from the buffer
                if block_len.is_empty() && BlockLen::have_min_bytes(buf.len()) {
                    *block_len = BlockLen::from(buf.split_to(U16_SIZE));
                }

                // now, do we have enough bytes in the buffer to decrypt this block?
                if block_len.need_more(buf.len()) {
                    // nope, signal to caller to send us more when ready
                    return Ok(None);
                }

                // we are good to go for decryption of this block
                let cipher_block_len = block_len.len_with_auth_tag();
                let encrypted = buf.split_to(cipher_block_len);
                let decrypted = cipher.write().unwrap().decrypt(encrypted, **block_len)?;
                tracing::debug!("\nDECRYPTED {:?}", decrypted.hex_dump());

                // accumulate the decrypted bytes
                // yes, for the moment, we're doing buffer copies.  TODO: optimize to reuse buf
                let plaintext = self.plaintext.get_or_insert(BytesMut::with_capacity(4096));
                plaintext.extend_from_slice(&decrypted);

                // finished with current block or have returned early, clear block_len
                inflight.block_len = None;

                if !BlockLen::have_min_bytes(buf.len()) {
                    break;
                }
            }

            if !buf.is_empty() {
                tracing::warn!("\nRESIDUAL CIPHER BUF {:?}", buf.hex_dump());
            }
        } else {
            // we are operating in clear text mode, move buf to plaintext.
            // yes, we are doing a buffer copy however we only receive two
            // messages in clear text so it's not a big deal
            let plaintext_buf = self.plaintext.get_or_insert(BytesMut::with_capacity(4096));
            plaintext_buf.extend_from_slice(&buf.split());
        }

        if let Some(plaintext_buf) = self.plaintext.as_mut() {
            let plaintext_len = plaintext_buf.len();

            if plaintext_len > PLAINTEXT_MIN_LEN {
                if plaintext_len > 2048 {
                    tracing::info!("\nLARGE MESSAGE {:?}", plaintext_buf.hex_dump());
                }

                let rollback_buf = plaintext_buf.clone();

                let frame = Frame::try_from(plaintext_buf.split())?;

                if frame.pending.is_none() {
                    return Ok(Some(frame));
                }

                // frame creation failed, rollback plaintext
                *buf = rollback_buf;
            }
        }

        Ok(None)
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

        tracing::debug!("\nOUTBOUND CLEAR TEXT {:?}", dst.hex_dump());

        bin_save.persist(dst.as_ref())?;

        if let Some(cipher) = self.cipher.as_ref() {
            let cleartext = dst.split();
            let encrypted = cipher.write().unwrap().encrypt(cleartext)?;

            tracing::debug!("\nENCRYPTED (before unsplit) {:?}", encrypted.hex_dump());

            dst.unsplit(encrypted);
        }

        tracing::debug!("\nOUTBOUND BUF {:?}", dst.hex_dump());

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
