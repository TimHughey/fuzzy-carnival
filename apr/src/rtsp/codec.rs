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
    kit::{BlockLen, CipherCtx, CipherLock},
    rtsp::{Body, Frame, InflightFrame, Response},
    util::BinSave,
    Result,
};
use bytes::{BufMut, BytesMut};
use pretty_hex::PrettyHex;
use std::sync::{Arc, RwLock};
use tokio_util::codec::{Decoder, Encoder};

/// A simple [`Decoder`] and [`Encoder`] implementation that splits up data into lines.
///
/// [`Decoder`]: crate::codec::Decoder
/// [`Encoder`]: crate::codec::Encoder
#[derive(Debug, Default)]
pub struct Rtsp {
    cipher: CipherLock,
    plaintext: Option<BytesMut>,
    inflight: Option<InflightFrame>,
    bin_save: BinSave,
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
        const PLAINTEXT_MIN_LEN: usize = 50;
        const ENCRYPTED_LEN_MAX: usize = 0x400;

        if let Some(cipher) = self.cipher.as_ref() {
            let buf_len = buf.len();
            let n_blocks = num_traits::clamp_min(buf_len / ENCRYPTED_LEN_MAX, 1);
            tracing::debug!("buf len={buf_len} n_blocks={n_blocks}");

            loop {
                // must get mut reference inside loop to make borrow checker happy
                let inflight = self.inflight.get_or_insert(InflightFrame::default());

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
                self.bin_save.persist(&rollback_buf, BinSave::ALL, None)?;

                match InflightFrame::try_from(plaintext_buf) {
                    Ok(inflight) => {
                        match Frame::try_from(inflight) {
                            Ok(frame) => {
                                self.bin_save.persist(
                                    &rollback_buf,
                                    BinSave::IN,
                                    frame.headers.cseq(),
                                )?;
                                return Ok(Some(frame));
                            }
                            
                            Err(e) => {
                                // frame creation failed, rollback plaintext
                                *buf = rollback_buf;
                                tracing::error!("failed to decode:\nBUF {:?}", buf.hex_dump());
                                return Err(e);
                            }
                        }
                    }
                    Err(e) => return Err(e),
                }
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

            Dict(dict) => {
                item.extend_with_content_info(dst)?;
                plist::to_writer_binary(dst.writer(), &dict)?;
            }
            Empty => dst.write_str("\r\n")?,
        }

        tracing::debug!("\nOUTBOUND CLEAR TEXT {:?}", dst.hex_dump());

        self.bin_save
            .persist(dst.as_ref(), BinSave::OUT, Some(cseq))?;

        if let Some(cipher) = self.cipher.as_ref() {
            let cleartext = dst.split();
            let encrypted = cipher.write().unwrap().encrypt(cleartext)?;

            tracing::debug!("\nENCRYPTED (before unsplit) {:?}", encrypted.hex_dump());

            dst.unsplit(encrypted);
        }

        tracing::debug!("\nOUTBOUND BUF {:?}", dst.hex_dump());

        self.bin_save.persist(dst.as_ref(), BinSave::ALL, None)?;

        Ok(())
    }
}
