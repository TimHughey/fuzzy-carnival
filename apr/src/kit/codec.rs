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
    kit::{
        msg::{Frame, Inflight, Response},
        BlockLen, CipherCtx, CipherLock,
    },
    util::BinSave,
    Result,
};
use anyhow::anyhow;
use bytes::BytesMut;
use pretty_hex::PrettyHex;
use std::sync::{Arc, RwLock};
use tokio_util::codec::{Decoder, Encoder};

/// A [`Decoder`] and [`Encoder`] implementation that assembles incoming packets
/// into [`Inflight`] messages to accomodate fragmented messages.  Complete
/// [`Inflight`] messages are then converted to a [`Frame`] and returned.
///
/// [`Decoder`]: tokio_util::codec::Decoder
/// [`Encoder`]: tokio_util::codec::Encoder
#[derive(Debug, Default)]
pub struct Rtsp {
    cipher: CipherLock,
    clear: Option<BytesMut>,
    inflight: Option<Inflight>,
    bin_save: BinSave,
}

impl Rtsp {
    pub fn install_cipher(&mut self, ctx: CipherCtx) {
        self.cipher = Some(Arc::new(RwLock::new(ctx)));
    }
}

impl Decoder for Rtsp {
    type Item = Frame;
    type Error = anyhow::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>> {
        const ENCRYPTED_LEN_MAX: usize = 0x400;
        const U16_SIZE: usize = std::mem::size_of::<u16>();

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
                    // nope, signal to caller to send additional data
                    return Ok(None);
                }

                // we are good to go for decryption of this block
                let cipher_block_len = block_len.len_with_auth_tag();
                let encrypted = buf.split_to(cipher_block_len);
                let decrypted = cipher.write().unwrap().decrypt(encrypted, **block_len)?;
                tracing::debug!("\nDECRYPTED {:?}", decrypted.hex_dump());

                // accumulate the decrypted bytes
                // yes, for the moment, we're doing buffer copies.  TODO: optimize to reuse buf
                let plaintext = self.clear.get_or_insert(BytesMut::with_capacity(4096));
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
            let clear = self.clear.get_or_insert(BytesMut::with_capacity(4096));
            clear.extend_from_slice(&buf.split());
        }

        if let Some(clear) = self.clear.as_mut() {
            const CLEAR_MIN_LEN: usize = 50;
            const CLEAR_LARGE_MSG: usize = 3 * 1024;

            let clear_len = clear.len();

            if clear_len < CLEAR_MIN_LEN {
                return Ok(None);
            }

            // if plaintext_len > PLAINTEXT_MIN_LEN {
            if clear_len >= CLEAR_LARGE_MSG {
                tracing::info!("\nLARGE MESSAGE {:?}", clear.hex_dump());
            } else {
                tracing::debug!("CLEAR TEXT INBOUND {:?}", clear.hex_dump());
            }

            // let rollback = clear.clone();
            self.bin_save.persist(clear, BinSave::ALL, None)?;

            let mut persist_buf = clear.clone();

            let mut inflight = self.inflight.take().unwrap_or_default();
            inflight.absorb_buf(clear)?;
            inflight.absorb_content(clear);

            match inflight.check_complete() {
                Ok(true) => {
                    let frame = Frame::try_from(inflight)?;
                    self.inflight = None;

                    self.bin_save
                        .persist(&persist_buf, BinSave::IN, Some(frame.cseq))?;
                    persist_buf.clear();

                    return Ok(Some(frame));
                }
                Ok(false) => {
                    tracing::debug!("incomplete clear text, saving inflight");
                    self.inflight = Some(inflight);

                    return Ok(None);
                }
                Err(e) => return Err(e),
            }
        }

        Ok(None)
    }

    fn decode_eof(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>> {
        tracing::warn!("decode eof invoked");

        match self.decode(buf)? {
            Some(frame) => Ok(Some(frame)),
            None => {
                if buf.is_empty() {
                    Err(anyhow!("session closed"))
                } else {
                    Err(anyhow!("bytes remaining on stream"))
                }
            }
        }
    }
}

/// Implementation of encoding an RTSP response into a `BytesMut`, basically
/// just writing out an RTSP/1.0 response.
impl Encoder<Response> for Rtsp {
    type Error = anyhow::Error;

    fn encode(&mut self, item: Response, dst: &mut BytesMut) -> Result<()> {
        use std::fmt::Write;

        let status = item.status_code;
        let cseq = item.cseq;

        write!(dst, "RTSP/1.0 {status}\r\n")?;
        write!(dst, "CSeq: {cseq}\r\n")?;
        write!(dst, "Server: AirPierre/366.0\r\n")?;

        if let Some(content) = item.content {
            write!(dst, "Content-Kind: {}\r\r", content.kind)?;
            write!(dst, "Content-Length: {}\r\n", content.len)?;
            write!(dst, "\r\n")?;
            dst.extend_from_slice(&content.data);
        } else {
            write!(dst, "\r\n")?;
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
