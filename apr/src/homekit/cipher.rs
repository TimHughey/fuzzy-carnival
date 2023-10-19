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

use super::Result;
use anyhow::anyhow;
use bytes::{Buf, BytesMut};
use chacha20poly1305::{
    aead::KeyInit, AeadInPlace, ChaCha20Poly1305 as ChaCha, Key, Nonce, Tag as AugTag,
};
use std::{
    fmt,
    sync::{Arc, RwLock},
};

pub type Lock = Option<Arc<RwLock<Context>>>;

#[allow(unused)]
#[derive(Default)]
pub struct Context {
    shared_secret: Vec<u8>,
    pub encrypt_key: Key,
    pub decrypt_key: Key,
    frames_in: RwLock<u64>,
    frames_out: RwLock<u64>,
}

const AUTH_TAG_LEN: usize = 16;
// const BLOCK_LEN_LEN: usize = mem::size_of::<u16>();
const SALT: &[u8; 12] = b"Control-Salt";
const WRITE_INFO: &[u8; 29] = b"Control-Write-Encryption-Key\x01";
const READ_INFO: &[u8; 28] = b"Control-Read-Encryption-Key\x01";

impl Context {
    pub fn new(shared_secret: &[u8]) -> Self {
        Self {
            shared_secret: shared_secret.into(),
            ..Self::default()
        }
        .make_keys()
    }

    pub fn decrypt(&self, mut buf: BytesMut) -> Result<BytesMut> {
        // an encrypted block is prefixed by a u16 that describes
        // the length of the block.  not clear why this is little
        // endian.  anyways, get it from the buffer and advance the
        // the internal cursor
        let block_len_u16 = buf.get_u16_le();

        // for splitting the block into it the data and auth tag
        // we need the block len as a usize so let's safely convert it
        let block_len: usize = block_len_u16.try_into()?;

        // extract the block from the buffer (advancing the cursor)
        // make this mutable since we'll decrypt in-place
        let mut block = buf.split_to(block_len);

        // extract the auth tag immediately following the encrypted data
        // the chacha functions require the auth tag to be a generic array
        let mut auth_tag = AugTag::default();
        auth_tag.copy_from_slice(&buf.split_to(AUTH_TAG_LEN));

        // generate the `Nonce` (based on the number of decrypted blocks)
        let nonce = self.decrypt_nonce();

        // initialize the chacha cipher
        let chacha = ChaCha::new(&self.decrypt_key);

        // create the associated data for decryption which is simply the
        // block len.  again, not sure of the endianness here so use native
        let associated_data = block_len_u16.to_ne_bytes();

        // ok, we're ready to actually decrypt
        chacha
            .decrypt_in_place_detached(&nonce, &associated_data, &mut block, &auth_tag)
            .map_err(|e| anyhow!("decrypt: {e}"))?;

        // increment the number of blocks decrypted
        self.inc_decrypt();

        // finally, merge the plaintext block back into the original buffer
        // so we retain data that wasn't used to decrypt
        buf.unsplit(block);

        Ok(buf)
    }

    fn decrypt_nonce(&self) -> Nonce {
        use pretty_hex::PrettyHex;
        // the nonce is 12 bytes in length and contains a u64 of the
        // decrypted packets thus far

        let mut nonce = Nonce::default();
        let nonce_le_bytes = self.frames_in.read().unwrap().to_ne_bytes();

        nonce[4..].copy_from_slice(&nonce_le_bytes);

        tracing::info!("NONCE {:?}", nonce.hex_dump());

        nonce
    }

    fn inc_decrypt(&self) {
        *self.frames_in.write().unwrap() += 1;
    }

    fn make_keys(self) -> Self {
        use hmac_sha512::HMAC;

        let prk = HMAC::mac(&self.shared_secret, SALT);

        let encrypt_key = HMAC::mac(READ_INFO, prk);
        let encrypt_key = Key::clone_from_slice(&encrypt_key[..32]);

        let decrypt_key = HMAC::mac(WRITE_INFO, prk);
        let decrypt_key = Key::clone_from_slice(&decrypt_key[..32]);

        Self {
            encrypt_key,
            decrypt_key,
            ..self
        }
    }
}

// fn calc_block_len(buf: &BytesMut) -> Result<usize> {
//
//     // Ok(u16::from_le_bytes(buf[..BLOCK_LEN_LEN].try_into()?).try_into()?)
// }

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use pretty_hex::PrettyHex;

        writeln!(
            f,
            "CIPHER CONTEXT in={} out={}",
            self.frames_in.read().unwrap(),
            self.frames_out.read().unwrap()
        )?;

        if f.alternate() {
            writeln!(f, "\nSHARED SECRET {:?}", self.shared_secret.hex_dump())?;
            writeln!(f, "\nENCRYPT KEY {:?}", self.encrypt_key.hex_dump())?;
            writeln!(f, "\nDENCRYPT KEY {:?}", self.decrypt_key.hex_dump())?;
        }

        Ok(())
    }
}
