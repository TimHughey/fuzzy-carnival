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
use alkali::{mem, symmetric::auth::hmacsha512256 as AlkaliHMAC};
use anyhow::anyhow;
use bytes::{Buf, BytesMut};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key, Nonce, Tag,
};
use once_cell::sync::Lazy;
use std::{
    fmt,
    mem::size_of,
    ops::Deref,
    sync::{Arc, RwLock},
};

pub type Lock = Option<Arc<RwLock<Context>>>;
// pub type AlkaliKey = AlkaliKeyBase<mem::FullAccess>;
#[allow(unused)]
pub type AlkaliAuthKey = alkali::symmetric::auth::Key<mem::FullAccess>;

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlockLen(pub u16);

impl BlockLen {
    pub fn as_usize(self) -> usize {
        self.0 as usize
    }

    pub fn from(mut buf: BytesMut) -> Self {
        Self(buf.get_u16_le())
    }

    pub fn have_all_bytes(self, buf_len: usize) -> bool {
        let need = 16 + self.0 as usize;

        buf_len >= need
    }

    pub fn have_min_bytes(len: usize) -> bool {
        let min = 16 + std::mem::size_of::<u16>() + 1;

        len >= min
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn need_more(self, buf_len: usize) -> bool {
        let need = 16 + self.0 as usize;

        buf_len < need
    }

    pub fn len_with_auth_tag(self) -> usize {
        16 + self.0 as usize
    }
}

impl Deref for BlockLen {
    type Target = u16;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for BlockLen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Default)]
#[allow(unused)]
pub struct Context {
    shared_secret: Vec<u8>,
    pub encrypt_key: Key,
    // pub encrypt_key: AlkaliKey,
    pub decrypt_key: Key,
    // pub decrypt_key: AlkaliKey,
    // frames_in: u64,
    // frames_out: u64,
    decrypt_nonce: u64,
    encrypt_nonce: u64,
}

const ENCRYPTED_LEN_MAX: usize = 0x400;
const SALT: &[u8; 12] = b"Control-Salt";
#[allow(unused)]
static SALT2: Lazy<AlkaliAuthKey> = Lazy::new(|| {
    let mut salt = AlkaliAuthKey::new_empty().unwrap();

    salt[..SALT.len()].copy_from_slice(SALT);

    salt
});
const WRITE_INFO: &[u8; 29] = b"Control-Write-Encryption-Key\x01";
const READ_INFO: &[u8; 28] = b"Control-Read-Encryption-Key\x01";

impl Context {
    pub fn decrypt(&mut self, mut buf: BytesMut, block_len: u16) -> Result<BytesMut> {
        use pretty_hex::PrettyHex;

        // buf contains the encrypted block + auth tag
        // NOTE: block_len does not include the auth tag -- only the encrypted data
        tracing::debug!("DECRYPTING block_len={block_len}\nBUF {:?}", buf.hex_dump());

        // we will decrypt directly into buf so split off the auth tag bytes
        let auth_tag_bytes = buf.split_off(block_len as usize);
        let auth_tag_slice = &auth_tag_bytes[..16];

        if auth_tag_bytes.len() != 16 {
            tracing::warn!(
                "\nSPURIOUS AUTH TAG BYTES {:?}",
                &auth_tag_bytes[16..].hex_dump()
            );
            return Err(anyhow!("spurious auth tag bytes"));
        }

        let mut auth_tag = Tag::default();
        auth_tag.copy_from_slice(auth_tag_slice);

        // construct the associated data which is simply the
        // block len (minus the auth tag)
        let associated_data = block_len.to_ne_bytes();

        // the nonce is the u64 count of decrypted messages padding
        // in a 12 byte (96 bit) nonce for ChaCha20 with Poly1305
        let mut nonce = Nonce::default();
        nonce[4..].copy_from_slice(&self.decrypt_nonce.to_ne_bytes());

        // construct the cipher and decrypt directly into buf
        let chacha = ChaCha20Poly1305::new(&self.decrypt_key);
        chacha
            .decrypt_in_place_detached(&nonce, &associated_data, &mut buf, &auth_tag)
            .map_err(|e| anyhow!("decrypt: {e}"))?;

        tracing::debug!("\nDECRYPTED BUF {:?}", buf.hex_dump());

        // increment the decrypted message count
        self.decrypt_nonce += 1;

        Ok(buf)
    }

    pub fn encrypt(&mut self, mut buf: BytesMut) -> Result<BytesMut> {
        use pretty_hex::PrettyHex;

        if self.decrypt_nonce > 0 {
            tracing::debug!("beginning encrypt of buf len={}", buf.len());

            if buf.is_empty() || buf.len() > ENCRYPTED_LEN_MAX {
                return Err(anyhow!("cleartext buffer len={}", buf.len()));
            }

            tracing::debug!("\nMESSAGE (from codec) {:?}", buf.hex_dump());

            // first things first, split the clear text message from the buf
            // provided by the codec so we can build the complete encrypted
            // message in an empty buffer
            let mut message = buf.split();

            // determine the length of clear text data without u16 length prefix
            // or the authtag.
            let msg_len = message.len();
            let msg_len_u16: u16 = msg_len.try_into()?;

            // the associated data for encryption is simply the length
            // of the message
            let associated_data = msg_len_u16.to_le_bytes();
            let key = &self.encrypt_key;

            // create our encryption nonce based on the number of blocks
            // we've encrypted thus far noting the padding requirements
            // for the u64 into a 12-byte nonce
            let mut nonce = Nonce::default();
            nonce[4..].copy_from_slice(&self.encrypt_nonce.to_le_bytes());

            // construct our the cipher instance
            let cipher = ChaCha20Poly1305::new(key);

            // ensure we have enough capacity in the message buffer for the
            // encrypted data + auth tag
            message.reserve(msg_len + 16);

            // do the actual encryption
            let tag = cipher
                .encrypt_in_place_detached(&nonce, &associated_data, &mut message)
                .map_err(|e| anyhow!("encrypt failed: {e}"))?;

            // build the complete message (message len header, encrypted data + auth tag) that we
            // want the codec to send.  NOTE: buf is empty

            // ensure buf has enough capacity to accept the complete message (lenght header,
            // encrypted data and auth tag)

            buf.reserve(msg_len + size_of::<u16>() + 16);
            buf.extend_from_slice(&msg_len_u16.to_le_bytes());
            buf.extend_from_slice(&message);
            buf.extend_from_slice(&tag);

            // increment our nonce
            self.encrypt_nonce += 1;
        }

        Ok(buf)
    }

    fn make_keys(self) -> Result<Self> {
        use hmac_sha512::HMAC;
        use AlkaliHMAC::authenticate as alkali_authenticate;

        let _prk = alkali_authenticate(&self.shared_secret, &SALT2)?;
        let prk = HMAC::mac(&self.shared_secret, SALT.as_slice());

        let mut encrypt_key = Key::default();
        encrypt_key.copy_from_slice(&HMAC::mac(READ_INFO, prk)[..32]);

        let mut decrypt_key = Key::default();
        decrypt_key.copy_from_slice(&HMAC::mac(WRITE_INFO, prk)[..32]);

        Ok(Self {
            encrypt_key,
            decrypt_key,
            ..self
        })
    }

    pub fn new(shared_secret: &[u8]) -> Result<Self> {
        Self {
            shared_secret: shared_secret.into(),
            ..Self::default()
        }
        .make_keys()
    }

    pub fn total_cipher_bytes(block_len: u16) -> usize {
        16 + block_len as usize
    }
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use pretty_hex::PrettyHex;

        writeln!(
            f,
            "CIPHER CONTEXT in={} out={}",
            self.decrypt_nonce, self.encrypt_nonce
        )?;

        if f.alternate() {
            writeln!(f, "\nSHARED SECRET {:?}", self.shared_secret.hex_dump())?;
            writeln!(f, "\nENCRYPT KEY {:?}", self.encrypt_key.hex_dump())?;
            writeln!(f, "\nDENCRYPT KEY {:?}", self.decrypt_key.hex_dump())?;
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use crate::Result;

    #[test]
    fn alkali_and_hmac_sha512_generate_same_prk() -> Result<()> {
        use super::SALT2;
        use crate::kit::tests::Data;
        use alkali::symmetric::auth::hmacsha512256::authenticate as alkali_authenticate;
        use hmac_sha512::HMAC;
        use pretty_hex::PrettyHex;

        let td = Data::get();

        let shared_secret = td.shared_secret;

        let alkali_auth = alkali_authenticate(&shared_secret, &SALT2)?;

        let hmac_auth = HMAC::mac(shared_secret, **SALT2);

        assert_eq!(alkali_auth.0.as_slice(), &hmac_auth[..32]);

        // println!(
        //     "\nALKALI AUTH {:?}\n\nHMAC AUTH {:?}",
        //     alkali_auth.0.hex_dump(),
        //     hmac_auth.hex_dump()
        // );

        Ok(())
    }
}
