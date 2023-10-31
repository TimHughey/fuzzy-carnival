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

use crate::Result;
use anyhow::anyhow;
use bstr::ByteSlice;
use bytes::BytesMut;
use once_cell::sync::Lazy;
use pretty_hex::PrettyHex;
use std::fmt;

pub(crate) mod kit;
pub(crate) mod msgs;
pub(crate) mod srp;

static TEST_DATA: Lazy<Data> = Lazy::new(Data::default);

#[derive(Clone)]
#[allow(unused, non_snake_case)]
pub struct Data {
    pub A: Vec<u8>,
    pub B: Vec<u8>,
    pub b: Vec<u8>,
    pub client_M1: Vec<u8>,
    pub H_AMK: Vec<u8>,
    pub s: Vec<u8>,
    pub server_M: Vec<u8>,
    pub server_M2: Vec<u8>,
    pub session_key: Vec<u8>,
    pub u: Vec<u8>,
    pub user_M: Vec<u8>,
    pub v: Vec<u8>,
    pub shared_secret: Vec<u8>, // should match session key
    pub read_key: Vec<u8>,      // after HKDF expand/extract
    pub write_key: Vec<u8>,     // after HKDF expand/extract
    pub alice: String,          // first chapter of Alice in Wonderland
    pub msgs: BytesMut,         // all inbound saved messages
}

impl Data {
    pub fn get() -> Self {
        TEST_DATA.clone()
    }

    #[allow(unused)]
    pub fn get_ref() -> &'static Self {
        &TEST_DATA
    }

    #[allow(unused)]
    pub fn shared_secret_as_ref() -> &'static Vec<u8> {
        TEST_DATA.shared_secret.as_ref()
    }

    pub fn get_msg(method: &str) -> Result<BytesMut> {
        let mut buf = TEST_DATA.msgs.clone();

        let at = buf
            .find(method)
            .ok_or_else(|| anyhow!("{method} not available"))?;

        let mut msg = buf.split_off(at);
        let at = msg
            .find(b"\x00!*!*!*\x00")
            .ok_or_else(|| anyhow!("could not find message end"))?;

        Ok(msg.split_to(at))
    }
}

impl Default for Data {
    fn default() -> Self {
        use std::{fs, path::Path};

        let base = std::env::var("CARGO_MANIFEST_DIR").unwrap();

        let data_dir = Path::new(&base)
            .parent()
            .unwrap()
            .join("extra")
            .join("test-data");

        let pairing_dir = data_dir.clone().join("pairing");
        let text_dir = data_dir.clone().join("text");
        let msgs_dir = data_dir.clone().join("msgs");

        let read_bin = |f: &str| {
            let mut file = pairing_dir.clone().join(f);

            file.set_extension("bin");

            fs::read(&file).unwrap()
        };

        let read_txt = |f: &str| {
            let mut file = text_dir.clone().join(f);

            file.set_extension("txt");

            fs::read(&file).unwrap().as_bstr().to_string()
        };

        let read_msgs = |f: &str| {
            let mut file = msgs_dir.clone().join(f);
            file.set_extension("bin");

            BytesMut::from(fs::read(&file).unwrap().as_slice())
        };

        Self {
            A: read_bin("A"),
            B: read_bin("B"),
            b: read_bin("b"),
            client_M1: read_bin("client_M1"),
            H_AMK: read_bin("H_AMK"),
            s: read_bin("s"),
            server_M: read_bin("server_M"),
            server_M2: read_bin("server_M2"),
            session_key: read_bin("session_key"),
            u: read_bin("u"),
            user_M: read_bin("user_M"),
            v: read_bin("v"),
            shared_secret: read_bin("shared_secret"),
            read_key: read_bin("read_key"),
            write_key: read_bin("write_key"),
            alice: read_txt("alice"),
            msgs: read_msgs("all"),
        }
    }
}

impl fmt::Debug for Data {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TestData\n")?;
        writeln!(f, "A {:?}\n", self.A.hex_dump())?;
        writeln!(f, "B {:?}\n", self.B.hex_dump())?;
        writeln!(f, "b {:?}\n", self.b.hex_dump())?;
        writeln!(f, "client M1 {:?}\n", self.client_M1.hex_dump())?;
        writeln!(f, "H_AMK {:?}\n", self.H_AMK.hex_dump())?;
        writeln!(f, "s {:?}\n", self.s.hex_dump())?;
        writeln!(f, "server M {:?}\n", self.server_M.hex_dump())?;
        writeln!(f, "server M2 {:?}\n", self.server_M2.hex_dump())?;
        writeln!(f, "sesion_key {:?}\n", self.session_key.hex_dump())?;
        writeln!(f, "u {:?}\n", self.u.hex_dump())?;
        writeln!(f, "user_bin {:?}\n", self.user_M.hex_dump())?;
        writeln!(f, "v {:?}\n", self.v.hex_dump())?;
        writeln!(f, "shared_secret {:?}\n", self.shared_secret.hex_dump())?;
        writeln!(f, "read_key {:?}\n", self.read_key.hex_dump())?;
        writeln!(f, "write_key {:?}\n", self.write_key.hex_dump())?;
        writeln!(f, "alice {:?}\n", self.alice.hex_dump())?;
        writeln!(f, "msgs {:?}\n", self.msgs.hex_dump())?;

        Ok(())
    }
}

#[cfg(test)]
use num_bigint::BigUint;
use num_traits::FromBytes;

#[test]
fn can_load_test_data() {
    use alkali::hash::sha2;

    const PUB_KEY_LEN: usize = 384;
    const SALT_LEN: usize = 16;
    const SEC_KEY_LEN: usize = 32;
    const SHA512_LEN: usize = sha2::sha512::DIGEST_LENGTH;

    let td = Data::get();

    let members: Vec<(&Vec<u8>, usize)> = vec![
        (&td.A, PUB_KEY_LEN),
        (&td.B, PUB_KEY_LEN),
        (&td.b, SEC_KEY_LEN),
        (&td.client_M1, SHA512_LEN),
        (&td.H_AMK, SHA512_LEN),
        (&td.s, SALT_LEN),
        (&td.server_M, SHA512_LEN),
        (&td.server_M2, SHA512_LEN),
        (&td.session_key, SHA512_LEN),
        (&td.user_M, SHA512_LEN),
        (&td.v, PUB_KEY_LEN),
        (&td.shared_secret, SHA512_LEN),
        (&td.read_key, SEC_KEY_LEN),
        (&td.write_key, SEC_KEY_LEN),
    ];

    for (member, expected_len) in members {
        // validate the length in bytes
        assert_eq!(member.len(), expected_len);

        let bnum = BigUint::from_be_bytes(member);
        let want_bits = ((expected_len * 8) - 1) as u64;

        // validate sufficient bits are required to represent the
        // big integer (aka non-zero)
        assert!(bnum.bits() >= want_bits);
    }

    let alice = &td.alice;
    assert!(alice.len() > 2048);

    let msgs = &td.msgs;
    assert!(msgs.len() > 4096);
}
