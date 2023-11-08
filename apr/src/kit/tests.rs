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

#[cfg(test)]
use crate::{
    kit::msg::{Frame, Inflight},
    Result,
};
use anyhow::anyhow;
use bstr::ByteSlice;
use bytes::{Buf, BytesMut};
use once_cell::sync::Lazy;
use pretty_hex::PrettyHex;
use std::fmt;

pub(crate) mod kit;
pub(crate) mod msgs;
pub(crate) mod srp;

static TEST_DATA: Lazy<Data> = Lazy::new(Data::default);

enum Kind {
    Rtsp,
    Text,
    Ptp,
    Pairing,
}

impl Kind {
    pub fn filename(self, f: &str) -> String {
        let extension = match self {
            Kind::Rtsp | Kind::Ptp | Kind::Pairing => "bin",
            Kind::Text => "txt",
        };

        format!("{f}.{extension}")
    }
}

impl AsRef<str> for Kind {
    fn as_ref(&self) -> &str {
        match self {
            Kind::Rtsp => "rtsp",
            Kind::Text => "text",
            Kind::Ptp => "ptp",
            Kind::Pairing => "pairing",
        }
    }
}

fn read(kind: Kind, f: &str) -> BytesMut {
    use std::{fs, path::Path};

    let base = std::env::var("CARGO_MANIFEST_DIR").expect("CARFO_MANIFEST_DIR missing");

    let file = Path::new(&base)
        .parent()
        .unwrap()
        .join("extra")
        .join("test-data")
        .join(kind.as_ref())
        .join(kind.filename(f));

    BytesMut::from(fs::read(file).unwrap().as_slice())
}

#[derive(Clone)]
#[allow(unused, non_snake_case)]
pub struct Data {
    pub A: BytesMut,
    pub B: BytesMut,
    pub b: BytesMut,
    pub client_M1: BytesMut,
    pub H_AMK: BytesMut,
    pub s: BytesMut,
    pub server_M: BytesMut,
    pub server_M2: BytesMut,
    pub session_key: BytesMut,
    pub u: BytesMut,
    pub user_M: BytesMut,
    pub v: BytesMut,
    pub shared_secret: BytesMut, // should match session key
    pub read_key: BytesMut,      // after HKDF expand/extract
    pub write_key: BytesMut,     // after HKDF expand/extract
    pub alice: BytesMut,         // first chapter of Alice in Wonderland
    pub msgs: BytesMut,          // all inbound saved rtsp messages
    pub ptp: BytesMut,           // all inbound saved ptp messages
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

    pub fn get_inflight(method: &str, cseq: Option<u32>) -> Result<Inflight> {
        let needle_eom = b"\x00!*!*!*\x00";
        let mut buf: BytesMut = TEST_DATA.msgs.clone();

        let needle = [method.to_string(), " ".to_string()].concat();

        'all_msgs: loop {
            if let Some(msg_at) = buf.find(needle.as_bytes()) {
                buf.advance(msg_at); // ignore everything prior to this message

                // now find the end of the message
                if let Some(eom_at) = buf.find(needle_eom) {
                    let mut maybe_raw_msg = buf.split_to(eom_at);

                    let mut inflight = Inflight::default();
                    inflight.absorb_buf(&mut maybe_raw_msg)?;
                    inflight.absorb_content(&mut maybe_raw_msg);

                    if inflight.check_complete()? && cseq.is_none()
                        || (cseq.is_some() && inflight.cseq == cseq)
                    {
                        return Ok(inflight);
                    }

                    // not the frame we're looking for, skip EOM and continue
                    buf.advance(needle_eom.len());
                }
            } else {
                break 'all_msgs;
            }

            if buf.is_empty() {
                break 'all_msgs;
            }
        }

        let mut error = format!("message not available: {method}");

        if let Some(cseq) = cseq {
            error = [error, format!(" {cseq:03}")].concat();
        }

        Err(anyhow!(error))
    }

    pub fn get_frame(method: &str, cseq: Option<u32>) -> Result<Frame> {
        let inflight = Self::get_inflight(method, cseq)?;

        Frame::try_from(inflight)
    }
}

impl Default for Data {
    fn default() -> Self {
        Self {
            A: read(Kind::Pairing, "A"),
            B: read(Kind::Pairing, "B"),
            b: read(Kind::Pairing, "b"),
            client_M1: read(Kind::Pairing, "client_M1"),
            H_AMK: read(Kind::Pairing, "H_AMK"),
            s: read(Kind::Pairing, "s"),
            server_M: read(Kind::Pairing, "server_M"),
            server_M2: read(Kind::Pairing, "server_M2"),
            session_key: read(Kind::Pairing, "session_key"),
            u: read(Kind::Pairing, "u"),
            user_M: read(Kind::Pairing, "user_M"),
            v: read(Kind::Pairing, "v"),
            shared_secret: read(Kind::Pairing, "shared_secret"),
            read_key: read(Kind::Pairing, "read_key"),
            write_key: read(Kind::Pairing, "write_key"),
            alice: read(Kind::Text, "alice"),
            msgs: read(Kind::Rtsp, "all"),
            ptp: read(Kind::Ptp, "all"),
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
        writeln!(f, "rtsp msgs {:?}\n", self.msgs.hex_dump())?;
        writeln!(f, "ptp msgs {:?}\n", self.ptp.hex_dump())?;

        Ok(())
    }
}

#[cfg(test)]
use num_bigint::BigUint;
use num_traits::FromBytes;
use tracing_test::traced_test;

#[test]
fn can_load_test_data() {
    use alkali::hash::sha2;

    const PUB_KEY_LEN: usize = 384;
    const SALT_LEN: usize = 16;
    const SEC_KEY_LEN: usize = 32;
    const SHA512_LEN: usize = sha2::sha512::DIGEST_LENGTH;

    let td = Data::get();

    let members: Vec<(&BytesMut, usize)> = vec![
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

    let rtsp_msgs = &td.msgs;
    assert!(rtsp_msgs.len() > 4096);

    let ptp_msgs = &td.ptp;
    assert!(ptp_msgs.len() > 1024);
}

#[test]
#[traced_test]
fn can_get_frame_by_cseq() -> Result<()> {
    let frame = Data::get_frame("SETUP", Some(14))?;
    let method = frame.routing.method_cloned();

    assert_eq!(method.as_str(), "SETUP");
    assert!(frame.routing.is_rtsp());
    assert_eq!(frame.cseq, 14);
    assert!(frame.content.is_some());

    Ok(())
}
