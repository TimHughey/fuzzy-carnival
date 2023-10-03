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
    rtsp::{Body, Frame, HeaderList, Response},
    HostInfo, Result,
};
use anyhow::anyhow;
use bytes::{Bytes, BytesMut};
use std::fmt;
use tracing::{error, info};

pub mod info;
pub mod states;
pub mod tags;
pub mod verify;

pub use states::Generic as GenericState;
pub use states::Verify as VerifyState;
pub use tags::Map as Tags;
pub use tags::Val as TagVal;
pub use verify::Context as VerifyCtx;

pub struct Context {
    pub device_id: BytesMut,
    pub verify: VerifyCtx,
}

pub use Context as HomeKit;

unsafe impl Send for HomeKit {}

impl fmt::Debug for HomeKit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "HomeKit")
    }
}

impl HomeKit {
    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if unable to
    /// generate security `Seed` or `KeyPair`.
    #[must_use]
    pub fn build() -> Self {
        let mut id_buf = BytesMut::with_capacity(64);
        id_buf.extend_from_slice(HostInfo::id_as_slice());

        Self {
            device_id: id_buf,
            // signing_seed: HostInfo::clone_seed()?,
            // signing_kp: Keys::clone_signing()?,
            // server_eph: cipher::Keypair::generate()?,
            // client_eph_pk: OnceCell::new(),
            // shared_secret: OnceCell::new(),
            // session_key: None,
            verify: VerifyCtx::build(),
        }
    }

    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    pub fn hkdf_extract_expand(&self, in_km: BytesMut) -> [u8; 32] {
        // use hex::ToHex;
        use bytes::BufMut;
        use hmac_sha256::HKDF;

        let salt = "Pair-Verify-Encrypt-Salt".as_bytes();
        let info = "Pair-Verify-Encrypt-Info".as_bytes();

        let mut info1 = BytesMut::from(info);
        info1.put_u8(1);

        let mut out_km = [0u8; 32];

        let prk = HKDF::extract(salt, in_km);
        HKDF::expand(&mut out_km, prk, info);

        out_km
    }

    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    pub fn respond_to(&mut self, frame: Frame) -> Result<Response> {
        let path = frame.path.as_str();

        match (path, frame.body) {
            (path, Body::Bulk(bulk)) if path.ends_with("verify") => {
                use VerifyState::{Msg01, Msg02, Msg03, Msg04};

                let buf = BytesMut::from(bulk.as_slice());
                let list = Tags::try_from(buf)?;
                let state = VerifyState::try_from(list.get_state()?)?;

                match state {
                    Msg01 => {
                        info!("{path} {state:?}");
                        let verify = &self.verify;

                        let pk = list.get_public_key()?;
                        let tags = verify.m1_m2(pk)?;

                        let body = Body::OctetStream(tags.encode().to_vec());

                        Ok(Response {
                            headers: HeaderList::make_response2(frame.headers, &body)?,
                            body,
                            ..Response::default()
                        })
                    }
                    Msg02 | Msg03 | Msg04 => Err(anyhow!("{path}: got state {state:?}")),
                }
            }

            (path, Body::Bulk(bulk)) if path.ends_with("setup") => {
                let buf = BytesMut::from(bulk.as_slice());
                let list = Tags::try_from(buf)?;
                let state = list.get_state()?;

                info!("\nstate: {state:?} {path} {list:?}");

                Ok(Response::default())
            }

            (path, body) => {
                error!("{body:?}");

                Err(anyhow!("unhandled path: {path}"))
            }
        }
    }

    #[must_use]
    pub fn make_info(a: &[u8], b: &[u8], c: &[u8]) -> Bytes {
        let capacity = a.len() + c.len() + c.len();

        let mut buf = BytesMut::with_capacity(capacity);
        buf.extend_from_slice(a);
        buf.extend_from_slice(b);
        buf.extend_from_slice(c);

        buf.into()
    }
}

/// Creates a response to a `Frame`
///
///
///
/// # Errors
///
/// This function will return an error if .
pub fn respond_to(mut frame: Frame) -> Result<Response> {
    if let Some(mut kit) = frame.homekit.take() {
        let response = kit.respond_to(frame)?;

        return Ok(Response {
            homekit: Some(kit),
            ..response
        });
    }

    error!("homekit not present in {frame}");

    Err(anyhow!("frame missing homekit"))
}

mod helper {
    use bytes::{Bytes, BytesMut};

    #[must_use]
    #[allow(dead_code)]
    pub fn make_info(a: &[u8], b: &[u8], c: &[u8]) -> Bytes {
        let capacity = a.len() + c.len() + c.len();

        let mut buf = BytesMut::with_capacity(capacity);
        buf.extend_from_slice(a);
        buf.extend_from_slice(b);
        buf.extend_from_slice(c);

        buf.into()
    }
}

#[cfg(test)]
mod tests {

    use super::{Result, Tags};
    use crate::HostInfo;
    use alkali::{
        asymmetric::{cipher, sign::Seed},
        hash,
        symmetric::auth,
    };
    use bstr::ByteSlice;
    use bytes::{BufMut, BytesMut};
    use num_bigint::BigUint;
    use pretty_hex::PrettyHex;
    use rand::RngCore;
    use sha2::Sha512;
    use srp::{client::SrpClient, groups::G_3072, server::SrpServer};

    pub mod keys {
        use crate::Result;
        use alkali::{
            asymmetric::cipher,
            // hash::{self, generic::Key},
            mem,
            // symmetric::auth,
        };
        // use anyhow::anyhow;

        pub struct Ephemral {
            pub server: cipher::Keypair,
            pub client: cipher::Keypair,
        }

        impl Ephemral {
            pub fn client_pk(&self) -> &[u8] {
                self.client.public_key.as_slice()
            }

            pub fn server_pk(&self) -> &[u8] {
                self.server.public_key.as_slice()
            }

            pub fn server_sk(&self) -> &[u8] {
                self.server.private_key.as_slice()
            }

            #[must_use = "mutates and returns self"]
            pub fn put_client_pk(mut self, pk: cipher::PublicKey) -> Self {
                self.client.public_key = pk;

                self
            }

            pub fn zero(mut self) -> Result<Ephemral> {
                let sk = cipher::PrivateKey::<mem::FullAccess>::new_empty()?;

                self.server = cipher::Keypair {
                    public_key: [0u8; cipher::PUBLIC_KEY_LENGTH],
                    private_key: sk.try_clone()?,
                };

                self.client = cipher::Keypair {
                    public_key: [0u8; cipher::PUBLIC_KEY_LENGTH],
                    private_key: sk,
                };

                Ok(self)
            }
        }

        impl Default for Ephemral {
            fn default() -> Self {
                let msg = "failed to generate server keys";

                Self {
                    server: cipher::Keypair::generate().expect(msg),
                    client: cipher::Keypair::generate().expect("failed to generate client keys"),
                }
            }
        }
    }

    #[test]
    fn can_generate_ephermal_keys() -> Result<()> {
        let mut eph = keys::Ephemral::default();

        println!("CLIENT PublicKey{:?}\n", eph.client_pk().hex_dump());

        eph = eph.zero()?;

        println!("SERVER  PublicKey{:?}\n", eph.server_pk().hex_dump());
        println!("SERVER PrivateKey{:?}\n", eph.server_sk().hex_dump());

        let new_key = cipher::Keypair::generate()?;

        let (eph, ()) = (eph.put_client_pk(new_key.public_key), ());

        println!("CLIENT PublicKey{:?}\n", eph.client_pk().hex_dump());

        Ok(())
    }

    #[test]
    pub fn can_generate_derived_key() -> Result<()> {
        use hash::generic::hash;

        let server_eph = cipher::Keypair::generate()?;
        let client_eph = cipher::Keypair::generate()?;

        let mut message = BytesMut::try_from(server_eph.public_key.as_slice())?;
        message.extend_from_slice(client_eph.public_key.as_slice());

        println!("MESSAGE {:?}\n", message.hex_dump());

        let salt_raw = b"Pair-Verify-Encrypt-Salt";
        let mut salt = BytesMut::with_capacity(32);

        salt.extend_from_slice(salt_raw);
        salt.put_bytes(0u8, 32 - salt_raw.len());

        println!("SALT {:?}\n", salt.hex_dump());

        let hashed = hash(&message, Some(&salt))?;

        println!("HASHED {:?}\n", hashed.hex_dump());

        let key = auth::Key::try_from(salt.to_vec().as_slice())?;

        let derived_key = auth::authenticate(&message, &key)?;

        println!("DERIVED KEY: {:?}", derived_key.0.hex_dump());

        Ok(())
    }

    #[derive(Debug)]
    pub struct Musing {
        alpha: u8,
        beta: String,
        gamma: Option<String>,
    }

    #[test]
    pub fn musing_test() {
        let musing = Musing {
            alpha: 13u8,
            beta: "day".into(),
            gamma: Some("night".into()),
        };

        let Musing { alpha, .. } = musing;

        println!("musing {musing:?} beta: {}", musing.beta);

        let musing2 = Musing { alpha, ..musing };

        let Musing { gamma, .. } = musing2;

        println!("musing2 beta {}", musing2.beta);

        let musing3 = Musing {
            gamma: None,
            ..musing2
        };

        println!("musing3 {musing3:?}");
        println!("musing2 gamma {gamma:?}");
    }

    #[test]
    pub fn create_srp() {
        let mut rng = rand::rngs::OsRng;

        let username = b"alice";
        let true_pwd = b"password";

        // Client instance creation
        let client = SrpClient::<Sha512>::new(&G_3072);

        // Begin Registration

        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        let verifier = client.compute_verifier(username, true_pwd, &salt);

        // Client sends username and verifier and salt to the Server for storage

        // Registration Ends

        // Begin Authentication

        // User sends username

        let server = SrpServer::<Sha512>::new(&G_3072);

        // Server retrieves verifier, salt and computes a public B value
        let mut b = [0u8; 64];
        rng.fill_bytes(&mut b);
        let b_pub: Vec<u8> = server.compute_public_ephemeral(&b, &verifier);

        // println!(
        //     "verifier {:?}\nsalt {:?}\n b_pub {:?}",
        //     PrettyHex::hex_dump(&verifier),
        //     PrettyHex::hex_dump(&salt),
        //     PrettyHex::hex_dump(&b_pub)
        // );

        salt.iter().for_each(|b| assert_ne!(b, &0u8));
        let b_pub_sum: BigUint = b_pub.into_iter().sum();
        assert_ne!(b_pub_sum, BigUint::new(vec![0]));

        // Server sends salt and b_pub to client
    }

    #[test]
    pub fn parse_verify_request1a() {
        let bytes: [u8; 37] = [
            0x06, 0x01, 0x01, 0x03, 0x20, 0xf0, 0x0B, 0x71, 0x42, 0x70, 0x26, 0xe1, 0x7e, 0x23,
            0xed, 0x0a, 0x8b, 0x71, 0x17, 0x87, 0xa6, 0x79, 0x3d, 0x50, 0xd3, 0x21, 0x48, 0x4a,
            0xa6, 0x49, 0xac, 0xaa, 0x44, 0x26, 0x81, 0x9f, 0x38,
        ];

        let mut buf = BytesMut::new();
        buf.extend_from_slice(bytes.as_bytes());

        let tags = Tags::try_from(buf);

        assert!(tags.is_ok());
    }

    #[test]
    pub fn check_key_creation() -> crate::Result<()> {
        // println!("seed1 {:?}", seed0.hex_dump());

        let dev_id1 = HostInfo::seed();
        let seed1 = Seed::try_from(dev_id1.as_bytes())?;

        // println!("host seed {:?}", dev_id1.hex_dump());
        // println!("seed1 {:?}", seed1.hex_dump());

        assert_eq!(dev_id1.as_slice(), seed1.as_slice());

        Ok(())
    }
}
