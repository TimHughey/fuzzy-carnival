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

pub mod states;
pub use states::Generic as GenericState;
pub use states::Verify as VerifyState;

pub mod tags;
pub use tags::Map as Tags;

use crate::{
    asym::Keys,
    rtsp::{Body, HeaderContType, HeaderList, Response, StatusCode},
    HostInfo, Result,
};
#[allow(unused)]
use alkali::{
    asymmetric::{cipher, sign},
    mem,
    symmetric::auth,
};
use anyhow::anyhow;
use bytes::{Bytes, BytesMut};
use once_cell::sync::Lazy;
#[allow(unused)]
use pretty_hex::PrettyHex;
use std::{fmt, sync::RwLock};
use tracing::{error, info};

type SignSeed = sign::Seed<mem::FullAccess>;
type SignKeyPair = sign::Keypair;

pub struct Context {
    // copy signing info from HostInfo for easy access
    signing_seed: SignSeed,
    #[allow(unused)]
    signing_kp: SignKeyPair,
    #[allow(unused)]
    server_eph: cipher::Keypair,
    client_eph_pk: RwLock<Option<cipher::PublicKey>>,
    session_key: RwLock<Option<cipher::SessionKey<mem::FullAccess>>>,
}

pub use Context as HomeKit;

unsafe impl Send for HomeKit {}

impl fmt::Debug for HomeKit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "HomeKit")
    }
}

static HOMEKIT: Lazy<HomeKit> = Lazy::new(|| {
    let homekit = Context::build();

    match homekit {
        Ok(hk) => hk,
        Err(e) => {
            error!("HomeKit build failed: {e}");
            panic!("unable to continue");
        }
    }
});

impl HomeKit {
    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if unable to
    /// generate security `Seed` or `KeyPair`.
    pub fn build() -> crate::Result<Self> {
        Ok(Self {
            signing_seed: HostInfo::clone_seed()?,
            signing_kp: Keys::clone_signing()?,
            server_eph: cipher::Keypair::generate()?,
            client_eph_pk: RwLock::new(None),
            session_key: RwLock::new(None),
        })
    }

    /// .
    ///
    /// # Panics
    ///
    /// Panics if .
    #[must_use]
    pub fn get_client_eph_pk() -> cipher::PublicKey {
        let pk_lock = HOMEKIT.client_eph_pk.read().unwrap();

        if let Some(pk) = *pk_lock {
            return pk;
        }

        panic!("foo");
    }

    #[must_use]
    pub fn get_server_eph() -> &'static cipher::Keypair {
        &HOMEKIT.server_eph
    }

    #[must_use]
    pub fn get_signing_seed() -> &'static SignSeed {
        &HOMEKIT.signing_seed
    }

    #[must_use]
    pub fn get_server_sign_keys() -> &'static SignKeyPair {
        &HOMEKIT.signing_kp
    }

    /// .
    ///
    /// # Panics
    ///
    /// Panics if Session Key is not available.
    #[must_use]
    pub fn get_session_key() -> cipher::SessionKey<mem::FullAccess> {
        let lock = HOMEKIT.session_key.read().unwrap();

        if let Some(session_key) = &*lock {
            if let Ok(key) = session_key.try_clone() {
                return key;
            }
        }

        panic!("coding error");
    }

    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    pub fn handle_request(headers: HeaderList, body: Body, path: &str) -> Result<Response> {
        match (path, body) {
            ("/pair-verify", Body::Bulk(bulk)) => {
                use VerifyState::{Msg01, Msg02, Msg03, Msg04};

                let buf: BytesMut = BytesMut::from(bulk.as_slice());

                let list = Tags::try_from(buf)?;

                let state = VerifyState::try_from(list.get_state()?)?;

                match state {
                    Msg01 => {
                        info!("{path} {state:?}");

                        let pk = list.get_public_key()?;

                        HomeKit::push_client_pub_key(pk);

                        // create and sign accessory info
                        let device_id = HostInfo::id_as_slice();
                        let server_sign = HomeKit::get_server_sign_keys();
                        let server_eph = HomeKit::get_server_eph();
                        let server_pk = server_eph.public_key;
                        let client_pk = HomeKit::get_client_eph_pk();

                        let info: Bytes = [device_id, server_pk.as_slice(), client_pk.as_slice()]
                            .concat()
                            .into();

                        let capacity = info.len() + sign::SIGNATURE_LENGTH;
                        let mut signature = BytesMut::with_capacity(capacity);

                        sign::sign(&info, server_sign, &mut signature)?;

                        // info!("signature {:?}\nlen check {sig_len}", signature.hex_dump());

                        let mut reply_tags = Tags::default();
                        reply_tags.push(tags::Val::Identifier(device_id.into()));
                        reply_tags.push(tags::Val::Signature(signature.into()));

                        let part1: Bytes = reply_tags.clone().try_into()?;

                        // HMAC
                        let session_key = HomeKit::get_session_key();
                        let mut auth_key = auth::Key::new_empty()?;

                        auth_key.copy_from_slice(session_key.as_slice());

                        let derived_key = auth::authenticate(&part1, &auth_key)?;

                        info!("DERIVED KEY {:?}", derived_key);

                        let body = reply_tags.encode();

                        Ok(Response {
                            status_code: StatusCode::OK,
                            headers: HeaderList::make_response(
                                headers,
                                HeaderContType::AppOctetStream,
                                0,
                            ),
                            body,
                        })
                    }
                    Msg02 | Msg03 | Msg04 => Err(anyhow!("{path}: got state {state:?}")),
                }
            }
            (path, body) => Err(anyhow!("unhandled path: {path}\nbody {}", body)),
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

    fn push_client_pub_key(client_eph_pk: cipher::PublicKey) {
        let server_kp = &HOMEKIT.server_eph;
        let mut cpk = HOMEKIT.client_eph_pk.write().unwrap();
        let mut sess_key = HOMEKIT.session_key.write().unwrap();

        *sess_key = Some(server_kp.session_key(&client_eph_pk).unwrap());
        *cpk = Some(client_eph_pk);
    }
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

    use super::{HomeKit, Result, Tags, HOMEKIT};
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
                Self {
                    server: cipher::Keypair::generate().expect("failed to generate server keys"),
                    client: cipher::Keypair::generate().expect("failed to generate client keys"),
                }
            }
        }

        // #[derive(Default)]
        // pub struct Keys {
        //     eph: Ephemral,
        // }

        // impl Keys {
        //     pub fn eph_server(&self) -> (&[u8], &[u8]) {
        //         (self.eph.server_pk(), self.eph.server_sk())
        //     }
        // }
    }

    #[test]
    pub fn can_generate_ephermal_keys() -> Result<()> {
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
    fn can_lazy_create_homekit() {
        let signing_seed = HomeKit::get_signing_seed();

        println!("signing seed: {:?}", signing_seed.hex_dump());
    }

    #[test]
    pub fn can_push_client_eph_public_key() -> crate::Result<()> {
        let kp = cipher::Keypair::generate()?;
        let pk = kp.public_key;

        HomeKit::push_client_pub_key(kp.public_key);

        let check_pk_lock = HOMEKIT.client_eph_pk.read().unwrap();
        let check_pk_ref = check_pk_lock.as_ref().unwrap();
        let check_pk = *check_pk_ref;

        assert_eq!(check_pk, pk);

        let sess_key_lock = HOMEKIT.session_key.read().unwrap();
        let sess_key = sess_key_lock.as_ref();

        assert!(matches!(sess_key, Some(_)));

        Ok(())
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

// enum pair_status {
//     PAIR_STATUS_IN_PROGRESS,
//     PAIR_STATUS_COMPLETED,
//     PAIR_STATUS_AUTH_FAILED,
//     PAIR_STATUS_INVALID,
//   };

// struct pair_setup_context {
//     struct pair_definition *type;
//
//     enum pair_status status;
//     const char *errmsg;
//
//     struct pair_result result;
//     char result_str[256]; // Holds the hex string version of the keys that
//                           // pair_verify_new() needs
//
//     // Hex-formatet concatenation of public + private, 0-terminated
//     char auth_key[2 * (crypto_sign_PUBLICKEYBYTES + crypto_sign_SECRETKEYBYTES) + 1];
//
//     union pair_setup_union {
//       struct pair_client_setup_context client;
//       struct pair_server_setup_context server;
//     } sctx;
//   };

// struct pair_server_setup_context {
//     struct SRPVerifier *verifier;
//
//     uint8_t pin[4];
//     char device_id[PAIR_AP_DEVICE_ID_LEN_MAX];
//
//     pair_cb add_cb;
//     void *add_cb_arg;
//
//     uint8_t public_key[crypto_sign_PUBLICKEYBYTES];
//     uint8_t private_key[crypto_sign_SECRETKEYBYTES];
//
//     bool is_transient;
//
//     uint8_t *pkA;
//     uint64_t pkA_len;
//
//     uint8_t *pkB;
//     int pkB_len;
//
//     uint8_t *b;
//     int b_len;
//
//     uint8_t *M1;
//     uint64_t M1_len;
//
//     const uint8_t *M2;
//     int M2_len;
//
//     uint8_t *v;
//     int v_len;
//
//     uint8_t *salt;
//     int salt_len;
//   };

// struct pair_server_verify_context {
//     char device_id[PAIR_AP_DEVICE_ID_LEN_MAX];
//
//     // Same keys as used for pair-setup, derived from device_id
//     uint8_t server_public_key[crypto_sign_PUBLICKEYBYTES];  // 32
//     uint8_t server_private_key[crypto_sign_SECRETKEYBYTES]; // 64
//
//     bool verify_client_signature;
//     pair_cb get_cb;
//     void *get_cb_arg;
//
//     // For establishing the shared secret for encrypted communication
//     uint8_t server_eph_public_key[crypto_box_PUBLICKEYBYTES];  // 32
//     uint8_t server_eph_private_key[crypto_box_SECRETKEYBYTES]; // 32
//
//     uint8_t client_eph_public_key[crypto_box_PUBLICKEYBYTES]; // 32
//
//     uint8_t shared_secret[crypto_scalarmult_BYTES]; // 32
//   };

// struct pair_verify_context {
//     struct pair_definition *type;
//
//     enum pair_status status;
//     const char *errmsg;
//
//     struct pair_result result;
//
//     union pair_verify_union {
//       struct pair_client_verify_context client;
//       struct pair_server_verify_context server;
//     } vctx;
//   };
