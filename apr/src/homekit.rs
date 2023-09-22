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

pub mod verify;
pub use verify::Context as VerifyCtx;

pub mod tlv;
pub use tlv::Tag;
pub use tlv::TagList;
pub use tlv::Val as TagVal;
pub use tlv::Variant as TagVariant;

use crate::{asym::Keys, rtsp::HeaderList, rtsp::Response};
use alkali::{
    asymmetric::{cipher, sign},
    mem,
};
use once_cell::sync::Lazy;
use std::{fmt, sync::RwLock};
use tracing::{error, info, warn};

type SignSeed = sign::Seed<mem::FullAccess>;
type SignKeyPair = sign::Keypair;

// pub struct Context {
//     // copy signing info from HostInfo for easy access
//     signing_seed: SignSeed,
//     signing_kp: SignKeyPair,
//     server_eph: cipher::Keypair,
//     client_eph_pk: RefCell<Option<cipher::PublicKey>>,
// }

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
    /// This function will return an error if .
    pub fn build() -> crate::Result<Self> {
        use crate::HostInfo;

        Ok(Self {
            signing_seed: HostInfo::clone_seed()?,
            signing_kp: Keys::clone_signing()?,
            server_eph: cipher::Keypair::generate()?,
            client_eph_pk: RwLock::new(None),
            session_key: RwLock::new(None),
        })
    }

    #[must_use]
    pub fn get_signing_seed() -> &'static SignSeed {
        &HOMEKIT.signing_seed
    }

    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    pub fn handle_request(_hdr_list: HeaderList, list: &TagList, path: &str) -> crate::Result<()> {
        match path {
            "/pair-verify" => {
                use TagVal::PublicKey;
                use VerifyState::{Msg01, Msg02, Msg03, Msg04};

                let state = VerifyState::try_from(list.get_state()?)?;

                match state {
                    Msg01 => {
                        info!("state Msg01");

                        if let Tag {
                            val: PublicKey(pk), ..
                        } = list.get(&TagVariant::PublicKey)?
                        {
                            HomeKit::push_client_pub_key(pk);
                        }
                    }
                    Msg02 => {
                        info!("got state Msg02");
                    }
                    Msg03 => {
                        info!("got state Msg03");
                    }
                    Msg04 => {
                        info!("got state Msg04");
                    }
                }
            }
            path => warn!("unhandled path: {path}"),
        }

        Ok(())
    }

    fn push_client_pub_key(client_eph_pk: cipher::PublicKey) {
        let server_kp = &HOMEKIT.server_eph;
        let mut cpk = HOMEKIT.client_eph_pk.write().unwrap();
        let mut sess_key = HOMEKIT.session_key.write().unwrap();

        *sess_key = Some(server_kp.session_key(&client_eph_pk).unwrap());
        *cpk = Some(client_eph_pk);
    }
}

#[cfg(test)]
mod tests_homekit {
    use super::HomeKit;
    use pretty_hex::PrettyHex;

    #[test]
    fn can_lazy_create_homekit() {
        let signing_seed = HomeKit::get_signing_seed();

        println!("signing seed: {:?}", signing_seed.hex_dump());
    }
}

#[cfg(test)]
mod tests {

    use super::{HomeKit, TagList, HOMEKIT};
    use crate::HostInfo;
    use alkali::asymmetric::{
        cipher,
        sign::{self, Keypair, Seed},
    };
    use anyhow::anyhow;
    use bytes::BytesMut;
    use der_parser::{
        ber::{BerObject, BerObjectContent},
        nom::AsBytes,
        parse_ber,
    };
    use ed25519_compact as ed25519;
    use num_bigint::BigUint;
    use pretty_hex::PrettyHex;
    use rand::RngCore;
    use sha2::Sha512;
    use srp::{client::SrpClient, groups::G_3072, server::SrpServer};

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
    pub fn create_server_keys() -> crate::Result<()> {
        let mut rng = rand::rngs::OsRng;

        //
        // INITIAL ED25519 UNSECURE KEY PAIR SEEDED WITH DEVICE ID
        //

        let device_id = HostInfo::id_as_slice();

        let mut seed_src = [0u8; sign::KEYPAIR_SEED_LENGTH];
        seed_src[..device_id.len()].copy_from_slice(device_id);

        let seed = ed25519::Seed::try_from(seed_src)?;
        let key_pair = ed25519::KeyPair::from_seed(seed);
        let pub_key1 = key_pair.pk.as_slice();
        let sec_key1 = key_pair.sk.as_slice();

        // println!(
        //     "\npk {:?}\nsk {:?}\n\n",
        //     PrettyHex::hex_dump(pub_key1),
        //     PrettyHex::hex_dump(sec_key1)
        // );

        let mut seed_src = [0u8; 32];
        seed_src[..device_id.len()].copy_from_slice(device_id.as_bytes());

        let seed2 = Seed::try_from(seed_src.as_slice())?;
        let key_pair = Keypair::from_seed(&seed2)?;

        let pub_key2 = key_pair.public_key.as_slice();
        let sec_key2 = key_pair.private_key.as_slice();

        // println!(
        //     "\npk {:?}\nsk {:?}\n\n",
        //     PrettyHex::hex_dump(pub_key2),
        //     PrettyHex::hex_dump(sec_key2)
        // );

        assert_eq!(pub_key1, pub_key2);
        assert_eq!(sec_key1, sec_key2);

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

        Ok(())
    }

    #[test]
    pub fn parse_verify_request1() -> crate::Result<()> {
        let bytes = [
            0x06, 0x01, 0x01, 0x03, 0x20, 0xf0, 0x0B, 0x71, 0x42, 0x70, 0x26, 0xe1, 0x7e, 0x23,
            0xed, 0x0a, 0x8b, 0x71, 0x17, 0x87, 0xa6, 0x79, 0x3d, 0x50, 0xd3, 0x21, 0x48, 0x4a,
            0xa6, 0x49, 0xac, 0xaa, 0x44, 0x26, 0x81, 0x9f, 0x38,
        ];

        let mut objs = Vec::<BerObject>::with_capacity(10);
        let mut rest = bytes.as_slice();

        while !rest.is_empty() {
            match parse_ber(rest) {
                Ok((tail, obj)) => {
                    rest = tail;
                    println!("{obj:?}");
                    objs.push(obj);
                }
                Err(e) => Err(anyhow!(e))?,
            }
        }

        objs.iter().for_each(|obj| match &obj.content {
            BerObjectContent::BitString(unused, obj) => {
                println!("\nunused: {}, public key: {:?}", unused, obj.hex_dump());
            }
            BerObjectContent::OID(oid) => {
                println!("\nstate: {}", oid.as_bytes().hex_dump());
            }
            _ => (),
        });

        // let (rem, x) = parse_ber(&bytes)?;

        // let state = x.as_bytes();

        // println!("state: {:?}", state.hex_dump());
        // println!("\nfull parse remain: {:?}", rem.hex_dump());

        // let (rem, x) = BitString::from_ber(rem)?;
        // let x2 = x.to_der_vec()?;
        // println!(
        //     "\nfull second parse obj: {:?}",
        //     PrettyHex::hex_dump(&x2[2..])
        // );

        // let (rem, obj1) = parse_ber_oid(&bytes)?;
        // println!("first {obj1:?}");

        // println!("\nremaining: {:?}", PrettyHex::hex_dump(rem));

        // let (rem, obj2) = parse_ber_bitstring(rem)?;

        // println!("\nparsed second: {obj2:?}");

        // let data = obj2.as_bitstring()?.data;

        // println!("second {:?}", PrettyHex::hex_dump(&data));

        assert_eq!(rest.len(), 0);

        Ok(())
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

        match TagList::try_from(buf) {
            Ok(list) => println!("{list:?}"),
            Err(e) => println!("TVVList2::try_from() error: {e}"),
        }
    }

    #[test]
    pub fn check_key_creation() -> crate::Result<()> {
        // println!("seed1 {:?}", seed0.hex_dump());

        let dev_id1 = HostInfo::seed();
        let seed1 = Seed::try_from(dev_id1.as_bytes())?;

        println!("host seed {:?}", dev_id1.hex_dump());
        println!("seed1 {:?}", seed1.hex_dump());

        assert_eq!(dev_id1.as_slice(), seed1.as_slice());

        // assert_eq!(seed0, seed1);

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
