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

use crate::{homekit::Tags, HostInfo};
use alkali::asymmetric::sign::Seed;
use bstr::ByteSlice;
use bytes::BytesMut;

#[test]
pub fn parse_verify_request1a() {
    let bytes: [u8; 37] = [
        0x06, 0x01, 0x01, 0x03, 0x20, 0xf0, 0x0B, 0x71, 0x42, 0x70, 0x26, 0xe1, 0x7e, 0x23, 0xed,
        0x0a, 0x8b, 0x71, 0x17, 0x87, 0xa6, 0x79, 0x3d, 0x50, 0xd3, 0x21, 0x48, 0x4a, 0xa6, 0x49,
        0xac, 0xaa, 0x44, 0x26, 0x81, 0x9f, 0x38,
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

#[test]
fn can_generate_keys() -> crate::Result<()> {
    use crate::HostInfo;
    use alkali::asymmetric::sign::Keypair;
    use chacha20poly1305::ChaCha20Poly1305;
    use chacha20poly1305::{AeadCore, KeyInit};
    use pretty_hex::PrettyHex;
    use rand::rngs::OsRng;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    println!("\nSIGNING KEYS");
    println!("-------------");

    let secret: ed25519_dalek::SecretKey = HostInfo::id_as_key_src();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);

    println!(
        "\ned25519 secret key: {:?}\ned25519 signing key: {:?}",
        secret.hex_dump(),
        signing_key.as_ref().hex_dump()
    );

    println!("\nEPHEMERAL KEYS");
    println!("--------------");

    let chacha_poly_key = ChaCha20Poly1305::generate_key(&mut OsRng);
    let chacha_poly_nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    println!(
        "\nchacha_poly_key: {:?}\nchacha_poly_nonce: {:?}",
        chacha_poly_key.hex_dump(),
        chacha_poly_nonce.hex_dump()
    );

    let eph_sk = EphemeralSecret::random();
    let eph_pub = PublicKey::from(&eph_sk);

    let eph_client_es = EphemeralSecret::random();
    let eph_client_pub = PublicKey::from(&eph_client_es);
    let eph_shared_secret = eph_sk.diffie_hellman(&eph_client_pub);

    println!(
        "\nserver x25519 pk: {:?}\nclient x25519 pk: {:?}\nshared x25119 secret: {:?}",
        eph_pub.hex_dump(),
        eph_client_pub.hex_dump(),
        eph_shared_secret.hex_dump()
    );

    let sign0 = Keypair::generate()?;

    println!(
        "\ngenerated sign priv: {:?}\npub: {:?}",
        sign0.private_key.hex_dump(),
        sign0.public_key.hex_dump()
    );

    Ok(())
}
