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
    homekit::{
        helper,
        srp::{self, Verifier},
        tests::Data,
        SrpServer,
    },
    Result,
};
use num_bigint::BigUint;
use num_traits::{FromBytes, Zero};
use pretty_hex::PrettyHex;

fn make_server(td: &Data) -> SrpServer {
    use helper::slice_to_bnum;

    let user = "Pair-Setup";
    let passwd = br#"3939"#;
    let salt = Some(slice_to_bnum(&td.s));
    let b = Some(slice_to_bnum(&td.b));
    SrpServer::new(user, *passwd, salt, b)
}

#[test]
fn can_generate_same_proof() -> Result<()> {
    use helper::n_to_bytes;

    let td = Data::get();
    let server = make_server(&td);

    let verifier = Verifier::new(&server, &td.A, &td.client_M1)?;

    assert_eq!(n_to_bytes(&server.v), td.v.as_slice());
    assert_eq!(n_to_bytes(&verifier.A), td.A.as_slice());
    assert_eq!(n_to_bytes(&server.B), td.B.as_slice());
    assert_eq!(n_to_bytes(&verifier.u), td.u.as_slice());

    hash_cmp("M (server", &verifier.M_bytes, &td.server_M);
    hash_cmp("session_key", &verifier.session_key, &td.session_key);

    Ok(())
}

#[test]
fn can_authenticate() -> Result<()> {
    let td = Data::get();
    let server = make_server(&td);

    let mut verifier = Verifier::new(&server, &td.A, &td.client_M1)?;

    let res = match verifier.authenticate() {
        Ok(_cipher) => {
            // println!("{cipher:?}");
            true
        }
        Err(e) => {
            println!("{e:?}");

            // println!(
            //     "SERVER M {:?}\n\nCLIENT M {:?}",
            //     verifier.M_bytes.hex_dump(),
            //     verifier.client_M1.hex_dump()
            // );

            //   println!("\nVERIFIER {:?}", server.verifier);

            false
        }
    };

    assert!(res);

    assert!(hash_cmp("H_AMK", &verifier.H_AMK, &td.H_AMK));

    Ok(())
}

#[test]
fn can_generate_same_read_write_keys() -> Result<()> {
    use crate::homekit::CipherCtx;

    let td = Data::get();

    let cipher = CipherCtx::new(&td.shared_secret)?;

    let mut key = vec![];
    key.extend_from_slice(&cipher.encrypt_key[..]);

    hash_cmp("encrypt key", &td.write_key, &key);

    let mut key = vec![];
    key.extend_from_slice(&cipher.decrypt_key[..]);

    hash_cmp("decrypt key", &td.read_key, &key);

    Ok(())
}

#[test]
#[allow(non_snake_case)]
fn can_get_G3072() {
    let G = srp::groups::get_3072();

    assert_ne!(&G.n, &BigUint::zero());
    assert_ne!(&G.g, &BigUint::zero());

    let n_be_bytes = G.n.to_bytes_be();
    let g_be_bytes = G.g.to_bytes_be();

    assert_eq!(n_be_bytes.len(), 384);
    assert_eq!(g_be_bytes.len(), 1);
}

#[test]
fn can_create_srp_server() {
    let server = SrpServer::new("Pair-Setup", *b"3939", None, None);

    assert_eq!(server.N.to_bytes_be().len(), 384);
    assert_eq!(server.g.to_bytes_be().len(), 1);
    assert_eq!(server.s.to_bytes_be().len(), 16);
    assert_eq!(server.x.to_bytes_be().len(), 64);
    assert_eq!(server.v.to_bytes_be().len(), 384);
    assert_eq!(server.b.to_bytes_be().len(), 32);
    assert_eq!(server.B.to_bytes_be().len(), 384);
}

#[test]
fn can_compute_known_v() {
    use crate::homekit::SrpServer;

    let td = Data::get();

    let user = "Pair-Setup";
    let passwd = b"3939";
    let salt = Some(BigUint::from_be_bytes(&td.s));
    let server = SrpServer::new(user, *passwd, salt, None);

    let v = &server.v;
    assert!(v.bits() >= 3070);

    let v_bytes = v.to_bytes_be();
    assert_eq!(v_bytes.as_slice(), td.v.as_slice());
}

#[test]
fn can_hash_single_n() {
    use helper::{hash_bnum, slice_to_bnum, H_len};

    let n = BigUint::from_be_bytes(b"A");

    let hashed = hash_bnum(&n);
    assert_eq!(hashed.len(), H_len());

    let hashed_num = slice_to_bnum(&hashed);
    assert_ne!(hashed_num, BigUint::zero());
}

fn hash_cmp(desc: &str, z: &Vec<u8>, z_td: &Vec<u8>) -> bool {
    let equal = z == z_td;

    if !equal {
        println!("\n\n*** {desc} comparison FAILED ***");

        println!(
            "\n<<< {desc} {:?}\n\n>>> {desc} {:?}",
            z.hex_dump(),
            z_td.hex_dump()
        );
    }

    equal
}
