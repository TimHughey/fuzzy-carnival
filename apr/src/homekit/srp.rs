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

//! # Algorithm description
//! Here we briefly describe implemented algorithm. For additional information
//! refer to SRP literature. All arithmetic is done modulo `N`, where `N` is a
//! large safe prime (`N = 2q+1`, where `q` is prime). Additionally `g` MUST be
//! a generator modulo `N`. It's STRONGLY recommended to use SRP parameters
//! provided by this crate in the [`groups`](groups/index.html) module.
//!
//! |       Client                 |   Data transfer   |      Server2                     |
//! |------------------------------|-------------------|---------------------------------|
//! |`a_pub = g^a`                 | — `a_pub`, `I` —> | (lookup `s`, `v` for given `I`) |
//! |`x = PH(P, s)`                | <— `b_pub`, `s` — | `b_pub = k*v + g^b`             |
//! |`u = H(a_pub ‖ b_pub)`        |                   | `u = H(a_pub ‖ b_pub)`          |
//! |`s = (b_pub - k*g^x)^(a+u*x)` |                   | `S = (b_pub - k*g^x)^(a+u*x)`   |
//! |`K = H(s)`                    |                   | `K = H(s)`                      |
//! |`M1 = H(A ‖ B ‖ K)`           |     — `M1` —>     | (verify `M1`)                   |
//! |(verify `M2`)                 |    <— `M2` —      | `M2 = H(A ‖ M1 ‖ K)`            |
//!
//! Variables and notations have the following meaning:
//!
//! - `I` — user identity (username)
//! - `P` — user password
//! - `H` — one-way hash function
//! - `PH` — password hashing algroithm, in the RFC 5054 described as `H(s ‖ H(I ‖ ":" ‖ P))`
//! - `^` — (modular) exponentiation
//! - `‖` — concatenation
//! - `x` — user private key
//! - `s` — salt generated by user and stored on the server
//! - `v` — password verifier equal to `g^x` and stored on the server
//! - `a`, `b` — secret ephemeral values (at least 256 bits in length)
//! - `A`, `B` — Public ephemeral values
//! - `u` — scrambling parameter
//! - `k` — multiplier parameter (`k = H(N || g)` in SRP-6a)
//!
//! [1]: https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
//! [2]: https://tools.ietf.org/html/rfc5054

use crate::{
    homekit::{
        helper, CipherCtx,
        TagVal::{self, Proof, PublicKey, Salt},
    },
    Result,
};
use alkali::hash::sha2;
use anyhow::anyhow;
use core::fmt;
use num_bigint::BigUint;
use num_traits::{Euclid, Zero};
use pretty_hex::PrettyHex;

const SALT_BITS: u64 = 128;
const SERVER_PRIVATE_BITS: u64 = 256;

#[allow(non_snake_case)]
#[derive(Default)]
pub struct Server {
    pub username: Vec<u8>, // shared username
    pub passwd: [u8; 4],   // shared password
    pub N: BigUint,        // modulo
    pub g: BigUint,        // sufficiently large prime
    pub s: BigUint,        // salt
    pub x: BigUint,        // user private key (x = H(s || H(I || ":" || P)) from RFC 5054)
    pub v: BigUint,        // passwd verifier (v = g ^ x)
    pub B: BigUint,        // server ephemeral public
    pub b: BigUint,        // server ephemeral secret
    pub A: BigUint,        // client ephemeral public
}

#[allow(non_snake_case)]
#[allow(clippy::many_single_char_names)]
impl Server {
    pub fn new(user: &str, passwd: [u8; 4], salt: Option<BigUint>, b: Option<BigUint>) -> Self {
        use helper::{bnum_bytes, multipart_to_num};

        let seperator = b":";
        let (N, g, k) = get_group_bnums();
        let s = salt.unwrap_or_else(|| helper::random_uint(SALT_BITS));
        let b = b.unwrap_or_else(|| helper::random_uint(SERVER_PRIVATE_BITS));
        let username: Vec<u8> = user.into();

        // hash the user name and passwd
        // x = H(s | H(I | ":" | P))
        let mut hash_user = sha2::Multipart::new().unwrap();
        hash_user.update(&username);
        hash_user.update(seperator);
        hash_user.update(&passwd);

        let mut x = sha2::Multipart::new().unwrap();
        x.update(&bnum_bytes(&s));
        x.update(&hash_user.calculate().0);

        let x = multipart_to_num(x);
        let v = g.modpow(&x, &N);

        Self {
            username,
            passwd,
            N: N.clone(),
            g: g.clone(),
            s,
            x: x.clone(),
            v: v.clone(),
            B: ((k * v) + g.modpow(&b, &N)).rem_euclid(&N),
            b,
            A: BigUint::default(),
        }
    }

    pub fn get_pk(&self) -> TagVal {
        PublicKey(helper::bnum_bytes(&self.B))
    }

    pub fn get_salt(&self) -> TagVal {
        Salt(helper::bnum_bytes(&self.s))
    }
}

impl fmt::Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "srp::Server2\nSALT (s) {:?}\n\nUSER PRIVATE KEY (x) {:?}",
            self.s.to_bytes_be().hex_dump(),
            self.x.to_bytes_be().hex_dump()
        ))?;

        f.write_fmt(format_args!(
            "\n\nPASSWORD VERIFIER (v) {:?}\n\nSERVER EPHEREMAL PRIVATE (b) {:?}",
            self.v.to_bytes_be().hex_dump(),
            self.b.to_bytes_be().hex_dump()
        ))?;

        f.write_fmt(format_args!(
            "\n\nSERVER EPHEREMAL PUBLIC (B) {:?}\n\nCLIENT PUBLIC (A) {:?}",
            self.B.to_bytes_be().hex_dump(),
            self.A.to_bytes_be().hex_dump()
        ))
    }
}

#[derive(Default)]
#[allow(non_snake_case)]
pub struct Verifier {
    pub A: BigUint,
    pub B: BigUint,
    pub authenticated: bool,
    pub u: BigUint,
    pub username: Vec<u8>,
    pub M_bytes: Vec<u8>,
    pub H_AMK: Vec<u8>,
    pub session_key: Vec<u8>,
    pub client_M1: Vec<u8>,
}

#[allow(non_snake_case)]
impl Verifier {
    pub fn authenticate(&mut self) -> Result<CipherCtx> {
        use helper::calculate_H_AMK;

        self.H_AMK = calculate_H_AMK(&self.A, &self.M_bytes, &self.session_key);

        if self.M_bytes == self.client_M1 {
            tracing::debug!("authenticated");

            self.authenticated = true;

            return CipherCtx::new(&self.session_key);
        }

        Err(anyhow!("authentication failed, proofs do not match"))
    }

    pub fn new(server: &Server, A_bytes: &[u8], client_M1: &[u8]) -> Result<Verifier> {
        use helper::{calculate_M, hash_bnum, slice_to_bnum, H_nn_pad};

        let A = slice_to_bnum(A_bytes);
        let N = &server.N;
        let B = &server.B;
        let b = &server.b;
        let v = &server.v;
        let s = &server.s;

        // SRP-6a safety check
        let A_mod_N = A.rem_euclid(N);

        if A_mod_N > BigUint::zero() {
            let u = H_nn_pad(&A, B);

            let tmp1 = v.modpow(&u, N);
            let tmp2 = &A * tmp1;
            let S = tmp2.modpow(b, N);
            let session_key = hash_bnum(&S);
            let M_bytes = calculate_M(&server.username, s, &A, B, &session_key);

            return Ok(Self {
                A,
                B: B.clone(),
                authenticated: false,
                u,
                M_bytes,
                H_AMK: Vec::new(),
                username: server.username.clone(),
                session_key,
                client_M1: client_M1.into(),
            });
        }

        Err(anyhow!("client pub key is empty"))
    }

    pub fn proof(&self) -> TagVal {
        Proof(self.H_AMK.clone())
    }
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use helper::bnum_bytes;

        f.write_str("VERIFIER\n")?;
        writeln!(f, "authenticated: {}", self.authenticated)?;
        writeln!(f, "A {:?}\n", bnum_bytes(&self.A).hex_dump())?;
        writeln!(f, "B {:?}\n", bnum_bytes(&self.B).hex_dump())?;
        writeln!(f, "u {:?}\n", bnum_bytes(&self.u).hex_dump())?;
        writeln!(f, "username {:?}\n", self.username.hex_dump())?;
        writeln!(f, "M_bytes {:?}\n", self.M_bytes.hex_dump())?;
        writeln!(f, "H_AMK {:?}\n", self.H_AMK.hex_dump())?;
        writeln!(f, "session_key {:?}\n", self.session_key.hex_dump())?;
        writeln!(f, "client M1 {:?}\n", self.client_M1.hex_dump())
    }
}

#[allow(non_snake_case)]
pub(crate) mod groups {
    use num_bigint::BigUint;
    use once_cell::sync::Lazy;

    pub type BnumN = BigUint;
    pub type Bnumg = BigUint;
    pub type Bnumk = BigUint;

    const BINARY_3072: &[u8] = include_bytes!("srp/groups/3072.bin");

    static G_3072: Lazy<G> = Lazy::new(G::build);

    pub fn get_params() -> (BnumN, Bnumg, Bnumk) {
        G_3072.get_params()
    }

    #[allow(unused)]
    pub fn get_3072() -> &'static G {
        &G_3072
    }

    pub struct G {
        pub n: BigUint,
        pub n_len: usize,
        pub n_pad_bits: usize,
        pub g: BigUint,
        pub k: BigUint,
    }

    impl G {
        pub fn build() -> Self {
            use super::helper::H_nn_pad;
            use pretty_hex::PrettyHex;

            tracing::debug!("\nG_3072 BINARY {:?}", BINARY_3072.hex_dump());
            let n = BigUint::from_bytes_be(BINARY_3072);
            let n_len = BINARY_3072.len();
            let n_pad_bits = n_len * 8;
            let g = BigUint::from_bytes_be(&[5]);

            Self {
                k: H_nn_pad(&n, &g),
                n,
                n_len,
                n_pad_bits,
                g,
            }
        }

        pub fn get_params(&self) -> (BnumN, Bnumg, Bnumk) {
            (self.n.clone(), self.g.clone(), self.k_bnum())
        }

        pub fn k_bnum(&self) -> BigUint {
            self.k.clone()
        }

        pub fn N_len() -> usize {
            BINARY_3072.len()
        }
    }
}

pub use groups::{BnumN as GroupValN, Bnumg as GroupValg, Bnumk as GroupValk};

#[allow(unused)]
pub fn get_group_bnums() -> (GroupValN, GroupValg, GroupValk) {
    groups::get_params()
}
