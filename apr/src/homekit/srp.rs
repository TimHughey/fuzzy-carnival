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
//! |       Client                 |   Data transfer   |      Server                     |
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

use super::TagVal::{self, Proof, PublicKey, Salt};
use core::fmt;
use digest::Digest;
use groups::G_3072;
use num_bigint::BigUint;
use num_traits::{CheckedMul, FromBytes, Zero};
use pretty_hex::PrettyHex;
use std::marker::PhantomData;

const SALT_BITS: u64 = 128;
const SERVER_PRIVATE_BITS: u64 = 256;

#[allow(non_snake_case)]
pub struct Server<D: Digest> {
    pub username: String, // shared username
    pub passwd: String,   // shared password
    pub N: BigUint,       // modulo
    pub g: BigUint,       // sufficiently large prime
    pub s: BigUint,       // salt
    pub k: BigUint,       // multiplier parameter (k = H(N || g) in SRP-6a)
    pub x: BigUint,       // user private key (x = H(s || H(I || ":" || P)) from RFC 5054)
    pub v: BigUint,       // passwd verifier (v = g ^ x)
    pub b: BigUint,       // server ephemeral secret
    pub B: BigUint,       // server ephemeral public
    pub A: BigUint,       // client ephemeral public
    pub u: BigUint,       // scrambling parameter
    pub S: BigUint,       // session key
    pub K: BigUint,       // shared secret key
    pub M: BigUint,       // client
    pub M_bytes: Vec<u8>, // hashed M1
    pub M_AMK: BigUint,   // H(A | M | K)
    pub M2: BigUint,      // (hashed) server

    d: PhantomData<D>,
}

#[allow(non_snake_case)]
impl<D: Digest> Default for Server<D> {
    fn default() -> Self {
        let N = &G_3072.n;
        let g = &G_3072.g;

        let pad_bits = usize::try_from(G_3072.n.bits()).expect(r#"whoa!"#);

        Self {
            username: "Pair-Setup".into(),
            passwd: "3939".into(),
            N: G_3072.n.clone(),
            g: G_3072.g.clone(),
            s: helper::random_uint(SALT_BITS),
            k: helper::H_nn_pad::<D>(N, g, pad_bits), // H(N | PAD(g))
            x: BigUint::zero(),
            v: BigUint::zero(),
            b: helper::random_uint(SERVER_PRIVATE_BITS),
            B: BigUint::zero(),
            A: BigUint::zero(),
            u: BigUint::zero(),
            S: BigUint::zero(),
            K: BigUint::zero(),
            M: BigUint::zero(),
            M_bytes: Vec::new(),
            M_AMK: BigUint::zero(),
            M2: BigUint::zero(),

            d: PhantomData,
        }
    }
}

#[allow(non_snake_case)]
impl<D: Digest> Server<D> {
    pub fn new(user: &str, passwd: &str) -> Self {
        Self {
            username: user.to_string(),
            passwd: passwd.to_string(),
            ..Self::default()
        }
        .make_x()
        .make_v()
        .make_B()
    }

    pub fn get_pk(&self) -> TagVal {
        PublicKey(self.B.to_bytes_be())
    }

    pub fn get_salt(&self) -> TagVal {
        Salt(self.s.to_bytes_be())
    }

    pub fn proof(&self) -> TagVal {
        Proof(self.M2.to_bytes_be())
    }

    pub fn set_client_pk(self, client_pk: &[u8]) -> Self {
        // SRP-6a safety check
        // bnum_mod(tmp1, A, ng->N);
        // if (bnum_is_zero(tmp1)) goto error;
        //
        // // MODIFIED from H_nn(alg, ng->N, ng->g)
        // k = H_nn_pad(alg, ng->N, ng->g, ng->N_len);
        // // MODIFIED from H_nn(alg, A, B)
        // u = H_nn_pad(alg, A, B, ng->N_len);
        //
        // // S = (A *(v^u)) ^ b
        // bnum_modexp(tmp1, v, u, ng->N);
        // bnum_mul(tmp2, A, tmp1);
        // bnum_modexp(S, tmp2, b, ng->N);
        //
        // hash_num(alg, S, ver->session_key);
        // ver->session_key_len = hash_length(ver->alg);
        //
        // calculate_M(alg, ng, ver->M, username, s, A, B, ver->session_key, ver->session_key_len);
        // calculate_H_AMK(alg, ver->H_AMK, A, ver->M, ver->session_key, ver->session_key_len);

        let N = &self.N;
        let v = &self.v;
        let b = &self.b;
        let A = BigUint::from_be_bytes(client_pk);
        let B = &self.B;

        let u = helper::H_nn_pad::<D>(&A, B, 3072);

        let tmp1 = v.modpow(&u, N);
        let tmp2 = A.checked_mul(&tmp1).unwrap();

        Self {
            A,
            u,
            S: tmp2.modpow(b, N), // session key
            ..self
        }
        .make_M()

        // FROM RFC:
        // The premaster secret is calculated by the server as follows:
        //
        // N, g, s, v = <read from password file>
        // b = random()
        // k = SHA1(N | PAD(g))
        // B = k*v + g^b % N
        // A = <read from client>
        // u = SHA1(PAD(A) | PAD(B))
        // <premaster secret> = (A * v^u) ^ b % N
    }

    pub fn verify(&mut self, client_M1: &[u8]) -> bool {
        use helper::H;
        //  The verifier (v) is computed based on the salt (s), user name (I),
        //  password (P), and group parameters (N, g).
        //   x = H(s | H(I | ":" | P))
        //   v = g^x % N

        let client_M1 = BigUint::from_bytes_be(client_M1);

        self.M_AMK = BigUint::from_be_bytes(&H::<D>(vec![
            self.A.clone(),
            self.M.clone(),
            self.K.clone(),
        ]));

        let M2_args = vec![self.A.clone(), self.B.clone(), self.K.clone()];

        self.M2 = BigUint::from_bytes_be(&helper::H::<D>(M2_args)[..]);

        if self.M == client_M1 {
            return true;
        }

        false
    }

    // WORKING
    fn make_x(self) -> Self {
        // hash the user name and passwd
        // x = H(s | H(I | ":" | P))
        let hash_user = D::new()
            .chain_update(&self.username[..])
            .chain_update(b":")
            .chain_update(&self.passwd[..]);

        let x = D::new()
            .chain_update(self.s.to_bytes_be())
            .chain_update(hash_user.finalize());

        let xh = x.finalize();

        tracing::info!("\nSALTED x {:?}", xh.hex_dump());

        Self {
            x: BigUint::from_bytes_be(&xh[..]),
            ..self
        }
    }

    // WORKING
    fn make_v(self) -> Self {
        Self {
            v: self.g.modpow(&self.x, &self.N),
            ..self
        }
    }

    // MAYBE WORKING
    fn make_B(self) -> Self {
        // B = kv + g^b  (shairport)
        // bnum_mul(tmp1, k, v);
        // bnum_modexp(tmp2, ng->g, b, ng->N);
        // bnum_modadd(B, tmp1, tmp2, ng->N);

        let tmp1 = self.k.checked_mul(&self.v).unwrap();
        let tmp2 = self.g.modpow(&self.b, &self.N);

        Self {
            B: (tmp1 + tmp2) % &self.N,
            ..self
        }
    }

    // B = k*v + g^b % N (ap-receiver alternative)
    // B: (k * v + g.modpow(b, N)) % N,

    // M1 = H(A, B, K) this doesn't follow the spec but apparently no one does for M1
    // M1 should equal =  H(H(N) XOR H(g) | H(U) | s | A | B | K) according to the spec
    fn make_M(self) -> Self {
        /*
        static void calculate_M(enum hash_alg alg, NGConstant *ng, unsigned char *dest, const char *I,
            const bnum s, const bnum A, const bnum B, const unsigned char *K,
            int K_len) {
                unsigned char H_N[SHA512_DIGEST_LENGTH];
                unsigned char H_g[SHA512_DIGEST_LENGTH];
                unsigned char H_I[SHA512_DIGEST_LENGTH];
                unsigned char H_xor[SHA512_DIGEST_LENGTH];
                HashCTX ctx;
                int i = 0;
                int hash_len = hash_length(alg);

                hash_num(alg, ng->N, H_N);
                hash_num(alg, ng->g, H_g);

                hash(alg, (const unsigned char *)I, strlen(I), H_I);

                for (i = 0; i < hash_len; i++)
                H_xor[i] = H_N[i] ^ H_g[i];

                hash_init(alg, &ctx);

                hash_update(alg, &ctx, H_xor, hash_len);
                hash_update(alg, &ctx, H_I, hash_len);
                update_hash_n(alg, &ctx, s);
                update_hash_n(alg, &ctx, A);
                update_hash_n(alg, &ctx, B);
                hash_update(alg, &ctx, K, K_len);

                hash_final(alg, &ctx, dest);
        }   */

        use helper::{n_to_bytes, H_to_n, H_xor_nn};

        let mut hasher = D::new();
        for data in [
            H_xor_nn::<D>(&self.N, &self.g),
            D::digest(self.passwd.as_bytes()).to_vec(),
            n_to_bytes(&self.s),
            n_to_bytes(&self.A),
            n_to_bytes(&self.B),
            n_to_bytes(&self.K),
        ] {
            hasher.update(data);
        }

        let M_bytes: Vec<u8> = hasher.finalize().to_vec();

        tracing::info!("\nSERVER M {:?}", M_bytes.hex_dump());

        Self {
            M: H_to_n(&M_bytes),
            M_bytes,
            ..self
        }
    }
}

impl<D: Digest> fmt::Debug for Server<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("srp::Server\n")?;

        f.write_fmt(format_args!(
            "SALT (s) {:?}\n\nMULTIPILER PARAMETER (k) {:?}",
            self.s.to_bytes_be().hex_dump(),
            self.k.to_bytes_be().hex_dump()
        ))?;

        f.write_fmt(format_args!(
            "\n\nSERVER USER PRIVATE KEY (x) {:?}",
            self.x.to_bytes_be().hex_dump()
        ))?;

        f.write_fmt(format_args!(
            "\n\nPASSWORD VERIFIER (v) {:?}",
            self.v.to_bytes_be().hex_dump()
        ))?;

        f.write_fmt(format_args!(
            "\n\nSERVER EPHEREMAL PRIVATE (b) {:?}",
            self.b.to_bytes_be().hex_dump()
        ))?;

        f.write_fmt(format_args!(
            "\n\nSERVER EPHEREMAL PUBLIC (B) {:?}",
            self.B.to_bytes_be().hex_dump()
        ))?;

        f.write_fmt(format_args!(
            "\n\nSERVER M1 {:?}",
            self.M.to_bytes_be().hex_dump()
        ))
    }
}

#[allow(non_snake_case)]
mod helper {
    use digest::{Digest, Output};
    use num_bigint::{BigUint, RandBigInt};
    use num_traits::{FromBytes, ToBytes};

    pub fn digest_n<D: Digest>(n: &BigUint) -> Vec<u8> {
        D::digest(n.to_be_bytes()).to_vec()
    }

    #[must_use]
    pub fn H<D: Digest>(bnums: Vec<BigUint>) -> Output<D> {
        let mut hasher = D::new();

        for bnum in bnums {
            hasher.update(bnum.to_bytes_be());
        }

        hasher.finalize()
    }

    pub fn H_nn_pad<D: Digest>(n0: &BigUint, n1: &BigUint, pad_bits: usize) -> BigUint {
        let pad_len = pad_bits / 8;
        let capacity = pad_len * 2;

        let mut bin: Vec<u8> = Vec::with_capacity(capacity);

        for n in [&n0, &n1] {
            let be_bytes = n.to_be_bytes();

            bin.extend_from_slice(&vec![0u8; pad_len - be_bytes.len()]); // padding
            bin.extend_from_slice(&be_bytes);
        }

        H_to_n(D::digest(bin).as_ref())

        /*
        // See rfc5054 PAD()
        bnum H_nn_pad(enum hash_alg alg, const bnum n1, const bnum n2, int padded_len) {
        bnum bn;
        unsigned char *bin;
        unsigned char buff[SHA512_DIGEST_LENGTH];
        int len_n1 = bnum_num_bytes(n1);
        int len_n2 = bnum_num_bytes(n2);
        int nbytes = 2 * padded_len;
        int offset_n1 = padded_len - len_n1;
        int offset_n2 = nbytes - len_n2;

        assert(len_n1 <= padded_len);
        assert(len_n2 <= padded_len);

        bin = (unsigned char *)calloc(1, nbytes);

        bnum_bn2bin(n1, bin + offset_n1, len_n1);
        bnum_bn2bin(n2, bin + offset_n2, len_n2);
        hash(alg, bin, nbytes, buff);
        free(bin);
        bnum_bin2bn(bn, buff, hash_length(alg));
        return bn;
        }
        */
    }

    #[must_use]
    #[allow(unused)]
    pub fn H_pad_bnums<D: Digest>(bnums: Vec<&BigUint>, pad_len: usize) -> BigUint {
        let mut hasher = D::new();

        for bnum in bnums {
            let bytes_be = bnum.to_bytes_be();

            if bytes_be.len() < pad_len {
                let mut buf = vec![0u8; pad_len];
                buf[(pad_len - bytes_be.len())..].copy_from_slice(bytes_be.as_slice());

                hasher.update(buf);
            } else {
                hasher.update(bytes_be);
            }
        }

        BigUint::from_bytes_be(&hasher.finalize())
    }

    pub fn H_to_n(v: &[u8]) -> BigUint {
        BigUint::from_be_bytes(v)
    }

    pub fn H_xor_nn<D: Digest>(n0: &BigUint, n1: &BigUint) -> Vec<u8> {
        let n0_hash = digest_n::<D>(n0);
        let n1_hash = digest_n::<D>(n1);

        n0_hash
            .into_iter()
            .zip(n1_hash)
            .map(|(i, j)| i ^ j)
            .collect()
    }

    pub fn n_to_bytes(n: &BigUint) -> Vec<u8> {
        n.to_be_bytes()
    }

    pub fn random_uint(bits: u64) -> BigUint {
        let mut rng = rand::thread_rng();

        // rng.gen_biguint(bits) % &super::G_3072.n
        rng.gen_biguint(bits)
    }

    #[cfg(test)]
    mod tests {
        use num_bigint::BigUint;
        use num_traits::{FromBytes, FromPrimitive};

        #[test]
        fn can_hash_nn_with_padding() {
            use super::H_nn_pad;

            let n0 = BigUint::from_u8(b'A').unwrap();
            let n1 = BigUint::from_u8(b'B').unwrap();

            let h_n = H_nn_pad::<sha2::Sha512>(&n0, &n1, 64);

            assert!(h_n.bits() >= 508);
        }

        #[test]
        fn can_H_xor_nn() {
            use pretty_hex::PrettyHex;

            let n0 = BigUint::from_u16(0xDE).unwrap();
            let n1 = BigUint::from_u16(0xAD).unwrap();

            let xor = super::H_xor_nn::<sha2::Sha512>(&n0, &n1);

            assert_eq!(xor.len(), 64);

            let xor_n = BigUint::from_be_bytes(&xor);

            assert!(xor_n.bits() >= 508);

            println!("XOR {:?}", xor.hex_dump());
        }
    }
}

mod groups {
    use num_bigint::BigUint;
    use once_cell::sync::Lazy;

    const BINARY_3072: &[u8] = include_bytes!("srp/groups/3072.bin");

    pub static G_3072: Lazy<G> = Lazy::new(G::build);

    pub struct G {
        pub n: BigUint,
        pub g: BigUint,
    }

    impl G {
        pub fn build() -> Self {
            use pretty_hex::PrettyHex;

            tracing::debug!("\nG_3072 BINARY {:?}", BINARY_3072.hex_dump());

            Self {
                n: BigUint::from_bytes_be(BINARY_3072),
                g: BigUint::from_bytes_be(&[5]),
            }
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case, unused)]
mod tests {
    use super::{groups::G_3072, helper::random_uint, Server};
    use bstr::ByteSlice;
    use digest::OutputSizeUser;
    use num_bigint::BigUint;
    use num_traits::{FromBytes, ToBytes, Zero};
    use pretty_hex::PrettyHex;
    use ring::digest::digest;

    #[test]
    fn can_get_G3072() {
        let G = &G_3072;

        assert_ne!(&G.n, &BigUint::zero());
        assert_ne!(&G.g, &BigUint::zero());

        let n_be_bytes = G.n.to_bytes_be();
        let g_be_bytes = G.g.to_bytes_be();

        assert_eq!(n_be_bytes.len(), 384);
        assert_eq!(g_be_bytes.len(), 1);
    }

    #[test]
    fn can_create_srp_server() {
        let server = Server::<sha2::Sha512>::new("Pair-Setup", "3939");

        assert_eq!(server.N.to_bytes_be().len(), 384);
        assert_eq!(server.g.to_bytes_be().len(), 1);
        assert_eq!(server.s.to_bytes_be().len(), 16);
        assert_eq!(server.x.to_bytes_be().len(), 64);
        assert_eq!(server.v.to_bytes_be().len(), 384);
        assert_eq!(server.b.to_bytes_be().len(), 32);
        assert_eq!(server.B.to_bytes_be().len(), 384);

        // println!("\n{server:?}");
    }

    #[test]
    #[allow(non_snake_case)]
    fn can_compute_known_v() {
        use super::G_3072;
        use digest::Digest;
        use sha2::Sha512;

        let G3072 = &G_3072;
        let known_salt: [u8; 16] = [
            0x81, 0x8e, 0xa6, 0x75, 0x2a, 0x19, 0x91, 0x41, 0x5e, 0x97, 0x54, 0x09, 0xc0, 0x36,
            0x9e, 0x49,
        ];

        let salt = BigUint::from_be_bytes(&known_salt[..]);
        let data = b"Pair-Setup:3939";

        let hasher = Sha512::new()
            .chain_update(salt.to_be_bytes())
            .chain_update(Sha512::digest(data));

        let x = BigUint::from_be_bytes(&hasher.finalize());
        let v = G3072.g.modpow(&x, &G3072.n);
        assert!(v.bits() >= 3071);

        let v_bytes = v.to_bytes_be();
        assert_eq!(v_bytes.first(), Some(&0x71u8));
        assert_eq!(v_bytes.last(), Some(&0x7eu8));
    }

    #[test]
    fn can_hash_single_n() {
        use pretty_hex::PrettyHex;

        let n = BigUint::from_be_bytes(b"A");

        let hashed = super::helper::digest_n::<sha2::Sha512>(&n);

        println!("{:?}", hashed.hex_dump());
    }

    #[test]
    fn can_ensure_same_N() {
        let other_n = r#"
        FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63  B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E4    85B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4
        B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F8365
        5D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA182
        17C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCB
        F6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A3
        3A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8C
        DB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A645
        21F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0
        FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"#;

        let n_bytes = other_n
            .split_ascii_whitespace()
            .collect::<Vec<&str>>()
            .concat();

        let N = BigUint::parse_bytes(n_bytes.as_bytes(), 16).unwrap();

        assert_eq!(&N, &G_3072.n);
    }
}