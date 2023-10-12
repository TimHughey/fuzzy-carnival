//! Groups from [RFC 5054](https://tools.ietf.org/html/rfc5054)
//!
//! It is strongly recommended to use them instead of custom generated
//! groups. Additionally it is not recommended to use `G_1024` and `G_1536`,
//! they are provided only for compatibility with the legacy software.

use digest::Digest;
use num_bigint::BigUint;
use once_cell::sync::Lazy;
use std::marker::PhantomData;

pub struct G<D: Digest> {
    pub n: BigUint,
    pub n_be: Vec<u8>,
    pub g: BigUint,
    pub n_len: usize,

    d: PhantomData<D>,
}

pub static G_3072: Lazy<G<sha2::Sha512>> = Lazy::new(G::<sha2::Sha512>::build);

// H(N | PAD(g))
impl<D: Digest> G<D> {
    pub fn build() -> Self {
        use pretty_hex::PrettyHex;

        let bin = include_bytes!("groups/3072.bin");
        let n_len = bin.len();

        tracing::debug!("\nG_3072 bin {:?}", bin.hex_dump());

        G {
            n: BigUint::from_bytes_be(bin),
            n_be: bin.to_vec(),
            g: BigUint::from_bytes_be(&[5]),
            n_len,

            d: PhantomData,
        }
    }

    pub fn compute_k(&self) -> BigUint {
        use pretty_hex::PrettyHex;

        let n = self.n.to_bytes_be();
        let g_bytes = self.g.to_bytes_be();

        tracing::debug!(
            "\nG_3072 N {:?}\nG_3072 G {:?}",
            n.hex_dump(),
            g_bytes.hex_dump()
        );

        let mut buf = vec![0u8; n.len()];
        buf[(n.len() - g_bytes.len())..].copy_from_slice(&g_bytes);

        let mut d = D::new();
        d.update(&n);
        d.update(&buf);

        BigUint::from_bytes_be(d.finalize().as_slice())
    }

    // pub fn random_u512(bits: u64) -> U512 {
    //     let mut rng = rand::thread_rng();

    //    let x = RandomBits::new(512);

    //    let y = x.

    // }
}

use crypto_bigint::{Encoding, U3072, U512};

const PAD_L: usize = U3072::BYTES;
#[allow(non_snake_case)]
pub struct G2 {
    pub N: U3072,
    #[allow(unused)]
    pub N_len: usize,
    pub g: U3072,
}

impl G2 {
    #[allow(dead_code)]
    pub fn build() -> Self {
        let bin = include_bytes!("groups/3072.bin");
        let n_len = bin.len();

        let mut g = [0u8; PAD_L];
        g[PAD_L - 1] = 5u8;

        Self {
            N: U3072::from_be_bytes(*bin),
            N_len: n_len,
            g: U3072::from_be_bytes(g),
        }
    }

    #[allow(dead_code)]
    pub fn compute_k(&self) -> U512 {
        let mut hasher = sha2::Sha512::new();
        hasher.update(self.N.to_be_bytes());
        hasher.update(self.g.to_be_bytes());

        U512::from_be_slice(&hasher.finalize())
    }
}

#[allow(non_snake_case)]
#[cfg(test)]
mod tests {

    use super::{G2, G_3072};
    use crypto_bigint::Encoding;
    // use num_bigint::{BigUint, ToBigUint};
    // use hex::ToHex;
    // use num::checked_pow;
    // use pretty_hex::PrettyHex;

    #[test]
    fn can_compute_G2_k() {
        let k1 = G_3072.compute_k();

        let G3072 = G2::build();

        let k2 = G3072.compute_k();

        assert_eq!(k1.to_bytes_be(), k2.to_be_bytes());
    }
}
