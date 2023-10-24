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

use crate::homekit::srp::groups::G;
use alkali::hash::sha2;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{FromBytes, ToBytes};

pub fn bnum_bytes(num: &BigUint) -> Vec<u8> {
    num.to_be_bytes()
}

#[allow(non_snake_case)]
pub fn calculate_H_AMK(A: &BigUint, M: &[u8], K: &[u8]) -> Vec<u8> {
    use sha2::sha512::Multipart;

    let mut hasher = Multipart::new().unwrap();
    hasher.update(&n_to_bytes(A));
    hasher.update(M);
    hasher.update(K);

    hasher.calculate().0.to_vec()
}

#[allow(non_snake_case)]
pub fn calculate_M(I: &[u8], s: &BigUint, A: &BigUint, B: &BigUint, K: &[u8]) -> Vec<u8> {
    use super::srp;
    use sha2::sha512::Multipart;

    let (N, g, _k) = srp::get_group_bnums();

    let h_N = hash_bnum(&N);
    let h_g = hash_bnum(&g);
    let h_I = hash_slice(I);

    let h_xor: Vec<u8> = h_N.iter().zip(h_g.iter()).map(|(n0, n1)| n0 ^ n1).collect();

    let mut hasher = Multipart::new().unwrap();
    hasher.update(&h_xor);
    hasher.update(&h_I);
    hasher.update(&n_to_bytes(s));
    hasher.update(&n_to_bytes(A));
    hasher.update(&n_to_bytes(B));
    hasher.update(K);

    hasher.calculate().0.to_vec()
}

pub fn slice_to_bnum<T: AsRef<[u8]>>(data: T) -> BigUint {
    BigUint::from_be_bytes(data.as_ref())
}

pub fn multipart_to_num(mp: sha2::Multipart) -> BigUint {
    BigUint::from_be_bytes(mp.calculate().0.as_ref())
}

pub fn hash_bnum(n: &BigUint) -> Vec<u8> {
    sha2::sha512::hash(&n.to_be_bytes()).unwrap().0.into()
}

pub fn hash_slice(s: &[u8]) -> Vec<u8> {
    sha2::sha512::hash(s).unwrap().0.into()
}

#[allow(unused, non_snake_case)]
pub fn H_len() -> usize {
    sha2::DIGEST_LENGTH
}

#[allow(non_snake_case)]
pub fn H_nn_pad(n0: &BigUint, n1: &BigUint) -> BigUint {
    let pad_len = G::N_len();
    let capacity = pad_len * 2;

    let mut bin: Vec<u8> = Vec::with_capacity(capacity);

    for n in [n0, n1] {
        let be_bytes = n.to_be_bytes();

        bin.extend_from_slice(&vec![0u8; pad_len - be_bytes.len()]); // padding
        bin.extend_from_slice(&be_bytes);
    }

    BigUint::from_be_bytes(&sha2::sha512::hash(&bin).unwrap().0)
}

pub fn n_to_bytes(n: &BigUint) -> Vec<u8> {
    n.to_be_bytes()
}

pub fn random_uint(bits: u64) -> BigUint {
    let mut rng = rand::thread_rng();

    // BigUint::from_be_bytes(&rng.gen_biguint(bits).to_le_bytes())
    rng.gen_biguint(bits)
}

#[test]
fn can_hash_nn_with_padding() {
    use num_traits::FromPrimitive;

    let n0 = BigUint::from_u8(b'A').unwrap();
    let n1 = BigUint::from_u8(b'B').unwrap();

    let h_n = H_nn_pad(&n0, &n1);

    assert!(h_n.bits() == 511);
}
