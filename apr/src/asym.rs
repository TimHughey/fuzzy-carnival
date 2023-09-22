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

use alkali::asymmetric::sign;
use once_cell::sync::Lazy;
use pretty_hex::PrettyHex;
use std::fmt;

pub struct Keys {
    pub signing: sign::Keypair,
    pub signing_pk: String,
}

static KEYS: Lazy<Keys> = Lazy::new(|| {
    let seed = crate::HostInfo::seed();
    let signing = sign::Keypair::from_seed(seed).expect("key generation failed");

    Keys {
        signing_pk: hex::encode(signing.public_key.as_slice()),
        signing,
    }
});

impl Keys {
    #[inline]
    #[must_use]
    pub fn get_signing_pub() -> &'static str {
        &KEYS.signing_pk
    }

    #[inline]
    #[must_use]
    pub fn get_signing() -> &'static sign::Keypair {
        &KEYS.signing
    }

    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    #[inline]
    pub fn clone_signing() -> crate::Result<sign::Keypair> {
        let cloned = sign::Keypair::from_private_key(&KEYS.signing.private_key);

        Ok(cloned?)
    }
}

impl fmt::Debug for Keys {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let signing = &self.signing;

        writeln!(fmt, "Keys:\n")?;

        writeln!(fmt, "sign pub {:?}\n", signing.public_key.hex_dump())?;
        writeln!(fmt, "sign pri {:?}\n", signing.private_key.hex_dump())
    }
}

#[cfg(test)]
mod tests {
    use super::{Keys, KEYS};

    #[test]
    fn can_get_public_signing_key() -> crate::Result<()> {
        let pk = Keys::get_signing_pub();

        // print!("pub key: {pk}\n{:?}\n", *KEYS);

        let decoded = hex::decode(pk)?;

        assert_eq!(decoded, KEYS.signing.public_key);

        Ok(())
    }
}
