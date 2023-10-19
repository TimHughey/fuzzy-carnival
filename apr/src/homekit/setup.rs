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

use crate::homekit::srp::Verifier;

#[allow(unused_imports)]
use super::{states, CipherCtx, HostInfo, Result, SrpServer, TagIdx, TagVal, Tags};
use once_cell::sync::Lazy;
use tracing::error;

#[derive(Debug, Default)]
pub struct Context {
    pub transient: bool,
    pub server: Lazy<SrpServer>,
    cipher: Option<CipherCtx>,
}

impl Context {
    const USERNAME: &str = "Pair-Setup";
    const PASSWORD: &[u8; 4] = b"3939";

    pub fn build() -> Self {
        Self {
            transient: false,
            server: Lazy::new(|| SrpServer::new(Self::USERNAME, *Self::PASSWORD, None, None)),
            cipher: None,
        }
    }

    pub fn cipher_available(&self) -> bool {
        self.cipher.is_some()
    }

    pub fn m1_m2(&mut self, tags_in: &Tags) -> Tags {
        use TagIdx::{Flags as FlagsIdx, Method as MethodIdx};
        use TagVal::{Flags, Method, State};

        const PAIR_SETUP: TagVal = Method(0);
        const TRANSIENT: TagVal = Flags(0x10);

        let mut tags = Tags::default();

        let method = tags_in.get_cloned(MethodIdx);
        let flags = tags_in.get_cloned(FlagsIdx);

        match (method, flags) {
            (Ok(PAIR_SETUP), Ok(TRANSIENT)) => {
                self.transient = true;

                tags.push(State(states::Generic(2)));
                tags.push(self.server.get_salt());
                tags.push(self.server.get_pk());
            }

            other => {
                error!("{other:?}");
            }
        }

        tags
    }

    #[allow(clippy::unused_self)]
    pub fn m3_m4(&mut self, tags_in: &Tags) -> Result<(Tags, Option<CipherCtx>)> {
        use TagIdx::{Proof as ProofIdx, PublicKey as PublicKeyIdx};
        use TagVal::{Proof, PublicKey};

        let mut tags_out = Tags::default();

        let client_pk = tags_in.get_cloned(PublicKeyIdx);
        let client_proof = tags_in.get_cloned(ProofIdx);

        match (client_pk, client_proof) {
            (Ok(PublicKey(pk)), Ok(Proof(proof))) => {
                let mut verifier = Verifier::new(&self.server, &pk, &proof)?;

                match verifier.authenticate() {
                    // authentication success returns the cipher context
                    Ok(cipher) => {
                        tags_out.push(TagVal::make_state(4));
                        tags_out.push(verifier.proof());

                        return Ok((tags_out, Some(cipher)));
                    }
                    Err(e) => {
                        tracing::error!("setup M3_M4: {e}");
                    }
                }
            }

            (not_pk, not_proof) => {
                error!("{not_pk:?} {not_proof:?}");
            }
        }

        Ok((tags_out, None))
    }

    pub fn take_cipher(&mut self) -> Option<CipherCtx> {
        self.cipher.take()
    }
}

#[cfg(test)]
mod tests {

    use crate::Result;
    use alkali::hash::sha2;
    use anyhow::anyhow;
    use base16ct::lower;
    use bytes::BytesMut;

    #[test]
    fn can_work_with_hasher() -> Result<()> {
        let hash = sha2::hash(b"Pair-Setup:3939").unwrap();
        let mut buf = BytesMut::zeroed(128);
        let e = lower::encode(&hash.0, &mut buf).map_err(|e| anyhow!("{e}"))?;

        assert_eq!(e.len(), 128);

        Ok(())
    }
}
