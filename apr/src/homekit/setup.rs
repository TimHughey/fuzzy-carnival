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

#[allow(unused_imports)]
use super::{states, HostInfo, SrpServer, TagIdx, TagVal, Tags};
use tracing::error;

#[derive(Debug, Default)]
pub struct Context {
    pub steps_n: u8,
    pub transient: bool,
    pub encrypted: bool,
    pub server: Option<SrpServer>,
}

impl Context {
    const USERNAME: &str = "Pair-Setup";
    const PASSWORD: &[u8; 4] = b"3939";

    pub fn build(steps_n: u8) -> Self {
        Self {
            steps_n,
            transient: false,
            encrypted: false,
            server: Some(SrpServer::new(Self::USERNAME, *Self::PASSWORD, None, None)),
        }
    }

    pub fn m1_m2(&mut self, tags_in: &Tags) -> Tags {
        use TagIdx::{Flags as FlagsIdx, Method as MethodIdx};
        use TagVal::{Flags, Method, State};

        const PAIR_SETUP: TagVal = Method(0);
        const TRANSIENT: TagVal = Flags(0x10);

        let mut tags = Tags::default();

        let method = tags_in.get_cloned(MethodIdx);
        let flags = tags_in.get_cloned(FlagsIdx);

        let server = self.server.as_ref().unwrap();

        match (method, flags) {
            (Ok(PAIR_SETUP), Ok(TRANSIENT)) => {
                self.transient = true;

                tags.push(State(states::Generic(2)));
                tags.push(server.get_salt());
                tags.push(server.get_pk());
            }

            other => {
                error!("{other:?}");
            }
        }

        tags
    }

    #[allow(clippy::unused_self)]
    pub fn m3_m4(&mut self, tags_in: &Tags) -> Tags {
        use TagIdx::{Proof as ProofIdx, PublicKey as PublicKeyIdx};
        use TagVal::{Proof, PublicKey};

        let mut tags = Tags::default();

        let client_pk = tags_in.get_cloned(PublicKeyIdx);
        let client_proof = tags_in.get_cloned(ProofIdx);

        match (client_pk, client_proof) {
            (Ok(PublicKey(pk)), Ok(Proof(proof))) => {
                let mut server = self.server.take().unwrap();

                if server.build_verifier(&pk, &proof).is_ok() {
                    if server.authenticate().is_ok() {
                        tags.push(TagVal::make_state(4));
                        tags.push(server.proof());
                        self.encrypted = true;
                    }

                    self.server = Some(server);
                }
            }

            (not_pk, not_proof) => {
                error!("{not_pk:?} {not_proof:?}");
            }
        }

        tags
    }
}

#[cfg(test)]
mod tests {

    use alkali::hash::sha2;
    use base16ct::lower;
    use bytes::BytesMut;
    use pretty_hex::PrettyHex;

    #[test]
    fn can_work_with_hasher() {
        let hash = sha2::hash(b"Pair-Setup:3939").unwrap();
        let encoded = hex::encode(hash.0);

        println!("{:?}", encoded.hex_dump());

        let mut buf = BytesMut::zeroed(512);
        let e = lower::encode(&hash.0, &mut buf);

        if let Ok(e) = e {
            println!("\nvia base16ct:\n{:?}", e.hex_dump());
        } else {
            println!("{e:?}");
        }
    }
}
