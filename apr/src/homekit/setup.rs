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

#[allow(unused)]
use super::{states, HostInfo, SrpServer, TagIdx, TagVal, Tags};

// use bytes::BytesMut;
use tracing::{error, info, warn};

#[derive(Debug, Default)]
pub struct Context {
    pub steps_n: u8,
    pub transient: bool,
    pub encrypted: bool,
    pub server: Option<SrpServer<sha2::Sha512>>,
}

impl Context {
    const USERNAME: &str = "Pair-Setup";
    const PASSWORD: &str = "3939";

    pub fn build(steps_n: u8) -> Self {
        Self {
            steps_n,
            transient: false,
            encrypted: false,
            server: Some(SrpServer::new(Self::USERNAME, Self::PASSWORD)),
        }
    }

    // pub fn get_shared_key() -> &[u8] {}

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
        use pretty_hex::PrettyHex;
        use TagIdx::{Proof as ProofIdx, PublicKey as PublicKeyIdx};
        use TagVal::{Proof, PublicKey};

        let mut tags = Tags::default();

        let client_pk = tags_in.get_cloned(PublicKeyIdx);
        let client_proof = tags_in.get_cloned(ProofIdx);

        match (client_pk, client_proof) {
            (Ok(PublicKey(pk)), Ok(Proof(proof))) => {
                info!("\nCLIENT PUB KEY {:?}", pk.hex_dump());

                let mut server = self.server.take().unwrap().set_client_pk(pk.as_slice());

                if !server.verify(proof.as_slice()) {
                    error!("client proof did not match server");

                    warn!("\nCLIENT M1 {:?}", proof.hex_dump());
                    warn!("\nSERVER M1 {:?}", server.M.to_bytes_be().hex_dump());
                }

                let server_proof = server.proof();
                info!("\nSERVER PROOF {server_proof:?}");

                tags.push(TagVal::make_state(4));
                tags.push(server_proof);
                self.encrypted = true;

                self.server = Some(server);
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

    use base16ct::lower;
    use bytes::BytesMut;
    use pretty_hex::PrettyHex;
    use sha2::{Digest, Sha512};

    #[test]
    fn can_work_with_hasher() {
        let hash = Sha512::digest(b"Pair-Setup:3939");
        let encoded = hex::encode(hash);

        println!("{:?}", encoded.hex_dump());

        let mut buf = BytesMut::zeroed(512);
        let e = lower::encode(hash.as_slice(), &mut buf);

        if let Ok(e) = e {
            println!("\nvia base16ct:\n{:?}", e.hex_dump());
        } else {
            println!("{e:?}");
        }
    }
}
