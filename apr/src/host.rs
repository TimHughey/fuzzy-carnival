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

use alkali::{asymmetric::sign, mem};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use once_cell::sync::Lazy;
use tracing::error;

#[derive(Debug)]
pub struct Info {
    pub name: String,
    pub ip: String,
    pub mac: String,
    pub id: String,
    pub reeceiver_name: String,
    pub sign_seed: sign::Seed<mem::FullAccess>,
}

static INFO: Lazy<Info> = Lazy::new(|| {
    use gethostname::gethostname;

    let ifaces = NetworkInterface::show();
    let hostname = gethostname();
    let seed = sign::Seed::new_empty();

    match (ifaces, hostname.to_str(), seed) {
        (Ok(ifaces), Some(name), Ok(mut seed)) => {
            if let Some(ni) = ifaces.into_iter().find(Info::useable_iff) {
                let mac = ni.mac_addr.unwrap().to_ascii_uppercase();

                if let Some(addr) = ni.addr.into_iter().find(|a| a.ip().is_ipv4()) {
                    let id = mac.replace(':', "");
                    // let mut seed_bytes = [0u8; sign::KEYPAIR_SEED_LENGTH];
                    // seed_bytes[0..id.len()].clone_from_slice(id.as_bytes());
                    seed[0..id.len()].clone_from_slice(id.as_bytes());

                    return Info {
                        name: format!("{name}.local"),
                        ip: addr.ip().to_string(),
                        id,
                        mac,
                        reeceiver_name: "Alpha".into(),
                        sign_seed: seed,
                    };
                }
            }
        }

        (Err(e), _, _) => {
            error!("unable to find viable network interface: {e}");
        }

        (Ok(_), None, _) => {
            error!("unable to determine host name");
        }

        (Ok(_), Some(_), Err(e)) => {
            error!("unable to create seed: {e}");
        }
    }

    panic!("unable to determine host runtime information");
});

impl Info {
    #[inline]
    #[must_use]
    pub fn bind_address(port: u16) -> String {
        format!("{}:{port}", INFO.ip.as_str())
    }

    #[inline]
    ///
    /// # Errors
    /// May return an error if unable to clone seed
    ///
    pub fn clone_seed() -> crate::Result<sign::Seed<mem::FullAccess>> {
        type SignSeed = sign::Seed<mem::FullAccess>;
        let seed = SignSeed::try_clone(&INFO.sign_seed);

        Ok(seed?)
    }

    #[inline]
    #[must_use]
    pub fn ip_as_str() -> &'static str {
        INFO.ip.as_str()
    }

    #[must_use]
    pub fn id_as_str() -> &'static str {
        INFO.id.as_str()
    }

    #[inline]
    #[must_use]
    pub fn id_as_slice() -> &'static [u8] {
        INFO.id.as_bytes()
    }

    #[must_use]
    pub fn name_as_str() -> &'static str {
        INFO.name.as_str()
    }

    #[must_use]
    pub fn mac_as_str() -> &'static str {
        INFO.mac.as_str()
    }

    #[must_use]
    pub fn receiver_as_str() -> &'static str {
        INFO.reeceiver_name.as_str()
    }

    #[must_use]
    pub fn useable_iff(ni: &NetworkInterface) -> bool {
        // no loopback
        !ni.name.starts_with("lo") &&
        // has a mac addr
        ni.mac_addr.is_some() &&
        // has assigned IP addrs
        !ni.addr.is_empty()
    }

    #[inline]
    #[must_use]
    pub fn seed() -> &'static sign::Seed<mem::FullAccess> {
        &INFO.sign_seed
    }
}

#[cfg(test)]
mod tests {
    use super::INFO;
    use crate::HostInfo;

    #[test]
    fn can_lazy_create_host_info() {
        let name = HostInfo::name_as_str();

        println!("{:#?}", *INFO);

        assert!(name.is_ascii());
        assert!(!HostInfo::id_as_str().contains(':'));

        assert_eq!(INFO.sign_seed.len(), 32);
    }
}
