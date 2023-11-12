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
use bytes::{BufMut, BytesMut};
use ed25519_dalek::{SecretKey, SigningKey};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use once_cell::sync::Lazy;
#[allow(unused)]
use pretty_hex::PrettyHex;
use tracing::error;
use uuid::Uuid;

pub struct Info {
    pub name: String,
    pub ip: String,
    pub mac: String,
    pub mac_bytes: [u8; 6],
    pub id: String,
    pub id2: Uuid,
    pub reeceiver_name: String,
    pub sign_seed: sign::Seed<mem::FullAccess>,
    pub accessory_secret_key: SecretKey,
    pub accessory_sign_key: SigningKey,
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

                    // we'll need the mac in binary format, create it now
                    let mut mac_bytes = [0u8; 6];
                    hex::decode_to_slice(&id, &mut mac_bytes).unwrap();

                    seed[0..id.len()].clone_from_slice(id.as_bytes());

                    let mut secret_key = SecretKey::default();
                    secret_key.copy_from_slice(seed.as_slice());

                    return Info {
                        name: format!("{name}.local"),
                        ip: addr.ip().to_string(),
                        id,
                        id2: Uuid::new_v4(),
                        mac,
                        mac_bytes,
                        reeceiver_name: "Alpha".into(),
                        sign_seed: seed,
                        accessory_sign_key: SigningKey::from_bytes(&secret_key),
                        accessory_secret_key: secret_key,
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
    pub fn get() -> &'static Info {
        &INFO
    }

    #[inline]
    #[must_use]
    pub fn ip_as_str() -> &'static str {
        INFO.ip.as_str()
    }

    #[inline]
    #[must_use]
    pub fn id() -> &'static Uuid {
        &INFO.id2
    }

    #[inline]
    #[must_use]
    pub fn id2_as_key_src() -> [u8; 45] {
        let mut buf = Uuid::encode_buffer();

        INFO.id2.simple().encode_lower(&mut buf);

        buf
    }

    #[must_use]
    pub fn id_as_key_src() -> [u8; 32] {
        let mut src = [0u8; 32];

        let id = Self::id_as_slice();

        src[0..id.len()].copy_from_slice(id);

        src
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

    #[inline]
    #[must_use]
    pub fn id_padded(prefix_pad: Option<usize>, suffix_pad: Option<usize>) -> BytesMut {
        let id = &INFO.mac_bytes[..];
        let prefix_pad_len = prefix_pad.unwrap_or_default();
        let suffix_pad_len = suffix_pad.unwrap_or_default();

        let mut buf = BytesMut::with_capacity(id.len() + prefix_pad_len + suffix_pad_len);
        buf.put_bytes(0x00, prefix_pad_len);
        buf.put(id);
        buf.put_bytes(0x00, suffix_pad_len);

        buf
    }

    #[must_use]
    pub fn name_as_str() -> &'static str {
        INFO.name.as_str()
    }

    #[must_use]
    pub fn mac_as_byte_slice() -> &'static [u8] {
        INFO.mac_bytes.as_slice()
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

impl std::fmt::Debug for Info {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use pretty_hex::HexConfig;

        let cfg = HexConfig {
            title: false,
            ascii: false,
            width: 8,
            group: 0,
            ..HexConfig::default()
        };

        f.debug_struct("HostInfo")
            .field("name", &self.name)
            .field("id", &self.id)
            .field("ip", &self.ip)
            .field("id2", &self.id2)
            .field("receiver_name", &self.reeceiver_name)
            .field(
                "sign_seed",
                &format_args!("{}", self.sign_seed.hex_conf(cfg)),
            )
            .field(
                "accessory_secret_key",
                &format_args!("{}", self.accessory_secret_key.hex_conf(cfg)),
            )
            // .field("accessory_sign_key", &self.accessory_sign_key)
            .finish_non_exhaustive()
    }
}
