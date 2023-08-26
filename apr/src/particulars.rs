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

use crate::{flags::Features, flags::Status, Result};
use alkali::{
    asymmetric::cipher::{Keypair, Seed},
    encode::hex,
    mem::FullAccess,
};
use anyhow::anyhow;
use network_interface::{NetworkInterface, NetworkInterfaceConfig};

type MacAddr = String;
type HostIp = String;

use once_cell::sync::OnceCell;

static PARTICULARS: OnceCell<Particulars> = OnceCell::new();
static KEYPAIR: OnceCell<Keypair> = OnceCell::new();

const DEFAULT_SERVICE_NAME: &str = "Pierre";

#[derive(Debug, Clone)]
pub struct Particulars {
    pub service_name: String,
    pub host_name: String,
    pub mac_addr: MacAddr,
    pub host_ip: HostIp,
    pub public_key: String,
    feat_flags: Features,
    stat_flags: Status,
}

impl Particulars {
    ///
    /// # Panics
    ///
    /// Will panic if global() is called before build()

    pub fn global() -> &'static Particulars {
        if let Some(particulars) = PARTICULARS.get() {
            return particulars;
        }

        panic!("global particulars are not available")
    }

    ///
    /// # Errors
    ///
    /// Will return an error if key pair creation fails or
    /// retrieving the host's IP address fails
    pub fn build() -> Result<Option<&'static Particulars>> {
        let host_name = get_hostname().map(|h| h + ".local.")?;
        let (mac_addr, host_ip) = get_net()?;
        let key_pair = make_keypair(&mac_addr)?;

        if KEYPAIR.set(key_pair).is_err() {
            return Err(anyhow!("failed to set keypair"));
        }

        let buf = Self::get_keypair().public_key;
        let public_key = hex::encode(&buf)?;

        if PARTICULARS
            .set(Particulars {
                service_name: DEFAULT_SERVICE_NAME.into(),
                host_name,
                mac_addr,
                host_ip,
                public_key,
                feat_flags: Features::default(),
                stat_flags: Status::default(),
            })
            .is_err()
        {
            return Err(anyhow!("faied to set particulars"));
        }

        Ok(PARTICULARS.get())
    }

    #[must_use]
    #[inline]
    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.host_ip, 7000)
    }

    #[must_use]
    #[inline]
    pub fn device_id(&self) -> String {
        mac_to_id(&self.mac_addr)
    }

    #[must_use]
    #[inline]
    pub fn features(&self) -> &Features {
        &self.feat_flags
    }

    #[must_use]
    #[inline]
    pub fn feature_bits(&self) -> u64 {
        self.feat_flags.bits()
    }

    #[must_use]
    #[inline]
    pub fn get_keypair() -> &'static Keypair {
        KEYPAIR.get().expect("key pair not initialized")
    }

    #[must_use]
    #[inline]
    pub fn simple_id(&self) -> String {
        self.mac_addr.replace(':', "").to_lowercase()
    }

    #[must_use]
    #[inline]
    pub fn status(&self) -> &Status {
        &self.stat_flags
    }

    #[must_use]
    #[inline]
    pub fn status_bits(&self) -> u32 {
        self.stat_flags.bits()
    }
}

fn get_hostname() -> Result<String> {
    match gethostname::gethostname().to_str() {
        Some(hostname) => Ok(hostname.to_string()),
        None => Err(anyhow!("unable to get host name")),
    }
}

fn get_net() -> Result<(MacAddr, HostIp)> {
    // find the first useable interface defined as:
    //  1. not loopback
    //  2. has an ipv4 address
    //  3. has a mac address

    let good = |iff: &NetworkInterface| -> bool {
        !iff.name.starts_with("lo") && iff.mac_addr.is_some() && !iff.addr.is_empty()
    };

    NetworkInterface::show()?
        .iter()
        .find(|iff| good(iff))
        .map_or_else(
            || Err(anyhow!("unable to find any network interfaces")),
            |iff| {
                let ip = iff.addr.iter().find(|a| a.ip().is_ipv4()).map_or_else(
                    || Err(anyhow!("unable to find an IPv4 address")),
                    |addr| Ok(addr.ip().to_string()),
                )?;

                // safe to directly unwrap - good() confirmed is_some
                let mac_addr = iff.mac_addr.as_ref().unwrap().to_ascii_uppercase();

                Ok((mac_addr, ip))
            },
        )
}

fn mac_to_id(mac_addr: &str) -> String {
    mac_addr.replace(':', "-").to_ascii_uppercase()
}

fn make_keypair(mac_addr: &str) -> Result<Keypair> {
    let device_id = mac_addr.replace(':', "-");

    let seed = make_seed(&device_id)?;

    let keypair = Keypair::from_seed(&seed)?;
    Ok(keypair)
}

fn make_seed(device_id: &str) -> Result<Seed<FullAccess>> {
    let mut seed_src: [u8; 32] = [0x00; 32];

    for (idx, c) in device_id.as_bytes().iter().enumerate() {
        seed_src[idx] = *c;
    }

    // let mut seed_src = Vec::from(device_id);
    // seed_src.resize(32, 0x00);

    let seed = Seed::try_from(seed_src.as_slice())?;

    Ok(seed)
}

#[cfg(test)]
mod tests {
    use crate::{Particulars, Result};

    #[test]
    fn can_create_particulars() -> Result<()> {
        let _p = Particulars::build()?;

        Ok(())
    }

    #[test]
    fn particulars_creates_hex_encoded_public_key() -> Result<()> {
        let p = Particulars::build()?;

        assert!(p.unwrap().public_key.len() == 64);

        Ok(())
    }
}
