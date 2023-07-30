// Rusty Pierre
//
// Copyright 2023 Tim Hughey
//
// Licensed under the Apache License, Version 2.0 (the "License");
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

use alkali::{
    asymmetric::cipher::{Keypair, Seed},
    encode::hex,
    mem::FullAccess,
};

use anyhow::{anyhow, Result};

use mdns_sd::{DaemonEvent, ServiceDaemon, ServiceInfo};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use std::time::Duration;

#[allow(unused_imports)]
use tracing::{debug, error, info};

use crate::flags::{FeatureFlags, StatusFlags};

const RECEIVER_NAME: &str = "Pierre";
const ST_AIRPLAY: &str = "_airplay._tcp.local.";
const ST_RAOP: &str = "_raop._tcp.local.";

pub struct ApReceiver {
    mdns: ServiceDaemon,
    host_ip: String,
    device_id: String,
    id: String,
    services: Vec<ServiceInfo>,
    keypair: Keypair,
}

impl ApReceiver {
    pub fn new() -> Result<ApReceiver> {
        const GIT_VERSION: &str = git_version::git_version!();

        let (mac_addr, host_ip) = get_net()?;

        // create our device id and unique id
        let (device_id, id) = Self::make_ids(&mac_addr);

        // create our security keys
        let keypair = make_keypair(&device_id)?;

        let host = get_hostname()?;
        let pk = Self::get_pub_key(&keypair);
        let ff_hex = FeatureFlags::default().as_lsb_msb_hex();
        let st_hex = format!("{:#x}", StatusFlags::default());

        let serial_num = Self::serial_num(&device_id);

        let txt_raop = [
            ("pk", pk.as_str()),
            ("vs", "366.0"),
            ("vn", "65537"),
            ("tp", "UDP"),
            ("sf", &st_hex),
            ("md", "0,1,2"),
            ("am", "Pierre"),
            ("fv", GIT_VERSION),
            ("ft", &ff_hex),
            ("et", "0,4"),
            ("da", "true"),
            ("cn", "0,4"),
        ];

        let txt_airplay = [
            ("pk", pk.as_str()),
            ("gcgl", "0"),
            ("gid", &mac_addr),
            ("pi", &mac_addr),
            ("srcvers", "366.0"),
            ("protovers", "1.1"),
            ("serial_num", &serial_num),
            ("manufacturer", "Hughey"),
            ("model", "Pierre"),
            ("flags", &st_hex),
            ("fv", GIT_VERSION),
            ("rsf", "0x0"),
            ("features", &ff_hex),
            ("deviceid", &device_id),
            ("acl", "0"),
        ];

        let services = vec![
            ServiceInfo::new(
                ST_RAOP,
                format!("{}@{}", id, RECEIVER_NAME).as_str(),
                &host,
                &host_ip,
                ApReceiver::port(),
                &txt_raop[..],
            )?,
            ServiceInfo::new(
                ST_AIRPLAY,
                RECEIVER_NAME,
                &host,
                &host_ip,
                ApReceiver::port(),
                &txt_airplay[..],
            )?,
        ];

        // initialize our mdns daemon
        let mdns = ServiceDaemon::new()?;

        // Register with the daemon, which publishes the service.
        for service_info in &services {
            mdns.register(service_info.to_owned())?;
        }

        Ok(ApReceiver {
            mdns,
            host_ip,
            device_id,
            id,
            services,
            keypair,
        })
    }

    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.host_ip, Self::port())
    }

    pub fn device_id(&self) -> String {
        self.device_id.to_owned()
    }

    fn make_ids(mac_addr: &str) -> (String, String) {
        // use of temporary variables for readability
        let device_id = mac_addr.to_ascii_uppercase();
        let id = device_id.replace(':', "");

        (device_id, id)
    }

    pub fn monitor(&self) -> mdns_sd::Receiver<DaemonEvent> {
        self.mdns.monitor().expect("failed to create mdns monitor")
    }

    pub fn port() -> u16 {
        7000
    }

    pub fn primary_ip(&self) -> String {
        self.host_ip.to_owned()
    }

    pub fn pub_key(&self) -> String {
        let buf = self.keypair.public_key.to_ascii_lowercase();

        hex::encode(&buf).expect("failed to convert public key to string")
    }

    fn get_pub_key(kp: &Keypair) -> String {
        let pk = hex::encode(&kp.public_key);
        pk.expect("failed generate public key")
    }

    pub fn raop_sname(&self) -> String {
        format!("{}@{}", self.id, RECEIVER_NAME)
    }

    fn serial_num(device_id: &str) -> String {
        device_id.to_owned().replace(':', "-")
    }

    pub fn airplay_sname(&self) -> &str {
        RECEIVER_NAME
    }

    pub fn shutdown(&self) {
        let timeout = Duration::from_millis(1000);
        self.services.iter().for_each(|s| {
            let fullname = s.get_fullname();
            let receiver = self.mdns.unregister(fullname).unwrap();

            match receiver.recv_timeout(timeout) {
                Ok(_) => info!("unregistered {}", fullname),
                Err(e) => error!("{} {:#?}", fullname, e),
            }
        });
    }
}

fn get_hostname() -> Result<String> {
    gethostname::gethostname().to_str().map_or_else(
        || Err(anyhow!("unable to get host name")),
        |s| Ok(format!("{}.local.", s)),
    )

    // let host = format!("{}.local.", host.to)
    // host.push(".local.");

    // host.to_str().map_or_else(
    //     || Err(anyhow!("unable to get host name")),
    //     |host| Ok(host.to_string()),
    // )
}

fn get_net() -> Result<(String, String)> {
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

                let mac_addr = iff.mac_addr.as_ref().map_or_else(
                    || Err(anyhow!("unable to find mac address")),
                    |mac_addr| Ok(mac_addr.to_owned()),
                )?;

                Ok((mac_addr, ip))
            },
        )
}

fn make_keypair(device_id: &str) -> Result<Keypair> {
    let seed = make_seed(device_id)?;

    let keypair = Keypair::from_seed(&seed)?;
    Ok(keypair)
}

fn make_seed(device_id: &str) -> Result<Seed<FullAccess>> {
    let mut seed_src = Vec::from(device_id.to_owned());
    seed_src.resize(32, 0x00);

    let seed = Seed::try_from(seed_src.as_slice())?;

    Ok(seed)
}

#[cfg(test)]
mod tests {

    use crate::ApReceiver;
    use anyhow::Result;

    fn test_mac_addr() -> String {
        "78:28:CA:B0:C5:64".to_string()
    }

    #[test]
    fn can_make_ids() -> Result<()> {
        let mac_addr = test_mac_addr();
        let (device_id, id) = ApReceiver::make_ids(&mac_addr);

        assert!(device_id.len() == 17);

        assert!(
            device_id.chars().fold(0, |acc, c| {
                match c {
                    ':' => acc + 1,
                    _ => acc,
                }
            }) == 5
        );

        assert!(id.len() == 12);
        assert!(!id.contains(':') && !id.contains('-'));

        Ok(())
    }

    #[test]
    fn apreceiver_can_retrieve_saved_public_key() {
        let receiver = ApReceiver::new().ok().unwrap();

        let pub_key = receiver.pub_key();

        assert!(pub_key.len() == 64);
        assert!(pub_key.is_ascii());
    }
}
