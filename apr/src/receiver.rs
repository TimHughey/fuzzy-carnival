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

use mdns_sd::{DaemonEvent, ServiceDaemon, ServiceInfo};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use std::{error::Error, fmt, result, time::Duration};

use crate::flags::{FeatureFlags, StatusFlags};

/// Result Type for ApReceiver
pub type ApReceiverResult<T> = result::Result<T, ApReceiverError>;

// Define our error types. These may be customized for our error handling cases.
// Now we will be able to write our own errors, defer to an underlying error
// implementation, or do something in between.
#[derive(Debug, Clone)]
pub struct ApReceiverError {
    details: String,
}

impl ApReceiverError {
    pub fn new(detail_str: &str) -> Self {
        Self {
            details: detail_str.to_string(),
        }
    }
}

// Generation of an error is completely separate from how it is displayed.
// There's no need to be concerned about cluttering complex logic with the display style.
//
// Note that we don't store any extra info about the errors. This means we can't state
// which string failed to parse without modifying our types to carry that information.
impl fmt::Display for ApReceiverError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AP receiver failure")
    }
}

impl Error for ApReceiverError {
    fn description(&self) -> &str {
        self.details.as_str()
    }
}

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
    pub fn new() -> ApReceiverResult<ApReceiver> {
        const GIT_VERSION: &str = git_version::git_version!();

        if let Some((mac_addr, host_ip)) = Self::get_net() {
            // create our device id and unique id
            let (device_id, id) = Self::make_ids(&mac_addr);

            // create our security keys
            let keypair = Self::make_keypair(&device_id);

            let host = Self::hostname();
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

            // initialize our mdns daemon
            let mdns = ServiceDaemon::new().expect("failed to create mdns daemon");

            let si_raop = ServiceInfo::new(
                ST_RAOP,
                format!("{}@{}", id, RECEIVER_NAME).as_str(),
                host.as_str(),
                host_ip.as_str(),
                ApReceiver::port(),
                &txt_raop[..],
            )
            .unwrap();

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

            let si_airplay = ServiceInfo::new(
                ST_AIRPLAY,
                RECEIVER_NAME,
                &host,
                &host_ip,
                ApReceiver::port(),
                &txt_airplay[..],
            )
            .expect("failure creating ServiceInfo");

            let services = vec![si_raop.to_owned(), si_airplay.to_owned()];

            // Register with the daemon, which publishes the service.
            mdns.register(si_raop)
                .expect("Failed to register raop service");

            mdns.register(si_airplay)
                .expect("Failed to register airplay service");

            return Ok(ApReceiver {
                mdns,
                host_ip,
                device_id,
                id,
                services,
                keypair,
            });
        }

        Err(ApReceiverError {
            details: "failed".to_string(),
        })
    }

    pub fn bind_address(&self) -> String {
        let mut ip_and_port = self.host_ip.to_owned();
        ip_and_port.push_str(format!(":{}", Self::port()).as_str());

        ip_and_port
    }

    pub fn device_id(&self) -> String {
        self.device_id.to_owned()
    }

    pub fn hostname() -> String {
        let mut host = gethostname::gethostname().to_ascii_lowercase();
        host.push(".local.");

        host.into_string().expect("failed to get hostname")
    }

    // pub fn id(&self) -> String {
    //     self.device_id.replace(':', "")
    // }

    fn make_ids(mac_addr: &str) -> (String, String) {
        let device_id = mac_addr.to_ascii_uppercase();
        let id = device_id.replace(':', "");

        (device_id, id)
    }

    fn make_keypair(device_id: &str) -> Keypair {
        let seed = Self::make_seed(device_id);

        Keypair::from_seed(&seed).expect("failed to create keypair")
    }

    fn make_seed(device_id: &str) -> Seed<FullAccess> {
        let mut seed_src = Vec::from(device_id.to_owned());
        seed_src.resize(32, 0x00);
        let mut seed = Seed::new_empty().ok().unwrap();
        seed.copy_from_slice(seed_src.as_slice());

        seed
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

    pub fn get_net() -> Option<(String, String)> {
        let netif = NetworkInterface::show().expect("unable to get network interfaces");

        // find the first useable interface defined as:
        //  1. not loopback
        //  2. has an ipv4 address
        //  3. has a mac address

        if let Some(iff) = netif
            .iter()
            .find(|i| !i.name.starts_with("lo") && i.mac_addr.is_some() && !i.addr.is_empty())
        {
            if let Some(addr) = iff.addr.iter().find(|addr| addr.ip().is_ipv4()) {
                return Some((
                    iff.mac_addr.as_ref().unwrap().to_owned(),
                    addr.ip().to_string(),
                ));
            }
        }

        None
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
                Ok(_) => println!("Unregistered {}", fullname),
                Err(e) => println!("{} {:#?}", fullname, e),
            }
        });
    }
}

#[cfg(test)]
mod tests {

    use crate::ApReceiver;

    fn test_mac_addr() -> String {
        "78:28:CA:B0:C5:64".to_string()
    }

    #[test]
    fn apreceiver_can_get_hostname() {
        let host = ApReceiver::hostname();

        assert!(host.len() > 2);
    }

    #[test]
    fn apreceiver_can_make_keypair() {
        let (device_id, _) = ApReceiver::make_ids(&test_mac_addr());
        let key_pair = ApReceiver::make_keypair(&device_id);

        assert!(key_pair.public_key.len() > 1);
        assert!(key_pair.private_key.len() > 1);
    }

    #[test]
    fn apreceiver_can_make_ids() {
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
    }

    #[test]
    fn apreceiver_can_retrieve_saved_public_key() {
        let receiver = ApReceiver::new().ok().unwrap();

        let pub_key = receiver.pub_key();

        assert!(pub_key.len() == 64);
        assert!(pub_key.is_ascii());
    }
}
