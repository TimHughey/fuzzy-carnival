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

use crate::{Particulars, Result};
use mdns_sd::{ServiceDaemon, ServiceInfo};

#[derive(Debug)]
pub(crate) struct SerDis {
    flavors: [ServiceInfo; 2],
}

impl SerDis {
    pub fn build() -> Result<SerDis> {
        const RECEIVER_NAME: &str = "Pierre";
        const ST_AIRPLAY: &str = "_airplay._tcp.local.";
        const ST_RAOP: &str = "_raop._tcp.local.";
        const PORT: u16 = 7000;
        const GIT_VERSION: &str = git_version::git_version!();

        let particulars = Particulars::global();

        let host = particulars.host_name.as_str();
        let host_ip = particulars.host_ip.as_str();
        let mac_addr = particulars.mac_addr.as_str();
        let pk = particulars.public_key.as_str();
        let ff_hex = particulars.features().as_lsb_msb_hex();
        let st_hex = format!("{:#x}", particulars.status());
        let device_id = particulars.device_id();
        let serial_num = device_id.replace(':', "-").to_ascii_uppercase();

        let txt_raop = [
            ("vs", "366.0"),
            ("vn", "65537"),
            ("tp", "UDP"),
            ("pk", pk),
            ("am", "Pierre"),
            ("md", "0,1,2"),
            ("sf", &st_hex),
            ("ft", &ff_hex),
            ("et", "0,4"),
            ("da", "true"),
            ("cn", "0,4"),
        ];

        let txt_airplay = [
            ("pk", pk),
            ("gcgl", "0"),
            ("gid", mac_addr),
            ("pi", mac_addr),
            ("srcvers", "366.0"),
            ("protovers", "1.1"),
            ("serialNumber", &serial_num),
            ("manufacturer", "Hughey"),
            ("model", "Pierre"),
            ("flags", &st_hex),
            ("fv", GIT_VERSION),
            ("rsf", "0x0"),
            ("features", &ff_hex),
            ("deviceid", &device_id),
            ("acl", "0"),
        ];

        Ok(SerDis {
            flavors: [
                ServiceInfo::new(
                    ST_AIRPLAY,
                    RECEIVER_NAME,
                    host,
                    host_ip,
                    PORT,
                    &txt_airplay[..],
                )?,
                ServiceInfo::new(
                    ST_RAOP,
                    format!("{}@{}", particulars.simple_id(), RECEIVER_NAME).as_str(),
                    host,
                    host_ip,
                    PORT,
                    &txt_raop[..],
                )?,
            ],
        })
    }

    pub fn register(&self, mdns: &ServiceDaemon) -> Result<()> {
        for si in &self.flavors {
            let service_info = si.to_owned();
            mdns.register(service_info)?;
        }

        Ok(())
    }

    pub fn unregister(&self, mdns: &ServiceDaemon) -> Result<()> {
        for si in &self.flavors {
            let fullname = si.get_fullname();

            mdns.unregister(fullname)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn can_get_embedded_info_plist() -> crate::Result<()> {
        use plist::Dictionary;

        let bytes = include_bytes!("../plists/get_info_resp.plist");
        let mut dict: Dictionary = plist::from_bytes(bytes)?;

        assert!(dict.len() == 9);

        dict.insert("features".into(), 0x4000.into());

        assert!(dict.len() == 10);

        let val = dict.get("features");

        assert!(val.is_some());

        let val = val.unwrap();

        assert!(val.as_string().is_none());
        assert!(val.as_unsigned_integer().is_some());
        assert!(val.as_unsigned_integer().unwrap() == 0x4000);

        Ok(())
    }
}
