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

use crate::{FlagsCalc, HostInfo, Result};
use mdns_sd::{ServiceDaemon, ServiceInfo};

#[derive(Debug)]
pub struct SerDis {
    flavors: [ServiceInfo; 2],
}

impl SerDis {
    ///
    /// # Errors
    ///
    /// May return an error if ``ServiceInfo`` creation fails
    pub fn build() -> Result<SerDis> {
        use crate::asym::Keys;

        const ST_AIRPLAY: &str = "_airplay._tcp.local.";
        const ST_RAOP: &str = "_raop._tcp.local.";
        const PORT: u16 = 7000;
        const GIT_VERSION: &str = git_version::git_version!();

        let txt_raop = [
            ("vs", "366.0"),
            ("vn", "65537"),
            ("tp", "UDP"),
            ("pk", Keys::get_signing_pub()),
            ("am", "Pierre"),
            ("md", "0,1,2"),
            ("sf", FlagsCalc::status_as_str()),
            ("ft", FlagsCalc::features_as_lsb_msb_str()),
            ("et", "0,4"),
            ("da", "true"),
            ("cn", "0,4"),
        ];

        let txt_airplay = [
            ("pk", Keys::get_signing_pub()),
            ("gcgl", "0"),
            ("gid", HostInfo::mac_as_str()),
            ("pi", HostInfo::mac_as_str()),
            ("srcvers", "366.0"),
            ("protovers", "1.1"),
            ("serialNumber", HostInfo::id_as_str()),
            ("manufacturer", "Hughey"),
            ("model", "Pierre"),
            ("flags", FlagsCalc::status_as_str()),
            ("fv", GIT_VERSION),
            ("rsf", "0x0"),
            ("features", FlagsCalc::features_as_lsb_msb_str()),
            ("deviceid", HostInfo::mac_as_str()),
            ("acl", "0"),
        ];

        let receiver_name = HostInfo::receiver_as_str();
        let raop_name = format!("{}@{}", HostInfo::id_as_str(), receiver_name);

        Ok(SerDis {
            flavors: [
                ServiceInfo::new(
                    ST_AIRPLAY,
                    receiver_name,
                    HostInfo::name_as_str(),
                    HostInfo::ip_as_str(),
                    PORT,
                    &txt_airplay[..],
                )?,
                ServiceInfo::new(
                    ST_RAOP,
                    raop_name.as_str(),
                    HostInfo::name_as_str(),
                    HostInfo::ip_as_str(),
                    PORT,
                    &txt_raop[..],
                )?,
            ],
        })
    }

    ///
    /// # Errors
    ///
    /// May return an error if mdns registration fails
    pub fn register(&self, mdns: &ServiceDaemon) -> Result<()> {
        for si in &self.flavors {
            let service_info = si.clone();
            mdns.register(service_info)?;
        }

        Ok(())
    }

    ///
    /// # Errors
    ///
    /// May return an error if mdns registration fails
    pub fn unregister(&self, mdns: &ServiceDaemon) -> Result<()> {
        for si in &self.flavors {
            let fullname = si.get_fullname();

            mdns.unregister(fullname)?;
        }

        Ok(())
    }
}
