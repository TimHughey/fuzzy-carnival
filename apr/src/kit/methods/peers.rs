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

use crate::{
    kit::{
        msg::{Frame, Response},
        ptp::clock,
    },
    Result,
};

use plist::Value;
use pretty_hex::PrettyHex;
const MATCH_OVERRIDE: &str = "SupportsClockPortMatchingOverride";
const CLOCK_PORTS: &str = "ClockPorts";
const DEVICE_TYPE: &str = "DeviceType";
const ADDRESSES: &str = "Addresses";
const ID: &str = "ID";
const CLOCK_ID: &str = "ClockID";

#[derive(Default, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Peer {
    supports_clock_port_matching_override: Option<bool>,
    clock_ports: Vec<clock::PeerNet>,
    device_type: u8,
    addresses: Vec<String>,
    id: String,
    clock_identity: Option<clock::Identity>,
}

impl Peer {
    pub fn absorb_kv(&mut self, key: &str, val: &Value) -> Result<()> {
        match key {
            MATCH_OVERRIDE => {
                self.supports_clock_port_matching_override = val.as_boolean();
            }
            CLOCK_PORTS => {
                if let Some(ip_port_map) = val.as_dictionary() {
                    for (ip, port) in ip_port_map {
                        if let Some(port) = port.as_unsigned_integer() {
                            let ip_port = clock::PeerNet::try_from((ip.as_str(), port))?;
                            self.clock_ports.push(ip_port);
                        }
                    }
                }
            }
            DEVICE_TYPE => {
                if let Some(device_type) = val.as_unsigned_integer() {
                    self.device_type = device_type.try_into()?;
                }
            }
            ADDRESSES => {
                if let Some(addrs) = val.as_array() {
                    for addr in addrs {
                        if let Some(addr) = addr.as_string() {
                            self.addresses.push(addr.into());
                        }
                    }
                }
            }
            ID => {
                if let Some(id) = val.as_string() {
                    self.id = id.into();
                }
            }
            CLOCK_ID => {
                if let Some(clock_id) = val.as_signed_integer() {
                    if clock_id == 0 {
                        self.clock_identity = None;
                    } else {
                        self.clock_identity = Some(clock_id.to_ne_bytes().into());
                    }
                }
            }
            key => {
                tracing::warn!("'{key}': unrecognized");
            }
        }

        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct Set {
    inner: Vec<Peer>,
}

impl Set {
    pub fn response(&mut self, frame: Frame) -> Result<Response> {
        use plist::Value as Val;

        let Frame {
            cseq,
            routing,
            content,
            ..
        } = frame;

        if let Some(content) = content {
            tracing::debug!("\nPEERS CONTENT {:#?}", content.data.hex_dump());

            let val: Val = content.try_into()?;
            if let Some(array) = val.as_array() {
                tracing::debug!("examining array:\n{array:#?}");

                for entry in array {
                    if let Some(dict) = entry.as_dictionary() {
                        let mut peer = Peer::default();

                        for (key, val) in dict.iter() {
                            peer.absorb_kv(key, val)?;
                        }

                        self.inner.push(peer);
                    }
                }
            }
        }

        if self.inner.is_empty() {
            tracing::warn!("{routing}: empty peer list");
        }

        Ok(Response::ok_simple(cseq))
    }
}
