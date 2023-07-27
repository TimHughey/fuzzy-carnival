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

use bitflags::bitflags;
use mdns_sd::TxtProperty;

bitflags! {
  #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
  pub struct Status : u32 {
    const B00_PROBLEMS_EXIST = 0x01;
    const B01_NOT_YET_CONFIGURED = 0x01 << 1;
    const B02_AUDIO_LINK = 0x01 << 2;  // must set
    const B03_PIN_MODE = 0x01 << 3;
    const B04_PIN_MATCH = 0x01 << 4;
    const B05_SUPPORTS_AIRPLAY_FROM_CLOUD = 0x01 << 5;
    const B06_PASSWORD_NEEDED = 0x01 << 6;
    const B07_UNKNOWN = 0x01 << 7;
    const B08_PAIRING_PIN_AKA_OTP = 0x01 << 8;
    const B09_ENABLE_HK_ACCESS_CONTROL = 0x01 << 9;
    const B10_REMOTE_CONTROL_RELAY = 0x01 << 10;
    const B11_SILENT_PRIMARY = 0x01 << 11;
    const B12_TIGHT_SYNC_IS_GROUP_LEADER = 0x01 << 12;
    const B13_TIGHT_SYNC_BUDDY_NOT_REACHABLE = 0x01 << 13;
    const B14_IS_APPLE_MUSIC_SUBSCRIBER = 0x01 << 14;
    const B15_ICLOUD_LIBRARY_IS_ON = 0x01 << 15;
    const B16_RECEIVER_SESSION_ACTIVE = 0x01 << 16; // toggle based on connection
  }
}

impl Status {
    #[allow(dead_code)]
    pub fn as_plist_val(&self) -> i64 {
        self.bits() as i64
    }

    #[allow(dead_code)]
    pub fn as_txt_airplay(&self) -> TxtProperty {
        TxtProperty::from(("status", format!("{:#x}", self.bits())))
    }

    #[allow(dead_code)]
    pub fn as_txt_raop(&self) -> TxtProperty {
        TxtProperty::from(("st", format!("{:#x}", self.bits())))
    }

    #[allow(dead_code)]
    pub fn set_session(&mut self, value: bool) -> &Self {
        self.set(Status::B16_RECEIVER_SESSION_ACTIVE, value);

        self
    }
}

impl Default for Status {
    fn default() -> Status {
        Self::B02_AUDIO_LINK
    }
}

#[cfg(test)]
mod tests {

    use super::Status;

    #[test]
    fn status_flags_default() {
        assert!(Status::default().bits() == 0x04);
    }

    #[test]
    fn status_flags_produces_raop_txt() {
        let txt = Status::default().as_txt_raop();

        assert!(txt.key() == "st");
        assert!(txt.val_str() == "0x4");
    }

    #[test]
    fn status_flags_produces_airplay_txt() {
        let txt = Status::default().as_txt_airplay();

        assert!(txt.key() == "status");
        assert!(txt.val_str() == "0x4");
    }

    #[test]
    fn status_flags_can_set_session() {
        let mut st = Status::default();

        assert!(st.bits() == 0x04);

        st.set_session(true);

        assert!(st.bits() == 0x10004);
    }
}
