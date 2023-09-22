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

use bitflags::bitflags;
use mdns_sd::TxtProperty;
use once_cell::sync::Lazy;

bitflags! {
  ///
  /// Features Flags
  ///
  #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
  pub struct Features : u64 {
    const B00_VIDEO = 0x01;
    const B01_PHOTO = 0x01 << 1;
    const B02_VIDEO_FAIRPLAY = 0x01 << 2;
    const B03_VIDEO_VOL_CTRL = 0x01 << 3;
    const B04_VIDEO_HTTP_LIVE_STREAMING = 0x01 << 4;
    const B05_SLIDE_SHOW = 0x01 << 5;
    const B06_UNKNOWN = 0x01 << 6;
    // BIT07: seems to need NTP
    const B07_SCREEN_MIRRORING = 0x01 << 7;
    const B08_SCREEN_ROTATE = 0x01 << 8;
    // BIT09: is necessary for iPhone/Music audio
    const B09_AIRPLAY_AUDIO = 0x01 << 9;
    const B10_UNKNOWN = 0x01 << 10;
    const B11_AUDIO_REDUNDANT = 0x01 << 11;
    // BIT12: iTunes4Win ends ANNOUNCE with rsaaeskey, does not attempt FPLY auth.
    // also coerces frequent OPTIONS packets (keepalive) from iPhones
    const B12_FPS_APV2P5_AES_GCM = 0x01 << 12;
    // BIT13-14: MFi stuff.
    const B13_MFI_HARDWARE = 0x01 << 13;
    // BIT14: Needed on iPhone Music to stream audio
    const B14_MFI_SOFT_AIRPLAY = 0x01 << 14;
    // BIT15-17 not mandatory, faster pairing without
    const B15_AUDIO_META_COVERS = 0x01 << 15;
    const B16_AUDIO_META_PROGRESS = 0x01 << 16;
    const B17_AUDIO_META_TXT_DAAP = 0x01 << 17;
    // BIT18: Needed by MacOS to pair
    const B18_RECEIVE_AUDIO_PCM = 0x01 << 18;
    // BIT19: Needed by MacOS
    const B19_RECEIVE_AUDIO_ALAC = 0x01 << 19;
    // BTI20: Needed by iOS
    const B20_RECEIVE_AUDIO_AAC_LC = 0x01 << 20;
    const B21_UNKNOWN = 0x01 << 21;
    // Try 22 without 40 - ANNOUNCE + SDP
    const B22_AUDIO_UNENCRYPTED = 0x01 << 22;
    const B23_RSA_AUTH = 0x01 << 23;
    const B24_UNKNOWN = 0x01 << 24;
    // Pairing stalls with longer /auth-setup string w/26
    // BIT25 seems to require ANNOUNCE
    const B25_ITUNES4_WITH_ENCRYPTION = 0x01 << 25;
    // try BIT26 without BIT40. BIT26 = crypt audio?
    // mutex w/BIT22?
    const B26_AUDIO_AES_MFI = 0x01 << 26;
    const B27_LEGACY_PAIRING = 0x01 << 27;
    const B28_UNKNOWN = 0x01 << 28;
    const B29_PLIST_META_DATA = 0x01 << 29;
    const B30_UNIFIDED_ADVERTISING_INFO = 0x01 << 30;
    // BIT31: reserved
    const B32_CAR_PLAY = 0x01 << 32;
    const B33_AIRPLAY_VIDEO_PLAY_QUEUE = 0x01 << 33;
    const B34_AIRPLAY_FROM_CLOUD = 0x01 << 34;
    const B35_TLS_PSK = 0x01 << 35;
    const B36_UNKNOWN = 0x01 << 36;
    const B37_CARPLAY_CONTROL = 0x01 << 37;
    // BIT38: seems to be implicit with other flags; works with or without 38.
    const B38_CONTROL_CHANNEL_ENCRYPT = 0x01 << 38;
    const B39_UNKNOWN = 0x01 << 39;
    // BIT40: when absence requires ANNOUNCE method
    const B40_BUFFERED_AUDIO = 0x01 << 40;
    const B41_PTP_CLOCK = 0x01 << 41;
    const B42_SCREEN_MULTI_CODEC = 0x01 << 42;
    const B43_SYSTEM_PAIRING = 0x01 << 43;
    const B44_AIRPLAY_VALERIA_SCREEN_SEND = 0x01 << 44;
    // BIT45: macOS wont connect, iOS will, but dies on play.
    // BIT45 || BIT41: seem mutually exclusive.
    // BIT45 triggers stream type:96 (without ft41, PTP)
    const B45_NTP_CLOCK = 0x01 << 45;
    const B46_HOME_KIT_PAIRING = 0x01 << 46;
    // BIT46: needed for PTP
    const B47_PEER_MANAGEMENT = 0x01 << 47;
    const B48_TRANSIENT_PAIRING = 0x01 << 48;
    const B49_AIRPLAY_VIDEO_V2 = 0x01 << 49;
    const B50_NOW_PLAYING_INFO = 0x01 << 50;
    const B51_MFI_PAIR_SETUP = 0x01 << 51;
    const B52_PEERS_EXTENDED_MESSAGE = 0x01 << 52;
    const B53_UNKNOWN = 0x01 << 53;
    const B54_SUPPORTS_AIRPLAY_SYNC = 0x01 << 54;
    const B55_SUPPORTS_WAKE_ON_LAN = 0x01 << 55;
    const B56_SUPPORTS_WAKE_ON_LAN = 0x01 << 56;
    const B57_UNKNOWN = 0x01 << 57;
    const B58_HANG_DOG_REMOTE = 0x01 << 58;
    const B59_AUDIO_STREAM_CONNECTION_SETUP = 0x01 << 59;
    const B60_AUDIO_MEDIA_DATA_CONTROL = 0x01 << 60;
    const B61_RFC2198_REDUNDANT = 0x01 << 61;
    const B62_UNKNOWN = 0x01 << 62;

    // BIT51 - macOS sits for a while. Perhaps trying a closed connection port or
    // medium?; iOS just fails at Pair-Setup [2/5]

    // features are 64-bits and used for both mDNS (broadcast) and plist (RTSP replies)
    //  1. least significant 32-bits in uppercase hex with 0x prefix
    //  2. comma seperator
    //  3. most significant 32-bits in uppercase hex with 0x prefix
    //
    // examples:
    //  mDNS  -> 0x1C340405F4A00: features=0x405F4A00,0x1C340
    //  plist -> 0x1C340405F4A00: 496155702020608 (signed int)
    //
    // features: u64 = 0x1C340445F8A00; // based on Sonos Amp
  }
}

impl Features {
    #[must_use]
    pub fn as_lsb_msb_hex(self) -> String {
        let bits = self.bits();
        let most_sb = bits >> 32;
        let least_sb = (bits << 32) >> 32;

        format!("{least_sb:#X},{most_sb:#X}")
    }

    // #[must_use]
    // pub fn as_u64(self) -> u64 {
    //     self.bits()
    // }

    // #[must_use]
    // #[allow(clippy::cast_possible_wrap)]
    // pub fn as_plist_val(self) -> i64 {
    //     self.bits() as i64
    // }

    // #[must_use]
    // pub fn as_txt_airplay(self) -> TxtProperty {
    //     TxtProperty::from(("features", self.as_lsb_msb_hex()))
    // }

    // #[must_use]
    // pub fn as_txt_raop(self) -> TxtProperty {
    //     TxtProperty::from(("ft", self.as_lsb_msb_hex()))
    // }
}

impl Default for Features {
    fn default() -> Self {
        Self::B48_TRANSIENT_PAIRING
            | Self::B47_PEER_MANAGEMENT
            | Self::B46_HOME_KIT_PAIRING
            | Self::B41_PTP_CLOCK
            | Self::B40_BUFFERED_AUDIO
            | Self::B30_UNIFIDED_ADVERTISING_INFO
            | Self::B22_AUDIO_UNENCRYPTED
            | Self::B20_RECEIVE_AUDIO_AAC_LC
            | Self::B19_RECEIVE_AUDIO_ALAC
            | Self::B18_RECEIVE_AUDIO_PCM
            | Self::B17_AUDIO_META_TXT_DAAP
            | Self::B16_AUDIO_META_PROGRESS
            | Self::B15_AUDIO_META_COVERS
            | Self::B14_MFI_SOFT_AIRPLAY
            | Self::B09_AIRPLAY_AUDIO
    }
}

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
    pub fn as_plist_val(self) -> i64 {
        i64::from(self.bits())
    }

    #[allow(dead_code)]
    pub fn as_txt_airplay(self) -> TxtProperty {
        TxtProperty::from(("status", format!("{:#x}", self.bits())))
    }

    #[allow(dead_code)]
    pub fn as_txt_raop(self) -> TxtProperty {
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

#[derive(Debug, Default)]
pub struct Calculated {
    features_hex: String,
    features: Features,
    status_hex: String,
    status: Status,
}

static CALCULATED: Lazy<Calculated> = Lazy::new(|| {
    let features = Features::default();
    let status = Status::default();

    Calculated {
        features_hex: features.as_lsb_msb_hex(),
        features,
        status_hex: format!("{status:#x}"),
        status,
    }
});

impl Calculated {
    #[must_use]
    #[inline]
    pub fn features_as_lsb_msb_str() -> &'static str {
        CALCULATED.features_hex.as_str()
    }

    #[must_use]
    #[inline]
    #[allow(dead_code)]
    pub fn features_as_u64() -> u64 {
        CALCULATED.features.bits()
    }

    #[must_use]
    #[inline]
    pub fn status_as_str() -> &'static str {
        CALCULATED.status_hex.as_str()
    }

    #[must_use]
    #[inline]
    #[allow(dead_code)]
    pub fn status_as_u32() -> u32 {
        CALCULATED.status.bits()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn feature_flags_default() {
        assert!(Features::default().bits() == 0x1_C300_405F_C200);
    }

    // #[test]
    // fn feature_flags_produces_raop_txt() {
    //     let txt = Features::default().as_txt_raop();

    //     assert!(txt.key() == "ft");
    //     assert!(txt.val_str() == "0x405FC200,0x1C300");
    // }

    // #[test]
    // fn feature_flags_produces_airplay_txt() {
    //     let txt = Features::default().as_txt_airplay();

    //     assert!(txt.key() == "features");
    //     assert!(txt.val_str() == "0x405FC200,0x1C300");
    // }

    #[test]
    #[ignore]
    fn feature_flags_musing() {
        let ff = Features::default();

        ff.iter_names().for_each(|name| println!("{}", name.0));
    }

    #[test]
    #[ignore]
    fn feature_flags_dump() {
        let mut alpha = Features::default();

        // println!("alpha as plist val: {}", alpha.as_plist_val());

        let r = std::ops::Range { start: 0, end: 64 }.step_by(8);

        print!("alpha: ");
        r.for_each(|r0| {
            let x: u64 = 0xff << r0;
            let y: u64 = (alpha.bits() & x) >> r0;

            print!("{y:08b} ");
        });

        println!();

        let beta: u64 = 0x1_C340_445F_8A00u64;

        let r = std::ops::Range { start: 0, end: 64 }.step_by(8);

        print!("beta:  ");
        r.for_each(|r0| {
            let x: u64 = 0xff << r0;
            let y: u64 = (beta & x) >> r0;

            print!("{y:08b} ");
        });

        println!();

        let as_str = |x| -> String {
            let most_sb = x >> 32;
            let least_sb = (x << 32) >> 32;

            format!("{least_sb:#X},{most_sb:#X}")
        };

        println!("alpha: {}", as_str(alpha.bits()));
        println!("beta:  {}", as_str(beta));

        alpha.remove(Features::B03_VIDEO_VOL_CTRL);
        println!("alpha={alpha:#08b}");

        let two = Features::B00_VIDEO | Features::B01_PHOTO;

        let two_string = format!("{two:#06x}");

        assert_eq!(two_string, "0x0003");
    }

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
