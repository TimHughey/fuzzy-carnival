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
    pub fn as_lsb_msb_hex(&self) -> String {
        let bits = self.bits();
        let msb = bits >> 32;
        let lsb = (bits << 32) >> 32;

        format!("{:#X},{:#X}", lsb, msb)
    }

    pub fn as_u64(&self) -> u64 {
        self.bits()
    }

    pub fn as_plist_val(&self) -> i64 {
        self.bits() as i64
    }

    pub fn as_txt_airplay(&self) -> TxtProperty {
        TxtProperty::from(("features", self.as_lsb_msb_hex()))
    }

    pub fn as_txt_raop(&self) -> TxtProperty {
        TxtProperty::from(("ft", self.as_lsb_msb_hex()))
    }

    // fn as_ref(&self) -> &Features {
    //     &self
    // }
}

impl Default for Features {
    fn default() -> Features {
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

// impl std::convert::From<u64> for Features {
//     fn from(v: u64) -> Self {
//         Features(v.into())
//     }
// }

// impl From<plist::Integer> for Features {
//     fn from(v: plist::Integer) -> Self {
//         Features(v.)
//     }
// }

// impl std::convert::TryFrom<plist::Integer> for Features {
//     type Error = anyhow::Error;

//     fn try_from(v: plist::Integer) -> Result<plist::Integer> {
//         match v.as_unsigned() {
//             Some(v) => Ok(Features(v.into())),
//             None => Err(anyhow::anyhow!("failed to convert Value")),
//         }
//     }
// }

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn feature_flags_default() {
        assert!(Features::default().bits() == 0x1C300405FC200);
    }

    #[test]
    fn feature_flags_produces_raop_txt() {
        let txt = Features::default().as_txt_raop();

        assert!(txt.key() == "ft");
        assert!(txt.val_str() == "0x405FC200,0x1C300");
    }

    #[test]
    fn feature_flags_produces_airplay_txt() {
        let txt = Features::default().as_txt_airplay();

        assert!(txt.key() == "features");
        assert!(txt.val_str() == "0x405FC200,0x1C300");
    }

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

        println!("alpha as plist val: {}", alpha.as_plist_val());

        let r = std::ops::Range { start: 0, end: 64 }.step_by(8);

        print!("alpha: ");
        r.for_each(|r0| {
            let x: u64 = 0xff << r0;
            let y: u64 = (alpha.bits() & x) >> r0;

            print!("{:08b} ", y);
        });

        println!();

        let beta: u64 = 0x1C340445F8A00u64;

        let r = std::ops::Range { start: 0, end: 64 }.step_by(8);

        print!("beta:  ");
        r.for_each(|r0| {
            let x: u64 = 0xff << r0;
            let y: u64 = (beta & x) >> r0;

            print!("{:08b} ", y);
        });

        println!();

        fn as_str(x: u64) -> String {
            let msb = x >> 32;
            let lsb = (x << 32) >> 32;

            format!("{:#X},{:#X}", lsb, msb)
        }

        println!("alpha: {}", as_str(alpha.bits()));
        println!("beta:  {}", as_str(beta));

        alpha.remove(Features::B03_VIDEO_VOL_CTRL);
        println!("alpha={:#08b}", alpha);

        let two = Features::B00_VIDEO | Features::B01_PHOTO;

        let two_string = format!("{:#06x}", two);

        assert_eq!(two_string, "0x0003");
    }
}
