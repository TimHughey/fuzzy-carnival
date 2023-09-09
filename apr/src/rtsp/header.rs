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

use crate::Result;
use anyhow::anyhow;
use indexmap::IndexMap;
use std::str::FromStr;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ContType {
    AppDMapTagged,
    AppAppleBinaryPlist,
    AppOctetStream,
    TextParameters,
    PeerListChangedX,
    ImageNone,
}

impl ContType {
    const BINARY_PLIST: &str = "application/x-apple-binary-plist";
    const DMAP_TAGGED: &str = "application/x-dmap-tagged";
    const OCTET_STREAM: &str = "application/octet-stream";
    const TEXT_PARAMS: &str = "text/parameters";
    const PEER_LIST_CHANGED: &str = "/peer-list-changed";
    const IMAGE_NONE: &str = "image/none";

    pub fn description(&self) -> &str {
        match self {
            Self::AppAppleBinaryPlist => Self::BINARY_PLIST,
            Self::AppDMapTagged => Self::DMAP_TAGGED,
            Self::AppOctetStream => Self::OCTET_STREAM,
            Self::TextParameters => Self::TEXT_PARAMS,
            Self::PeerListChangedX => Self::PEER_LIST_CHANGED,
            Self::ImageNone => Self::IMAGE_NONE,
        }
    }
}

impl FromStr for ContType {
    type Err = anyhow::Error;

    fn from_str(src: &str) -> Result<ContType> {
        if let Some((p1, p2)) = src.trim().split_once('/') {
            match p1.len() {
                11 if p2.ends_with("plist") => Ok(ContType::AppAppleBinaryPlist),
                11 if p2.ends_with("tagged") => Ok(ContType::AppDMapTagged),
                11 if p2.ends_with("stream") => Ok(ContType::AppOctetStream),
                4 if p2.ends_with("meters") => Ok(ContType::TextParameters),
                5 if p2.ends_with("changed-x") => Ok(ContType::PeerListChangedX),
                0 if p2.ends_with("none") => Ok(ContType::ImageNone),
                _ => Err(anyhow!("unknown content type: {p1}/{p2}")),
            }
        } else {
            Err(anyhow!("unknown content type: {src:?}"))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Key2 {
    ActiveRemote,
    Cseq,
    ContentLength,
    ContentType,
    DacpId,
    RtpInfo,
    UserAgent,
    Extension(String),
}

impl Key2 {
    const ACTIVE_REMOTE: &str = "Active-Remote";
    const CONTENT_LEN: &str = "Content-Length";
    const CONTENT_TYPE: &str = "Content-Type";
    const CSEQ: &str = "CSeq";
    const DHCP_ID: &str = "DACP-ID";
    const RTP_INFO: &str = "RTP-INFO";
    const USER_AGENT: &str = "User-Agent";
}

impl FromStr for Key2 {
    type Err = anyhow::Error;

    fn from_str(src: &str) -> Result<Key2> {
        match src {
            Self::ACTIVE_REMOTE => Ok(Self::ActiveRemote),
            Self::CONTENT_LEN => Ok(Self::ContentLength),
            Self::CONTENT_TYPE => Ok(Self::ContentType),
            Self::CSEQ => Ok(Self::Cseq),
            Self::DHCP_ID => Ok(Self::DacpId),
            Self::RTP_INFO => Ok(Self::RtpInfo),
            Self::USER_AGENT => Ok(Self::UserAgent),
            ext if ext.starts_with("X-") => Ok(Self::Extension(ext.into())),
            unknown => Err(anyhow!("unknown header key: {unknown}")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Val2 {
    ActiveRemote(u32),
    Cseq(u64),
    ContentLength(usize),
    ContentType(ContType),
    DacpId(String),
    RtpInfo(u32),
    UserAgent(String),
    Extension(String),
}

impl Val2 {
    fn new(key: &Key2, src: &str) -> Result<Val2> {
        match key {
            Key2::ActiveRemote => Ok(Self::ActiveRemote(src.parse()?)),
            Key2::ContentLength => Ok(Self::ContentLength(src.parse()?)),
            Key2::ContentType => Ok(Self::ContentType(ContType::from_str(src)?)),
            Key2::Cseq => Ok(Self::Cseq(src.parse()?)),
            Key2::DacpId => Ok(Self::DacpId(src.to_ascii_lowercase())),
            Key2::RtpInfo => {
                if let Some(("rtptime", rtp_time)) = src.split_once('=') {
                    Ok(Self::RtpInfo(rtp_time.parse()?))
                } else {
                    Err(anyhow!("bad RTP-Info: {src}"))
                }
            }
            Key2::UserAgent => Ok(Self::UserAgent(src.into())),
            Key2::Extension(_) => Ok(Self::Extension(src.into())),
        }
    }
}

// #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
// pub enum Key {
//     ActiveRemote(u32),
//     Cseq(u64),
//     ContentLength(usize),
//     ContentType(ContType),
//     DacpId(u64),
//     RtpInfo(u32),
//     UserAgent(String),
//     Extension(String),
// }

// impl Key {
//     const ACTIVE_REMOTE: &str = "Active-Remote";
//     const CONTENT_LEN: &str = "Content-Length";
//     const CONTENT_TYPE: &str = "Content-Type";
//     const CSEQ: &str = "CSeq";
//     const DHCP_ID: &str = "DACP-ID";
//     const RTP_INFO: &str = "RTP-INFO";
//     const USER_AGENT: &str = "User-Agent";
// }

// impl FromStr for Key {
//     type Err = anyhow::Error;

//     fn from_str(src: &str) -> Result<Key> {
//         if let Some((k, v)) = src.trim().split_once(": ") {
//             match k {
//                 Self::ACTIVE_REMOTE => Ok(Self::ActiveRemote(v.parse()?)),
//                 Self::CONTENT_LEN => Ok(Self::ContentLength(v.parse()?)),
//                 Self::CONTENT_TYPE => Ok(Self::ContentType(ContType::from_str(v)?)),
//                 Self::CSEQ => Ok(Self::Cseq(v.parse()?)),
//                 Self::DHCP_ID => Ok(Self::DacpId(v.parse()?)),
//                 Self::RTP_INFO => {
//                     if let Some(("rtptime", rtp_time)) = v.split_once("=") {
//                         Ok(Self::RtpInfo(rtp_time.parse()?))
//                     } else {
//                         Err(anyhow!("bad RTP-Info: {v}"))
//                     }
//                 }
//                 Self::USER_AGENT => Ok(Self::UserAgent(v.into())),
//                 ext if ext.starts_with("X-") => Ok(Self::Extension(ext.into())),
//                 unknown => Err(anyhow!("unknown header key: {unknown}")),
//             }
//         } else {
//             Err(anyhow!("unknown content type: {src}"))
//         }
//     }
// }

// #[derive(Default, Debug, Clone, Eq, PartialEq)]
// pub struct List {
//     inner: Vec<Key>,
//     _priv: (),
// }

// impl List {
//     pub fn get_dacp_id(&self) -> Result<u64> {
//         let id = self.inner.iter().find(|k| matches!(k, Key::DacpId(_)));

//         if let Some(Key::DacpId(id)) = id {
//             return Ok(id.to_owned());
//         }

//         Err(anyhow!("DACP-ID missing"))
//     }
// }

// impl<'a> TryFrom<&'a str> for List {
//     type Error = anyhow::Error;

//     fn try_from(src: &'a str) -> Result<Self> {
//         let mut inner = Vec::<Key>::new();

//         for line in src.trim().lines() {
//             inner.push(Key::from_str(line)?);
//         }

//         if !inner.is_empty() {
//             Ok(List {
//                 inner,
//                 ..Self::default()
//             })
//         } else {
//             Err(anyhow!("empty header list"))
//         }
//     }
// }

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct Map {
    // inner: IndexMap<String, String>,
    inner: IndexMap<Key2, Val2>,
    _priv: (),
}

impl Map {
    // pub fn add(mut self, kv_pairs: &[(&str, &str)]) -> Self {
    //     for (k, v) in kv_pairs {
    //         self.inner.insert(Key2::from_str(k)?, v.to_string());
    //     }

    //     self
    // }

    // /// # Errors
    // ///
    // /// Will return `Err` if `filename` does not exist or the user does not have
    // /// permission to read it.
    // pub fn append(&mut self, src: &str) -> Result<()> {
    //     let parts = src.split_once(":");

    //     // if let Some(parts) = parts {
    //     //     match parts {
    //     //         ("", "") => Err(anyhow!("not a header: {src}")),
    //     //         (cat, detail) =>
    //     //     }
    //     // } else {
    //     //     Err(anyhow!("not a header: {}", src))
    //     // }

    //     if src.contains(':') {
    //         const MAX_PARTS: usize = 2;
    //         const KEY: usize = 0;
    //         const VAL: usize = 1;

    //         let p: ArrayVec<&str, 2> = src
    //             .split_ascii_whitespace()
    //             .map(|s| s.trim_end_matches(':'))
    //             .take(MAX_PARTS)
    //             .collect();

    //         self.inner.insert(p[KEY].into(), p[VAL].into());

    //         Ok(())
    //     } else {
    //         Err(anyhow!("not a header: {}", src))
    //     }
    // }

    #[must_use]
    pub fn content_len(&self) -> Option<&Val2> {
        let key = Key2::ContentLength;

        self.inner.get(&key)

        // if let Some(Val2::ContentLength(len)) = self.inner.get(&key) {
        //     return Some(len.to_owned());
        // }

        // None
    }

    #[allow(clippy::must_use_candidate)]
    pub fn headers(&self) -> &IndexMap<Key2, Val2> {
        &self.inner
    }

    #[allow(clippy::must_use_candidate)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[allow(clippy::must_use_candidate)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[must_use]
    pub fn new() -> Map {
        Map {
            inner: IndexMap::new(),
            _priv: (),
        }
    }
}

impl<'a> TryFrom<&'a str> for Map {
    type Error = anyhow::Error;

    fn try_from(src: &'a str) -> Result<Self> {
        let mut map = Map::new();

        for line in src.trim().lines() {
            if let Some((k, v)) = line.split_once(": ") {
                let key = Key2::from_str(k)?;
                let value = Val2::new(&key, v)?;

                map.inner.insert(key, value);
            }
        }

        if map.inner.is_empty() {
            Err(anyhow!("empty header list"))
        } else {
            Ok(map)
        }
    }
}

#[cfg(test)]
mod tests {

    use super::Map;
    // use crate::Result;

    const CONTENT_LEN_LINE: &str =
        "Content-Length: 30\r\nContent-Type: application/x-apple-binary-plist\r\n";

    #[test]
    fn can_create_map() {
        let res = Map::try_from(CONTENT_LEN_LINE);

        assert!(res.is_ok());
    }

    // #[test]
    // fn can_get_content_len_when_present() -> Result<()> {
    //     let mut hdr_map = Map::new();

    //     hdr_map.append(CONTENT_LEN_LINE)?;

    //     let len = hdr_map.content_len()?;

    //     assert_eq!(Some(30), len);

    //     Ok(())
    // }
}
