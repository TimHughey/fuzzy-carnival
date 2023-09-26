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
use std::fmt::{self, Debug};
use std::str::FromStr;
use tracing::error;

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

    #[must_use]
    pub fn as_str(&self) -> &str {
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

impl AsRef<str> for ContType {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
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
    const DACP_ID: &str = "DACP-ID";
    const RTP_INFO: &str = "RTP-INFO";
    const USER_AGENT: &str = "User-Agent";

    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::ActiveRemote => Self::ACTIVE_REMOTE,
            Self::Cseq => Self::CSEQ,
            Self::ContentLength => Self::CONTENT_LEN,
            Self::ContentType => Self::CONTENT_TYPE,
            Self::DacpId => Self::DACP_ID,
            Self::RtpInfo => Self::RTP_INFO,
            Self::UserAgent => Self::USER_AGENT,
            Self::Extension(ext) => ext.as_str(),
        }
    }
}

impl AsRef<str> for Key2 {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for Key2 {
    type Err = anyhow::Error;

    fn from_str(src: &str) -> Result<Key2> {
        match src {
            Self::ACTIVE_REMOTE => Ok(Self::ActiveRemote),
            Self::CONTENT_LEN => Ok(Self::ContentLength),
            Self::CONTENT_TYPE => Ok(Self::ContentType),
            Self::CSEQ => Ok(Self::Cseq),
            Self::DACP_ID => Ok(Self::DacpId),
            Self::RTP_INFO => Ok(Self::RtpInfo),
            Self::USER_AGENT => Ok(Self::UserAgent),
            ext if ext.starts_with("X-") => Ok(Self::Extension(ext.into())),
            unknown => Err(anyhow!("unknown header key: {unknown}")),
        }
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct List {
    pub active_remote: Option<u32>,
    pub cseq: Option<u32>,
    pub content_length: Option<usize>,
    pub content_type: Option<ContType>,
    pub dacp_id: Option<String>,
    rtp_info: Option<u64>,
    user_agent: Option<String>,
    extensions: Vec<(String, String)>,
}

impl List {
    #[must_use]
    pub fn make_response(self, content: ContType, content_len: usize) -> Self {
        List {
            active_remote: None,
            content_length: Some(content_len),
            content_type: Some(content),
            dacp_id: None,
            rtp_info: None,
            user_agent: None,
            extensions: Vec::new(),
            ..self
        }
    }

    /// Returns the content len of this [`List`].
    ///
    /// # Panics
    ///
    /// Panics if .
    #[must_use]
    pub fn content_len(&self) -> usize {
        self.content_length.unwrap()
    }
}

impl<'a> TryFrom<&'a str> for List {
    type Error = anyhow::Error;

    fn try_from(src: &'a str) -> Result<Self> {
        let list = src
            .trim()
            .lines()
            .fold(List::default(), |mut acc: List, line| {
                if let Some((k, v)) = line.split_once(": ") {
                    match k {
                        Key2::ACTIVE_REMOTE => List {
                            active_remote: v.parse().ok(),
                            ..acc
                        },

                        Key2::CSEQ => List {
                            cseq: v.parse().ok(),
                            ..acc
                        },

                        Key2::CONTENT_LEN => List {
                            content_length: v.parse().ok(),
                            ..acc
                        },

                        Key2::CONTENT_TYPE => List {
                            content_type: ContType::from_str(v).ok(),
                            ..acc
                        },

                        Key2::DACP_ID => List {
                            dacp_id: Some(v.to_ascii_lowercase()),
                            ..acc
                        },

                        Key2::RTP_INFO => {
                            if let Some(("rtptime", rptime)) = v.split_once('=') {
                                List {
                                    rtp_info: rptime.parse().ok(),
                                    ..acc
                                }
                            } else {
                                acc
                            }
                        }

                        Key2::USER_AGENT => List {
                            user_agent: Some(v.to_string()),
                            ..acc
                        },

                        k if k.starts_with("X-") => {
                            acc.extensions.push((k.to_string(), v.to_string()));

                            acc
                        }

                        _k => {
                            error!("unhandled header: {line}");
                            acc
                        }
                    }
                } else {
                    acc
                }
            });

        if list.cseq.is_some() {
            Ok(list)
        } else {
            Err(anyhow!("failed to parse: {src}"))
        }
    }
}

impl fmt::Display for List {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(active_remote) = self.active_remote {
            writeln!(fmt, "{}: {active_remote}", Key2::ACTIVE_REMOTE)?;
        }

        if let Some(cseq) = self.cseq {
            writeln!(fmt, "{}: {cseq}", Key2::CSEQ)?;
        }

        if let Some(content_len) = self.content_length {
            writeln!(fmt, "{}: {content_len}", Key2::CONTENT_LEN)?;
        }

        if let Some(content_type) = &self.content_type {
            writeln!(fmt, "{}: {}", Key2::CONTENT_TYPE, content_type.as_str())?;
        }

        if let Some(dacp_id) = &self.dacp_id {
            writeln!(fmt, "{}: {dacp_id}", Key2::DACP_ID)?;
        }

        if let Some(rtp_info) = self.rtp_info {
            writeln!(fmt, "{}: {rtp_info}", Key2::DACP_ID)?;
        }

        if let Some(user_agent) = &self.user_agent {
            writeln!(fmt, "{}: {user_agent}", Key2::USER_AGENT)?;
        }

        for (key, val) in &self.extensions {
            writeln!(fmt, "{key}: {val}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::List;
    // use crate::Result;

    const CONTENT_LEN_LINE: &str =
        "Content-Length: 30\r\nContent-Type: application/x-apple-binary-plist\r\n";

    #[test]
    fn can_create_map() {
        let res = List::try_from(CONTENT_LEN_LINE);

        assert!(res.is_ok());
    }
}
