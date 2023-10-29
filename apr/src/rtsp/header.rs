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

use crate::{rtsp::Body, Result};
use anyhow::anyhow;
use bstr::ByteSlice;
use bytes::BytesMut;
use std::{
    fmt::{self, Debug},
    str::FromStr,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ContType {
    AppDMapTagged,
    AppAppleBinaryPlist,
    AppOctetStream,
    TextParameters,
    PeerListChanged,
    PeerListChangedX,
    ImageNone,
}

impl ContType {
    const BINARY_PLIST: &str = "application/x-apple-binary-plist";
    const DMAP_TAGGED: &str = "application/x-dmap-tagged";
    const OCTET_STREAM: &str = "application/octet-stream";
    const TEXT_PARAMS: &str = "text/parameters";
    const PEER_LIST_CHANGED_X: &str = "/peer-list-changed-x";
    const PEER_LIST_CHANGED: &str = "/peer-list-changed";
    const IMAGE_NONE: &str = "image/none";

    const BINARY_PLIST_LEN: usize = Self::BINARY_PLIST.len();
    const DMAP_TAGGED_LEN: usize = Self::DMAP_TAGGED.len();
    const OCTET_STREAM_LEN: usize = Self::OCTET_STREAM.len();
    const TEXT_PARAMS_LEN: usize = Self::TEXT_PARAMS.len();
    const PEER_LIST_LEN: usize = Self::PEER_LIST_CHANGED.len();
    const PEER_LIST_X_LEN: usize = Self::PEER_LIST_CHANGED_X.len();
    const IMAGE_NONE_LEN: usize = Self::IMAGE_NONE.len();

    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::AppAppleBinaryPlist => Self::BINARY_PLIST,
            Self::AppDMapTagged => Self::DMAP_TAGGED,
            Self::AppOctetStream => Self::OCTET_STREAM,
            Self::TextParameters => Self::TEXT_PARAMS,
            Self::PeerListChanged => Self::PEER_LIST_CHANGED,
            Self::PeerListChangedX => Self::PEER_LIST_CHANGED_X,
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
        use ContType::{
            AppAppleBinaryPlist, AppDMapTagged, AppOctetStream, ImageNone, PeerListChanged,
            PeerListChangedX, TextParameters,
        };

        Ok(match src.len() {
            Self::BINARY_PLIST_LEN if src.ends_with("plist") => AppAppleBinaryPlist,
            Self::DMAP_TAGGED_LEN if src.ends_with("tagged") => AppDMapTagged,
            Self::OCTET_STREAM_LEN if src.ends_with("stream") => AppOctetStream,
            Self::TEXT_PARAMS_LEN if src.ends_with("meters") => TextParameters,
            Self::PEER_LIST_LEN if src.ends_with("changed") => PeerListChanged,
            Self::PEER_LIST_X_LEN if src.ends_with("changed-x") => PeerListChangedX,
            Self::IMAGE_NONE_LEN if src.ends_with("none") => ImageNone,
            _ => {
                tracing::error!("unknown content type: {src}");
                return Err(anyhow!("unknown content type: {src}"));
            }
        })
    }
}

impl fmt::Display for ContType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
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
        Ok(match src {
            Self::ACTIVE_REMOTE => Self::ActiveRemote,
            Self::CONTENT_LEN => Self::ContentLength,
            Self::CONTENT_TYPE => Self::ContentType,
            Self::CSEQ => Self::Cseq,
            Self::DACP_ID => Self::DacpId,
            Self::RTP_INFO => Self::RtpInfo,
            Self::USER_AGENT => Self::UserAgent,
            ext if ext.starts_with("X-") => Self::Extension(ext.into()),
            unknown => return Err(anyhow!("unknown header key: {unknown}")),
        })
    }
}

impl fmt::Display for Key2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Default)]
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
    /// Returns the content len of this [`List`].
    ///
    /// # Panics
    ///
    /// Panics if .
    #[must_use]
    pub fn content_len(&self) -> usize {
        self.content_length.unwrap()
    }

    #[must_use]
    pub fn cseq(&self) -> Option<u32> {
        self.cseq
    }

    #[must_use]
    pub fn make_response(self, ctype: ContType, len: usize) -> Self {
        List {
            active_remote: None,
            content_length: Some(len),
            content_type: Some(ctype),
            dacp_id: None,
            rtp_info: None,
            user_agent: None,
            extensions: Vec::new(),
            ..self
        }
    }

    #[must_use]
    pub fn make_response_no_body(self) -> Self {
        Self {
            active_remote: None,
            content_length: None,
            content_type: None,
            dacp_id: None,
            rtp_info: None,
            user_agent: None,
            extensions: Vec::new(),
            ..self
        }
    }

    /// Create RTSP response from the given [Body]
    ///
    /// # Errors
    ///
    /// This function will return an error if [Body] length
    /// can not be determined.
    pub fn make_response2(self, body: &Body) -> Result<Self> {
        use Body::{Bulk, Dict, Empty, OctetStream, Text};

        let ctype = match body {
            Bulk(_) | OctetStream(_) => Some(ContType::AppOctetStream),
            Text(_) => Some(ContType::TextParameters),
            Dict(_) => Some(ContType::AppAppleBinaryPlist),
            Empty => None,
        };

        Ok(List {
            active_remote: None,
            content_length: Some(body.len()?),
            content_type: ctype,
            dacp_id: None,
            rtp_info: None,
            user_agent: None,
            extensions: Vec::new(),
            ..self
        })
    }

    #[must_use]
    pub fn push(mut self, k: &str, v: &str) -> Self {
        match k {
            Key2::ACTIVE_REMOTE => self.active_remote = v.parse().ok(),
            Key2::CSEQ => self.cseq = v.parse().ok(),
            Key2::CONTENT_LEN => self.content_length = v.parse().ok(),
            Key2::CONTENT_TYPE => self.content_type = ContType::from_str(v).ok(),
            Key2::DACP_ID => self.dacp_id = Some(v.to_ascii_lowercase()),
            Key2::RTP_INFO => self.rtp_info = make_rtptime(v),
            Key2::USER_AGENT => self.user_agent = Some(v.into()),

            k if k.starts_with("X-") => self.extensions.push((k.into(), v.into())),
            k => tracing::error!("unhandled header: {k} {v}"),
        }

        self
    }

    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if the key passed
    /// does not match a known or extended header "X-*".
    pub fn push_kv(&mut self, k: &str, v: &str) -> Result<()> {
        match k {
            Key2::ACTIVE_REMOTE => self.active_remote = v.parse().ok(),
            Key2::CSEQ => self.cseq = v.parse().ok(),
            Key2::CONTENT_LEN => self.content_length = v.parse().ok(),
            Key2::CONTENT_TYPE => self.content_type = ContType::from_str(v).ok(),
            Key2::DACP_ID => self.dacp_id = Some(v.to_ascii_lowercase()),
            Key2::RTP_INFO => self.rtp_info = make_rtptime(v),
            Key2::USER_AGENT => self.user_agent = Some(v.into()),

            k if k.starts_with("X-") => self.extensions.push((k.into(), v.into())),
            k => {
                tracing::error!("unhandled header: {k} {v}");
                return Err(anyhow!("unrecognized header key/val"));
            }
        }

        Ok(())
    }

    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    pub fn push_from_slice(&mut self, buf: &[u8]) -> Result<()> {
        if let Some((s0, s1)) = buf.to_str()?.split_once(':') {
            let k = s0.trim();
            let v = s1.trim();

            self.push_kv(k, v)?;
            return Ok(());
        }

        Err(anyhow!("not a header key/val slice"))
    }
}

impl<'a> TryFrom<&'a str> for List {
    type Error = anyhow::Error;

    fn try_from(src: &'a str) -> Result<Self> {
        const DELIMITER: &str = ": ";

        let init = List::default();

        let list = src
            .trim()
            .lines()
            .filter_map(|l| l.split_once(DELIMITER))
            .fold(init, |acc, (k, v)| acc.push(k, v));

        if list.cseq.is_none() {
            return Err(anyhow!("CSeq not found: {src}"));
        }

        Ok(list)
    }
}

impl TryFrom<BytesMut> for List {
    type Error = anyhow::Error;

    fn try_from(buf: BytesMut) -> Result<Self> {
        const DELIMITER: &str = ": ";

        let init = List::default();

        let src = buf.to_str()?;

        let list = src
            .trim()
            .lines()
            .filter_map(|l| l.split_once(DELIMITER))
            .fold(init, |acc, (k, v)| acc.push(k, v));

        if list.cseq.is_none() {
            return Err(anyhow!("CSeq not found: {src}"));
        }

        Ok(list)
    }
}

impl fmt::Display for List {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(active_remote) = self.active_remote.as_ref() {
            fmt.write_fmt(format_args!("{}: {active_remote}\n", Key2::ACTIVE_REMOTE))?;
        }

        if let Some(cseq) = self.cseq.as_ref() {
            fmt.write_fmt(format_args!("{}: {cseq}\n", Key2::CSEQ))?;
        }

        if let Some(x) = self.content_length.as_ref() {
            fmt.write_fmt(format_args!("{}: {x}\n", Key2::CONTENT_LEN))?;
        }

        if let Some(x) = self.content_type.as_ref() {
            fmt.write_fmt(format_args!("{}: {x}\n", Key2::CONTENT_TYPE))?;
        }

        if let (key, Some(x)) = (Key2::DACP_ID, self.dacp_id.as_ref()) {
            fmt.write_fmt(format_args!("{key}: {x}\n"))?;
        }

        if let (key, Some(x)) = (Key2::RTP_INFO, self.rtp_info.as_ref()) {
            fmt.write_fmt(format_args!("{key}: {x}\n"))?;
        }

        if let (key, Some(x)) = (Key2::USER_AGENT, self.user_agent.as_ref()) {
            fmt.write_fmt(format_args!("{key}: {x}\n"))?;
        }

        for (key, val) in &self.extensions {
            fmt.write_fmt(format_args!("{}: {}\n", key.as_str(), val.as_str()))?;
        }

        Ok(())
    }
}

fn make_rtptime(v: &str) -> Option<u64> {
    if let Some(("rtptime", rtptime)) = v.split_once('=') {
        return rtptime.parse::<u64>().ok();
    }

    None
}

#[cfg(test)]
mod tests {

    use super::List;

    const CONTENT_LEN_LINE: &str =
        "CSeq: 1\r\nContent-Length: 30\r\nContent-Type: application/x-apple-binary-plist\r\n";

    #[test]
    fn can_create_map() {
        let res = List::try_from(CONTENT_LEN_LINE);

        assert!(res.is_ok());
    }
}
