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
use once_cell::sync::OnceCell;
use std::{
    fmt::{self, Debug},
    fs,
    path::PathBuf,
    str::FromStr,
};
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

    debug_path: OnceCell<PathBuf>,
    dump_path: Option<PathBuf>,
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

    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    pub fn debug_file_path(&self, kind: &str) -> Result<PathBuf> {
        let cseq = self.cseq.as_ref().ok_or(anyhow!("CSeq is missing"))?;
        let file_name = format!("{cseq:03}-{kind}.bin");

        Ok(self
            .debug_path
            .get_or_try_init(|| self.make_debug_path())?
            .with_file_name(file_name))
    }

    pub fn dump_path(&self) -> Option<PathBuf> {
        self.dump_path.clone()
    }

    fn make_debug_path(&self) -> Result<PathBuf> {
        use std::env::var;

        const KEY: &str = "CARGO_MANIFEST_DIR";
        let path: PathBuf = var(KEY).map_err(|e| anyhow!(e))?.into();
        let mut path = path.parent().unwrap().to_path_buf();

        path.push("extra/ref/v2");

        if let List {
            dacp_id: Some(dacp_id),
            active_remote: Some(active_remote),
            ..
        } = &self
        {
            path.push(dacp_id);
            path.push(format!("{active_remote}"));

            fs::create_dir_all(&path)?;

            // this is replaced by with_filename
            path.push("unset.bin");

            return Ok(path);
        }

        Err(anyhow!("failed to create debug path"))
    }

    fn make_dump_path(&mut self) -> Result<()> {
        use std::env::var;

        const KEY: &str = "CARGO_MANIFEST_DIR";
        let path: PathBuf = var(KEY).map_err(|e| anyhow!(e))?.into();
        let mut path = path.parent().unwrap().to_path_buf();

        path.push("extra/ref/v2");

        if let List {
            dacp_id: Some(dacp_id),
            active_remote: Some(active_remote),
            ..
        } = &self
        {
            path.push(dacp_id);
            path.push(active_remote.to_string());

            fs::create_dir_all(&path)?;

            self.dump_path = Some(path);

            return Ok(());
        }

        Err(anyhow!("failed to create dump path"))
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

    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if the key passed
    /// does not match a known or extended header "X-*".
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
            k => error!("unhandled header: {k} {v}"),
        }

        self
    }
}

impl<'a> TryFrom<&'a str> for List {
    type Error = anyhow::Error;

    fn try_from(src: &'a str) -> Result<Self> {
        const DELIMITER: &str = ": ";

        let init = List::default();

        let mut list = src
            .trim()
            .lines()
            .filter_map(|l| l.split_once(DELIMITER))
            .fold(init, |acc, (k, v)| acc.push(k, v));

        if list.cseq.is_none() {
            return Err(anyhow!("CSeq not found: {src}"));
        }

        list.make_dump_path()?;

        Ok(list)
    }
}

impl TryFrom<BytesMut> for List {
    type Error = anyhow::Error;

    fn try_from(buf: BytesMut) -> Result<Self> {
        const DELIMITER: &str = ": ";

        let init = List::default();

        let src = buf.to_str()?;

        let mut list = src
            .trim()
            .lines()
            .filter_map(|l| l.split_once(DELIMITER))
            .fold(init, |acc, (k, v)| acc.push(k, v));

        if list.cseq.is_none() {
            return Err(anyhow!("CSeq not found: {src}"));
        }

        list.make_dump_path()?;

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
    // use crate::Result;

    const CONTENT_LEN_LINE: &str =
        "CSeq: 1\r\nContent-Length: 30\r\nContent-Type: application/x-apple-binary-plist\r\n";

    #[test]
    fn can_create_map() {
        let res = List::try_from(CONTENT_LEN_LINE);

        assert!(res.is_ok());
    }
}
