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
use bstr::ByteSlice;
use bytes::BytesMut;
use num_traits::clamp_max;
use once_cell::sync::Lazy;
use plist::Dictionary;
use pretty_hex::PrettyHex;
use std::{collections::hash_map::RandomState, hash::BuildHasher, str};

const PROTO: &[u8] = b"RTSP/1.0";

pub struct ContentMatch {
    pub kind_hash: u64,
    pub len_hash: u64,
    pub kind: &'static [u8],
    pub type_match: &'static [u8],
    pub len: &'static [u8],
    pub len_match: &'static [u8],
    pub hasher: RandomState,
}

impl ContentMatch {
    #[inline]
    fn hash(hasher: &RandomState, src: &[u8]) -> u64 {
        let n = src.len();
        let selected: [u8; 4] = [src[0], src[n - 1], src[n - 2], src[n - 3]];
        hasher.hash_one(selected)
    }

    #[inline]
    pub fn is_kind(&self, src: &[u8]) -> bool {
        src.len() == self.kind.len() && Self::hash(&self.hasher, src) == self.kind_hash
    }

    #[inline]
    pub fn is_len(&self, src: &[u8]) -> bool {
        src.len() == self.len.len() && Self::hash(&self.hasher, src) == self.len_hash
    }

    #[inline]
    pub fn get() -> &'static Lazy<ContentMatch> {
        &CONTENT_MATCH
    }
}

static CONTENT_MATCH: Lazy<ContentMatch> = Lazy::new(|| {
    const KIND: &[u8] = b"Content-Type";
    const LENGTH: &[u8] = b"Content-Length";
    let hasher = RandomState::new();

    ContentMatch {
        kind_hash: ContentMatch::hash(&hasher, KIND),
        len_hash: ContentMatch::hash(&hasher, LENGTH),
        kind: KIND,
        type_match: &KIND[(KIND.len() - 6)..],
        len: LENGTH,
        len_match: &LENGTH[(LENGTH.len() - 3)..],
        hasher,
    }
});

#[derive(Default)]
pub struct Content {
    pub cseq: u32,
    pub kind: String,
    pub len: usize,
    pub data: BytesMut,
}

impl Content {
    pub fn check_complete(&self) -> Result<bool> {
        if self.kind.is_empty() {
            let error = "content kind is empty";
            tracing::error!("{error}");
            return Err(anyhow!("{error}"));
        }

        let content_len = self.len;
        let data_len: usize = self.data.len();

        if content_len == data_len {
            Ok(true)
        } else {
            tracing::debug!("length mismatch: content={content_len} != data={data_len}");
            Ok(false)
        }
    }

    pub fn get_dict(&self) -> Result<Option<plist::Dictionary>> {
        if self.kind.ends_with("binary-plist") {
            if let Some(dict) = plist::from_bytes::<plist::Value>(&self.data)?.as_dictionary() {
                return Ok(Some(dict.clone()));
            }
        }

        Ok(None)
    }

    pub fn into_data(self) -> BytesMut {
        self.data
    }

    pub fn new_binary_plist(cseq: u32, dict: &Dictionary) -> Result<Self> {
        use bytes::BufMut;

        let mut this = Self::default();
        let buf = &mut this.data;
        plist::to_writer_binary(buf.writer(), &dict)?;

        Ok(Self {
            cseq,
            kind: "application/x-apple-binary-plist".into(),
            len: buf.len(),
            ..this
        })
    }

    pub fn new_octet_stream(cseq: u32, src: &[u8]) -> Self {
        let data = BytesMut::from(src);

        Self {
            cseq,
            kind: "application/octet-stream".into(),
            len: data.len(),
            data,
        }
    }

    pub fn new_text(cseq: u32, src: &str) -> Self {
        Self {
            cseq,
            kind: "text/parameters".into(),
            len: src.len(),
            data: BytesMut::from(src),
        }
    }

    pub fn want_bytes(&self, avail: usize) -> Option<usize> {
        if avail > 0 {
            let need_len = self.len;
            let have_len = self.data.len();

            if let Some(needed) = need_len.checked_sub(have_len) {
                let take = clamp_max(needed, avail);

                return Some(take);
            }
        }

        // either we don't need anymore buyes or there aren't
        None
    }
}

impl AsRef<[u8]> for Content {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl From<u32> for Content {
    fn from(cseq: u32) -> Self {
        Self {
            cseq,
            ..Self::default()
        }
    }
}

impl TryFrom<Option<u32>> for Content {
    type Error = anyhow::Error;

    fn try_from(maybe_cseq: Option<u32>) -> Result<Self> {
        if let Some(cseq) = maybe_cseq {
            return Ok(Self {
                cseq,
                ..Self::default()
            });
        }

        let error = "can not create Content with Cseq";
        tracing::error!("{error}");
        Err(anyhow!(error))
    }
}

impl TryInto<plist::Value> for Content {
    type Error = anyhow::Error;

    fn try_into(self) -> std::result::Result<plist::Value, Self::Error> {
        const HDR: &[u8] = b"bplist00";

        if self.data.starts_with(HDR) {
            let parsed: plist::Value = plist::from_bytes(&self.data)?;

            return Ok(parsed);
        }

        let error = "unable to convert content to plist";
        tracing::error!("{error}\nDATA {:?}", self.data.hex_dump());
        Err(anyhow!(error))
    }
}

impl std::fmt::Display for Content {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "\nCONTENT {} {:?}", self.kind, self.data.hex_dump())
    }
}

impl std::fmt::Debug for Content {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "\nCONTENT {} {:?}", self.kind, self.data.hex_dump())
    }
}

const META_ACTIVE_REMOTE: &str = "Active-Remote";
const META_DACPD_ID: &str = "DACP-ID";
const META_RTP_INFO: &str = "RTP-INFO";
const META_USER_AGENT: &str = "User-Agent";

#[derive(Debug, Default)]
pub struct MetaData {
    pub active_remote: Option<u32>,
    pub dacpd_id: Option<String>,
    pub rtp_info: Option<u32>,
    pub user_agent: Option<String>,
    pub extensions: Vec<(String, String)>,
}

impl MetaData {
    pub fn push_from_slice(&mut self, desc: &[u8], field: &[u8]) -> Result<()> {
        const L0: usize = META_ACTIVE_REMOTE.len();
        const L1: usize = META_DACPD_ID.len();
        const L2: usize = META_RTP_INFO.len();
        const L3: usize = META_USER_AGENT.len();
        const X_DESC: &str = "X-";

        let desc = desc.to_str()?;
        let field = field.to_str()?.trim();

        match desc.len() {
            L0 if desc.ends_with(&META_ACTIVE_REMOTE[(L0 - 4)..]) => {
                self.active_remote.get_or_insert(field.parse()?);
            }
            L1 if desc[(L1 - 4)..] == META_DACPD_ID[(L1 - 4)..] => {
                self.dacpd_id.get_or_insert(field.into());
            }
            L2 if desc[(L2 - 4)..] == META_RTP_INFO[(L2 - 4)..] => {
                self.rtp_info = make_rtptime(field);
            }
            L3 if desc[(L3 - 2)..] == META_USER_AGENT[(L3 - 2)..] => {
                self.user_agent.get_or_insert(field.into());
            }
            _len if desc.starts_with(X_DESC) => {
                self.extensions.push((desc.to_string(), field.to_string()));
            }
            _len => {
                let error = "unrecognized header";
                tracing::error!("{error}: [{desc}] [{field}]");
                return Err(anyhow!("{error}"));
            }
        }

        Ok(())
    }
}

fn make_rtptime(v: &str) -> Option<u32> {
    if let Some(("rtptime", rtptime)) = v.split_once('=') {
        return rtptime.parse::<u32>().ok();
    }

    None
}

impl std::fmt::Display for MetaData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for tuple in [
            (META_ACTIVE_REMOTE, self.active_remote.as_ref()),
            (META_RTP_INFO, self.rtp_info.as_ref()),
        ] {
            if let (desc, Some(field)) = tuple {
                writeln!(f, "{desc}: {field}").ok();
            }
        }

        for tuple in [
            (META_DACPD_ID, self.dacpd_id.as_ref()),
            (META_USER_AGENT, self.user_agent.as_ref()),
        ] {
            if let (desc, Some(field)) = tuple {
                writeln!(f, "{desc}: {field}").ok();
            }
        }

        self.extensions.iter().for_each(|(desc, field)| {
            writeln!(f, "{desc}: {field}").ok();
        });

        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
pub struct Routing {
    method: String,
    path: String,
}

impl Routing {
    pub fn is_rtsp(&self) -> bool {
        self.path.starts_with("rtsp")
    }

    pub fn method_cloned(&self) -> String {
        self.method.clone()
    }

    #[allow(unused)]
    pub fn parts_tuple(&self) -> (String, String) {
        (self.method.clone(), self.path.clone())
    }

    pub fn please_log(&self) -> bool {
        !self.path.ends_with("feedback")
    }
}

impl TryFrom<&[u8]> for Routing {
    type Error = anyhow::Error;

    fn try_from(buf: &[u8]) -> Result<Self> {
        let idx = buf.find_char(' ').ok_or_else(|| {
            tracing::warn!("space delimiter not found:\nBUF {:?}", buf.hex_dump());

            anyhow!("method and/or path not found")
        })?;

        let (method, path) = buf.split_at(idx);
        let path = path
            .strip_suffix(PROTO)
            .ok_or_else(|| anyhow!("PROTOCOL not found"))?
            .trim();

        Ok(Self {
            method: method.to_str()?.into(),
            path: path.to_str()?.into(),
        })
    }
}

impl std::fmt::Display for Routing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.method.as_str(), self.path)
    }
}
