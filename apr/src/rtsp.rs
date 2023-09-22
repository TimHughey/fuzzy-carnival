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

pub(crate) mod method;
pub use method::Method;
pub mod codec;

pub(crate) mod header;
pub use header::List as HeaderList;

pub(crate) mod status;
use status::Code as StatusCode;

use crate::homekit::TagList;
use crate::{rtsp::header::ContType, FlagsCalc, HomeKit, HostInfo, Result};
use anyhow::anyhow;
use bstr::ByteSlice;
use bytes::{BufMut, BytesMut};
use plist;
use pretty_hex::PrettyHex;
use std::fmt;
use std::fmt::Write;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use tracing::{debug, error, info};

#[derive(Default, Debug, Clone, PartialEq)]
pub enum Body {
    Dict(plist::Dictionary),
    Bulk(Vec<u8>),
    Text(String),
    #[default]
    Empty,
}

impl Body {
    // const LENGTH: &str = "Content-Length";
    // const TYPE: &str = "Content-Type";

    // const APP_PLIST: &str = "application/x-apple-binary-plist";
}

impl fmt::Display for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Body::Bulk(bulk) => writeln!(f, "{:?}", PrettyHex::hex_dump(bulk)),
            Body::Dict(dict) => writeln!(f, "{dict:?}"),
            Body::Text(text) => writeln!(f, "{text}"),
            Body::Empty => writeln!(f, "<<EMPTY>>"),
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for Body {
    type Error = anyhow::Error;

    ///
    /// Errors:
    ///
    #[inline]
    fn try_from(raw: &'a [u8]) -> Result<Self> {
        const PLIST_HDR: &[u8; 6] = b"bplist";

        match raw {
            // detect and handle empty body
            r if r.is_empty() => Ok(Self::Empty),

            // detect and parse Apple Property List
            r if r.starts_with(PLIST_HDR) => {
                let pdict = Self::Dict(plist::from_bytes(r)?);

                Ok(pdict)
            }

            // detect and copy plain ascii text
            r if r.is_utf8() => {
                let text = r.to_str()?;

                Ok(Self::Text(text.into()))
            }

            // unknown or unhandled body
            r => Ok(Self::Bulk(r.into())),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Frame {
    pub method: Method,
    pub path: String,
    pub headers: header::List,
    pub body: Body,
}

impl Frame {
    const MIN_BYTES: usize = 80;
    const SPACE: char = ' ';
    const PROTOCOL: &str = "RTSP/1.0";

    /// # Errors
    ///
    /// Will return `Err` if content length value can not
    /// be parsed into a usize
    #[must_use]
    pub fn content_len(&self) -> Option<usize> {
        self.headers.content_length
    }

    #[must_use]
    pub fn debug_file(&self) -> Option<PathBuf> {
        const BASE_DIR: &str = "extra/ref/v2";
        let headers = &self.headers;

        match (&headers.dacp_id, &headers.active_remote, &headers.cseq) {
            (Some(dacp_id), Some(active_remote), Some(seq_num)) => {
                let mut path = PathBuf::from(BASE_DIR);

                path.push(dacp_id);
                path.push(format!("{active_remote}"));

                match fs::create_dir_all(&path) {
                    Ok(()) => {
                        let file = format!("{seq_num:<03}");
                        path.push(file);
                        path.set_extension("bin");

                        Some(path)
                    }

                    Err(e) => {
                        error!("failed to create path: {e:?}");
                        None
                    }
                }
            }
            (_, _, _) => None,
        }
    }

    #[must_use]
    pub fn min_bytes(cnt: usize) -> bool {
        cnt >= Self::MIN_BYTES
    }

    #[must_use]
    pub fn method_path(&self) -> (&Method, &str) {
        (&self.method, self.path.as_str())
    }

    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// # Errors
    ///
    /// May return error if body is not recognized
    ///
    pub fn include_body(&mut self, src: &[u8]) -> Result<()> {
        if let Some(len) = self.headers.content_length {
            self.body = Body::try_from(&src[0..len])?;
        }

        Ok(())
    }
}

impl<'a> TryFrom<&'a [u8]> for Frame {
    type Error = anyhow::Error;

    #[inline]
    fn try_from(buf: &'a [u8]) -> Result<Self> {
        let src = buf.to_str()?.trim_end();

        // split on the protocol to validate the version and remove the protocol
        // text from further comparisons
        let chunks = src.split_once(Self::PROTOCOL);

        match chunks {
            Some((request, rest)) => {
                // the first line is the request: METHOD PATH RTSP/1.0
                let line = request.split_once(Self::SPACE);

                // get the method and path
                if let Some((method, path)) = line {
                    return Ok(Self {
                        method: Method::from_str(method)?,
                        path: path.trim_end().to_owned(),
                        headers: header::List::try_from(rest)?,
                        ..Self::default()
                    });
                }

                Ok(Self::default())
            }
            None => Err(anyhow!("protocol version not found")),
        }
    }
}

impl fmt::Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "\n{} {} ", self.method, self.path)?;

        writeln!(f, "{}", self.headers)?;

        if self.body != Body::Empty {
            writeln!(f, "CONTENT {}", self.body)?;
        }

        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
pub struct Response {
    pub status_code: StatusCode,
    pub headers: header::List,
    pub body: Body,
}

impl Response {
    #[inline]
    #[must_use]
    pub fn has_body(&self) -> bool {
        !matches!(self.body, Body::Empty)
    }

    /// # Errors
    ///
    #[inline]
    pub fn extend_with_content_info(&self, dst: &mut BytesMut) -> Result<()> {
        let ctype = &self.headers.content_type;
        let clen = self.headers.content_length;

        if let (Some(ctype), Some(clen)) = (ctype, clen) {
            let avail = dst.capacity();
            info!("buf avail: {avail}");

            let ctype_key = header::Key2::ContentType.as_str();
            let ctype_val = ctype.as_str();
            let clen_key = header::Key2::ContentLength.as_str();

            let res = write!(
                dst,
                "\
                {ctype_key}: {ctype_val}\r\n\
                {clen_key}: {clen}\r\n\
                \r\n\
                "
            );

            return Ok(res?);
        }

        Err(anyhow!("no content type or length"))
    }

    /// # Errors
    ///
    pub fn respond_to(frame: Frame) -> Result<Response> {
        match frame {
            Frame {
                method: Method::GET,
                path,
                headers,
                body: Body::Dict(dict),
                ..
            } if path.as_str() == "/info" && dict.contains_key("qualifier") => {
                use plist::Dictionary;
                use plist::Value::Integer as ValInt;
                use plist::Value::String as ValString;

                let xml = include_bytes!("../plists/get_info_resp.plist");
                let dict: Dictionary = plist::from_bytes(xml)?;

                let dict = [
                    ("features", ValInt(FlagsCalc::features_as_u64().into())),
                    ("statusFlags", ValInt(FlagsCalc::status_as_u32().into())),
                    ("deviceID", ValString(HostInfo::id_as_str().into())),
                    ("pi", ValString(HostInfo::id_as_str().into())),
                    ("name", ValString(HostInfo::receiver_as_str().into())),
                    ("model", ValString("Hughey".into())),
                ]
                .into_iter()
                .fold(dict, |mut acc, (k, v)| {
                    acc.insert(k.to_string(), v);
                    acc
                });

                let binary = BytesMut::with_capacity(4096);
                let mut writer = binary.writer();
                plist::to_writer_binary(&mut writer, &dict)?;
                let binary = writer.into_inner();

                Ok(Response {
                    status_code: StatusCode::OK,
                    headers: header::List::make_response(
                        headers,
                        ContType::AppAppleBinaryPlist,
                        binary.len(),
                    ),
                    body: Body::Bulk(binary.into()),
                })
            }

            Frame {
                method: Method::POST,
                path,
                headers,
                body: Body::Bulk(bulk),
                ..
            } if path.as_str().starts_with("/pair-") => {
                let buf: BytesMut = BytesMut::from(bulk.as_slice());

                debug!("buf: {:?}", buf.hex_dump());
                let tlv_list = TagList::try_from(buf)?;

                debug!("parsed tlv list:\n{tlv_list:?}");

                if tlv_list.len_ne(2) {
                    return Err(anyhow!("expected tlv list"));
                }

                HomeKit::handle_request(headers.clone(), &tlv_list, path.as_str())?;

                Ok(Response {
                    status_code: StatusCode::OK,
                    headers: header::List::make_response(headers, ContType::AppOctetStream, 0),
                    body: Body::Bulk(Vec::with_capacity(10)),
                })
            }

            Frame {
                method,
                path,
                headers,
                body,
                ..
            } => {
                info!("got {method} {path} \n{headers:?}\n{body}");
                Err(anyhow!("unhandled frame"))
            }
        }
    }
}

impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.status_code)?;
        writeln!(f, "headers: {:?}", self.headers)?;
        writeln!(f, "{}", self.body)
    }
}
