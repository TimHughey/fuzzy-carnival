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
pub(crate) mod msg;
pub(crate) mod status;

use crate::{HomeKit, Result};
use anyhow::anyhow;
use bytes::BytesMut;
pub use header::ContType as HeaderContType;
pub use header::List as HeaderList;
pub use msg::Body;
pub use msg::Frame;
pub use status::Code as StatusCode;
use std::fmt;
use std::fmt::Write;
use tracing::{debug, error};

pub struct Response {
    pub status_code: StatusCode,
    pub headers: header::List,
    pub body: Body,
    pub homekit: Option<HomeKit>,
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
        let ctype = self.headers.content_type.as_ref();
        let clen = self.headers.content_length.as_ref();

        if let (Some(ctype), Some(clen)) = (ctype, clen) {
            let avail = dst.capacity();
            debug!("buf avail: {avail}");

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

    /// Creates a response for RTSP messages
    ///
    /// # Panics
    ///
    /// Panics if `HomeKit` option is `None`
    ///
    /// # Errors
    ///
    /// This function will return an error if a response can not be created.
    pub fn respond_to(frame: Frame) -> Result<Response> {
        use crate::homekit;

        let method = frame.method;
        let path = frame.path.as_str();

        match (method, path) {
            // first request, general info (does not use homekit)
            (Method::GET, "/info") => homekit::info::response(frame),

            (Method::POST, path) if path.starts_with("/pair-") => homekit::respond_to(frame),

            (method, path) => {
                error!("unhandled {method} {path}");
                Err(anyhow!("Response unhandled {method} {path}"))
            }
        }
    }

    /// Returns the `HomeKit` from this [`Response`].
    pub fn take_homekit(&mut self) -> Option<HomeKit> {
        self.homekit.take()
    }

    /// Move `HomeKit` into `Response` and wrap in `Result`
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    #[inline]
    pub fn wrap_ok(self, homekit: HomeKit) -> Result<Self> {
        Ok(Self {
            homekit: Some(homekit),
            ..self
        })
    }
}

impl Default for Response {
    fn default() -> Self {
        Self {
            status_code: StatusCode::OK,
            headers: HeaderList::default(),
            body: Body::Empty,
            homekit: None,
        }
    }
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status_code = &self.status_code;
        let headers = &self.headers;
        let body = &self.body;
        let homekit = if self.homekit.is_some() {
            "HOMEKIT"
        } else {
            ""
        };

        f.write_fmt(format_args!("{status_code} {homekit}\n{headers}{body}"))
    }
}

impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status_code = &self.status_code;
        let headers = &self.headers;
        let body = &self.body;

        f.write_fmt(format_args!("{status_code}\n{headers}\n{body:?}"))
    }
}
