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

use crate::{
    rtsp::{Body, Frame, Response},
    HostInfo, Result,
};
use anyhow::anyhow;
use bytes::BytesMut;
use std::fmt;

pub mod auth;
pub mod cipher;
pub mod fairplay;
pub mod helper;
pub mod info;
pub mod setup;
pub mod srp;
pub mod states;
pub mod tags;

#[cfg(test)]
pub(crate) mod tests;

pub use auth::setup::Context as SetupCtx;
pub use auth::verify::Context as VerifyCtx;
pub use cipher::BlockLen;
pub use cipher::Context as CipherCtx;
pub use cipher::Lock as CipherLock;
pub use fairplay as Fairplay;
use setup as Setup;
pub use srp::Server as SrpServer;
pub use states::Generic as GenericState;
pub use states::Verify as VerifyState;
pub use tags::Idx as TagIdx;
pub use tags::Map as Tags;
pub use tags::Val as TagVal;

pub struct Context {
    pub device_id: Vec<u8>,
    pub setup: SetupCtx,
    pub verify: VerifyCtx,
    pub encrypted: bool,
    pub cipher: Option<CipherCtx>,
}

pub use Context as HomeKit;

unsafe impl Send for HomeKit {}

impl fmt::Debug for HomeKit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "HomeKit")
    }
}

impl HomeKit {
    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if unable to
    /// generate security `Seed` or `KeyPair`.
    #[must_use]
    pub fn build() -> Self {
        let mut id_buf = BytesMut::with_capacity(64);
        id_buf.extend_from_slice(HostInfo::id_as_slice());

        let device_id = id_buf.freeze();

        tracing::debug!("\nDEVICE ID {:?}", pretty_hex::pretty_hex(&device_id));

        Self {
            device_id: device_id.into(),
            setup: SetupCtx::build(),
            verify: VerifyCtx::build(),
            encrypted: false,
            cipher: None,
        }
    }

    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    pub fn respond_to(&mut self, frame: Frame) -> Result<Response> {
        use crate::rtsp::Method;

        let (method, path) = frame.method_path();

        match (method, path.as_str()) {
            (Method::GET, "/info") => info::make_response(frame),
            (Method::POST, "/fp-setup") => Fairplay::make_response(frame),
            (Method::SETUP, path) if path.starts_with("rtsp") => Setup::make_response(frame),
            (Method::GET_PARAMETER, path) if path.starts_with("rtsp") => {
                Response::ok_with_body(frame.headers, Body::Text("\r\nvolume: 0.0\r\n".into()))
            }
            (Method::RECORD, path) if path.starts_with("rtsp") => {
                Response::ok_without_body(frame.headers)
            }
            (Method::GET | Method::POST, "/pair-verify") => {
                use VerifyState::{Msg01, Msg02, Msg03, Msg04};

                let t_in = Tags::try_from(frame.body)?;
                let state = VerifyState::try_from(t_in.get_state()?)?;

                match state {
                    Msg01 => {
                        tracing::debug!("{path} {state:?}");

                        let tags = self.verify.m1_m2(t_in.get_public_key()?)?;
                        Response::ok_with_body(
                            frame.headers,
                            Body::OctetStream(tags.encode().into()),
                        )
                    }
                    Msg02 | Msg03 | Msg04 => Err(anyhow!("{path}: got state {state:?}")),
                }
            }

            (Method::GET | Method::POST, "/pair-setup") => {
                use states::Generic as State;

                const M1: State = State(1);
                const M3: State = State(3);

                let t_in = Tags::try_from(frame.body)?;
                let state = t_in.get_state()?;

                match state {
                    M1 => {
                        tracing::debug!("{path} M1");
                        self.setup = SetupCtx::build();
                        let t_out = self.setup.m1_m2(&t_in);

                        Response::ok_with_body(
                            frame.headers,
                            Body::OctetStream(t_out.encode().into()),
                        )
                    }

                    M3 => {
                        tracing::debug!("{path} M3");

                        let (t_out, mut cipher) = self.setup.m3_m4(&t_in)?;

                        if self.cipher.is_none() && cipher.is_some() {
                            self.cipher = cipher.take();
                        }

                        Response::ok_with_body(
                            frame.headers,
                            Body::OctetStream(t_out.encode().into()),
                        )
                    }

                    _state => {
                        tracing::warn!("Setup UNKNOWN  {t_in:?}");
                        Response::internal_server_error(frame.headers)
                    }
                }
            }

            (_method, _path) => {
                tracing::warn!("\nUNHANDLED {frame:#}");

                Response::internal_server_error(frame.headers)
            }
        }
    }
}
