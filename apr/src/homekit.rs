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
    rtsp::{Body, Frame, HeaderList, Response},
    HostInfo, Result,
};
use anyhow::anyhow;
use bytes::BytesMut;
use std::fmt;
use tracing::{error, info};

pub mod info;
pub mod setup;
pub mod srp;
pub mod states;
pub mod tags;
pub mod verify;

pub use setup::Context as SetupCtx;
pub use srp::Server as SrpServer;
pub use states::Generic as GenericState;
pub use states::Verify as VerifyState;
pub use tags::Idx as TagIdx;
pub use tags::Map as Tags;
pub use tags::Val as TagVal;
pub use verify::Context as VerifyCtx;

pub struct Context {
    pub device_id: Vec<u8>,
    pub setup: Option<SetupCtx>,
    pub verify: VerifyCtx,
    pub encrypted: bool,
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
        use pretty_hex::PrettyHex;

        let mut id_buf = BytesMut::with_capacity(64);
        id_buf.extend_from_slice(HostInfo::id_as_slice());

        let device_id = id_buf.freeze();

        info!("\nDEVICE ID {:?}", device_id.hex_dump());

        Self {
            device_id: device_id.into(),
            setup: None,
            verify: VerifyCtx::build(),
            encrypted: false,
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

        if method == Method::GET && path == "/info" {
            info::response(frame)
        } else {
            let t_in = Tags::try_from(frame.body)?;
            let state = t_in.get_state()?;

            match (method, path) {
                (Method::GET | Method::POST, path) if path.ends_with("verify") => {
                    use VerifyState::{Msg01, Msg02, Msg03, Msg04};

                    let state = VerifyState::try_from(state)?;

                    match state {
                        Msg01 => {
                            info!("{path} {state:?}");
                            let verify = &self.verify;

                            let pk = t_in.get_public_key()?;

                            let tags = verify.m1_m2(pk)?;

                            let body = Body::OctetStream(tags.encode().to_vec());

                            Ok(Response {
                                headers: HeaderList::make_response2(frame.headers, &body)?,
                                body,
                                ..Response::default()
                            })
                        }
                        Msg02 | Msg03 | Msg04 => Err(anyhow!("{path}: got state {state:?}")),
                    }
                }

                (Method::GET | Method::POST, path) if path.ends_with("setup") => {
                    use states::Generic as State;

                    const M1: State = State(1);
                    const M3: State = State(3);

                    let setup_ctx = self.setup.take();

                    match (state, setup_ctx) {
                        (M1, None) => {
                            info!("{path} M1");
                            let mut setup_ctx = SetupCtx::build(2);
                            let t_out = setup_ctx.m1_m2(&t_in);

                            let body = Body::OctetStream(t_out.encode().to_vec());

                            self.setup = Some(setup_ctx);

                            Ok(Response {
                                headers: HeaderList::make_response2(frame.headers, &body)?,
                                body,
                                ..Response::default()
                            })
                        }

                        (M3, Some(mut setup_ctx)) => {
                            info!("{path} M2");

                            let t_out = setup_ctx.m3_m4(&t_in);

                            let body = Body::OctetStream(t_out.encode().to_vec());

                            self.setup = Some(setup_ctx);

                            Ok(Response {
                                headers: HeaderList::make_response2(frame.headers, &body)?,
                                body,
                                ..Response::default()
                            })
                        }

                        (_state, _setup_ctx) => {
                            info!("Setup UNKNOWN  {t_in:?}");

                            Ok(Response::default())
                        }
                    }
                }

                (method, path) => {
                    error!("unhandled {path}\n{t_in:?}");

                    Err(anyhow!("unhandled: {method} {path}"))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use super::Tags;
    use crate::HostInfo;
    use alkali::asymmetric::sign::Seed;
    use bstr::ByteSlice;
    use bytes::BytesMut;

    #[test]
    pub fn parse_verify_request1a() {
        let bytes: [u8; 37] = [
            0x06, 0x01, 0x01, 0x03, 0x20, 0xf0, 0x0B, 0x71, 0x42, 0x70, 0x26, 0xe1, 0x7e, 0x23,
            0xed, 0x0a, 0x8b, 0x71, 0x17, 0x87, 0xa6, 0x79, 0x3d, 0x50, 0xd3, 0x21, 0x48, 0x4a,
            0xa6, 0x49, 0xac, 0xaa, 0x44, 0x26, 0x81, 0x9f, 0x38,
        ];

        let mut buf = BytesMut::new();
        buf.extend_from_slice(bytes.as_bytes());

        let tags = Tags::try_from(buf);

        assert!(tags.is_ok());
    }

    #[test]
    pub fn check_key_creation() -> crate::Result<()> {
        // println!("seed1 {:?}", seed0.hex_dump());

        let dev_id1 = HostInfo::seed();
        let seed1 = Seed::try_from(dev_id1.as_bytes())?;

        // println!("host seed {:?}", dev_id1.hex_dump());
        // println!("seed1 {:?}", seed1.hex_dump());

        assert_eq!(dev_id1.as_slice(), seed1.as_slice());

        Ok(())
    }
}
