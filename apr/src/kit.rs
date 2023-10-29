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
    rtsp::{codec, Body, Frame, Response},
    HostInfo, Result,
};
use anyhow::anyhow;
use bytes::BytesMut;
use futures::SinkExt;
use once_cell::sync::Lazy;
use std::fmt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{self, Duration};
use tokio_stream::StreamExt;
use tokio_util::{
    codec::{Decoder, Framed},
    sync::CancellationToken,
};

mod auth;
pub mod cipher;
mod fairplay;
pub mod helper;
pub mod info;
pub mod msg;
pub mod setup;
pub mod states;
pub mod tags;

#[cfg(test)]
pub(crate) mod tests;

use auth::setup::Context as SetupCtx;
use auth::verify::Context as VerifyCtx;
pub use cipher::BlockLen;
pub use cipher::Context as CipherCtx;
pub use cipher::Lock as CipherLock;
use fairplay as Fairplay;
use setup::Method as SetupMethod;
use states::Generic as GenericState;
use states::Verify as VerifyState;
use tags::Idx as TagIdx;
use tags::Map as Tags;
use tags::Val as TagVal;

type Codec = Framed<TcpStream, codec::Rtsp>;

struct Pair {
    setup: Lazy<SetupCtx>,
    verify: Lazy<VerifyCtx>,
}

impl Default for Pair {
    fn default() -> Self {
        Self {
            setup: Lazy::new(SetupCtx::build),
            verify: Lazy::new(VerifyCtx::build),
        }
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct ListenerPorts {
    event: Option<u16>,
}

pub struct Context {
    pub device_id: Vec<u8>,
    pair: Lazy<Pair>,
    pub cipher: Option<CipherCtx>,
    setup: Option<SetupMethod>,
    listener_ports: ListenerPorts,
}

pub use Context as Kit;

unsafe impl Send for Kit {}

impl fmt::Debug for Kit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Kit")
    }
}

impl Kit {
    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if unable to
    /// generate security `Seed` or `KeyPair`.
    pub fn build() -> Self {
        let mut id_buf = BytesMut::with_capacity(64);
        id_buf.extend_from_slice(HostInfo::id_as_slice());

        let device_id = id_buf.freeze();

        tracing::debug!("\nDEVICE ID {:?}", pretty_hex::pretty_hex(&device_id));

        Self {
            device_id: device_id.into(),
            pair: Lazy::new(Pair::default),
            cipher: None,
            setup: None,
            listener_ports: ListenerPorts::default(),
        }
    }

    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    pub async fn run(listener: TcpListener, cancel_token: CancellationToken) -> Result<()> {
        let mut kit = Kit::build();

        let addr = format!("{}:0", HostInfo::ip_as_str());
        let event_listener = TcpListener::bind(addr).await?;

        kit.listener_ports = ListenerPorts {
            event: Some(event_listener.local_addr()?.port()),
        };

        let cancel_token = cancel_token.clone();
        tokio::pin!(cancel_token);

        // step 1: wait for a RTSP receiver connection in a new scope
        //         so temporary resources are freed
        let framed = {
            let sleep = time::sleep(Duration::from_secs(60 * 5));
            tokio::pin!(sleep);

            tokio::select! {
                Ok((socket, _remote_addr)) = listener.accept() => {
                   codec::Rtsp::default().framed(socket)
                },

                _ = &mut sleep => return Err(anyhow!("timeout")),
                _ = cancel_token.cancelled() => return Ok(()),
            }
        };

        tokio::pin!(framed);

        // step 2: process inbound RTSP messages and run until
        //         client disconnects or the app is shutdown

        let mut event_socket = None;

        loop {
            tokio::select! {
                maybe_frame = framed.next() => {
                    match maybe_frame {
                        Some(Ok(frame)) => {
                            kit.handle_frame(&mut framed, frame).await?;
                        },
                        Some(Err(e)) => {
                            tracing::error!("framed error: {e}");
                            break;
                        },
                        None => ()
                    }
                },
                event = event_listener.accept(), if event_socket.is_none() => {
                    match event {
                        Ok((socket, remote_addr)) => {
                            let port = event_listener.local_addr()?.port();
                            tracing::info!(
                                "ACCEPTED EVENT 0.0.0.0:{port} <= {remote_addr}"
                            );
                            event_socket = Some(socket);
                        },
                        Err(e) => tracing::error!("event connection failed: {e}"),
                    }
                },
                _ = cancel_token.cancelled() => {
                    tracing::warn!("kit task cancelled");
                    return Ok(());
                },
            }
        }

        Ok(())
    }

    async fn handle_frame(&mut self, framed: &mut Codec, frame: Frame) -> Result<()> {
        tracing::info!("{frame}");

        let response = self.respond_to(frame)?;
        if let Some(cipher) = self.pair.setup.cipher.take() {
            framed.codec_mut().install_cipher(cipher);
        }

        framed.send(response).await
    }

    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    pub fn respond_to(&mut self, frame: Frame) -> Result<Response> {
        use crate::rtsp::Method;

        let (method, path) = frame.routing().as_tuple();

        match (method, path.as_str()) {
            (Method::GET, "/info") => info::make_response(frame),
            (Method::POST, "/fp-setup") => Fairplay::make_response(frame),
            (Method::SETUP, path) if path.starts_with("rtsp") => {
                let setup = self
                    .setup
                    .get_or_insert_with(|| SetupMethod::build(self.listener_ports));
                setup.make_response(frame)
            }
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
                        let tags = self.pair.verify.m1_m2(t_in.get_public_key()?)?;

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

                        let t_out = self.pair.setup.m1_m2(&t_in);

                        Response::ok_with_body(
                            frame.headers,
                            Body::OctetStream(t_out.encode().into()),
                        )
                    }

                    M3 => {
                        tracing::debug!("{path} M3");

                        let t_out = self.pair.setup.m3_m4(&t_in)?;

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

            (Method::SET_PEERS, path) if path.starts_with("rtsp") => {
                tracing::error!("implement {}", Method::SET_PEERS);

                Response::internal_server_error(frame.headers)
            }
            (Method::SET_PEERSX, path) if path.starts_with("rtsp") => {
                tracing::error!("implement {}", Method::SET_PEERSX);

                Response::internal_server_error(frame.headers)
            }
            (method, path) => {
                tracing::warn!("UNHANDLED {method:?} {path}");

                Response::internal_server_error(frame.headers)
            }
        }
    }
}

#[cfg(test)]
mod tests_alt {
    use super::Kit;
    use crate::Result;
    use tokio::net::TcpListener;
    use tokio::task;
    use tokio_util::sync::CancellationToken;
    use tracing_test::traced_test;

    #[traced_test]
    #[tokio::test]
    async fn can_run_kit() -> Result<()> {
        let cancel_token = CancellationToken::new();
        let rtsp_listener = TcpListener::bind("0.0.0.0:0").await.unwrap();

        let jh = task::spawn(Kit::run(rtsp_listener, cancel_token.clone()));

        match jh.await {
            Ok(Ok(())) => (),
            Ok(Err(e)) => tracing::error!("task error: {e}"),
            Err(e) => tracing::error!("join error: {e}"),
        }

        Ok(())

        // match jh.await {
        //     Ok(Ok(port)) => println!("connected port: {port}"),
        //     Ok(Err(e)) => println!("task error: {e}"),
        //     Err(e) => println!("{e}"),
        // }
    }
}
