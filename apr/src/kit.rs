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

use crate::{HostInfo, Result};
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
pub mod codec;
pub mod helper;
pub(crate) mod methods;
pub mod msg;
pub mod states;
pub mod tags;

#[cfg(test)]
pub(crate) mod tests;

use auth::setup::Context as SetupCtx;
use auth::verify::Context as VerifyCtx;
pub use cipher::BlockLen;
pub use cipher::Context as CipherCtx;
pub use cipher::Lock as CipherLock;
use methods::{FairPlay, Info, SetPeers, Setup as SetupMethod};
pub use msg::{Frame, Response};
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
    setpeers: Option<SetPeers>,
    listener_ports: ListenerPorts,
}

pub use Context as Kit;
unsafe impl Send for Kit {}

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
            setpeers: None,
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
        if frame.routing.please_log() {
            tracing::info!("{frame}");
        }

        let response = self.respond_to(frame)?;
        if let Some(cipher) = self.pair.setup.cipher.take() {
            framed.codec_mut().install_cipher(cipher);
        }

        framed.send(response).await
    }

    /// .
    ///
    /// # Panics
    ///
    /// Panics if .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    pub fn respond_to(&mut self, frame: Frame) -> Result<Response> {
        use msg::method::{
            GET, GET_PARAMETER, POST, RECORD, SETUP, SET_PARAMETER, SET_PEERS, SET_PEERSX, TEARDOWN,
        };

        let cseq = frame.cseq;
        let routing = &frame.routing;
        let (method, path) = routing.parts_tuple();

        match (method.as_str(), path.as_str()) {
            (POST, "/feedback" | "/command") => Ok(Response::ok_simple(cseq)),
            (GET, "/info") => Info::make_response(frame),
            (POST, "/fp-setup") => FairPlay::make_response(frame),
            (SETUP, _) if routing.is_rtsp() => {
                let setup = self
                    .setup
                    .get_or_insert_with(|| SetupMethod::build(self.listener_ports));
                setup.make_response(frame)
            }
            (GET_PARAMETER, _path) if routing.is_rtsp() => {
                Ok(Response::ok_text(cseq, "\r\nvolume: 0.0\r\n"))
            }
            (RECORD, _path) if routing.is_rtsp() => Ok(Response::ok_simple(cseq)),
            (GET | POST, "/pair-verify") => {
                use VerifyState::{Msg01, Msg02, Msg03, Msg04};

                let t_in = Tags::try_from(frame.content.unwrap().data)?;
                let state = VerifyState::try_from(t_in.get_state()?)?;

                match state {
                    Msg01 => {
                        tracing::debug!("{path} {state:?}");
                        let tags = self.pair.verify.m1_m2(t_in.get_public_key()?)?;

                        Ok(Response::ok_octet_stream(cseq, &tags.encode()))
                    }
                    Msg02 | Msg03 | Msg04 => Err(anyhow!("{path}: got state {state:?}")),
                }
            }
            (GET | POST, "/pair-setup") => {
                use states::Generic as State;

                const M1: State = State(1);
                const M3: State = State(3);

                let t_in = Tags::try_from(frame.content.unwrap().data)?;
                let state = t_in.get_state()?;

                match state {
                    M1 => {
                        tracing::debug!("{path} M1");

                        let t_out = self.pair.setup.m1_m2(&t_in);
                        Ok(Response::ok_octet_stream(cseq, &t_out.encode()))
                    }

                    M3 => {
                        tracing::debug!("{path} M3");

                        let t_out = self.pair.setup.m3_m4(&t_in)?;
                        Ok(Response::ok_octet_stream(cseq, &t_out.encode()))
                    }

                    _state => {
                        tracing::warn!("Setup UNKNOWN  {t_in:?}");
                        Ok(Response::internal_server_error(cseq))
                    }
                }
            }

            (SET_PEERS | SET_PEERSX, _path) if routing.is_rtsp() => {
                let setpeers = self.setpeers.get_or_insert(SetPeers::default());
                setpeers.make_response(frame)
            }
            (SET_PEERSX, _path) if routing.is_rtsp() => {
                tracing::error!("implement {}", SET_PEERSX);

                Ok(Response::internal_server_error(cseq))
            }
            (SET_PARAMETER, _path) if routing.is_rtsp() => Ok(Response::ok_simple(cseq)),

            (TEARDOWN, _path) if routing.is_rtsp() => Ok(Response::ok_simple(cseq)),

            (method, path) => {
                tracing::warn!("UNHANDLED {method} {path}");

                Ok(Response::internal_server_error(cseq))
            }
        }
    }
}

impl fmt::Debug for Kit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Kit")
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
    }
}
