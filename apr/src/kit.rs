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
#[allow(unused_imports)]
use pretty_hex::PrettyHex;
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
pub mod tags;

#[cfg(test)]
pub(crate) mod tests;

// use auth::setup::Context as SetupCtx;
// use auth::verify::Context as VerifyCtx;
pub use auth::Pair;
pub use cipher::BlockLen;
pub use cipher::Context as CipherCtx;
pub use cipher::Lock as CipherLock;
use methods::{Command, FairPlay, Info, SetPeers, Setup};
pub use msg::{Frame, Response};
use tags::Idx as TagIdx;
use tags::Map as Tags;
use tags::Val as TagVal;

type Codec = Framed<TcpStream, codec::Rtsp>;

#[allow(unused)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct ListenerPorts {
    event: Option<u16>,
    audio: Option<u16>,
    control: Option<u16>,
}

impl ListenerPorts {
    pub fn new(event_port: u16) -> Self {
        Self {
            event: Some(event_port),
            audio: None,
            control: None,
        }
    }
}

pub struct Context {
    pub device_id: Vec<u8>,
    pair: Lazy<Pair>,
    pub cipher: Option<CipherCtx>,
    setup: Option<Setup>,
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

        kit.listener_ports = ListenerPorts::new(event_listener.local_addr()?.port());

        kit.listener_ports = ListenerPorts {
            event: Some(event_listener.local_addr()?.port()),
            audio: None,
            control: None,
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

                            tracing::error!("framimg error: {e}");
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
                                "ACCEPTED EVENT connection 0.0.0.0:{port} <= {remote_addr}"
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

    /// Handles the framed received by [`Framed`] codec implementation.  The goal of
    /// this function is to perform any pre/post side-effects associated withe
    /// processing the [`Frame`].
    ///
    /// # Errors
    ///
    /// This function will return any errors produced while creating the [`Response`] .
    async fn handle_frame(&mut self, framed: &mut Codec, frame: Frame) -> Result<()> {
        if frame.routing.please_log() {
            tracing::info!("{frame}");
        }

        let response = self.response(frame)?;

        if let Some(cipher) = self.pair.cipher_take() {
            framed.codec_mut().install_cipher(cipher);
        }

        framed.send(response).await
    }

    /// Creates and returns a [`Response`] using the routing (method and path)
    /// included in the [`Frame`] to invoke the required method implementation.
    ///
    /// # Errors
    ///
    /// This function will return an error if there is a logic error or defect.
    pub fn response(&mut self, frame: Frame) -> Result<Response> {
        use methods::consts::{
            GET, GET_PARAMETER, POST, RECORD, SETUP, SET_PARAMETER, SET_PEERS, SET_PEERSX, TEARDOWN,
        };

        let cseq = frame.cseq;
        let routing = &frame.routing;
        let (method, path) = routing.parts_tuple();

        match (method.as_str(), path.as_str()) {
            (POST, "/feedback") => Ok(Response::ok_simple(cseq)),

            (GET, "/info") => Info::make_response(frame),
            (POST, "/fp-setup") => FairPlay::make_response(frame),
            (SETUP, _) if routing.is_rtsp() => {
                let setup = self.setup_mut();
                setup.make_response(frame)
            }
            (GET_PARAMETER, _path) if routing.is_rtsp() => {
                Ok(Response::ok_text(cseq, "\r\nvolume: 0.0\r\n"))
            }
            (RECORD, _path) if routing.is_rtsp() => Ok(Response::ok_simple(cseq)),
            (GET | POST, path) if routing.starts_with("/pair-") => self.pair.response(path, frame),

            (SET_PEERS | SET_PEERSX, _path) if routing.is_rtsp() => {
                let setpeers = self.setpeers_mut();
                setpeers.make_response(frame)
            }

            (SET_PEERSX, _path) if routing.is_rtsp() => {
                tracing::error!("implement {}", SET_PEERSX);

                Ok(Response::internal_server_error(cseq))
            }
            (SET_PARAMETER, _path) if routing.is_rtsp() => Ok(Response::ok_simple(cseq)),

            (POST, "/command") => Command::make_response(frame),

            (TEARDOWN, _path) if routing.is_rtsp() => Ok(Response::ok_simple(cseq)),

            (method, path) => {
                tracing::warn!("UNHANDLED {method} {path}");

                Ok(Response::internal_server_error(cseq))
            }
        }
    }

    fn setpeers_mut(&mut self) -> &mut SetPeers {
        self.setpeers.get_or_insert_with(SetPeers::default)
    }

    fn setup_mut(&mut self) -> &mut Setup {
        self.setup
            .get_or_insert_with(|| Setup::build(self.listener_ports))
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
