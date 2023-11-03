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
use tokio::net::TcpListener;
use tokio::time::{self, Duration};
use tokio_stream::StreamExt;
use tokio_util::{codec::Decoder, sync::CancellationToken};

mod auth;
pub mod cipher;
pub mod codec;
pub mod helper;
pub(crate) mod methods;
pub mod msg;
pub mod tags;

#[cfg(test)]
pub(crate) mod tests;

pub use auth::Pair;
pub use cipher::BlockLen;
pub use cipher::Context as CipherCtx;
pub use cipher::Lock as CipherLock;
use methods::{Command, FairPlay, Info, SetPeers, Setup};
pub use msg::{Frame, Response};
use tags::Idx as TagIdx;
use tags::Map as Tags;
use tags::Val as TagVal;

// type Codec = Framed<TcpStream, codec::Rtsp>;

#[derive(Debug, Default, Copy, Clone, PartialEq, PartialOrd)]
pub struct Ports {
    pub event: u16,
    pub data: u16,
    pub control: u16,
}

/*impl Ports {
    pub fn control_as_val(&self) -> Result<plist::Value> {
        if let Some(ports) = self.ports.as_ref() {
            return Ok(plist::Value::try_from(ports.control)?);
        }

        let error = "control port is None";
        tracing::error!(error);
        Err(anyhow!(error))
    }

    pub fn data_as_val(&self) -> Result<plist::Value> {
        if let Some(ports) = self.ports.as_ref() {
            return Ok(plist::Value::try_from(ports.data)?);
        }

        let error = "data port is None";
        tracing::error!(error);
        Err(anyhow!(error))
    }

    pub fn event_as_val(&self) -> Result<plist::Value> {
        if let Some(ports) = self.ports.as_ref() {
            return Ok(plist::Value::try_from(ports.event)?);
        }

        let error = "event port is None";
        tracing::error!(error);
        Err(anyhow!(error))
    }
}*/

#[derive(Debug)]
pub struct Listeners {
    pub event: TcpListener,
    pub data: TcpListener,
    pub control: TcpListener,
}

#[allow(unused)]
#[derive(Debug, Default)]
pub struct ListenerPorts {
    ports: Option<Ports>,
    listeners: Option<Listeners>,
}

impl ListenerPorts {
    pub async fn new() -> Result<Self> {
        let addr = format!("{}:0", HostInfo::ip_as_str());

        let listeners = Listeners {
            event: TcpListener::bind(&addr).await?,
            data: TcpListener::bind(&addr).await?,
            control: TcpListener::bind(&addr).await?,
        };

        let ports = Ports {
            event: listeners.event.local_addr()?.port(),
            data: listeners.data.local_addr()?.port(),
            control: listeners.control.local_addr()?.port(),
        };

        Ok(Self {
            listeners: Some(listeners),
            ports: Some(ports),
        })
    }

    pub fn take_listeners(&mut self) -> Option<Listeners> {
        self.listeners.take()
    }

    pub fn take_ports(&mut self) -> Option<Ports> {
        self.ports.take()
    }
}

type MaybeFrame = Option<Result<Frame>>;
type MaybeResponse = Option<Result<Response>>;

pub struct Context {
    pub device_id: Vec<u8>,
    pair: Lazy<Pair>,
    pub cipher: Option<CipherCtx>,
    setup: Option<Setup>,
    setpeers: Option<SetPeers>,
    ports: Option<Ports>,
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
            ports: None,
        }
    }

    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    pub async fn run(listener: TcpListener, cancel_token: CancellationToken) -> Result<()> {
        let mut kit = Kit::build();

        // let addr = format!("{}:0", HostInfo::ip_as_str());
        // let event_listener = TcpListener::bind(&addr).await?;
        // let data_listener = TcpListener::bind(&addr).await?;
        // let ctrl_listener = TcpListener::bind(addr).await?;

        let mut listener_ports = ListenerPorts::new().await?;

        // SAFETY
        // ListenerPorts::new() would have errored
        let listeners = listener_ports
            .take_listeners()
            .ok_or_else(|| anyhow!("listener ports are None"))?;
        kit.ports = listener_ports.take_ports();

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
        tokio::pin!(listeners);

        // step 2: process inbound RTSP messages and run until
        //         client disconnects or the app is shutdown
        let mut event_socket = None;
        let mut data_socket = None;
        let mut ctrl_socket = None;

        loop {
            tokio::select! {
                maybe_frame = framed.next() => {
                    match kit.handle_frame(maybe_frame) {
                        Some(Ok(response)) => {
                            if let Some(cipher) = kit.pair.cipher_take() {
                                framed.codec_mut().install_cipher(cipher);
                            }

                            if let Err(e) = framed.send(response).await {
                                tracing::error!("{e}");
                                break;
                            }
                        },
                        Some(Err(_)) => break,
                        None => ()
                    }
                },
                event = listeners.event.accept(), if event_socket.is_none() => {
                    match event {
                        Ok((socket, remote_addr)) => {
                            let port = socket.local_addr()?.port();
                            tracing::info!(
                                "ACCEPTED EVENT *:{port} <= {remote_addr}"
                            );
                            event_socket = Some(socket);
                        },
                        Err(e) => {
                            tracing::error!("event connection failed: {e}");
                            break;
                        },
                    }
                },
                data = listeners.data.accept(), if data_socket.is_none() => {
                    match data {
                        Ok((socket, remote_addr)) => {
                            let port = socket.local_addr()?.port();
                            tracing::info!(
                                "ACCEPTED DATA 0.0.0.0:{port} <= {remote_addr}"
                            );

                            data_socket = Some(socket);
                        },
                        Err(e) => {
                            tracing::error!("data connection failed: {e}");
                            break;
                        }
                    }
                },

                ctrl = listeners.control.accept(), if ctrl_socket.is_none() => {
                    match ctrl {
                        Ok((socket, remote_addr)) => {
                            let port = socket.local_addr()?.port();
                            tracing::info!(
                                "ACCEPTED CONTROL 0.0.0.0:{port} <= {remote_addr}"
                            );

                            ctrl_socket = Some(socket);
                        },
                        Err(e) => {
                            tracing::error!("control connection failed: {e}");
                            break;
                        }
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
    fn handle_frame(&mut self, frame: MaybeFrame) -> MaybeResponse {
        match frame {
            Some(Ok(frame)) => {
                if frame.routing.please_log() {
                    tracing::info!("{frame}");
                }

                Some(self.response(frame))
            }
            Some(Err(e)) => {
                tracing::error!("framimg error: {e}");
                Some(Err(e))
            }
            None => None,
        }
    }

    fn invoke_pair(&mut self, path: &str, frame: Frame) -> Result<Response> {
        self.pair.response(path, frame)
    }

    fn invoke_setpeers(&mut self, frame: Frame) -> Result<Response> {
        self.setpeers
            .get_or_insert_with(SetPeers::default)
            .response(frame)
    }

    fn invoke_setup(&mut self, frame: Frame) -> Result<Response> {
        let ports = self.ports;
        self.setup
            .get_or_insert_with(Setup::default)
            .response(frame, ports)
    }

    /// Creates and returns a [`Response`] using the routing (method and path)
    /// included in the [`Frame`] to invoke the required method implementation.
    ///
    /// # Errors
    ///
    /// This function will return an error if there is a logic error or defect.
    pub fn response(&mut self, frame: Frame) -> Result<Response> {
        use methods::consts::{
            GET, GET_PARAMETER, POST, RECORD, SETRATEANCHORTIME, SETUP, SET_PARAMETER, SET_PEERS,
            SET_PEERSX, TEARDOWN,
        };

        let cseq = frame.cseq;
        let routing = &frame.routing;
        let (method, path) = routing.parts_tuple();

        Ok(match (method.as_str(), path.as_str()) {
            (POST, "/feedback") => Response::ok_simple(cseq),
            (SETUP, _path) => self.invoke_setup(frame)?,
            (GET_PARAMETER, _path) => Response::ok_text(cseq, "\r\nvolume: 0.0\r\n"),
            (RECORD, _path) if routing.is_rtsp() => Response::ok_simple(cseq),
            (SET_PEERS | SET_PEERSX, _path) => self.invoke_setpeers(frame)?,
            (SET_PARAMETER, _path) => Response::ok_simple(cseq),
            (POST, "/command") => Command::response(frame)?,
            (SETRATEANCHORTIME, _path) => {
                use methods::SetRateAnchorTime;

                if let Some(content) = frame.content {
                    let anchor_time: SetRateAnchorTime = plist::from_bytes(&content.data)?;

                    tracing::info!("{routing} CONTENT {anchor_time:#?}");
                }

                Response::ok_simple(cseq)
            }
            (GET, "/info") => Info::response(frame)?,
            (POST, "/fp-setup") => FairPlay::response(frame)?,
            (GET | POST, "/pair-setup" | "/pair-verify") => self.invoke_pair(&path, frame)?,
            (TEARDOWN, _path) => Response::ok_simple(cseq),
            (method, path) => Self::unknown(method, path, cseq),
        })
    }

    fn unknown(method: &str, path: &str, cseq: u32) -> Response {
        tracing::warn!("UNHANDLED {method} {path}");
        Response::internal_server_error(cseq)
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
