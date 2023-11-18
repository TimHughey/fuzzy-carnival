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
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::{self, Duration},
};
use tokio_stream::StreamExt;
use tokio_util::{codec::Decoder, sync::CancellationToken};

mod auth;
pub mod cipher;
pub(crate) mod codec;
pub(crate) mod conn;
pub mod helper;
pub(crate) mod methods;
pub mod msg;
pub mod ptp;
pub mod tags;

#[cfg(test)]
pub(crate) mod tests;

pub use auth::Pair;
pub use cipher::BlockLen;
pub use cipher::Context as CipherCtx;
pub use cipher::Lock as CipherLock;
use conn::{ListenersAndPorts, Ports};
use methods::{Command, FairPlay, Info, SetPeers, SetRateAnchorTime, Setup};
pub use msg::{Frame, Response};
use tags::Idx as TagIdx;
use tags::Map as Tags;
use tags::Val as TagVal;

// type Codec = Framed<TcpStream, codec::Rtsp>;

type MaybeFrame = Option<Result<Frame>>;
type MaybeResponse = Option<Result<Response>>;

pub struct Context {
    pub device_id: Vec<u8>,
    pair: Lazy<Pair>,
    pub cipher: Option<CipherCtx>,
    setup: Option<Setup>,
    setpeers: Option<SetPeers>,
    ports: Option<Ports>,
    anchor: Option<SetRateAnchorTime>,
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
            anchor: None,
        }
    }

    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    #[allow(clippy::too_many_lines)]
    pub async fn run(listener: TcpListener, cancel_token: CancellationToken) -> Result<()> {
        let mut kit = Kit::build();

        // step 1: wait for a RTSP receiver connection in a new scope
        //         so temporary resources are freed
        let framed = accept_rtsp(&listener, &cancel_token).await?;
        tokio::pin!(framed);

        let mut listener_ports = ListenersAndPorts::new().await?;

        kit.ports = listener_ports.take_ports();

        let listeners = listener_ports
            .take_listeners()
            .ok_or_else(|| anyhow!("listener ports are None"))?;

        let mut js_ptp = JoinSet::new();

        let ptp_ct = cancel_token.clone();
        js_ptp.spawn(async move { ptp::run_loop(ptp_ct).await });

        // let mut js_conn = JoinSet::new();

        let conn_ct = cancel_token.clone();
        js_ptp.spawn(async move { conn::run(listeners, conn_ct).await });

        loop {
            tokio::select! {
                maybe_frame = framed.next(), if !js_ptp.is_empty() => {
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

                maybe_joined = js_ptp.join_next() => {
                    match maybe_joined {
                        None => break,
                        Some(Ok(jh)) => {
                            tracing::info!("task joined: {jh:#?}");
                        },
                        Some(Err(e)) => {
                            tracing::error!("join failed: {e}");
                            break;
                        }

                    }
                },

                // maybe_joined = js_conn.join_next() => {
                //     match maybe_joined {
                //         None => break,
                //         Some(Ok(jh)) => {
                //             let res = jh.await;
                //             tracing::info!("task joined: {res:#?}");
                //         },
                //         Some(Err(e)) => {
                //             tracing::error!("join failed: {e}");
                //             break;
                //         }
                //     }
                // },




                // res = &mut ptp_join => {
                //     if let Err(e) = res {
                //         tracing::error!("ptp task error: {e}");
                //         break;
                //     }
                // },

                // res = &mut conn_join => {
                //     if let Err(e) = res {
                //         tracing::error!("connection task error: {e}");
                //         break;
                //     }
                // }

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

    fn invoke_anchor(&mut self, frame: Frame) -> Result<Response> {
        self.anchor
            .get_or_insert(SetRateAnchorTime::default())
            .response(frame)
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
            (SETRATEANCHORTIME, _path) => self.invoke_anchor(frame)?,
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

async fn accept_rtsp(
    listener: &TcpListener,
    cancel_token: &CancellationToken,
) -> Result<tokio_util::codec::Framed<TcpStream, codec::Rtsp>> {
    let cancel_token = cancel_token.clone();

    tokio::pin!(cancel_token);
    let sleep = time::sleep(Duration::from_secs(60 * 5));
    tokio::pin!(sleep);

    tokio::select! {
        Ok((socket, _remote_addr)) = listener.accept() => {
           Ok(codec::Rtsp::default().framed(socket))
        },

        _ = &mut sleep =>  Err(anyhow!("timeout")),
        _ = cancel_token.cancelled() =>  Err(anyhow!("cancel requested")),
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
