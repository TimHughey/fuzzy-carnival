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
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

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
pub struct ListenersAndPorts {
    ports: Option<Ports>,
    listeners: Option<Listeners>,
}

impl ListenersAndPorts {
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

pub async fn run(listeners: Listeners, cancel_token: CancellationToken) -> Result<()> {
    tokio::pin!(listeners);
    tokio::pin!(cancel_token);

    let mut event_socket = None;
    let mut data_socket = None;
    let mut ctrl_socket = None;

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                tracing::warn!("received cancel request");
                break;
            },
            event = listeners.event.accept(), if event_socket.is_none() => {
                match event {
                    Ok((socket, remote_addr)) => {
                        log_accept("EVENT", &socket, &remote_addr)?;

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
                        log_accept("DATA", &socket, &remote_addr)?;

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
                        log_accept("CONTROL", &socket, &remote_addr)?;

                        ctrl_socket = Some(socket);
                    },
                    Err(e) => {
                        tracing::error!("control connection failed: {e}");
                        break;
                    }
                }
            },

        }
    }

    Ok(())
}

fn log_accept(desc: &str, socket: &TcpStream, remote: &SocketAddr) -> Result<()> {
    let port = socket.local_addr()?.port();
    tracing::info!("ACCEPTED {desc} *:{port} <= {remote}");
    Ok(())
}
