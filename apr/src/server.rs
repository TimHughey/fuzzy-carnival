// Rusty Pierre
//
// Copyright 2023 Tim Hughey
//
// Licensed under the Apache License, Version 2.0 (the "License");
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

//! Minimal ``AirPlay`` server implementation
//!
//! Provides an async `run` function that listens for inbound connections,
//! spawning a task per connection.

use crate::{
    rtsp::{codec, Frame},
    serdis::SerDis,
    HomeKit, Result, Shutdown,
};
use anyhow::anyhow;
use futures::SinkExt;
use mdns_sd as Mdns;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio::sync::{broadcast, mpsc, Semaphore};
use tokio::time::{self, Duration};
use tokio_stream::StreamExt;
use tokio_util::{
    codec::{Decoder, Framed},
    sync::CancellationToken,
};

#[allow(unused)]
use tracing::{debug, error, info, warn};

/// Server listener state. Created in the `run` call. It includes a `run` method
/// which performs the TCP listening and initialization of per-connection state.
#[derive(Debug)]
struct Listener {
    /// RTSP Server Handle
    ///
    /// This holds a wrapper around an `Arc`. The internal `Db` can be
    /// retrieved and passed into the per connection state (`Handler`).

    /// TCP listener supplied by the `run` caller.
    listener: TcpListener,

    /// Limit the max number of connections.
    ///
    /// A `Semaphore` is used to limit the max number of connections. Before
    /// attempting to accept a new connection, a permit is acquired from the
    /// semaphore. If none are available, the listener waits for one.
    ///
    /// When handlers complete processing a connection, the permit is returned
    /// to the semaphore.
    limit_connections: Arc<Semaphore>,

    /// Broadcasts a shutdown signal to all active connections.
    ///
    /// The initial `shutdown` trigger is provided by the `run` caller. The
    /// server is responsible for gracefully shutting down active connections.
    /// When a connection task is spawned, it is passed a broadcast receiver
    /// handle. When a graceful shutdown is initiated, a `()` value is sent via
    /// the broadcast::Sender. Each active connection receives it, reaches a
    /// safe terminal state, and completes the task.
    notify_shutdown: broadcast::Sender<()>,

    /// Used as part of the graceful shutdown process to wait for client
    /// connections to complete processing.
    ///
    /// Tokio channels are closed once all `Sender` handles go out of scope.
    /// When a channel is closed, the receiver receives `None`. This is
    /// leveraged to detect all connection handlers completing. When a
    /// connection handler is initialized, it is assigned a clone of
    /// `shutdown_complete_tx`. When the listener shuts down, it drops the
    /// sender held by this `shutdown_complete_tx` field. Once all handler tasks
    /// complete, all clones of the `Sender` are also dropped. This results in
    /// `shutdown_complete_rx.recv()` completing with `None`. At this point, it
    /// is safe to exit the server process.
    shutdown_complete_tx: mpsc::Sender<()>,
}

/// Per-connection handler. Reads requests from `connection` and applies the
/// commands to `db`.
#[derive(Debug)]
struct Handler {
    /// The TCP connection decorated with a codec encoder / decoder which
    /// operates in terms of `Frame` (complete messages).
    ///
    /// The `Framed` codec allocates the required buffers and handles the
    /// details of receiving data, ensuring it is a complete message before
    /// returning the `Frame`.
    framed: Framed<TcpStream, codec::Rtsp>,

    /// Listen for shutdown notifications.
    ///
    /// A wrapper around the `broadcast::Receiver` paired with the sender in
    /// `Listener`. The connection handler processes requests from the
    /// connection until the peer disconnects **or** a shutdown notification is
    /// received from `shutdown`. In the latter case, any in-flight work being
    /// processed for the peer is continued until it reaches a safe state, at
    /// which point the connection is terminated.
    shutdown: Shutdown,

    /// Not used directly. Instead, when `Handler` is dropped...?
    _shutdown_complete: mpsc::Sender<()>,

    active: bool,
}

type MaybeFrame = Option<Result<Frame>>;
type HandleResult = Result<(HomeKit, Result<()>)>;

impl Handler {
    /// Process a single connection.
    ///
    /// Request frames are read from the socket and processed. Responses are
    /// written back to the socket.
    ///
    /// Currently, pipelining is not implemented. Pipelining is the ability to
    /// process more than one request concurrently per connection without
    /// interleaving frames. See for more details:
    /// <https://redis.io/topics/pipelining>
    ///
    /// When the shutdown signal is received, the connection is processed until
    /// it reaches a safe state, at which point it is terminated.
    async fn run(mut self) -> Result<()> {
        let mut homekit = HomeKit::build();

        while !self.shutdown.is_shutdown() && self.active {
            tokio::select! {
                maybe_frame = self.framed.next(), if self.active => {
                   let (kit, _) = self.handle_frame(homekit, maybe_frame).await?;
                   homekit = kit;
                },
                _ = self.shutdown.recv() => (),
            }
        }

        Ok(())
    }

    async fn handle_frame(&mut self, mut kit: HomeKit, frame: MaybeFrame) -> HandleResult {
        self.active = false;

        match frame {
            Some(Ok(frame)) => {
                info!("\n{}", frame);

                match kit.respond_to(frame) {
                    Ok(response) => {
                        self.active = true;
                        info!("sending response:\n{response:?}");
                        Ok((kit, self.framed.send(response).await))
                    }

                    Err(e) => {
                        error!(cause = ?e);
                        Ok((kit, Err(anyhow!(e))))
                    }
                }
            }

            Some(Err(e)) => {
                error!(cause = ?e);
                Ok((kit, Err(anyhow!(e))))
            }

            None => {
                warn!("stream finished");
                Ok((kit, Ok(())))
            }
        }
    }
}

/// Maximum number of concurrent connections the server will accept.
const MAX_CONNECTIONS: usize = 2;

/// Run the server.
///
/// Accepts connections from the supplied listener. For each inbound connection,
/// a task is spawned to handle that connection. The server runs until the
/// `shutdown` future completes, at which point the server shuts down
/// gracefully.
///
/// `tokio::signal::ctrl_c()` can be used as the `shutdown` argument. This will
/// listen for a SIGINT signal.
///
/// # Errors
///
/// Returns an error for listener related errors
pub async fn run(listener: TcpListener, cancel_token: CancellationToken) -> Result<()> {
    // When the provided `shutdown` future completes, we must send a shutdown
    // message to all active connections. We use a broadcast channel for this
    // purpose. The call below ignores the receiver of the broadcast pair, and when
    // a receiver is needed, the subscribe() method on the sender is used to create
    // one.
    let (notify_shutdown, _) = broadcast::channel(1);
    let (shutdown_complete_tx, mut _shutdown_complete_rx) = mpsc::channel(1);

    let serdis = SerDis::build()?;

    let mdns = Mdns::ServiceDaemon::new()?;
    let monitor = mdns.monitor()?;

    serdis.register(&mdns)?;

    // Initialize the listener state
    let mut server = Listener {
        listener,
        limit_connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        notify_shutdown: notify_shutdown.clone(),
        shutdown_complete_tx: shutdown_complete_tx.clone(),
    };

    // The `select!` macro is a foundational building block for writing
    // asynchronous Rust. See the API docs for more details:
    //
    // https://docs.rs/tokio/*/tokio/macro.select.html

    // we do not want the listener or signal::ctrl_c restarted on
    // invocation of select.  we wrap the async calls in a variable
    // for select to interrogate
    let listener_run = { server.run() };
    tokio::pin!(listener_run);

    let catch_shutdown = { signal::ctrl_c() };
    tokio::pin!(catch_shutdown);

    loop {
        tokio::select! {
            res = &mut listener_run => {
                // If an error is received here, accepting connections from the TCP
                // listener failed multiple times and the server is giving up and
                // shutting down.
                //
                // Errors encountered when handling individual connections do not
                // bubble up to this point.
                if let Err(err) = res {
                    error!(cause = %err, "failed to accept");
                }
                break;
            }

            res = &mut catch_shutdown => {
                if let Err(e) = res {
                    error!("catching ctrl-c: {}",e);
                }

                break;
            }

            event = monitor.recv_async() => mdns_report(event),

            _res = cancel_token.cancelled() => {
                info!("cancel requested");
                break;
            }
        }
    }

    drop(monitor);

    // Extract the `shutdown_complete` receiver and transmitter
    // explicitly drop `shutdown_transmitter`. This is important, as the
    // `.await` below would otherwise never complete.
    // let Listener {
    //      shutdown_complete_tx,
    //     notify_shutdown,
    //     ..
    // } = server;

    serdis.unregister(&mdns)?;

    // When `notify_shutdown` is dropped, all tasks which have `subscribe`d will
    // receive the shutdown signal and can exit
    drop(notify_shutdown);
    // Drop final `Sender` so the `Receiver` below can complete
    drop(shutdown_complete_tx);

    info!("waiting for complete shutdown");

    // Wait for all active connections to finish processing. As the `Sender`
    // handle held by the listener has been dropped above, the only remaining
    // `Sender` instances are held by connection handler tasks. When those drop,
    // the `mpsc` channel will close and `recv()` will return `None`.
    // let _ = shutdown_complete_rx.recv().await;

    Ok(()) // tlh
}

impl Listener {
    /// Run the server
    ///
    /// Listen for inbound connections. For each inbound connection, spawn a
    /// task to process that connection.
    ///
    /// # Errors
    ///
    /// Returns `Err` if accepting returns an error. This can happen for a
    /// number reasons that resolve over time. For example, if the underlying
    /// operating system has reached an internal limit for max number of
    /// sockets, accept will fail.
    ///
    /// The process is not able to detect when a transient error resolves
    /// itself. One strategy for handling this is to implement a back off
    /// strategy, which is what we do here.
    async fn run(&mut self) -> Result<()> {
        info!("accepting inbound connections");

        loop {
            // Wait for a permit to become available
            //
            // `acquire_owned` returns a permit that is bound to the semaphore.
            // When the permit value is dropped, it is automatically returned
            // to the semaphore.
            //
            // `acquire_owned()` returns `Err` when the semaphore has been
            // closed. We don't ever close the semaphore, so `unwrap()` is safe.
            let permit = self
                .limit_connections
                .clone()
                .acquire_owned()
                .await
                .unwrap();

            // Accept a new socket. This will attempt to perform error handling.
            // The `accept` method internally attempts to recover errors, so an
            // error here is non-recoverable.
            let socket = self.accept().await?;

            // Create the necessary per-connection handler state.
            let handler = Handler {
                // Initialize the connection state. This allocates read/write
                // buffers to perform redis protocol frame parsing.
                framed: codec::Rtsp::new().framed(socket),

                // Receive shutdown notifications.
                shutdown: Shutdown::new(&self.notify_shutdown),

                // Notifies the receiver half once all clones are
                // dropped.
                _shutdown_complete: self.shutdown_complete_tx.clone(),

                active: true,
            };

            // Spawn a new task to process the connections. Tokio tasks are like
            // asynchronous green threads and are executed concurrently.
            tokio::spawn(async move {
                // Process the connection. If an error is encountered, log it.

                if let Err(err) = Handler::run(handler).await {
                    error!(cause = ?err, "connection error");
                }
                // Move the permit into the task and drop it after completion.
                // This returns the permit back to the semaphore.
                drop(permit);
            });
        }
    }

    /// Accept an inbound connection.
    ///
    /// Errors are handled by backing off and retrying. An exponential backoff
    /// strategy is used. After the first failure, the task waits for 1 second.
    /// After the second failure, the task waits for 2 seconds. Each subsequent
    /// failure doubles the wait time. If accepting fails on the 6th try after
    /// waiting for 64 seconds, then this function returns with an error.
    async fn accept(&mut self) -> Result<TcpStream> {
        let mut backoff = 1;

        // Try to accept a few times
        loop {
            // Perform the accept operation. If a socket is successfully
            // accepted, return it. Otherwise, save the error.
            match self.listener.accept().await {
                Ok((socket, _)) => return Ok(socket),
                Err(err) => {
                    if backoff > 64 {
                        // Accept has failed too many times. Return the error.
                        return Err(err.into());
                    }
                }
            }

            // Pause execution until the back off period elapses.
            time::sleep(Duration::from_secs(backoff)).await;

            // Double the back off
            backoff *= 2;
        }
    }
}

use mdns_sd::DaemonEvent;
use std::fmt::Debug;

fn mdns_report<E: Debug>(event: anyhow::Result<DaemonEvent, E>) {
    match event {
        Ok(event) => {
            info!("mdns event: {event:?}");
        }
        Err(e) => {
            error!("mdns error: {e:?}");
        }
    }
}
