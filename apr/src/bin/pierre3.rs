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

use anyhow::anyhow;
use apr::{serdis::SerDis, HostInfo, Kit, Result};
use mdns_sd::{self as Mdns, DaemonEvent};
use std::env;
use tokio::{net::TcpListener, signal, sync::oneshot};
use tokio_util::sync::CancellationToken;

///
///
/// # Errors
///
/// Returns errors for any failure related to establishing
/// the base app runtime information (e.g. hostname) or setup
/// of the networking socket.
#[tokio::main(worker_threads = 4)]
pub async fn main() -> crate::Result<()> {
    setup_logging()?;
    let cancel_token = CancellationToken::new();
    let main_cancel_token = cancel_token.clone();
    let kit_cancel_token = cancel_token.clone();

    let bind_addr = env::args()
        .nth(1)
        .unwrap_or_else(|| HostInfo::bind_address(7000));

    // Bind a TCP listener
    tracing::info!("starting up, binding to {}", bind_addr);
    let listener = TcpListener::bind(&bind_addr).await?;

    // let ptp_sock1 = tokio::net::UdpSocket::bind("0.0.0.0:319").await?;
    // tracing::info!("opened udp port {}", ptp_sock1.local_addr()?);

    let (main_tx, mut main_rx) = oneshot::channel();

    let main_handle = tokio::spawn(async move {
        let ctrl_c = { signal::ctrl_c() };
        tokio::pin!(ctrl_c);

        let serdis = SerDis::build().expect("SerDis build failed");
        let mdns = Mdns::ServiceDaemon::new().expect("ServiceDaemon creation failed");
        serdis.register(&mdns).expect("MDNS registration failed");

        let monitor = mdns.monitor().expect("MDNS monitor creation failed");

        loop {
            tokio::select! {
                _ = &mut ctrl_c => {
                    tracing::warn!("caught ctrl-c, issuing cancel");
                    break;
                },
                mdns_event = monitor.recv_async() => mdns_report(mdns_event),
                _ = main_cancel_token.cancelled() => {
                    tracing::warn!("main task cancelled");
                    break;
                }
            }
        }

        if let Err(e) = serdis.unregister(&mdns) {
            tracing::warn!("ServiceDiscovery MDNS unregister failed: {e}");
        }

        mdns.shutdown().expect("MDNS shutdown failed");
        main_tx.send("main".to_string()).unwrap();
    });

    let (kit_tx, mut kit_rx) = oneshot::channel();

    let kit_handle = tokio::spawn(async move {
        match Kit::run(listener, kit_cancel_token).await {
            Ok(()) => tracing::info!("kit has shutdown gracefully"),
            Err(e) => tracing::error!("kit error: {e}"),
        }

        kit_tx.send("kit".to_string()).unwrap();
    });

    let mut main_end = None;
    let mut kit_end = None;

    while main_end.is_none() && kit_end.is_none() {
        tokio::select! {
            v1 = (&mut main_rx), if main_end.is_none() => main_end = Some(v1.unwrap()),
            v2 = (&mut kit_rx), if kit_end.is_none() => kit_end = Some(v2.unwrap()),
        }

        cancel_token.cancel();
    }

    let _res = tokio::join!(main_handle, kit_handle);

    let res = (
        main_end.unwrap_or_else(|| "main none".to_string()),
        kit_end.unwrap_or_else(|| "kit none".to_string()),
    );

    tracing::info!("{res:?} exiting");

    Ok(())
}

fn mdns_report<E: std::fmt::Debug>(event: anyhow::Result<DaemonEvent, E>) {
    use DaemonEvent::Announce;

    match event {
        Ok(Announce(service, _ip)) => tracing::info!("{service} announced"),
        Ok(event) => tracing::warn!("{event:?}"),
        Err(e) => tracing::error!("mdns error: {e:#?}"),
    }
}

#[inline]
fn setup_logging() -> Result<()> {
    tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .compact()
        // Display source code file paths
        .with_file(true)
        // Display source code line numbers
        .with_line_number(true)
        // Display the thread ID an event was recorded on
        .with_thread_ids(true)
        // Don't display the event's target (module path)
        .with_target(false)
        // hard code max logging level (for now)
        .with_max_level(tracing::Level::INFO)
        .try_init()
        .map_err(|e| anyhow!(e))
}
