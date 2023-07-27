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

use apr::server;
use apr::ApReceiver;

use std::time::{Duration, Instant};
use tokio::{net::TcpListener, signal, task::JoinSet};
use tracing::info;

#[tokio::main]
pub async fn main() -> apr::Result<()> {
    set_up_logging()?;

    let receiver = ApReceiver::new()?;
    let mut tasks = JoinSet::new();

    let bind_addr = receiver.bind_address();

    // let cli = Cli::parse();
    // let port = cli.port.unwrap_or(DEFAULT_PORT);

    tasks.spawn(async move {
        let monitor = receiver.monitor();

        let start_at = Instant::now();
        let max_runtime = Duration::from_secs(30);
        let recv_timeout = Duration::from_millis(777);

        while start_at.elapsed() <= max_runtime {
            if let Ok(event) = monitor.recv_timeout(recv_timeout) {
                info!("daemon event: {:?}", event);
            }
        }

        receiver.shutdown();
    });

    // Bind a TCP listener
    info!("binding to {}", bind_addr);
    let listener = TcpListener::bind(&bind_addr).await?;

    server::run(listener, signal::ctrl_c()).await;

    while let Some(res) = tasks.join_next().await {
        match res {
            Ok(_) => info!("joined task"),
            Err(e) => info!("join task error: {}", e),
        }
    }

    Ok(())
}

fn set_up_logging() -> apr::Result<()> {
    // See https://docs.rs/tracing for more info
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .try_init()
}
