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
use apr::{server, Result};

use tokio::{net::TcpListener, signal};
use tracing::info;

#[tokio::main(worker_threads = 10)]
pub async fn main() -> crate::Result<()> {
    setup_logging()?;

    let (_mac_addr, host_ip) = server::get_net()?;

    let bind_addr = format!("{}:{}", host_ip, 7000);

    // let cli = Cli::parse();
    // let port = cli.port.unwrap_or(DEFAULT_PORT);

    // Bind a TCP listener
    info!("binding to {}", bind_addr);
    let listener = TcpListener::bind(&bind_addr).await?;

    server::run(listener, signal::ctrl_c()).await
}

fn setup_logging() -> Result<()> {
    let subscriber = tracing_subscriber::fmt()
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
        .try_init();

    if let Err(e) = subscriber {
        return Err(anyhow!(e));
    }

    Ok(())
}
