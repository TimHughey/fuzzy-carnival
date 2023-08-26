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
use apr::{server, Particulars, Result};
use std::env;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

#[tokio::main(worker_threads = 10)]

///
///
/// # Errors
///
///
pub async fn main() -> crate::Result<()> {
    setup_logging()?;

    // let cli = Cli::parse();
    // let port = cli.port.unwrap_or(DEFAULT_PORT);

    let particulars = Particulars::build()?.unwrap();

    // Allow passing an address to listen on as the first argument of this
    // program, but otherwise we'll just set up our TCP listener on
    // 127.0.0.1:8080 for connections.
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| particulars.bind_address());

    // let bind_addr = particulars.unwrap().bind_address();

    // Bind a TCP listener
    info!("binding to {}", addr);
    let listener = TcpListener::bind(&addr).await?;

    let cancel_token = CancellationToken::new();
    let cancel_token2 = cancel_token.clone();

    info!("cancel token created {:?}", cancel_token);

    let handle = tokio::spawn(async move {
        let cancel_token = cancel_token2;

        match server::run(listener, cancel_token).await {
            Ok(()) => info!("server has shutdown"),
            Err(e) => error!("server error: {}", e),
        }
    });

    Ok(handle.await?)
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
