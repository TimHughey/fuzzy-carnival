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
use std::env;
use tokio::net::TcpListener;
use tokio_stream::StreamExt;
use tokio_util::codec::Decoder;
use tracing::{error, info};

#[tokio::main]
async fn main() -> apr::Result<()> {
    // Allow passing an address to listen on as the first argument of this
    // program, but otherwise we'll just set up our TCP listener on
    // 127.0.0.1:8080 for connections.
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "192.168.2.4:7000".to_string());

    setup_logging()?;

    // Next up we create a TCP listener which will listen for incoming
    // connections. This TCP listener is bound to the address we determined
    // above and must be associated with an event loop, so we pass in a handle
    // to our event loop. After the socket's created we inform that we're ready
    // to go and start accepting connections.
    let listener = TcpListener::bind(&addr).await?;
    println!("Listening on: {}", addr);

    loop {
        // Asynchronously wait for an inbound socket.
        let (socket, _) = listener.accept().await?;

        // And this is where much of the magic of this server happens. We
        // crucially want all clients to make progress concurrently, rather than
        // blocking one on completion of another. To achieve this we use the
        // `tokio::spawn` function to execute the work in the background.
        //
        // Essentially here we're executing a new task to run concurrently,
        // which will allow all of our clients to be processed concurrently.
        tokio::spawn(async move {
            // We're parsing each socket with the `BytesCodec` included in `tokio::codec`.

            use apr::rtsp::codec::Rtsp;
            let mut framed = Rtsp::new().framed(socket);

            //  let mut framed = LinesCodec::new().framed(socket);

            // We loop while there are messages coming from the Stream `framed`.
            // The stream will return None once the client disconnects.
            while let Some(maybe_frame) = framed.next().await {
                match maybe_frame {
                    Ok(frame) => info!("got frame: {}", frame),
                    Err(err) => error!("socket closed with error: {:?}", err),
                }
            }

            info!("socket received FIN packet and closed connection");
        });
    }
}

fn setup_logging() -> apr::Result<()> {
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
