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
use apr::{Particulars, Result};
#[allow(unused)]
use bytes::{BufMut, BytesMut};
#[allow(unused)]
use plist::Dictionary;
use pretty_hex::*;
use std::io::ErrorKind;
#[allow(unused)]
use std::{
    fs::{File, OpenOptions},
    path::Path,
};
#[allow(unused)]
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::StreamExt;
#[allow(unused)]
use tokio_util::codec::{Decoder, Encoder, Framed};
use tokio_util::codec::{LinesCodec, LinesCodecError};

// use tokio::net::TcpListener;
// use tokio_util::sync::CancellationToken;
#[allow(unused)]
use tracing::{error, info};

#[tokio::main(worker_threads = 2)]
pub async fn main() -> crate::Result<()> {
    setup_logging()?;

    // let bytes = include_bytes!("../../plists/get_info_resp.plist");
    // let dict: Dictionary = plist::from_bytes(bytes)?;
    // let mut bulk = BytesMut::new();
    // bulk.extend_from_slice(b"RTSP/1.0\r\n");
    // let mut writer = bulk.writer();
    // write!(&mut writer, "Server: AirPierre/366.0\r\n")?;
    // plist::to_writer_binary(&mut writer, &dict)?;
    // let buf = writer.into_inner();
    // info!("buf len after plist encode: {}", buf.len());
    // info!("{}", buf.hex_dump());
    // let path = Path::new("foo");
    // let mut file = OpenOptions::new().create(true).write(true).open(path)?;
    // write!(&mut file, "hello\r\n")?;

    let particulars = Particulars::build()?;
    let bind_addr = particulars.unwrap().bind_address();

    // Bind a TCP listener
    info!("binding to {}", bind_addr);
    let listener = TcpListener::bind(&bind_addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = process(stream).await {
                println!("failed to process connection; error = {}", e);
            }
        });
    }

    // Ok(())
}

async fn process(stream: TcpStream) -> Result<()> {
    // let seek_delimiters = b"\r\n\r\n".to_vec();
    // let sequence_writer = seek_delimiters.clone();
    let codec = LinesCodec::new();

    let mut transport = Framed::with_capacity(stream, codec, 4096);

    while let Some(line) = transport.next().await {
        match line {
            Ok(line) if !line.is_empty() => {
                info!("\n{:?}", line.hex_dump());

                let pieces = line.split_ascii_whitespace().collect::<Vec<&str>>();

                match pieces.len() {
                    3 => {
                        info!("STATUS {}", line);
                    }
                    2 => {
                        info!("HEADER {}", line)
                    }
                    _ => {
                        error!("UNKOWN {}", line)
                    }
                }

                // let response = respond(request).await?;
                // transport.send(response).await?;
            }
            Ok(_request) => {
                let x = transport.read_buffer_mut();
                let len = x.len();

                info!("BYTES REMAINING={}\n{:?}", len, x.hex_dump());

                // transport.x.truncate(len);
            }
            Err(LinesCodecError::Io(e)) if e.kind() == ErrorKind::InvalidData => {
                let x = transport.read_buffer_mut();

                if !x.is_empty() {
                    info!("NOT UTF8\n{:?}", x.hex_dump());
                } else {
                    info!("skipping empty line");
                }
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

// struct Rtsp;

// pub struct Request<T> {
//     head: Parts,
//     body: T,
// }

/// Component parts of an HTTP `Response`
///
/// The HTTP response head consists of a status, version, and a set of
/// header fields.
// pub struct Parts {
//     /// The response's status
//     pub status: StatusCode,

//     /// The response's version
//     pub version: Version,

//     /// The response's headers
//     pub headers: HeaderMap<HeaderValue>,

//     /// The response's extensions
//     pub extensions: Extensions,

//     _priv: (),
// }

/// An HTTP response builder
///
/// This type can be used to construct an instance of `Response` through a
/// builder-like pattern.
// #[derive(Debug)]
// pub struct Builder {
//     inner: Result<Parts>,
// }

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
