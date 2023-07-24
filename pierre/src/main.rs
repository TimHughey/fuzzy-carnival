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

extern crate plist;
//#[macro_use]
extern crate serde_derive;

use apr::ApReceiver;
use bstr::{ByteSlice, B};
use plist::Dictionary;
use std::{
    error::{self},
    time::{Duration, Instant},
};

use tokio::{io::AsyncReadExt, net::TcpListener, task::JoinSet};

#[tokio::main]
async fn main() -> Result<(), Box<dyn error::Error>> {
    let receiver = ApReceiver::new()?;
    let mut tasks = JoinSet::new();

    let bind_addr = receiver.bind_address();
    let listener = TcpListener::bind(&bind_addr).await?;

    let start_at = Instant::now();
    let max_runtime = Duration::from_secs(30);

    // delimiter between RTP prelude and data
    let splitter = B("\r\n\r\n");

    tasks.spawn(async move {
        while start_at.elapsed() <= max_runtime {
            let res = listener.accept().await;
            match res {
                Ok((mut socket, _)) => {
                    let mut buf = [0; 1024];
                    let start_at = Instant::now();

                    while start_at.elapsed() <= max_runtime {
                        match socket.read(&mut buf).await {
                            Ok(n) if n == 0 => break,
                            Ok(n) => {
                                // split the reeived buffer into the prelude and data parts
                                let parts = &buf[0..n].split_str(splitter).collect::<Vec<_>>();

                                println!("parts len={}", parts.len());

                                parts.iter().for_each(|p| match p.to_str() {
                                    Ok(part) => {
                                        let lines: Vec<&str> = part.split("\r\n").collect();

                                        println!("lines:\n{:?}", lines);
                                    }
                                    Err(_e) => {
                                        if let Ok(dict) = plist::from_bytes::<Dictionary>(&p[..]) {
                                            println!("{:?}", dict);
                                        }
                                    }
                                });
                            }

                            Err(e) => {
                                println!("failed to read from socket; err = {:?}", e);
                                break;
                            }
                        };
                    }
                }
                Err(e) => println!("accept error: {e}"),
            }
        }
    });

    tasks.spawn(async move {
        let monitor = receiver.monitor();

        let start_at = Instant::now();
        let max_runtime = Duration::from_secs(30);
        let recv_timeout = Duration::from_millis(777);

        while start_at.elapsed() <= max_runtime {
            if let Ok(event) = monitor.recv_timeout(recv_timeout) {
                println!("Daemon event: {:?}", event);
            }
        }

        receiver.shutdown();
    });

    while let Some(res) = tasks.join_next().await {
        match res {
            Ok(_) => println!("joined task"),
            Err(e) => println!("join task error: {}", e),
        }
    }

    Ok(())
}
