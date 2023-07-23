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

use std::{
    error::{self},
    time::{Duration, Instant},
};

use tokio::task::JoinSet;

use apr::ApReceiver;
#[tokio::main]
async fn main() -> Result<(), Box<dyn error::Error>> {
    let receiver = ApReceiver::new()?;
    let mut tasks = JoinSet::new();

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
