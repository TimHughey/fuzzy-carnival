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

use crate::Result;
use anyhow::anyhow;
use bytes::BytesMut;
use chrono::Local;
use std::{io, path::PathBuf};

#[derive(Debug)]
pub(crate) struct BinSave {
    path_base: PathBuf,
}

impl Default for BinSave {
    fn default() -> Self {
        BinSave::new().expect("BinSave new failed")
    }
}

#[allow(unused)]
impl BinSave {
    pub const ALL: &str = "all";
    pub const ERR: &str = "err";
    pub const IN: &str = "in";
    pub const OUT: &str = "out";

    pub fn new() -> Result<Self> {
        use std::env::var;

        const KEY: &str = "CARGO_MANIFEST_DIR";

        let now = Local::now();
        let base: PathBuf = var(KEY).map_err(|e| anyhow!(e))?.into();
        let mut base = base.parent().unwrap().to_path_buf();
        base.push("extra/run");
        base.push(format!("{}", now.format("%s")));

        std::fs::create_dir_all(&base)?;

        Ok(Self { path_base: base })
    }

    pub fn persist(&self, buf: &[u8], kind: &str, cseq: Option<u32>) -> Result<()> {
        use io::Write;

        let mut path = self.path_base.clone();

        if let Some(cseq) = cseq {
            path.push(format!("{cseq:03}-{kind}.bin"));
        } else {
            path.push(format!("{kind}.bin"));
        }

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .append(true)
            .open(path)?;

        file.write_all(buf)?;

        if kind == Self::ALL {
            let sep = b"\x00!*!*!*\x00";
            file.write_all(sep)?;
        }

        Ok(())
    }
}

// Right now `write!` on `Vec<u8>` goes through io::Write and is not
// super speedy, so inline a less-crufty implementation here which
// doesn't go through io::Error.
pub(crate) struct BytesWrite<'a>(pub &'a mut BytesMut);

impl std::io::Write for BytesWrite<'_> {
    fn write(&mut self, s: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(s);
        Ok(s.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
