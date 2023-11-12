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
use bytes::BytesMut;
use chrono::Local;
use std::{io, path::PathBuf};

pub mod bin_save {
    use crate::Result;
    use anyhow::anyhow;
    use std::path::PathBuf;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Cat {
        Rtsp,
        Ptp,
    }

    impl Cat {
        pub fn base(self) -> PathBuf {
            use Cat::{Ptp, Rtsp};

            const FALLBACK: &str = "/tmp/pierre/run";
            const RTSP_KEY: &str = "APR_RTSP_BIN_SAVE";
            const PTP_KEY: &str = "APR_PTP_BIN_SAVE";

            match self {
                Rtsp => Self::get_var(RTSP_KEY)
                    .unwrap_or_else(|_x| format!("{FALLBACK}/rtsp"))
                    .into(),
                Ptp => Self::get_var(PTP_KEY)
                    .unwrap_or_else(|_x| format!("{FALLBACK}/ptp"))
                    .into(),
            }
        }

        fn get_var(key: &str) -> Result<String> {
            use std::env::var;

            var(key).map_err(|e| anyhow!("{key}: {e}"))
        }
    }
}

pub(crate) use bin_save::Cat as BinSaveCat;

#[derive(Debug)]
pub(crate) struct BinSave {
    cat: bin_save::Cat,
    path_base: PathBuf,
}

#[allow(unused)]
impl BinSave {
    pub const ALL: &str = "all";
    pub const ERR: &str = "err";
    pub const IN: &str = "in";
    pub const OUT: &str = "out";

    pub fn new(cat: bin_save::Cat) -> Result<Self> {
        use std::env::var;

        let now = Local::now();
        let mut base = cat.base();
        base.push(format!("{}", now.format("%s")));

        std::fs::create_dir_all(&base)?;

        Ok(Self {
            cat,
            path_base: base,
        })
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

        if kind.contains(Self::ALL) && self.cat != bin_save::Cat::Ptp {
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
