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
use arrayvec::ArrayVec;
use indexmap::IndexMap;

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct Map {
    inner: IndexMap<String, String>,
}

const CONTENT_LEN: &str = "Content-Length";

impl Map {
    /// # Errors
    ///
    /// Will return `Err` if `filename` does not exist or the user does not have
    /// permission to read it.
    pub fn append(&mut self, src: &str) -> Result<()> {
        if src.contains(':') {
            const MAX_PARTS: usize = 2;
            const KEY: usize = 0;
            const VAL: usize = 1;

            let p: ArrayVec<&str, 2> = src
                .split_ascii_whitespace()
                .map(|s| s.trim_end_matches(':'))
                .take(MAX_PARTS)
                .collect();

            self.inner.insert(p[KEY].into(), p[VAL].into());

            Ok(())
        } else {
            Err(anyhow!("not a header: {}", src))
        }
    }

    /// # Errors
    ///
    /// Returns Err if content length key has a value and it
    /// can not be parsed into a usize
    pub fn content_len(&self) -> Result<Option<usize>> {
        if let Some(len) = self.inner.get(CONTENT_LEN) {
            return Ok(Some(len.parse::<usize>()?));
        }

        Ok(None)
    }

    #[allow(clippy::must_use_candidate)]
    pub fn headers(&self) -> &IndexMap<String, String> {
        &self.inner
    }

    #[allow(clippy::must_use_candidate)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[allow(clippy::must_use_candidate)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[must_use]
    pub fn new() -> Map {
        Map {
            inner: IndexMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::Map;
    use crate::Result;

    const CONTENT_LEN_LINE: &str = "Content-Length: 30";

    #[test]
    fn can_append_header() {
        let mut hdr_map = Map::new();

        let res = hdr_map.append(CONTENT_LEN_LINE);

        assert!(res.is_ok());
    }

    #[test]
    fn can_get_content_len_when_present() -> Result<()> {
        let mut hdr_map = Map::new();

        hdr_map.append(CONTENT_LEN_LINE)?;

        let len = hdr_map.content_len()?;

        assert_eq!(Some(30), len);

        Ok(())
    }
}
