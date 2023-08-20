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
pub struct HeaderMap {
    inner: IndexMap<String, String>,
}

const CONTENT_LEN: &str = "Content-Length";

impl HeaderMap {
    pub fn append(&mut self, src: &str) -> Result<()> {
        if !src.contains(':') {
            Err(anyhow!("not a header: {}", src))
        } else {
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
        }
    }

    pub fn content_len(&self) -> Result<Option<usize>> {
        if let Some(len) = self.inner.get(CONTENT_LEN) {
            return Ok(Some(len.parse::<usize>()?));
        }

        Ok(None)
    }

    pub fn headers(&self) -> &IndexMap<String, String> {
        &self.inner
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn new() -> HeaderMap {
        HeaderMap {
            inner: IndexMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::HeaderMap;
    use crate::Result;

    const CONTENT_LEN_LINE: &str = "Content-Length: 30";

    #[test]
    fn can_append_header() -> Result<()> {
        let mut hdr_map = HeaderMap::new();

        let res = hdr_map.append(CONTENT_LEN_LINE);

        assert!(res.is_ok());

        Ok(())
    }

    #[test]
    fn can_get_content_len_when_present() -> Result<()> {
        let mut hdr_map = HeaderMap::new();

        hdr_map.append(CONTENT_LEN_LINE)?;

        let len = hdr_map.content_len()?;

        assert_eq!(Some(30), len);

        Ok(())
    }
}
