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

use super::{anyhow, Buf, BytesMut, Result};

pub fn make_array_n<const N: usize>(src: &mut BytesMut) -> Result<[u8; N]> {
    if src.len() >= N {
        let mut buf = src.split_to(N);

        let mut array = [0u8; N];
        buf.copy_to_slice(array.as_mut());

        src.unsplit(buf);

        return Ok(array);
    }

    let error = "insufficient bytes";
    tracing::error!("{error}: {N} > {}", src.len());

    Err(anyhow!(error))
}
