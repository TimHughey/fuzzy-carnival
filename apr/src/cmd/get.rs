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

use crate::cmd::RespCode;
use crate::{ContentType, Particulars, Session};
use crate::{Frame, Result};

use anyhow::anyhow;
use plist::Dictionary;
#[allow(unused_imports)]
use tracing::{error, info};

#[derive(Debug)]
pub struct Get {
    #[allow(dead_code)]
    frame_in: Frame,
    dict: Option<Dictionary>,
    // ...
}

impl Get {
    pub fn apply_frame(frame_in: Frame) -> Result<Get> {
        use plist::Value::Integer as ValInt;
        use plist::Value::String as ValString;

        const QUALIFIER: &str = "qualifier";
        const QUALIFIER_VAL: Option<&str> = Some("txtAirPlay");

        // any path other than /info is invalid
        match frame_in.path_and_content() {
            // stage one: dictionary contains qualifier (txtAirPlay)
            ("/info", ContentType::Plist(dict)) => {
                let q = dict
                    .get(QUALIFIER)
                    .and_then(plist::Value::as_array)
                    .and_then(|a| a.first())
                    .and_then(plist::Value::as_string);

                if QUALIFIER_VAL == q {
                    info!("found qualifier txtAirPlay");
                }

                let pars = Particulars::global();

                let feat_flags = ValInt(pars.feature_bits().into());
                let stat_flags = ValInt(pars.status_bits().into());
                let dev_id = ValString(pars.device_id());
                let serv_name = ValString(pars.service_name.clone());

                let key_vals = [
                    ("features".to_string(), feat_flags),
                    ("statusFlags".to_string(), stat_flags),
                    ("deviceID".to_string(), dev_id.clone()),
                    ("pi".to_string(), dev_id),
                    ("name".to_string(), serv_name),
                    ("model".to_string(), ValString("Hughey".into())),
                ];

                let xml = include_bytes!("../../plists/get_info_resp.plist");
                let mut dict: Dictionary = plist::from_bytes(xml)?;

                for (k, v) in key_vals {
                    dict.insert(k, v);
                }

                info!("created cmd::Get");

                Ok(Get {
                    frame_in,
                    dict: Some(dict),
                })
            }

            // stage two: no content
            ("/info", ContentType::Empty) => Ok(Get {
                frame_in,
                dict: None,
            }),

            // invalid GET
            (path, content_type) => Err(anyhow!("unknown GET {path} {:?}", content_type)),
        }
    }

    pub(crate) async fn apply(self, dst: &mut Session) -> Result<()> {
        let Get { dict, .. } = self;

        let content = match dict {
            Some(dict) => ContentType::Plist(dict),
            None => ContentType::Empty,
        };

        let seq_num = self.frame_in.seq_num()?;

        info!("preparing to write reply for seq_num={}", seq_num);

        dst.write_reply(seq_num, content, RespCode::Ok).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn can_get_embedded_info_plist() -> crate::Result<()> {
        use plist::Dictionary;

        let bytes = include_bytes!("../../plists/get_info_resp.plist");
        let mut dict: Dictionary = plist::from_bytes(bytes)?;

        assert!(dict.len() == 9);

        dict.insert("features".into(), 0x4000.into());

        assert!(dict.len() == 10);

        let val = dict.get("features");

        assert!(val.is_some());

        let val = val.unwrap();

        assert!(val.as_string().is_none());
        assert!(val.as_unsigned_integer().is_some());
        assert!(val.as_unsigned_integer().unwrap() == 0x4000);

        Ok(())
    }
}
