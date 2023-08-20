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

mod get;
pub use get::Get;

use crate::{frame::Request, Frame, Result, Session};
use anyhow::anyhow;

use lazy_static::lazy_static;
use std::collections::BTreeMap;
lazy_static! {
    static ref LOOKUP4: BTreeMap<RespCode, String> = {
        use RespCode::*;
        BTreeMap::from_iter([
            (AuthRequired, "407 Connection Authorization Required".into()),
            (BadRequest, "400 Bad Request".into()),
            (Continue, "100 Continue".into()),
            (InternalServerError, "500 Internal Server Error".into()),
            (NotImplemented, "501 Not Implemented".into()),
            (Ok, "200 OK".into()),
            (Unauthorized, "403 Unauthorized".into()),
            (Unavailable, "451 Unavailable".into()),
        ])
    };
}

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum RespCode {
    AuthRequired,
    BadRequest,
    Continue,
    #[default]
    InternalServerError,
    NotImplemented,
    Ok,
    Unauthorized,
    Unavailable,
}

#[allow(unused)]
impl RespCode {
    pub fn to_string(&self) -> &String {
        LOOKUP4.get(self).unwrap()
    }
}

#[derive(Debug)]
pub enum Command {
    Get(Get),
    Unknown(String),
}

impl Command {
    /// Parse a command from a received frame.
    ///
    /// The `Frame` must represent a RTP client request
    ///
    /// # Returns
    ///
    /// On success, the command value is returned, otherwise, `Err` is returned.
    pub fn from_frame(frame: Frame) -> crate::Result<Command> {
        // The frame value is decorated with `Parse`. `Parse` provides a
        // "cursor" like API which makes parsing the command easier.
        //

        let Request { method, .. } = &frame.request;

        let command_name = method.to_lowercase();

        // Match the command name, delegating the rest of the parsing to the
        // specific command.
        let command = match &command_name[..] {
            "get" => Command::Get(Get::apply_frame(frame)?),
            // "publish" => Command::Publish(Publish::parse_frames(&mut parse)?),
            // "set" => Command::Set(Set::parse_frames(&mut parse)?),
            // "subscribe" => Command::Subscribe(Subscribe::parse_frames(&mut parse)?),
            // "unsubscribe" => Command::Unsubscribe(Unsubscribe::parse_frames(&mut parse)?),
            // "ping" => Command::Ping(Ping::parse_frames(&mut parse)?),
            _ => {
                // The command is not recognized and an Unknown command is
                // returned.
                //
                // `return` is called here to skip the `finish()` call below. As
                // the command is not recognized, there is most likely
                // unconsumed fields remaining in the `Parse` instance.
                // return Ok(Command::Unknown(Unknown::new(command_name)));
                return Ok(Command::Unknown(command_name));
            }
        };

        // The command has been successfully parsed
        Ok(command)
    }

    pub(crate) async fn apply(self, dst: &mut Session) -> Result<()> {
        use Command::*;

        match self {
            Get(cmd) => cmd.apply(dst).await,
            Unknown(v) => Err(anyhow!("unknown command from client: {}", v)),
        }
    }
}
