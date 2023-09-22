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

use crate::{
    rtsp::{codec, Frame, Response},
    HomeKit,
};
use crate::{Result, Shutdown};
use anyhow::anyhow;
use futures::SinkExt;
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_util::codec::Decoder;
#[allow(unused)]
use tracing::{debug, error, info};

/// Send and receive `Frame` values from a remote peer.
///
/// When implementing networking protocols, a message on that protocol is
/// often composed of several smaller messages known as frames. The purpose of
/// `Session` is to read and write frames on the underlying `TcpStream`.
///
/// To read frames, the `Session` uses an internal buffer, which is filled
/// up until there are enough bytes to create a full frame. Once this happens,
/// the `Session` creates the frame and returns it to the caller.
///
/// When sending frames, the frame is first encoded into the write buffer.
/// The contents of the write buffer are then written to the socket.
#[derive(Debug)]
pub struct Session {
    // The `TcpStream`. It is decorated with a `BufWriter`, which provides write
    // level buffering. The `BufWriter` implementation provided by Tokio is
    // sufficient for our needs.
    framed: tokio_util::codec::Framed<TcpStream, codec::Rtsp>,
    homekit: Option<HomeKit>,

    frame: Option<Frame>,

    active: bool,
    shutdown: Shutdown,
}

impl Session {
    /// Create a new `Session`, backed by `socket`.
    /// Read and write buffers are initialized.
    ///
    /// # Panics
    ///
    pub fn new(socket: TcpStream, notify_shutdown: &broadcast::Sender<()>) -> Session {
        let homekit = HomeKit::build();

        match homekit {
            Ok(homekit) => Session {
                framed: codec::Rtsp::new().framed(socket),
                homekit: Some(homekit),
                frame: None,
                active: true,
                shutdown: Shutdown::new(notify_shutdown),
            },
            Err(e) => {
                error!("failed to build homekit: {e}");
                panic!("aborting");
            }
        }
    }

    ///
    /// # Errors
    ///
    /// May return socket error
    pub fn handle_frame(&mut self, maybe_frame: Option<Result<Frame>>) -> Result<Option<Response>> {
        match maybe_frame {
            Some(Ok(frame)) => {
                info!("got frame: {}", frame);

                let response = Response::respond_to(frame)?;

                info!("response:\n{response}");

                self.active = true;

                Ok(Some(response))
            }

            Some(Err(e)) => {
                error!("socket closed: {e}");
                self.frame = None;

                Err(anyhow!(e))
            }

            None => Ok(None),
        }
    }

    ///
    /// # Errors
    ///
    ///
    pub async fn run(&mut self) -> Result<()> {
        while !self.shutdown.is_shutdown() && self.active {
            // default to end of session and override below if session
            // remains active
            self.active = false;

            tokio::select! {
                maybe_frame = self.framed.next() => {

                    match self.handle_frame(maybe_frame) {
                        Ok(Some(response)) => {
                            self.framed.send(response).await?;
                            self.active = true;
                        },

                        Err(e) => {
                            self.active = false;
                            error!("handle_frame: {e:?}");
                            Err(anyhow!(e))?;
                        },

                        res => {
                            info!("handle frame: {res:?}");
                        }
                    }
                }

                _res = self.shutdown.recv() => {
                    info!("session shutdown");
                }
            }
        }

        info!("session closing...");

        Ok(())
    }

    /// .
    ///
    /// # Panics
    ///
    /// Panics if .
    pub fn take_homekit(self) -> (Self, HomeKit) {
        if self.homekit.is_none() {
            error!("Session does not contain HomeKit");
            panic!("aborting");
        }

        let Session { homekit, .. } = self;

        (
            Session {
                homekit: None,
                ..self
            },
            homekit.unwrap(),
        )
    }

    #[must_use]
    pub fn put_homekit(self, homekit: HomeKit) -> Self {
        Session {
            homekit: Some(homekit),
            ..self
        }
    }

    // #[allow(unused)]
    // pub(crate) async fn write_reply(
    //     &mut self,
    //     seq_num: u32,
    //     content: ContentType,
    //     resp_code: RespCode,
    // ) -> Result<()> {
    //     let writer = Cursor::new(self.stream.buffer());

    //     // let mut buf = Vec::from("RTSP/1.0 ");

    //     // let x = buf.as_

    //     // write!(writer, "{}\r\n", resp_code.to_string())?;

    //     // let mut hdrs: Vec<(String, String)> = Vec::new();
    //     // hdrs.push(("CSeq".into(), seq_num.to_string()));
    //     // hdrs.push(("Server".into(), "AirPierre/366.0".into()));

    //     // match content {
    //     //     ContentType::Plist(dict) => {
    //     //         plist::to_writer_binary(&mut ccursor, &dict)?;

    //     //         hdrs.push((
    //     //             "ContentType".into(),
    //     //             "application/x-apple-binary-plist".into(),
    //     //         ));

    //     //         hdrs.push(("ContentLength".into(), (ccursor.position() + 1).to_string()));

    //     //         write!(cursor, "\r\n")?;

    //     //         for (key, val) in hdrs {
    //     //             write!(cursor, "{key}: {val}\r\n")?;
    //     //         }

    //     //         write!(cursor, "\r\n")?;

    //     //         info!("message (without body):\n{:#?}\n", cursor);

    //     //         let len = cursor.write(ccursor.get_ref())?;

    //     //         info!("added message body len={len}");
    //     //     }
    //     //     ContentType::Empty => (),
    //     //     _ => (),
    //     // }

    //     // info!("preparing to write bytes={}", cursor.position());

    //     // self.stream.write_all_buf(&mut cursor).await?;
    //     self.stream.flush().await?;

    //     // info!("after write cursor position={}", cursor.position());

    //     Ok(())
    // }

    // /// Write a single `Frame` value to the underlying stream.
    // ///
    // /// The `Frame` value is written to the socket using the various `write_*`
    // /// functions provided by `AsyncWrite`. Calling these functions directly on
    // /// a `TcpStream` is **not** advised, as this will result in a large number of
    // /// syscalls. However, it is fine to call these functions on a *buffered*
    // /// write stream. The data will be written to the buffer. Once the buffer is
    // /// full, it is flushed to the underlying socket.
    // pub async fn write_frame(&mut self, _frame: &Frame) -> Result<()> {
    //     // Arrays are encoded by encoding each entry. All other frame types are
    //     // considered literals. For now, mini-redis is not able to encode
    //     // recursive frame structures. See below for more details.
    //     // match frame {
    //     //     Frame::Array(val) => {
    //     //         // Encode the frame type prefix. For an array, it is `*`.
    //     //         self.stream.write_u8(b'*').await?;

    //     //         // Encode the length of the array.
    //     //         self.write_decimal(val.len() as u64).await?;

    //     //         // Iterate and encode each entry in the array.
    //     //         for entry in &**val {
    //     //             self.write_value(entry).await?;
    //     //         }
    //     //     }
    //     //     // The frame type is a literal. Encode the value directly.
    //     //     _ => self.write_value(frame).await?,
    //     // }

    //     // Ensure the encoded frame is written to the socket. The calls above
    //     // are to the buffered stream and writes. Calling `flush` writes the
    //     // remaining contents of the buffer to the socket.
    //     self.stream.flush().await?;

    //     Ok(())
    // }
}
