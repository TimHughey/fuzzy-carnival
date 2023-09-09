// use crate::frame::{self, Frame};

use crate::rtsp::{Body, Frame, Method, Response};
use crate::Particulars;
use crate::{rtsp::codec, Result, Shutdown};
use anyhow::anyhow;
#[allow(unused)]
use bstr::{ByteSlice, ByteVec};
// use bytes::{Buf, BytesMut};
#[allow(unused)]
use std::io::{Cursor, Write};
// use std::{fs::OpenOptions, path::Path};
// use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
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

    frame: Option<Frame>,

    active: bool,
    shutdown: Shutdown,
}

impl Session {
    /// Create a new `Session`, backed by `socket`.
    /// Read and write buffers are initialized.
    pub fn new(socket: TcpStream, notify_shutdown: &broadcast::Sender<()>) -> Session {
        Session {
            framed: codec::Rtsp::new().framed(socket),
            frame: None,
            active: true,
            shutdown: Shutdown::new(notify_shutdown),
        }
    }

    ///
    /// # Errors
    ///
    /// May return socket error
    pub fn handle_frame(&mut self, maybe_frame: Option<Result<Frame>>) -> Result<()> {
        let pars = Particulars::global();

        match maybe_frame {
            Some(Ok(frame)) => {
                info!("got frame: {}", frame);

                // let response = Response::respond_to(frame, status_code)

                match frame {
                    Frame {
                        method: Method::GET,
                        path,
                        headers,
                        body: Body::Dict(dict),
                        ..
                    } if path.as_str() == "/info" => {
                        let response = Frame {
                            method: Method::GET,
                            ..Frame::default()
                        };

                        info!("got GET /info\n{headers:?}\n{dict:?}");
                    }

                    Frame {
                        method,
                        path,
                        headers,
                        ..
                    } => {
                        info!("got {method} {path} \n{headers:?}");
                    }
                }

                // match (method, path.as_str(), body) {
                //     (Method::GET, "/info", Body::Dict(dict)) => {
                //         info!("got GET /info\n{headers:?}\n{dict:?}");
                //     }

                //     (m, path, _) => {
                //         error!("got {m} [{path}]");
                //     }
                // }

                // self.frame = Some(frame);
                self.active = true;

                Ok(())
            }

            Some(Err(e)) => {
                error!("socket closed: {e}");
                self.frame = None;

                Err(anyhow!(e))
            }

            None => Ok(()),
        }

        // match maybe_frame {
        //     Ok(frame) => {
        //         info!("got frame: {}", frame);
        //         self.frame = Some(frame);
        //     }
        //     Err(e) => {
        //         error!("socket closed: {e}");
        //         self.frame = None;
        //         self.active = false;
        //     }
        // }

        // self.active
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
                    self.handle_frame(maybe_frame)?;

                   self.active = true;
                }

                _res = self.shutdown.recv() => {
                    info!("session shutdown");
                }
            }

            // tokio::select! {
            //     maybe_frame = self.framed.next() => {

            //         if let Some(maybe_frame) = maybe_frame {
            //             self.handle_frame(maybe_frame?);
            //         } else {
            //             error!("maybe_frame: #{maybe_frame:?}");
            //             self.active = false;
            //         }
            //     }

            //     _res = self.shutdown.recv() => {
            //         info!("session shutdown");
            //     }
            // }
        }

        info!("session closing...");

        Ok(())
    }

    // /// Read a single `Frame` value from the underlying stream.
    // ///
    // /// The function waits until it has retrieved enough data to parse a frame.
    // /// Any data remaining in the read buffer after the frame has been parsed is
    // /// kept there for the next call to `read_frame`.
    // ///
    // /// # Returns
    // ///
    // /// On success, the received frame is returned. If the `TcpStream`
    // /// is closed in a way that doesn't break a frame in half, it returns
    // /// `None`. Otherwise, an error is returned.
    // pub async fn read_frame(&mut self) -> Result<Option<Frame>> {
    //     loop {
    //         if !self.buffer.is_empty() {
    //             let path = Path::new("foo");
    //             let mut file = OpenOptions::new().create(true).write(true).open(path)?;

    //             let n = file.write(&self.buffer)?;
    //             info!("{:?} bytes={}", file.metadata(), n);

    //             // let codec = AnyDelimiterCodec::new(b"\r\n".to_vec(), b"\r\n".to_vec());

    //             // let mut fbuf = self.buffer.clone();

    //             // let res = Framed::new(&mut fbuf, codec);
    //         }

    //         // Attempt to parse a frame from the buffered data. If enough data
    //         // has been buffered, the frame is returned.
    //         if let Some(frame) = self.parse_frame()? {
    //             return Ok(Some(frame));
    //         }

    //         // There is not enough buffered data to read a frame. Attempt to
    //         // read more data from the socket.
    //         //
    //         // On success, the number of bytes is returned. `0` indicates "end
    //         // of stream".
    //         if 0 == self.stream.read_buf(&mut self.buffer).await? {
    //             // The remote closed the connection. For this to be a clean
    //             // shutdown, there should be no data in the read buffer. If
    //             // there is, this means that the peer closed the socket while
    //             // sending a frame.
    //             if self.buffer.is_empty() {
    //                 return Ok(None);
    //             }
    //             return Err(anyhow!("connection reset by peer"));
    //         }
    //     }
    // }

    // /// Tries to parse a frame from the buffer. If the buffer contains enough
    // /// data, the frame is returned and the data removed from the buffer. If not
    // /// enough data has been buffered yet, `Ok(None)` is returned. If the
    // /// buffered data does not represent a valid frame, `Err` is returned.
    // fn parse_frame(&mut self) -> Result<Option<Frame>> {
    //     use crate::FrameError::Incomplete;

    //     // Cursor is used to track the "current" location in the
    //     // buffer. Cursor also implements `Buf` from the `bytes` crate
    //     // which provides a number of helpful utilities for working
    //     // with bytes.
    //     let mut buf = Cursor::new(&self.buffer[..]);

    //     match Frame::parse(&mut buf) {
    //         Ok(frame) => {
    //             let cnt = buf.position() as usize;
    //             self.buffer.advance(cnt);

    //             Ok(Some(frame))
    //         }

    //         // There is not enough data present in the read buffer to parse a
    //         // single frame. We must wait for more data to be received from the
    //         // socket.
    //         //
    //         // We do not want to return `Err` from here as this "error" is an
    //         // expected runtime condition.
    //         Err(Incomplete) => Ok(None),

    //         // An error was encountered while parsing the frame. The connection
    //         // is now in an invalid state. Returning `Err` from here will result
    //         // in the connection being closed.
    //         Err(e) => Err(e.into()),
    //     }
    // }

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

    // /// Write a frame literal to the stream
    // async fn write_value(&mut self, frame: &Frame) -> io::Result<()> {
    //     match frame {
    //         Frame::Simple(val) => {
    //             self.stream.write_u8(b'+').await?;
    //             self.stream.write_all(val.as_bytes()).await?;
    //             self.stream.write_all(b"\r\n").await?;
    //         }
    //         Frame::Error(val) => {
    //             self.stream.write_u8(b'-').await?;
    //             self.stream.write_all(val.as_bytes()).await?;
    //             self.stream.write_all(b"\r\n").await?;
    //         }
    //         Frame::Integer(val) => {
    //             self.stream.write_u8(b':').await?;
    //             self.write_decimal(*val).await?;
    //         }
    //         Frame::Null => {
    //             self.stream.write_all(b"$-1\r\n").await?;
    //         }
    //         Frame::Bulk(val) => {
    //             let len = val.len();

    //             self.stream.write_u8(b'$').await?;
    //             self.write_decimal(len as u64).await?;
    //             self.stream.write_all(val).await?;
    //             self.stream.write_all(b"\r\n").await?;
    //         }
    //         // Encoding an `Array` from within a value cannot be done using a
    //         // recursive strategy. In general, async fns do not support
    //         // recursion. Mini-redis has not needed to encode nested arrays yet,
    //         // so for now it is skipped.
    //         Frame::Array(_val) => unreachable!(),
    //     }

    //     Ok(())
    // }

    // /// Write a decimal frame to the stream
    // async fn write_decimal(&mut self, val: u64) -> io::Result<()> {
    //     use std::io::Write;

    //     // Convert the value to a string
    //     let mut buf = [0u8; 20];
    //     let mut buf = Cursor::new(&mut buf[..]);
    //     write!(&mut buf, "{}", val)?;

    //     let pos = buf.position() as usize;
    //     self.stream.write_all(&buf.get_ref()[..pos]).await?;
    //     self.stream.write_all(b"\r\n").await?;

    //     Ok(())
    // }
}
