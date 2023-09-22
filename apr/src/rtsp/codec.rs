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

use crate::rtsp::{Body, Frame, Response};
use crate::Result;
use anyhow::anyhow;
use bstr::ByteSlice;
use bytes::{Buf, BufMut, BytesMut};
use pretty_hex::PrettyHex;
// use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tracing::{debug, error, info};

/// A simple [`Decoder`] and [`Encoder`] implementation that splits up data into lines.
///
/// [`Decoder`]: crate::codec::Decoder
/// [`Encoder`]: crate::codec::Encoder
#[derive(Default, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Rtsp {
    // incomplete body tracking
    pending: Option<Pending>,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct Pending {
    head: usize,
    body: usize,
    attempts: usize,
}

impl Pending {
    pub fn new(head: usize, body: usize) -> Pending {
        Self {
            head,
            body,
            attempts: 1,
        }
    }

    pub fn new_or_update(src: &mut Option<Pending>, head: usize, body: usize) -> Pending {
        match src.as_ref() {
            Some(p) => Pending {
                attempts: p.attempts.saturating_add_signed(1),
                ..p.clone()
            },
            None => Pending::new(head, body),
        }
    }
}

impl Default for Pending {
    fn default() -> Self {
        Self {
            head: 0,
            body: 0,
            attempts: 1,
        }
    }
}

impl Rtsp {
    /// Returns a `RtspCode` for creating Rtsp frames from buffered bytes
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Implementation of encoding an HTTP response into a `BytesMut`, basically
/// just writing out an HTTP/1.1 response.
impl Encoder<Response> for Rtsp {
    type Error = anyhow::Error;

    fn encode(&mut self, item: Response, dst: &mut BytesMut) -> Result<()> {
        // use std::io::Write;
        // use std::fmt;

        // Right now `write!` on `Vec<u8>` goes through io::Write and is not
        // super speedy, so inline a less-crufty implementation here which
        // doesn't go through io::Error.
        // struct BytesWrite<'a>(&'a mut BytesMut);

        // impl fmt::Write for BytesWrite<'_> {
        //     fn write_str(&mut self, s: &str) -> fmt::Result {
        //         self.0.extend_from_slice(s.as_bytes());
        //         Ok(())
        //     }

        //     fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> fmt::Result {
        //         fmt::write(self, args)
        //     }
        // }

        let status = item.status_code;
        let cseq = item.headers.cseq.unwrap();

        let res = write!(
            dst.writer(),
            "\
             RTSP/1.0 {status}\r\n\
             CSeq: {cseq}\r\n\
             Server: AirPierre/366.0\r\n\
             ",
        )
        .map_err(|_| anyhow!("failed to write response to buffer"));

        if res.is_ok() {
            if let Body::Bulk(bulk) = &item.body {
                item.extend_with_content_info(dst)?;
                dst.extend_from_slice(bulk);
            } else {
                dst.extend_from_slice(b"\r\n");
            }
        }

        Ok(())
    }
}

impl Decoder for Rtsp {
    type Item = Frame;
    type Error = anyhow::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>> {
        // delimiter for end of RTSP message, content (if any) follows
        const NEEDLE: &[u8; 4] = b"\r\n\r\n";

        match buf.len() {
            // enough bytes in buffer for a potential frame
            cnt if Frame::min_bytes(cnt) => {
                debug!("\nDECODE BUFFER {:?}", buf.hex_dump());

                // Division of Concerns:
                //   Rtsp Codec:
                //      - finds needle (delimiter) representing the RTSP message
                //      - ensures content (if any) is in the buffer if frame creation
                //        signals content is incomplete
                //
                //   Rtsp Frame:
                //      - parses raw buffer based on codec needle
                //      - determines content (if any) is in the buffer
                //      - if content is available, creates Frame and returns bytes consumed
                //      - it content is incomplete, returns bytes required

                // locate the delim between head and body (aka needle)
                if let Some(needle_pos) = buf.as_bstr().find(NEEDLE) {
                    // grab the head and tail slice, noting tail contains the needle and
                    // potentially the body (depending on content len header)
                    let mid = needle_pos + NEEDLE.len();
                    let (head, body) = buf.split_at(mid);

                    let mut frame = Frame::try_from(head)?;

                    let path = frame.debug_file().unwrap_or_else(|| "bad_frame.bin".into());

                    let mut file = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .append(true)
                        .open(path)?;

                    match frame.content_len() {
                        // has content length header and all content is in buffer
                        Some(len) if body.len() >= len => {
                            let body = &body[0..len];

                            frame.include_body(body)?;

                            file.write_all(head)?;
                            file.write_all(body)?;

                            buf.advance(head.len() + body.len());

                            self.pending = None;

                            Ok(Some(frame))
                        }

                        // content header exists but full content check failed
                        // incomplete, need more bytes to proceed
                        Some(len) => {
                            Pending::new_or_update(&mut self.pending, head.len(), len);

                            info!("{:?}", self.pending);

                            Ok(None)
                        }
                        // no content header, frame is complete
                        _ => {
                            file.write_all(head)?;
                            buf.advance(head.len());

                            self.pending = None;

                            Ok(Some(frame))
                        }
                    }
                } else {
                    error!("unable to find request end");
                    Err(anyhow!("unable to find request end"))
                }
            }

            // not enough bytes in buffer for a minimal frame
            _cnt => Ok(None),
        }
    }
}

// /// Implementation of encoding an HTTP response into a `BytesMut`, basically
// /// just writing out an HTTP/1.1 response.
// impl Encoder<Response<String>> for Http {
//     type Error = io::Error;

//     fn encode(&mut self, item: Response<String>, dst: &mut BytesMut) -> io::Result<()> {
//         use std::fmt::Write;

//         write!(
//             BytesWrite(dst),
//             "\
//              HTTP/1.1 {}\r\n\
//              Server: Example\r\n\
//              Content-Length: {}\r\n\
//              Date: {}\r\n\
//              ",
//             item.status(),
//             item.body().len(),
//             date::now()
//         )
//         .unwrap();

//         for (k, v) in item.headers() {
//             dst.extend_from_slice(k.as_str().as_bytes());
//             dst.extend_from_slice(b": ");
//             dst.extend_from_slice(v.as_bytes());
//             dst.extend_from_slice(b"\r\n");
//         }

//         dst.extend_from_slice(b"\r\n");
//         dst.extend_from_slice(item.body().as_bytes());

//         return Ok(());

//         // Right now `write!` on `Vec<u8>` goes through io::Write and is not
//         // super speedy, so inline a less-crufty implementation here which
//         // doesn't go through io::Error.
//         struct BytesWrite<'a>(&'a mut BytesMut);

//         impl fmt::Write for BytesWrite<'_> {
//             fn write_str(&mut self, s: &str) -> fmt::Result {
//                 self.0.extend_from_slice(s.as_bytes());
//                 Ok(())
//             }

//             fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> fmt::Result {
//                 fmt::write(self, args)
//             }
//         }
//     }
// }

// /// Implementation of decoding an HTTP request from the bytes we've read so far.
// /// This leverages the `httparse` crate to do the actual parsing and then we use
// /// that information to construct an instance of a `http::Request` object,
// /// trying to avoid allocations where possible.
// impl Decoder for Http {
//     type Item = Request<()>;
//     type Error = io::Error;

//     fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Request<()>>> {
//         // TODO: we should grow this headers array if parsing fails and asks
//         //       for more headers
//         let mut headers = [None; 16];
//         let (method, path, version, amt) = {
//             let mut parsed_headers = [httparse::EMPTY_HEADER; 16];
//             let mut r = httparse::Request::new(&mut parsed_headers);
//             let status = r.parse(src).map_err(|e| {
//                 let msg = format!("failed to parse http request: {:?}", e);
//                 io::Error::new(io::ErrorKind::Other, msg)
//             })?;

//             let amt = match status {
//                 httparse::Status::Complete(amt) => amt,
//                 httparse::Status::Partial => return Ok(None),
//             };

//             let toslice = |a: &[u8]| {
//                 let start = a.as_ptr() as usize - src.as_ptr() as usize;
//                 assert!(start < src.len());
//                 (start, start + a.len())
//             };

//             for (i, header) in r.headers.iter().enumerate() {
//                 let k = toslice(header.name.as_bytes());
//                 let v = toslice(header.value);
//                 headers[i] = Some((k, v));
//             }

//             let method = http::Method::try_from(r.method.unwrap())
//                 .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

//             (
//                 method,
//                 toslice(r.path.unwrap().as_bytes()),
//                 r.version.unwrap(),
//                 amt,
//             )
//         };
//         if version != 1 {
//             return Err(io::Error::new(
//                 io::ErrorKind::Other,
//                 "only HTTP/1.1 accepted",
//             ));
//         }
//         let data = src.split_to(amt).freeze();
//         let mut ret = Request::builder();
//         ret = ret.method(method);
//         let s = data.slice(path.0..path.1);
//         let s = unsafe { String::from_utf8_unchecked(Vec::from(s.as_ref())) };
//         ret = ret.uri(s);
//         ret = ret.version(http::Version::HTTP_11);
//         for header in headers.iter() {
//             let (k, v) = match *header {
//                 Some((ref k, ref v)) => (k, v),
//                 None => break,
//             };
//             let value = HeaderValue::from_bytes(data.slice(v.0..v.1).as_ref())
//                 .map_err(|_| io::Error::new(io::ErrorKind::Other, "header decode error"))?;
//             ret = ret.header(&data[k.0..k.1], value);
//         }

//         let req = ret
//             .body(())
//             .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
//         Ok(Some(req))
//     }
// }
