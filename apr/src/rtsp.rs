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

pub(crate) mod status;
use bstr::ByteSlice;
use pretty_hex::PrettyHex;
// pub use status::StatusCode;
use std::fs;
use std::path::PathBuf;

pub(crate) mod method;
pub use method::Method;

pub(crate) mod header;
pub use header::Map;

pub mod codec;

use crate::Result;
use anyhow::anyhow;
use plist;
use std::fmt;
use std::num::NonZeroU16;
use std::str::FromStr;
use tracing::error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StatusCode(NonZeroU16);

impl StatusCode {
    /// Converts a u16 to a RTSP status code.
    ///
    /// The function validates the correctness of the supplied u16. It must be
    /// greater or equal to 100 and less than 1000.
    ///
    /// # Example
    ///
    /// ```
    /// use rtsp::StatusCode;
    ///
    /// let ok = StatusCode::from_u16(200).unwrap();
    /// assert_eq!(ok, StatusCode::OK);
    ///
    /// let err = StatusCode::from_u16(99);
    /// assert!(err.is_err());
    /// ```
    /// # Errors
    /// Returns `Err` if the u16 can not be converted to a valid `StatusCode`
    #[inline]
    pub fn from_u16(src: u16) -> Result<StatusCode> {
        if (100..1000).contains(&src) {
            return Err(anyhow!("invalid status code: {src}"));
        }

        NonZeroU16::new(src)
            .map(StatusCode)
            .ok_or_else(|| anyhow!("invalid status code: {src}"))
    }

    /// Returns a &str representation of the `StatusCode`
    ///
    /// The return value only includes a numerical representation of the
    /// status code. The canonical reason is not included.
    ///
    /// # Example
    ///
    /// ```
    /// let status = http::StatusCode::OK;
    /// assert_eq!(status.as_str(), "200");
    /// ```
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        let offset = (self.0.get() - 100) as usize;
        let offset = offset * 3;

        // Invariant: self has checked range [100, 999] and CODE_DIGITS is
        // ASCII-only, of length 900 * 3 = 2700 bytes

        #[cfg(debug_assertions)]
        {
            &CODE_DIGITS[offset..offset + 3]
        }

        #[cfg(not(debug_assertions))]
        unsafe {
            CODE_DIGITS.get_unchecked(offset..offset + 3)
        }
    }

    /// Get the standardised `reason-phrase` for this status code.
    ///
    /// This is mostly here for servers writing responses, but could potentially have application
    /// at other times.
    ///
    /// The reason phrase is defined as being exclusively for human readers. You should avoid
    /// deriving any meaning from it at all costs.
    ///
    /// Bear in mind also that in HTTP/2.0 and HTTP/3.0 the reason phrase is abolished from
    /// transmission, and so this canonical reason phrase really is the only reason phrase you’ll
    /// find.
    ///
    /// # Example
    ///
    /// ```
    /// let status = http::StatusCode::OK;
    /// assert_eq!(status.canonical_reason(), Some("OK"));
    /// ```
    #[must_use]
    pub fn canonical_reason(&self) -> Option<&'static str> {
        canonical_reason(self.0.get())
    }
}

impl From<StatusCode> for u16 {
    #[inline]
    fn from(status: StatusCode) -> u16 {
        status.0.get()
    }
}

impl TryFrom<u16> for StatusCode {
    type Error = anyhow::Error;

    #[inline]
    fn try_from(t: u16) -> Result<Self> {
        StatusCode::from_u16(t)
    }
}

/// Formats the status code, *including* the canonical reason.
///
/// # Example
///
/// ```
/// # use http::StatusCode;
/// assert_eq!(format!("{}", StatusCode::OK), "200 OK");
/// ```
impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}",
            u16::from(*self),
            self.canonical_reason().unwrap_or("<unknown status code>")
        )
    }
}

macro_rules! status_codes {
    (
        $(
            $(#[$docs:meta])*
            ($num:expr, $konst:ident, $phrase:expr);
        )+
    ) => {
        impl StatusCode {
        $(
            $(#[$docs])*
            pub const $konst: StatusCode = StatusCode(unsafe { NonZeroU16::new_unchecked($num) });
        )+

        }

        #[allow(dead_code)]
        fn canonical_reason(num: u16) -> Option<&'static str> {
            match num {
                $(
                $num => Some($phrase),
                )+
                _ => None
            }
        }
    }
}

status_codes! {
    /// 100 Continue
    /// [[RFC2326, Section 7.1.1](https://datatracker.ietf.org/doc/html/rfc2326#section-7.1.1)]
    (100, CONTINUE, "Continue");

    /// 200 OK
    /// [[RFC2326, Section 7.1.1](https://datatracker.ietf.org/doc/html/rfc2326#section-7.1.1)]
    (200, OK, "OK");

    /// 400 Bad Request
    /// [RFC2326, Section 7.1.1](https://datatracker.ietf.org/doc/html/rfc2326#section-7.1.1)]
    (400, BAD_REQUEST, "Bad Request");
    /// 401 Unauthorized
    /// [RFC2326, Section 7.1.1](https://datatracker.ietf.org/doc/html/rfc2326#section-7.1.1)]
    (401, UNAUTHORIZED, "Unauthorized");

    /// 403 Forbidden
   /// [RFC2326, Section 7.1.1](https://datatracker.ietf.org/doc/html/rfc2326#section-7.1.1)]
    (403, FORBIDDEN, "Forbidden");
    /// 404 Not Found
   /// [RFC2326, Section 7.1.1](https://datatracker.ietf.org/doc/html/rfc2326#section-7.1.1)]
    (404, NOT_FOUND, "Not Found");
    /// 405 Method Not Allowed
   /// [RFC2326, Section 7.1.1](https://datatracker.ietf.org/doc/html/rfc2326#section-7.1.1)]
    (405, METHOD_NOT_ALLOWED, "Method Not Allowed");
    /// 406 Not Acceptable
    /// [RFC2326, Section 7.1.1](https://datatracker.ietf.org/doc/html/rfc2326#section-7.1.1)]
    (406, NOT_ACCEPTABLE, "Not Acceptable");

    /// 408 Request Timeout
    /// [RFC2326, Section 7.1.1](https://datatracker.ietf.org/doc/html/rfc2326#section-7.1.1)]
    (408, REQUEST_TIMEOUT, "Request Timeout");


    /// 500 Internal Server Error
   /// [RFC2326, Section 7.1.1](https://datatracker.ietf.org/doc/html/rfc2326#section-7.1.1)]
    (500, INTERNAL_SERVER_ERROR, "Internal Server Error");
    /// 501 Not Implemented
    /// [RFC2326, Section 7.1.1](https://datatracker.ietf.org/doc/html/rfc2326#section-7.1.1)]
    (501, NOT_IMPLEMENTED, "Not Implemented");
    /// 502 Bad Gateway
    /// [RFC2326, Section 7.1.1](https://datatracker.ietf.org/doc/html/rfc2326#section-7.1.1)]
    (502, BAD_GATEWAY, "Bad Gateway");
    /// 503 Service Unavailable
    /// [RFC2326, Section 7.1.1](https://datatracker.ietf.org/doc/html/rfc2326#section-7.1.1)]
    (503, SERVICE_UNAVAILABLE, "Service Unavailable");
    /// 504 Gateway Timeout
    /// [RFC2326, Section 7.1.1](https://datatracker.ietf.org/doc/html/rfc2326#section-7.1.1)]
    (504, GATEWAY_TIMEOUT, "Gateway Timeout");
    /// 505 HTTP Version Not Supported
    /// [[RFC7231, Section 6.6.6](https://tools.ietf.org/html/rfc7231#section-6.6.6)]
    (505, RTSP_VERSION_NOT_SUPPORTED, "RTSP Version Not Supported");

}

#[derive(Default, Debug, Clone, PartialEq)]
pub enum Body {
    Dict(plist::Dictionary),
    Bulk(Vec<u8>),
    Text(String),
    #[default]
    Empty,
}

impl Body {
    // const LENGTH: &str = "Content-Length";
    // const TYPE: &str = "Content-Type";

    // const APP_PLIST: &str = "application/x-apple-binary-plist";
}

impl fmt::Display for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{self:?}")
    }
}

impl<'a> TryFrom<&'a [u8]> for Body {
    type Error = anyhow::Error;

    ///
    /// Errors:
    ///
    #[inline]
    fn try_from(raw: &'a [u8]) -> Result<Self> {
        const PLIST_HDR: &[u8; 6] = b"bplist";

        match raw {
            // detect and handle empty body
            r if r.is_empty() => Ok(Self::Empty),

            // detect and parse Apple Property List
            r if r.starts_with(PLIST_HDR) => {
                let pdict = Self::Dict(plist::from_bytes(r)?);

                Ok(pdict)
            }

            // detect and copy plain ascii text
            r if r.is_utf8() => {
                let text = r.to_str()?;

                Ok(Self::Text(text.into()))
            }

            // unknown or unhandled body
            r => {
                error!("unknown body:\n{:?}", r.hex_dump());
                Err(anyhow!("unknown body data"))
            }
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Frame {
    pub method: Method,
    pub path: String,
    pub headers: header::Map,
    pub body: Body,
}

impl Frame {
    const MIN_BYTES: usize = 80;
    const SPACE: char = ' ';
    const PROTOCOL: &str = "RTSP/1.0";

    /// # Errors
    ///
    /// Will return `Err` if content length value can not
    /// be parsed into a usize
    #[must_use]
    pub fn content_len(&self) -> Option<&header::Val2> {
        self.headers.content_len()
    }

    #[must_use]
    pub fn debug_file(&self) -> Option<PathBuf> {
        const BASE_DIR: &str = "extra/ref/v2";
        let headers = self.headers.headers();
        let mut path = PathBuf::from(BASE_DIR);

        for p in [&header::Key2::DacpId, &header::Key2::ActiveRemote] {
            match headers.get(p) {
                Some(header::Val2::DacpId(p)) => path.push(p),
                Some(header::Val2::ActiveRemote(p)) => path.push(format!("{p}")),
                _ => (),
            }
        }

        let seq_num = headers.get(&header::Key2::Cseq);

        match (fs::create_dir_all(&path), seq_num) {
            (Ok(()), Some(header::Val2::Cseq(seq_num))) => {
                let file = format!("{seq_num:<03}");
                path.push(file);
                path.set_extension(".bin");

                Some(path)
            }

            (Ok(()), _) => {
                error!("failed to find seq num");
                None
            }

            (Err(e), _) => {
                error!("failed to create path: {e:?}");
                None
            }
        }

        // Some(format!("{dacpd_id}-{active_remote}-{seq_num:<03}.bin"))
    }

    #[must_use]
    pub fn min_bytes(cnt: usize) -> bool {
        cnt >= Self::MIN_BYTES
    }

    #[must_use]
    pub fn method_path(&self) -> (&Method, &str) {
        (&self.method, self.path.as_str())
    }

    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// # Errors
    ///
    /// May return error if body is not recognized
    ///
    pub fn include_body(&mut self, src: &[u8]) -> Result<()> {
        if let Some(header::Val2::ContentLength(len)) = self.headers.content_len() {
            self.body = Body::try_from(&src[0..*len])?;
        }

        Ok(())
    }
}

// impl PartialEq<Frame> for Frame {
//     #[inline]
//     fn eq(&self, other: &Frame) -> bool {
//         let a = self.headers.headers();
//         let b = other.headers.headers();

//         let keys = ["DACP=ID", "Active-Remote", "CSeq"];

//         keys.into_iter().all(|k| match (a.get(k), b.get(k)) {
//             (Some(a_val), Some(b_val)) if a_val == b_val => true,
//             (_, _) => false,
//         })
//     }
// }

impl<'a> TryFrom<&'a [u8]> for Frame {
    type Error = anyhow::Error;

    #[inline]
    fn try_from(buf: &'a [u8]) -> Result<Self> {
        let src = buf.to_str()?.trim_end();

        // split on the protocol to validate the version and remove the protocol
        // text from further comparisons
        let chunks = src.split_once(Self::PROTOCOL);

        match chunks {
            Some((request, rest)) => {
                // the first line is the request: METHOD PATH RTSP/1.0
                let line = request.split_once(Self::SPACE);

                // get the method and path
                if let Some((method, path)) = line {
                    return Ok(Self {
                        method: Method::from_str(method)?,
                        path: path.trim_end().to_owned(),
                        headers: header::Map::try_from(rest)?,
                        ..Self::default()
                    });

                    // create the list of headers
                    // let headers = header::List::try_from(rest)?;

                    // get the header line slice and prepare the header map
                    // let headers = rest.trim_start();
                    // let mut header_map = Map::new();

                    // for line in headers.lines() {
                    //     header_map.append(line)?;
                    // }

                    // if !header_map.is_empty() {
                    //     return Ok(Self {
                    //         method: Method::from_str(method)?,
                    //         path: path.trim_end().to_owned(),
                    //         headers: header_map,
                    //         ..Self::default()
                    //     });
                    // }
                }

                Ok(Self::default())
            }
            None => Err(anyhow!("protocol version not found")),
        }
    }
}

impl fmt::Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "\n{} {} ", self.method, self.path)?;

        // for (key, val) in self.headers.headers() {
        //     writeln!(f, "{key}: {val}")?;
        // }

        let headers = self.headers.headers();
        writeln!(f, "{headers:?}")?;

        if self.body != Body::Empty {
            writeln!(f, "CONTENT {}", self.body)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status_code: StatusCode,
    pub headers: Map,
    pub body: Body,
}

// impl Response {
//     pub fn respond_to(frame: Frame, status_code: StatusCode) -> Result<Response> {
//         match frame {
//             Frame {
//                 method: Method::GET,
//                 path,
//                 headers,
//                 body: Body::Dict(dict),
//                 ..
//             } if path.as_str() == "/info" => {
//                 let resp_headers: Map =

//                 let response = Response { status_code };

//                 let response = Frame {
//                     method: Method(Get),
//                 };

//                 info!("got GET /info\n{headers:?}\n{dict:?}");
//             }

//             Frame {
//                 method,
//                 path,
//                 headers,
//                 ..
//             } => {
//                 info!("got {method} {path} \n{headers:?}");
//             }
//         }

//         Ok(Response::default())
//     }
// }

// A string of packed 3-ASCII-digit status code values for the supported range
// of [100, 999] (900 codes, 2700 bytes).
const CODE_DIGITS: &str = "\
100101102103104105106107108109110111112113114115116117118119\
120121122123124125126127128129130131132133134135136137138139\
140141142143144145146147148149150151152153154155156157158159\
160161162163164165166167168169170171172173174175176177178179\
180181182183184185186187188189190191192193194195196197198199\
200201202203204205206207208209210211212213214215216217218219\
220221222223224225226227228229230231232233234235236237238239\
240241242243244245246247248249250251252253254255256257258259\
260261262263264265266267268269270271272273274275276277278279\
280281282283284285286287288289290291292293294295296297298299\
300301302303304305306307308309310311312313314315316317318319\
320321322323324325326327328329330331332333334335336337338339\
340341342343344345346347348349350351352353354355356357358359\
360361362363364365366367368369370371372373374375376377378379\
380381382383384385386387388389390391392393394395396397398399\
400401402403404405406407408409410411412413414415416417418419\
420421422423424425426427428429430431432433434435436437438439\
440441442443444445446447448449450451452453454455456457458459\
460461462463464465466467468469470471472473474475476477478479\
480481482483484485486487488489490491492493494495496497498499\
500501502503504505506507508509510511512513514515516517518519\
520521522523524525526527528529530531532533534535536537538539\
540541542543544545546547548549550551552553554555556557558559\
560561562563564565566567568569570571572573574575576577578579\
580581582583584585586587588589590591592593594595596597598599\
600601602603604605606607608609610611612613614615616617618619\
620621622623624625626627628629630631632633634635636637638639\
640641642643644645646647648649650651652653654655656657658659\
660661662663664665666667668669670671672673674675676677678679\
680681682683684685686687688689690691692693694695696697698699\
700701702703704705706707708709710711712713714715716717718719\
720721722723724725726727728729730731732733734735736737738739\
740741742743744745746747748749750751752753754755756757758759\
760761762763764765766767768769770771772773774775776777778779\
780781782783784785786787788789790791792793794795796797798799\
800801802803804805806807808809810811812813814815816817818819\
820821822823824825826827828829830831832833834835836837838839\
840841842843844845846847848849850851852853854855856857858859\
860861862863864865866867868869870871872873874875876877878879\
880881882883884885886887888889890891892893894895896897898899\
900901902903904905906907908909910911912913914915916917918919\
920921922923924925926927928929930931932933934935936937938939\
940941942943944945946947948949950951952953954955956957958959\
960961962963964965966967968969970971972973974975976977978979\
980981982983984985986987988989990991992993994995996997998999";
