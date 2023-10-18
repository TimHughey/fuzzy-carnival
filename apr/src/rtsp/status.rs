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

use anyhow::anyhow;
use std::fmt;
use std::num::NonZeroU16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Code(NonZeroU16);

impl Code {
    /// Converts a u16 to a RTSP status code.
    ///
    /// The function validates the correctness of the supplied u16. It must be
    /// greater or equal to 100 and less than 1000.
    ///
    /// # Errors
    /// Returns `Err` if the u16 can not be converted to a valid `Code`
    #[inline]
    pub fn from_u16(src: u16) -> crate::Result<Code> {
        if (100..1000).contains(&src) {
            return Err(anyhow!("invalid status code: {src}"));
        }

        NonZeroU16::new(src)
            .map(Code)
            .ok_or_else(|| anyhow!("invalid status code: {src}"))
    }

    /// Returns a &str representation of the `Code`
    ///
    /// The return value only includes a numerical representation of the
    /// status code. The canonical reason is not included.
    ///
    /// # Example
    ///
    /// ```
    /// use apr::rtsp::StatusCode;
    ///
    /// let status = StatusCode::OK;
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
    /// # Example
    ///
    /// ```
    /// let status = apr::rtsp::StatusCode::OK;
    /// assert_eq!(status.canonical_reason(), Some("OK"));
    /// ```
    #[must_use]
    pub fn canonical_reason(self) -> Option<&'static str> {
        canonical_reason(self.0.get())
    }
}

impl From<Code> for u16 {
    #[inline]
    fn from(status: Code) -> u16 {
        status.0.get()
    }
}

impl TryFrom<u16> for Code {
    type Error = anyhow::Error;

    #[inline]
    fn try_from(t: u16) -> crate::Result<Self> {
        Code::from_u16(t)
    }
}

/// Formats the status code, *including* the canonical reason.
///
/// # Example
///
/// ```
/// # use apr::rtsp::StatusCode;
/// assert_eq!(format!("{}", StatusCode::OK), "200 OK");
/// ```
impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}",
            u16::from(*self),
            self.canonical_reason().unwrap_or("<unknown status code>")
        )
    }
}

impl Default for Code {
    fn default() -> Self {
        Code::INTERNAL_SERVER_ERROR
    }
}

macro_rules! status_codes {
    (
        $(
            $(#[$docs:meta])*
            ($num:expr, $konst:ident, $phrase:expr);
        )+
    ) => {
        impl Code {
        $(
            $(#[$docs])*
            pub const $konst: Code = Code(unsafe { NonZeroU16::new_unchecked($num) });
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
    (100, CONTINUE, "Continue");
    (200, OK, "OK");
    (400, BAD_REQUEST, "Bad Request");
    (401, UNAUTHORIZED, "Unauthorized");
    (403, FORBIDDEN, "Forbidden");
    (404, NOT_FOUND, "Not Found");
    (405, METHOD_NOT_ALLOWED, "Method Not Allowed");
    (406, NOT_ACCEPTABLE, "Not Acceptable");
    (408, REQUEST_TIMEOUT, "Request Timeout");
    (500, INTERNAL_SERVER_ERROR, "Internal Server Error");
    (501, NOT_IMPLEMENTED, "Not Implemented");
    (502, BAD_GATEWAY, "Bad Gateway");
    (503, SERVICE_UNAVAILABLE, "Service Unavailable");
    (504, GATEWAY_TIMEOUT, "Gateway Timeout");
    (505, RTSP_VERSION_NOT_SUPPORTED, "RTSP Version Not Supported");
}

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
