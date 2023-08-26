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

//! The RTSP request method
//!
//! This module contains RTSP-method related structs and errors and such.
//!
//! # Examples
//!
//! ```
//! use http::Method;
//!
//! assert_eq!(Method::GET, Method::from_bytes(b"GET").unwrap());
//! assert!(Method::GET.is_idempotent());
//! assert_eq!(Method::POST.as_str(), "POST");
//! ```

use self::Inner::{Connect, Delete, Get, Head, Options, Patch, Post, Put, Trace};

use std::convert::AsRef;
use std::convert::TryFrom;
use std::error::Error;
use std::str::FromStr;
use std::{fmt, str};

/// The Request Method (VERB)
///
/// This type also contains constants for a number of common HTTP methods such
/// as GET, POST, etc.
///
/// Currently includes 8 variants representing the 8 methods defined in
/// [RFC 7230](https://tools.ietf.org/html/rfc7231#section-4.1), plus PATCH,
/// and an Extension variant for all extensions.
///
/// # Examples
///
/// ```
/// use http::Method;
///
/// assert_eq!(Method::GET, Method::from_bytes(b"GET").unwrap());
/// assert!(Method::GET.is_idempotent());
/// assert_eq!(Method::POST.as_str(), "POST");
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Method(Inner);

/// A possible error value when converting `Method` from bytes.
pub struct Invalid {
    _priv: (),
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum Inner {
    Options,
    Get,
    Post,
    Put,
    Delete,
    Head,
    Trace,
    Connect,
    Patch,
}

impl Method {
    /// GET
    pub const GET: Method = Method(Get);

    /// POST
    pub const POST: Method = Method(Post);

    /// PUT
    pub const PUT: Method = Method(Put);

    /// DELETE
    pub const DELETE: Method = Method(Delete);

    /// HEAD
    pub const HEAD: Method = Method(Head);

    /// OPTIONS
    pub const OPTIONS: Method = Method(Options);

    /// CONNECT
    pub const CONNECT: Method = Method(Connect);

    /// PATCH
    pub const PATCH: Method = Method(Patch);

    /// TRACE
    pub const TRACE: Method = Method(Trace);

    /// Converts a slice of bytes to an HTTP method.
    ///
    /// # Errors
    ///
    /// Returns Err for unknown method
    ///
    pub fn from_bytes(src: &[u8]) -> Result<Method, Invalid> {
        match src.len() {
            0 => Err(Invalid::new()),
            3 => match src {
                b"GET" => Ok(Method(Get)),
                b"PUT" => Ok(Method(Put)),
                _ => Err(Invalid::new()),
            },
            4 => match src {
                b"POST" => Ok(Method(Post)),
                b"HEAD" => Ok(Method(Head)),
                _ => Err(Invalid::new()),
            },
            5 => match src {
                b"PATCH" => Ok(Method(Patch)),
                b"TRACE" => Ok(Method(Trace)),
                _ => Err(Invalid::new()),
            },
            6 => match src {
                b"DELETE" => Ok(Method(Delete)),
                _ => Err(Invalid::new()),
            },
            7 => match src {
                b"OPTIONS" => Ok(Method(Options)),
                b"CONNECT" => Ok(Method(Connect)),
                _ => Err(Invalid::new()),
            },
            _unknown => Err(Invalid { _priv: () }),
        }
    }

    /// Return a &str representation of the HTTP method
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self.0 {
            Options => "OPTIONS",
            Get => "GET",
            Post => "POST",
            Put => "PUT",
            Delete => "DELETE",
            Head => "HEAD",
            Trace => "TRACE",
            Connect => "CONNECT",
            Patch => "PATCH",
        }
    }
}

impl AsRef<str> for Method {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<'a> PartialEq<&'a Method> for Method {
    #[inline]
    fn eq(&self, other: &&'a Method) -> bool {
        self == *other
    }
}

impl<'a> PartialEq<Method> for &'a Method {
    #[inline]
    fn eq(&self, other: &Method) -> bool {
        *self == other
    }
}

impl PartialEq<str> for Method {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self.as_ref() == other
    }
}

impl PartialEq<Method> for str {
    #[inline]
    fn eq(&self, other: &Method) -> bool {
        self == other.as_ref()
    }
}

impl<'a> PartialEq<&'a str> for Method {
    #[inline]
    fn eq(&self, other: &&'a str) -> bool {
        self.as_ref() == *other
    }
}

impl<'a> PartialEq<Method> for &'a str {
    #[inline]
    fn eq(&self, other: &Method) -> bool {
        *self == other.as_ref()
    }
}

impl fmt::Debug for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl fmt::Display for Method {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str(self.as_ref())
    }
}

impl Default for Method {
    #[inline]
    fn default() -> Method {
        Method::GET
    }
}

impl<'a> From<&'a Method> for Method {
    #[inline]
    fn from(t: &'a Method) -> Self {
        t.clone()
    }
}

impl<'a> TryFrom<&'a [u8]> for Method {
    type Error = Invalid;

    #[inline]
    fn try_from(t: &'a [u8]) -> Result<Self, Self::Error> {
        Method::from_bytes(t)
    }
}

impl<'a> TryFrom<&'a str> for Method {
    type Error = Invalid;

    #[inline]
    fn try_from(t: &'a str) -> Result<Self, Self::Error> {
        TryFrom::try_from(t.as_bytes())
    }
}

impl FromStr for Method {
    type Err = Invalid;

    #[inline]
    fn from_str(t: &str) -> Result<Self, Self::Err> {
        TryFrom::try_from(t)
    }
}

impl Invalid {
    fn new() -> Invalid {
        Invalid { _priv: () }
    }
}

impl fmt::Debug for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("InvalidMethod")
            // skip _priv noise
            .finish()
    }
}

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid HTTP method")
    }
}

impl Error for Invalid {}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_method_eq() {
        assert_eq!(Method::GET, Method::GET);
        assert_eq!(Method::GET, "GET");
        assert_eq!(&Method::GET, "GET");

        assert_eq!("GET", Method::GET);
        assert_eq!("GET", &Method::GET);

        assert_eq!(&Method::GET, Method::GET);
        assert_eq!(Method::GET, &Method::GET);
    }

    #[test]
    fn test_invalid_method() {
        assert!(Method::from_str("").is_err());
        assert!(Method::from_bytes(b"").is_err());
        assert!(Method::from_bytes(&[0xC0]).is_err()); // invalid utf-8
        assert!(Method::from_bytes(&[0x10]).is_err()); // invalid method characters
    }

    #[test]
    fn test_extention_method() {
        assert_eq!(Method::from_str("WOW").unwrap(), "WOW");
        assert_eq!(Method::from_str("wOw!!").unwrap(), "wOw!!");

        let long_method = "This_is_a_very_long_method.It_is_valid_but_unlikely.";
        assert_eq!(Method::from_str(long_method).unwrap(), long_method);
    }
}
