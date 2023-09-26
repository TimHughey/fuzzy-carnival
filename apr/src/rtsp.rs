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

pub(crate) mod method;
pub use method::Method;
pub mod codec;

pub(crate) mod header;
pub use header::ContType as HeaderContType;
pub use header::List as HeaderList;

pub(crate) mod status;
pub use status::Code as StatusCode;

use crate::{rtsp::header::ContType, FlagsCalc, HomeKit, HostInfo, Result};
use anyhow::anyhow;
use bstr::ByteSlice;
use bytes::{BufMut, BytesMut};
use plist;
use pretty_hex::PrettyHex;
use std::fmt;
use std::fmt::Write;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use tracing::{error, info};

#[derive(Default, Debug, Clone, PartialEq)]
pub enum Body {
    Dict(plist::Dictionary),
    Bulk(Vec<u8>),
    Text(String),
    #[default]
    Empty,
}

impl Body {
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Body::Dict(plist) => plist.len(),
            Body::Bulk(bulk) => bulk.len(),
            Body::Text(text) => text.len(),
            Body::Empty => 0,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self {
            Body::Dict(plist) => plist.is_empty(),
            Body::Bulk(bulk) => bulk.is_empty(),
            Body::Text(text) => text.is_empty(),
            Body::Empty => true,
        }
    }

    // const LENGTH: &str = "Content-Length";
    // const TYPE: &str = "Content-Type";

    // const APP_PLIST: &str = "application/x-apple-binary-plist";
}

impl fmt::Display for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Body::Bulk(bulk) => writeln!(f, "{:?}", PrettyHex::hex_dump(bulk)),
            Body::Dict(dict) => writeln!(f, "{dict:?}"),
            Body::Text(text) => writeln!(f, "{text}"),
            Body::Empty => writeln!(f, "<<EMPTY>>"),
        }
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
            r => Ok(Self::Bulk(r.into())),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Frame {
    pub method: Method,
    pub path: String,
    pub headers: header::List,
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
    pub fn content_len(&self) -> Option<usize> {
        self.headers.content_length
    }

    #[must_use]
    pub fn debug_file(&self) -> Option<PathBuf> {
        const BASE_DIR: &str = "extra/ref/v2";
        let headers = &self.headers;

        match (&headers.dacp_id, &headers.active_remote, &headers.cseq) {
            (Some(dacp_id), Some(active_remote), Some(seq_num)) => {
                let mut path = PathBuf::from(BASE_DIR);

                path.push(dacp_id);
                path.push(format!("{active_remote}"));

                match fs::create_dir_all(&path) {
                    Ok(()) => {
                        let file = format!("{seq_num:<03}");
                        path.push(file);
                        path.set_extension("bin");

                        Some(path)
                    }

                    Err(e) => {
                        error!("failed to create path: {e:?}");
                        None
                    }
                }
            }
            (_, _, _) => None,
        }
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
        if let Some(len) = self.headers.content_length {
            self.body = Body::try_from(&src[0..len])?;
        }

        Ok(())
    }
}

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
                        headers: header::List::try_from(rest)?,
                        ..Self::default()
                    });
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

        writeln!(f, "{}", self.headers)?;

        if self.body != Body::Empty {
            writeln!(f, "CONTENT {}", self.body)?;
        }

        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
pub struct Response {
    pub status_code: StatusCode,
    pub headers: header::List,
    pub body: Body,
}

impl Response {
    #[inline]
    #[must_use]
    pub fn has_body(&self) -> bool {
        !matches!(self.body, Body::Empty)
    }

    /// # Errors
    ///
    #[inline]
    pub fn extend_with_content_info(&self, dst: &mut BytesMut) -> Result<()> {
        let ctype = &self.headers.content_type;
        let clen = self.headers.content_length;

        if let (Some(ctype), Some(clen)) = (ctype, clen) {
            let avail = dst.capacity();
            info!("buf avail: {avail}");

            let ctype_key = header::Key2::ContentType.as_str();
            let ctype_val = ctype.as_str();
            let clen_key = header::Key2::ContentLength.as_str();

            let res = write!(
                dst,
                "\
                {ctype_key}: {ctype_val}\r\n\
                {clen_key}: {clen}\r\n\
                \r\n\
                "
            );

            return Ok(res?);
        }

        Err(anyhow!("no content type or length"))
    }

    /// # Errors
    ///
    pub fn respond_to(frame: Frame) -> Result<Response> {
        match frame {
            Frame {
                method: Method::GET,
                path,
                headers,
                body: Body::Dict(dict),
                ..
            } if path.as_str() == "/info" && dict.contains_key("qualifier") => {
                use plist::Dictionary;
                use plist::Value::Integer as ValInt;
                use plist::Value::String as ValString;

                let xml = include_bytes!("../plists/get_info_resp.plist");
                let dict: Dictionary = plist::from_bytes(xml)?;

                let dict = [
                    ("features", ValInt(FlagsCalc::features_as_u64().into())),
                    ("statusFlags", ValInt(FlagsCalc::status_as_u32().into())),
                    ("deviceID", ValString(HostInfo::id_as_str().into())),
                    ("pi", ValString(HostInfo::id_as_str().into())),
                    ("name", ValString(HostInfo::receiver_as_str().into())),
                    ("model", ValString("Hughey".into())),
                ]
                .into_iter()
                .fold(dict, |mut acc, (k, v)| {
                    acc.insert(k.to_string(), v);
                    acc
                });

                let binary = BytesMut::with_capacity(4096);
                let mut writer = binary.writer();
                plist::to_writer_binary(&mut writer, &dict)?;
                let binary = writer.into_inner();

                Ok(Response {
                    status_code: StatusCode::OK,
                    headers: header::List::make_response(
                        headers,
                        ContType::AppAppleBinaryPlist,
                        binary.len(),
                    ),
                    body: Body::Bulk(binary.into()),
                })
            }

            Frame {
                method: Method::POST,
                path,
                headers,
                body,
                ..
            } if path.starts_with("/pair-") => {
                HomeKit::handle_request(headers, body, path.as_str())
            }

            Frame {
                method,
                path,
                headers,
                body,
                ..
            } => {
                info!("got {method} {path} \n{headers:?}\n{body}");
                Err(anyhow!("unhandled frame"))
            }
        }
    }
}

impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.status_code)?;
        writeln!(f, "headers: {:?}", self.headers)?;
        writeln!(f, "{}", self.body)
    }
}

/*
static uint8_t *server_verify_response1(size_t *len, struct pair_verify_context *handle) {
    struct pair_server_verify_context *vctx = &handle->vctx.server;
    enum pair_keys msg_state = PAIR_VERIFY_MSG02;
    pair_tlv_values_t *response;
    uint8_t nonce[NONCE_LENGTH] = {0};
    uint8_t tag[AUTHTAG_LENGTH];
    uint8_t derived_key[32];
    uint8_t *encrypted_data = NULL;
    size_t encrypted_data_len;
    uint8_t *data;
    size_t data_len;
    int ret;

    printf("HK ENTER %s DEVICE_ID: %s\n", __func__, handle->vctx.server.device_id);

    if (handle->status == PAIR_STATUS_AUTH_FAILED) return server_auth_failed_response(len, msg_state);

    data_len = REQUEST_BUFSIZE;
    data = (uint8_t *)malloc(data_len);
    response = pair_tlv_new();

    crypto_box_keypair(vctx->server_eph_public_key, vctx->server_eph_private_key);

    ret = crypto_scalarmult(vctx->shared_secret, vctx->server_eph_private_key,
                            vctx->client_eph_public_key);
    if (ret < 0) {
      RETURN_ERROR(PAIR_STATUS_INVALID, "Verify response 1: Error generating shared secret");
    }

    ret = create_and_sign_accessory_info(
        data, &data_len, vctx->server_eph_public_key, sizeof(vctx->server_eph_public_key),
        vctx->device_id, vctx->client_eph_public_key, sizeof(vctx->client_eph_public_key),
        vctx->server_private_key);
    if (ret < 0) {
      RETURN_ERROR(PAIR_STATUS_INVALID, "Verify response 1: Error creating device info");
    }

    ret = hkdf_extract_expand(derived_key, sizeof(derived_key), vctx->shared_secret,
                              sizeof(vctx->shared_secret), msg_state);
    if (ret < 0) {
      RETURN_ERROR(PAIR_STATUS_INVALID, "Verify response 1: hkdf error getting derived_key");
    }

    memcpy(nonce + 4, pair_keys_map[msg_state].nonce, NONCE_LENGTH - 4);

    encrypted_data_len = data_len + sizeof(tag); // Space for ciphered payload and authtag
    encrypted_data = (uint8_t *)malloc(encrypted_data_len);

    ret = encrypt_chacha(encrypted_data, data, data_len, derived_key, sizeof(derived_key), NULL, 0,
                         tag, sizeof(tag), nonce);
    if (ret < 0) {
      RETURN_ERROR(PAIR_STATUS_INVALID, "Verify response 1: Could not encrypt");
    }

    memcpy(encrypted_data + data_len, tag, sizeof(tag));

    pair_tlv_add_value(response, TLVType_State, &pair_keys_map[msg_state].state,
                       sizeof(pair_keys_map[msg_state].state));
    pair_tlv_add_value(response, TLVType_PublicKey, vctx->server_eph_public_key,
                       sizeof(vctx->server_eph_public_key));
    pair_tlv_add_value(response, TLVType_EncryptedData, encrypted_data, encrypted_data_len);

    data_len = REQUEST_BUFSIZE; // Re-using *data, so pass original length to
                                // pair_tlv_format
    ret = pair_tlv_format(response, data, &data_len);
    if (ret < 0) {
      RETURN_ERROR(PAIR_STATUS_INVALID, "Verify response 1: pair_tlv_format returned an error");
    }

    *len = data_len;

    printf("HK EXIT  %s\n\n", __func__);

    free(encrypted_data);
    pair_tlv_free(response);
    return data;

  error:
    free(encrypted_data);
    free(data);
    pair_tlv_free(response);
    return NULL;
  }
  */

/*
  static int create_and_sign_accessory_info(uint8_t *msg, size_t *msg_len, uint8_t *server_pk,
                                          size_t server_pk_len, const char *accessory_id,
                                          uint8_t *client_pk, size_t client_pk_len, uint8_t *sk) {
  pair_tlv_values_t *tlv;
  uint8_t accessory_info[256];
  size_t accessory_info_len;
  size_t accessory_id_len;
  uint8_t signature[crypto_sign_BYTES];
  int ret;

  accessory_id_len = strlen(accessory_id);
  accessory_info_len = sizeof(accessory_info);

  ret = create_info(accessory_info, &accessory_info_len, server_pk, server_pk_len,
                    (uint8_t *)accessory_id, accessory_id_len, client_pk, client_pk_len);
  if (ret < 0) return -1;

  crypto_sign_detached(signature, NULL, accessory_info, accessory_info_len, sk);

  tlv = pair_tlv_new();
  pair_tlv_add_value(tlv, TLVType_Identifier, (unsigned char *)accessory_id, accessory_id_len);
  pair_tlv_add_value(tlv, TLVType_Signature, signature, sizeof(signature));

  ret = pair_tlv_format(tlv, msg, msg_len);

  pair_tlv_free(tlv);
  return ret;
}
*/

/* /* Executes SHA512 RFC 5869 extract + expand, writing a derived key to okm

   hkdfExtract(SHA512, salt, salt_len, ikm, ikm_len, prk);
   hkdfExpand(SHA512, prk, SHA512_LEN, info, info_len, okm, okm_len);
 */

static int hkdf_extract_expand(uint8_t *okm, size_t okm_len, const uint8_t *ikm, size_t ikm_len,
                               enum pair_keys pair_key) {

  printf("HK ENTER %s: pair_key=%s\n", __func__, pair_key_desc(pair_key));

  uint8_t prk[SHA512_DIGEST_LENGTH];
  gcry_md_hd_t hmac_handle;

  if (okm_len > SHA512_DIGEST_LENGTH)
    return -1; // Below calculation not valid if output is larger than hash size
  if (gcry_md_open(&hmac_handle, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC) != GPG_ERR_NO_ERROR) return -1;
  if (gcry_md_setkey(hmac_handle, (const unsigned char *)pair_keys_map[pair_key].salt,
                     strlen(pair_keys_map[pair_key].salt)) != GPG_ERR_NO_ERROR)
    goto error;
  gcry_md_write(hmac_handle, ikm, ikm_len);
  memcpy(prk, gcry_md_read(hmac_handle, 0), sizeof(prk));

  gcry_md_reset(hmac_handle);

  if (gcry_md_setkey(hmac_handle, prk, sizeof(prk)) != GPG_ERR_NO_ERROR) goto error;
  gcry_md_write(hmac_handle, (const unsigned char *)pair_keys_map[pair_key].info,
                strlen(pair_keys_map[pair_key].info));
  gcry_md_putc(hmac_handle, 1);

  memcpy(okm, gcry_md_read(hmac_handle, 0), okm_len);

  gcry_md_close(hmac_handle);

  printf("\tpair_keys_map.salt: %s\n", pair_keys_map[pair_key].salt);

  printf("HK EXIT  %s: pair_key=%d\n", __func__, pair_key);

  return 0;

error:
  gcry_md_close(hmac_handle);
  return -1;
}
s*/
