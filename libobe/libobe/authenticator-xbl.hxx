// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <boost/asio/awaitable.hpp>

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/authenticator.hxx>

#include <libobe/export.hxx>

namespace obe
{
  // The Xbox Live style platform tokens.
  //
  // The client requests the token for the authentication server's URL from
  // the GDK (XUserGetTokenAndSignatureAsync) and sends it as is in the
  // Authorization header. On Xbox Live the token is an XSTS token issued by
  // Microsoft for the relying party:
  //
  // XBL3.0 x=<user hash>;<XSTS token>
  //
  // IW4x issues the tokens itself, so we keep the form and the claims of
  // the XSTS token but make it a JSON Web Signature (RFC 7515, compact
  // serialization) that each installation signs with its own key and that
  // carries the public key in its header:
  //
  // {"alg": "ES256",
  //  "jwk": {"kty": "EC", "crv": "P-256", "x": "<x>", "y": "<y>"}}
  //
  // {"aud": "<audience>", "nbf": <seconds>, "exp": <seconds>,
  //  "xui": [{"uhs": "<user hash>", "xid": "<XUID>", "gtg": "<gamertag>"}]}
  //
  // Where the coordinates are base64url-encoded big-endian 32-byte integers,
  // the times are seconds since the epoch, the XUID is decimal, and the
  // other members are ignored. The user's claims are the xui entry with the
  // user hash of the header (the x= value).
  //
  // The XUID belongs to the key: its low 48 bits are the first 6 bytes
  // (big-endian) of the key's SHA-256 thumbprint (RFC 7638) and its high 16
  // bits are 0x0009, the shape of the IW4x XUIDs. So nobody can present the
  // XUID of another installation without its key, while anybody can create
  // a new identity with a new key. Note that finding a key for a given XUID
  // takes about 2^48 key generations.
  //
  // The verification lives in libobe because the Demonware authentication
  // server is its first user. The Xbox Live services (xle) depend on libobe
  // and verify the tokens issued for their own audiences with the same
  // function, so its tests are here too (tests/xbl/).
  //
  struct xbl_settings
  {
    // The audience the tokens must be issued for (the URL the client
    // requests the token for).
    //
    string audience = "https://auth3.prod.demonware.net";

    // The longest validity period (from nbf to exp) we accept, which bounds
    // the time a leaked token can be replayed.
    //
    duration max_lifetime = std::chrono::hours (24);

    // The clock difference we tolerate when checking the validity period.
    //
    duration clock_skew = std::chrono::minutes (5);
  };

  // Verify the token as of the specified time and return the identity.
  // Throw invalid_argument describing the problem if it is not valid.
  //
  LIBOBE_SYMEXPORT auth_identity
  verify_xbl_token (string_view token, timestamp now, const xbl_settings&);

  // Return the XUID of the P-256 public key with the specified coordinates
  // (32 bytes each, big-endian).
  //
  LIBOBE_SYMEXPORT user_id
  xbl_user (span<const uint8_t> x, span<const uint8_t> y);

  // The authenticator of the above tokens. It verifies them locally, so it
  // never suspends.
  //
  class LIBOBE_SYMEXPORT xbl_authenticator: public authenticator
  {
  public:
    explicit
    xbl_authenticator (xbl_settings = {});

    // Throw invalid_argument if the token is not valid (see
    // verify_xbl_token()).
    //
    virtual boost::asio::awaitable<optional<auth_identity>>
    authenticate (string token, title_id) override;

  private:
    const xbl_settings settings_;
  };
}
