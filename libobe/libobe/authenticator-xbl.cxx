// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/authenticator-xbl.hxx>

#include <format>
#include <charconv> // from_chars()

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include <boost/json/parse.hpp>
#include <boost/json/value.hpp>

#include <libobe/base64.hxx>
#include <libobe/ticket.hxx> // client_ticket::max_user_name
#include <libobe/openssl.hxx>
#include <libobe/contract.hxx>

using namespace std;

namespace obe
{
  namespace json = boost::json;

  // The token prefix up to the user hash.
  //
  static const string_view prefix ("XBL3.0 x=");

  // The high 16 bits of the XUIDs.
  //
  static const uint64_t xuid_shape (0x0009000000000000ULL);

  // Owning OpenSSL handles.
  //
  struct pkey_deleter
  {
    void
    operator() (EVP_PKEY* p) const noexcept {EVP_PKEY_free (p);}
  };

  struct pkey_ctx_deleter
  {
    void
    operator() (EVP_PKEY_CTX* p) const noexcept {EVP_PKEY_CTX_free (p);}
  };

  struct md_ctx_deleter
  {
    void
    operator() (EVP_MD_CTX* p) const noexcept {EVP_MD_CTX_free (p);}
  };

  struct param_bld_deleter
  {
    void
    operator() (OSSL_PARAM_BLD* p) const noexcept {OSSL_PARAM_BLD_free (p);}
  };

  struct param_deleter
  {
    void
    operator() (OSSL_PARAM* p) const noexcept {OSSL_PARAM_free (p);}
  };

  struct ecdsa_sig_deleter
  {
    void
    operator() (ECDSA_SIG* p) const noexcept {ECDSA_SIG_free (p);}
  };

  using pkey      = unique_ptr<EVP_PKEY, pkey_deleter>;
  using pkey_ctx  = unique_ptr<EVP_PKEY_CTX, pkey_ctx_deleter>;
  using md_ctx    = unique_ptr<EVP_MD_CTX, md_ctx_deleter>;
  using param_bld = unique_ptr<OSSL_PARAM_BLD, param_bld_deleter>;
  using params    = unique_ptr<OSSL_PARAM, param_deleter>;
  using ecdsa_sig = unique_ptr<ECDSA_SIG, ecdsa_sig_deleter>;

  // Parse the base64url-encoded JSON object. Throw invalid_argument if it
  // is not one.
  //
  static json::object
  parse_object (string_view s, const char* what)
  {
    bytes d;
    try
    {
      d = base64url_decode (s);
    }
    catch (const invalid_argument& e)
    {
      throw invalid_input ("invalid token {}: {}", what, e.what ());
    }

    boost::system::error_code ec;
    json::value v (
      json::parse (string_view (reinterpret_cast<const char*> (d.data ()),
                                d.size ()),
                   ec));

    if (ec)
      throw invalid_input ("invalid token {}: {}", what, ec.message ());

    if (!v.is_object ())
      throw invalid_input ("invalid token {}: object expected", what);

    return move (v.as_object ());
  }

  // Return the object's string member. Throw invalid_argument if there is
  // none.
  //
  static string_view
  string_member (const json::object& o, string_view n, const char* what)
  {
    const json::value* v (o.if_contains (n));

    if (v == nullptr || !v->is_string ())
      throw invalid_input ("invalid token {}: string {} expected", what, n);

    const json::string& s (v->get_string ());
    return string_view (s.data (), s.size ());
  }

  // Return the object's integer member. Throw invalid_argument if there is
  // none.
  //
  static int64_t
  integer_member (const json::object& o, string_view n, const char* what)
  {
    const json::value* v (o.if_contains (n));

    if (v != nullptr && v->is_int64 ())
      return v->get_int64 ();

    throw invalid_input ("invalid token {}: integer {} expected", what, n);
  }

  // Return the base64url-encoded P-256 coordinate. Throw invalid_argument if
  // it is not one.
  //
  static bytes
  coordinate (const json::object& jwk, string_view n)
  {
    bytes r;
    try
    {
      r = base64url_decode (string_member (jwk, n, "key"));
    }
    catch (const invalid_argument& e)
    {
      throw invalid_input ("invalid token key {}: {}", n, e.what ());
    }

    if (r.size () != 32)
      throw invalid_input ("invalid token key {}: {} bytes instead of 32",
                           n, r.size ());

    return r;
  }

  // Verify the ES256 signature of the data with the P-256 public key. Throw
  // invalid_argument if the key or the signature is not valid.
  //
  static void
  verify_signature (span<const uint8_t> x,
                    span<const uint8_t> y,
                    string_view data,
                    span<const uint8_t> sig)
  {
    if (sig.size () != 64)
      throw invalid_input ("invalid token signature: {} bytes instead of 64",
                           sig.size ());

    // Make the key from its uncompressed point and make sure the point is
    // on the curve.
    //
    pkey k;
    {
      array<uint8_t, 65> pt;
      pt[0] = 0x04;
      ranges::copy (x, pt.begin () + 1);
      ranges::copy (y, pt.begin () + 33);

      param_bld b (OSSL_PARAM_BLD_new ());
      if (b == nullptr ||
          OSSL_PARAM_BLD_push_utf8_string (
            b.get (), OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) != 1 ||
          OSSL_PARAM_BLD_push_octet_string (
            b.get (), OSSL_PKEY_PARAM_PUB_KEY, pt.data (), pt.size ()) != 1)
        throw_crypto_error ("unable to build key parameters");

      params ps (OSSL_PARAM_BLD_to_param (b.get ()));
      if (ps == nullptr)
        throw_crypto_error ("unable to build key parameters");

      pkey_ctx c (EVP_PKEY_CTX_new_from_name (nullptr, "EC", nullptr));
      if (c == nullptr || EVP_PKEY_fromdata_init (c.get ()) != 1)
        throw_crypto_error ("unable to create key context");

      EVP_PKEY* p (nullptr);
      if (EVP_PKEY_fromdata (c.get (), &p, EVP_PKEY_PUBLIC_KEY, ps.get ()) != 1)
      {
        ERR_clear_error ();
        throw invalid_input ("invalid token key: point not on curve");
      }
      k.reset (p);

      pkey_ctx cc (EVP_PKEY_CTX_new_from_pkey (nullptr, k.get (), nullptr));
      if (cc == nullptr)
        throw_crypto_error ("unable to create key context");

      if (EVP_PKEY_public_check (cc.get ()) != 1)
      {
        ERR_clear_error ();
        throw invalid_input ("invalid token key: point not on curve");
      }
    }

    // Convert the signature from the JWS form (the big-endian r and s) to
    // DER, which OpenSSL expects.
    //
    bytes der;
    {
      ecdsa_sig s (ECDSA_SIG_new ());
      if (s == nullptr)
        throw_crypto_error ("unable to allocate signature");

      BIGNUM* r (BN_bin2bn (sig.data (), 32, nullptr));
      BIGNUM* t (BN_bin2bn (sig.data () + 32, 32, nullptr));

      if (r == nullptr || t == nullptr || ECDSA_SIG_set0 (s.get (), r, t) != 1)
      {
        BN_free (r);
        BN_free (t);
        throw_crypto_error ("unable to make signature");
      }

      const int n (i2d_ECDSA_SIG (s.get (), nullptr));
      if (n <= 0)
        throw_crypto_error ("unable to encode signature");

      der.resize (static_cast<size_t> (n));
      uint8_t* p (der.data ());
      i2d_ECDSA_SIG (s.get (), &p);
    }

    md_ctx m (EVP_MD_CTX_new ());
    if (m == nullptr ||
        EVP_DigestVerifyInit (
          m.get (), nullptr, EVP_sha256 (), nullptr, k.get ()) != 1)
      throw_crypto_error ("unable to initialize signature verification");

    const int r (
      EVP_DigestVerify (m.get (),
                        der.data (), der.size (),
                        reinterpret_cast<const uint8_t*> (data.data ()),
                        data.size ()));

    if (r != 1)
    {
      ERR_clear_error ();
      throw invalid_input ("invalid token signature");
    }
  }

  user_id
  xbl_user (span<const uint8_t> x, span<const uint8_t> y)
  {
    LIBOBE_PRE (x.size () == 32 && y.size () == 32);

    // The thumbprint input is the key's required members in lexicographic
    // order without whitespace (RFC 7638, section 3.2).
    //
    const string m (format (R"({{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}})",
                            base64url_encode (x),
                            base64url_encode (y)));

    uint8_t h[SHA256_DIGEST_LENGTH];
    SHA256 (reinterpret_cast<const uint8_t*> (m.data ()), m.size (), h);

    uint64_t r (0);
    for (size_t i (0); i != 6; ++i)
      r = r << 8 | h[i];

    return user_id {xuid_shape | r};
  }

  auth_identity
  verify_xbl_token (string_view t, timestamp now, const xbl_settings& s)
  {
    using std::chrono::seconds;

    // Split the token into the user hash and the signature parts.
    //
    if (!t.starts_with (prefix))
      throw invalid_input ("expected '{}' token", prefix.substr (0, 6));

    t.remove_prefix (prefix.size ());

    const size_t p (t.find (';'));
    if (p == string_view::npos || p == 0)
      throw invalid_input ("missing token user hash");

    const string_view uhs (t.substr (0, p));
    const string_view jws (t.substr (p + 1));

    const size_t d1 (jws.find ('.'));
    const size_t d2 (d1 != string_view::npos ? jws.find ('.', d1 + 1)
                                             : string_view::npos);

    if (d2 == string_view::npos || jws.find ('.', d2 + 1) != string_view::npos)
      throw invalid_input ("invalid token signature form");

    // Verify the signature with the key from the header.
    //
    const json::object h (parse_object (jws.substr (0, d1), "header"));

    if (const string_view a (string_member (h, "alg", "header")); a != "ES256")
      throw invalid_input ("unsupported token algorithm '{}'", a);

    const json::value* jv (h.if_contains ("jwk"));
    if (jv == nullptr || !jv->is_object ())
      throw invalid_input ("invalid token header: object jwk expected");

    const json::object& jwk (jv->get_object ());

    if (string_member (jwk, "kty", "key") != "EC" ||
        string_member (jwk, "crv", "key") != "P-256")
      throw invalid_input ("unsupported token key type");

    const bytes x (coordinate (jwk, "x"));
    const bytes y (coordinate (jwk, "y"));

    bytes sig;
    try
    {
      sig = base64url_decode (jws.substr (d2 + 1));
    }
    catch (const invalid_argument& e)
    {
      throw invalid_input ("invalid token signature: {}", e.what ());
    }

    verify_signature (x, y, jws.substr (0, d2), sig);

    // Check the audience and the validity period.
    //
    const json::object c (parse_object (jws.substr (d1 + 1, d2 - d1 - 1),
                                        "claims"));

    if (const string_view a (string_member (c, "aud", "claims"));
        a != s.audience)
      throw invalid_input ("token is for '{}' instead of '{}'", a, s.audience);

    const timestamp nbf (seconds (integer_member (c, "nbf", "claims")));
    const timestamp exp (seconds (integer_member (c, "exp", "claims")));

    if (exp <= nbf)
      throw invalid_input ("token expires before it is valid");

    if (exp - nbf > s.max_lifetime)
      throw invalid_input (
        "token validity period of {} exceeds {}",
        chrono::duration_cast<seconds> (exp - nbf),
        chrono::duration_cast<seconds> (s.max_lifetime));

    if (now + s.clock_skew < nbf)
      throw invalid_input ("token is not valid yet");

    if (exp + s.clock_skew <= now)
      throw invalid_input ("token expired");

    // Find the user's claims and make sure the XUID belongs to the key.
    //
    const json::value* uv (c.if_contains ("xui"));
    if (uv == nullptr || !uv->is_array ())
      throw invalid_input ("invalid token claims: array xui expected");

    const json::object* u (nullptr);
    for (const json::value& v: uv->get_array ())
    {
      if (!v.is_object ())
        throw invalid_input ("invalid token claims: object xui entry expected");

      if (string_member (v.get_object (), "uhs", "user claims") == uhs)
      {
        u = &v.get_object ();
        break;
      }
    }

    if (u == nullptr)
      throw invalid_input ("no token claims for user hash '{}'", uhs);

    const string_view xs (string_member (*u, "xid", "user claims"));

    uint64_t xid (0);
    if (auto [e, ec] = from_chars (xs.data (), xs.data () + xs.size (), xid);
        ec != errc () || e != xs.data () + xs.size ())
      throw invalid_input ("invalid token XUID '{}'", xs);

    if (const user_id k (xbl_user (x, y)); xid != to_underlying (k))
      throw invalid_input ("token XUID {} instead of key XUID {}",
                           xid, to_underlying (k));

    // The gamertag becomes the user name in the client ticket.
    //
    const string_view gtg (string_member (*u, "gtg", "user claims"));

    auto control = [] (char ch)
    {
      return static_cast<unsigned char> (ch) < 0x20 || ch == 0x7f;
    };

    if (gtg.empty () ||
        gtg.size () > client_ticket::max_user_name ||
        ranges::any_of (gtg, control))
      throw invalid_input ("invalid token gamertag");

    return auth_identity {user_id {xid}, license_id {0}, string (gtg)};
  }

  xbl_authenticator::
  xbl_authenticator (xbl_settings s)
    : settings_ (move (s))
  {
  }

  boost::asio::awaitable<optional<auth_identity>> xbl_authenticator::
  authenticate (string t, title_id)
  {
    co_return verify_xbl_token (t, system_clock::now (), settings_);
  }
}
