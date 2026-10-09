// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <map>
#include <memory>   // unique_ptr
#include <optional>
#include <array>
#include <print>
#include <chrono>
#include <string>
#include <cstdio>    // fopen(), fclose()
#include <cstdint>
#include <utility>   // to_underlying()
#include <iostream>
#include <stdexcept> // invalid_argument, runtime_error

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>

#include <libobe/base64.hxx>
#include <libobe/authenticator-xbl.hxx>

#undef NDEBUG
#include <cassert>

using namespace std;
using namespace obe;

// The time the tokens are verified at.
//
static const int64_t now (1700000000);

// The P-256 key pair.
//
struct pkey_deleter
{
  void
  operator() (EVP_PKEY* p) const noexcept {EVP_PKEY_free (p);}
};

struct key
{
  unique_ptr<EVP_PKEY, pkey_deleter> pkey;
  array<uint8_t, 32>                 x;
  array<uint8_t, 32>                 y;
};

static key
load_key (const char* f)
{
  key r;

  FILE* s (fopen (f, "r"));
  if (s == nullptr)
    throw runtime_error (string ("unable to open ") + f);

  r.pkey.reset (PEM_read_PrivateKey (s, nullptr, nullptr, nullptr));
  fclose (s);

  if (r.pkey == nullptr)
    throw runtime_error (string ("unable to read key from ") + f);

  // The public key is the uncompressed point (0x04, x, y).
  //
  array<uint8_t, 65> pt;
  size_t n;
  if (EVP_PKEY_get_octet_string_param (r.pkey.get (),
                                       OSSL_PKEY_PARAM_PUB_KEY,
                                       pt.data (), pt.size (),
                                       &n) != 1 || n != 65 || pt[0] != 0x04)
    throw runtime_error ("unable to get public key");

  copy (pt.begin () + 1, pt.begin () + 33, r.x.begin ());
  copy (pt.begin () + 33, pt.end (), r.y.begin ());
  return r;
}

// Return the ES256 signature of the data in the JWS form (r and s).
//
static bytes
sign (const key& k, const string& d)
{
  EVP_MD_CTX* c (EVP_MD_CTX_new ());
  assert (c != nullptr);

  size_t n (0);
  bool ok (
    EVP_DigestSignInit (
      c, nullptr, EVP_sha256 (), nullptr, k.pkey.get ()) == 1 &&
    EVP_DigestSign (c,
                    nullptr, &n,
                    reinterpret_cast<const uint8_t*> (d.data ()),
                    d.size ()) == 1);

  bytes der (n);
  ok = ok && EVP_DigestSign (c,
                             der.data (), &n,
                             reinterpret_cast<const uint8_t*> (d.data ()),
                             d.size ()) == 1;
  EVP_MD_CTX_free (c);

  if (!ok)
    throw runtime_error ("unable to sign");

  const uint8_t* p (der.data ());
  ECDSA_SIG* s (d2i_ECDSA_SIG (nullptr, &p, static_cast<long> (n)));
  assert (s != nullptr);

  bytes r (64);
  BN_bn2binpad (ECDSA_SIG_get0_r (s), r.data (), 32);
  BN_bn2binpad (ECDSA_SIG_get0_s (s), r.data () + 32, 32);
  ECDSA_SIG_free (s);
  return r;
}

static string
encode (const string& s)
{
  return base64url_encode (
    span<const uint8_t> (reinterpret_cast<const uint8_t*> (s.data ()),
                         s.size ()));
}

// Usage: argv[0] <key> [--xuid]
//
// Make tokens signed with the P-256 private key (PEM) and print the result
// of verifying them at the fixed time 1700000000 with the default settings:
// 'user <XUID> <gamertag>' or 'invalid: <description>'. With --xuid, print
// the key's XUID in decimal and exit.
//
// Each token starts with the 'token' line followed by the lines that
// override its parts, one per line:
//
// prefix <text>       The text up to the user hash ('XBL3.0 x=').
// uhs <text>          The user hash in the header part ('1234').
// alg <text>          The JWS algorithm ('ES256').
// x <base64url>       The key's x coordinate in the JWS header.
// header <json>       The JWS header, replacing the above two.
// aud <text>          The audience (the default audience).
// nbf <seconds>       The validity start relative to the time (-60).
// exp <seconds>       The validity end relative to the time (3600).
// xui-uhs <text>      The user hash in the claims (the uhs value).
// xid <text>          The XUID (the key's XUID).
// gtg <text>          The gamertag ('Tester').
// claims <json>       The JWS claims, replacing the above six.
// signature <base64url>
//                     The JWS signature (computed).
// tamper              Change the claims after signing.
//
// The values extend to the end of the line.
//
int
main (int argc, char* argv[])
{
  const bool xuid (argc == 3 && string (argv[2]) == "--xuid");

  if (argc != 2 && !xuid)
  {
    println (cerr, "usage: {} <key> [--xuid]", argv[0]);
    return 1;
  }

  try
  {
    const key k (load_key (argv[1]));
    const user_id u (xbl_user (k.x, k.y));

    if (xuid)
    {
      println ("{}", to_underlying (u));
      return 0;
    }

    optional<map<string, string>> ov; // The current token's overrides.

    auto verify = [&k, &u, &ov] ()
    {
      auto value = [&ov] (const string& n, string d)
      {
        auto i (ov->find (n));
        return i != ov->end () ? i->second : move (d);
      };

      const string uhs (value ("uhs", "1234"));

      string h (value ("header", "")), c (value ("claims", ""));

      if (h.empty ())
        h = format (R"({{"alg":"{}","jwk":{{"kty":"EC","crv":"P-256",)"
                    R"("x":"{}","y":"{}"}}}})",
                    value ("alg", "ES256"),
                    value ("x", base64url_encode (k.x)),
                    base64url_encode (k.y));

      if (c.empty ())
        c = format (R"({{"aud":"{}","nbf":{},"exp":{},)"
                    R"("xui":[{{"uhs":"{}","xid":"{}","gtg":"{}"}}]}})",
                    value ("aud", xbl_settings ().audience),
                    now + stoll (value ("nbf", "-60")),
                    now + stoll (value ("exp", "3600")),
                    value ("xui-uhs", uhs),
                    value ("xid", to_string (to_underlying (u))),
                    value ("gtg", "Tester"));

      const string d (encode (h) + '.' + encode (c));

      string s (value ("signature", ""));
      if (s.empty ())
        s = base64url_encode (sign (k, d));

      string jws (d + '.' + s);

      if (ov->contains ("tamper"))
        jws = encode (h) + '.' + encode (c + ' ') + '.' + s;

      const string t (value ("prefix", "XBL3.0 x=") + uhs + ';' + jws);

      try
      {
        const auth_identity id (
          verify_xbl_token (t,
                            timestamp (chrono::seconds (now)),
                            xbl_settings ()));

        assert (to_underlying (id.license) == 0);
        println ("user {} {}", to_underlying (id.user), id.user_name);
      }
      catch (const invalid_argument& e)
      {
        println ("invalid: {}", e.what ());
      }

    };

    for (string l; getline (cin, l); )
    {
      if (l == "token")
      {
        if (ov)
          verify ();

        ov.emplace ();
        continue;
      }

      if (!ov)
        throw invalid_argument ("expected 'token' instead of '" + l + "'");

      const size_t p (l.find (' '));
      (*ov)[l.substr (0, p)] = p != string::npos ? l.substr (p + 1) : "";
    }

    if (ov)
      verify ();
  }
  catch (const std::exception& e)
  {
    println (cerr, "error: {}", e.what ());
    return 1;
  }

  return 0;
}
