// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/base64.hxx>

#include <climits> // INT_MAX

#include <openssl/evp.h>

using namespace std;

namespace obe
{
  string
  base64_encode (span<const uint8_t> d)
  {
    LIBOBE_PRE (d.size () <= INT_MAX / 4 * 3);

    // Every 3 bytes become 4 characters plus the terminating '\0' that
    // EVP_EncodeBlock() writes.
    //
    string r ((d.size () + 2) / 3 * 4 + 1, '\0');

    const int n (
      EVP_EncodeBlock (reinterpret_cast<unsigned char*> (r.data ()),
                       d.data (),
                       static_cast<int> (d.size ())));

    r.resize (static_cast<size_t> (n));
    return r;
  }

  bytes
  base64_decode (string_view s)
  {
    // EVP_DecodeBlock() is too lenient for our taste: it skips leading and
    // trailing whitespace and doesn't account for the padding in the result
    // size. So we validate the representation ourselves and strip the
    // padding bytes afterwards.
    //
    if (s.size () % 4 != 0 || s.size () > INT_MAX)
      throw invalid_input ("invalid base64 length");

    size_t pad (0);
    if (!s.empty () && s.back () == '=')
      pad = s[s.size () - 2] == '=' ? 2 : 1;

    for (char c: s.substr (0, s.size () - pad))
    {
      if (!((c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '+' || c == '/'))
        throw invalid_input ("invalid base64 character");
    }

    bytes r (s.size () / 4 * 3);

    const int n (
      EVP_DecodeBlock (r.data (),
                       reinterpret_cast<const unsigned char*> (s.data ()),
                       static_cast<int> (s.size ())));

    LIBOBE_ASSERT (n >= 0);

    r.resize (static_cast<size_t> (n) - pad);
    return r;
  }
}
