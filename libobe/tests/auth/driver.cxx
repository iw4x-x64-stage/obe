// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <string>
#include <cstdint>
#include <utility>   // to_underlying()
#include <print>
#include <iostream>
#include <stdexcept> // invalid_argument

#include <libobe/auth.hxx>
#include <libobe/base64.hxx>

#undef NDEBUG
#include <cassert>

using namespace std;
using namespace obe;

static string
to_hex (span<const uint8_t> d)
{
  static const char map[] = "0123456789abcdef";

  string r;
  for (uint8_t b: d)
  {
    r += map[b >> 4];
    r += map[b & 0x0f];
  }
  return r;
}

// Usage: argv[0]
//
// Read commands from stdin, one per line, and print the results to stdout:
//
// request <json>            Parse the request and print '<seed> <title>'.
// make-request <seed> <title>
//                           Print the request JSON.
// reply <json>              Parse the reply and print '<code>' for errors or
//                           '<code> <seed> <sandbox> <platform>' followed by
//                           the client and server tickets in base64, one per
//                           line, for grants.
// make-error <code>         Print the error reply JSON.
// make-grant <seed> <sandbox> <platform>
//                           Print the grant reply JSON with the client and
//                           server tickets consisting of bytes 0 to 127 and
//                           127 to 0, respectively.
// encode <hex>              Print the data in base64.
// decode <base64>           Print the base64 data in hex.
//
// Integers are decimal. The JSON and base64 arguments extend to the end of
// the line. On error print it to stderr and exit with the non-zero status.
//
int
main ()
{
  try
  {
    for (string l; getline (cin, l); )
    {
      istringstream is (l);
      string c;
      is >> c;

      auto rest = [&is] ()
      {
        string r;
        if (is.get () == ' ')
          getline (is, r);
        return r;
      };

      auto u32 = [&is] ()
      {
        uint64_t v;
        if (!(is >> v) || v > UINT32_MAX)
          throw invalid_argument ("invalid integer");
        return static_cast<uint32_t> (v);
      };

      if (c == "request")
      {
        const auth_request r (rest ());
        println ("{} {}", r.iv_seed, to_underlying (r.title));
      }
      else if (c == "make-request")
      {
        const uint32_t s (u32 ());
        const title_id t {u32 ()};
        println ("{}", auth_request (s, t).json ());
      }
      else if (c == "reply")
      {
        const auth_reply r (rest ());
        assert (r.grant.has_value () == (r.code == auth_reply::success));

        if (const optional<auth_grant>& g = r.grant)
          println ("{} {} {} {}\n{}\n{}",
                   r.code,
                   g->iv_seed, g->sandbox, g->platform,
                   base64_encode (g->client),
                   base64_encode (g->server));
        else
          println ("{}", r.code);
      }
      else if (c == "make-error")
      {
        println ("{}", auth_reply (u32 ()).json ());
      }
      else if (c == "make-grant")
      {
        auth_grant g;
        g.iv_seed = u32 ();
        is >> g.sandbox >> g.platform;

        for (size_t i (0); i != ticket_size; ++i)
        {
          g.client[i] = static_cast<uint8_t> (i);
          g.server[i] = static_cast<uint8_t> (ticket_size - 1 - i);
        }

        println ("{}", auth_reply (move (g)).json ());
      }
      else if (c == "encode")
      {
        string h;
        is >> h;

        bytes d;
        for (size_t i (0); i + 1 < h.size (); i += 2)
          d.push_back (static_cast<uint8_t> (stoul (h.substr (i, 2),
                                                    nullptr,
                                                    16)));

        println ("{}", base64_encode (d));
      }
      else if (c == "decode")
      {
        println ("{}", to_hex (base64_decode (rest ())));
      }
      else
        throw invalid_argument ("unknown command '" + c + "'");
    }
  }
  catch (const invalid_argument& e)
  {
    println (cerr, "error: {}", e.what ());
    return 1;
  }

  return 0;
}
