// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <string>
#include <vector>
#include <cstdint>
#include <print>
#include <iostream>
#include <stdexcept> // invalid_argument

#include <libobe/frame.hxx>
#include <libobe/frame-cipher.hxx>

#undef NDEBUG
#include <cassert>

using namespace std;
using namespace obe;

static bytes
parse_hex (const string& s)
{
  if (s.size () % 2 != 0)
    throw invalid_argument ("odd number of hex digits");

  bytes r;
  for (size_t i (0); i != s.size (); i += 2)
  {
    size_t n;
    const unsigned long v (stoul (s.substr (i, 2), &n, 16));

    if (n != 2)
      throw invalid_argument ("invalid hex digit");

    r.push_back (static_cast<uint8_t> (v));
  }
  return r;
}

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
// key <hex>                     Set the session key (24 bytes).
// iv <seed>                     Print the initialization vector.
// prelude <hex>                 Parse the prelude and print it.
// parse <hex>                   Append the client stream data and print the
//                               complete frames, one per line, as either
//                               'plain <payload>' or 'encrypted <seed>
//                               <payload>'.
// plain <type> <hex>            Print the plain server frame.
// encrypted <type> <seed> <hex> Print the encrypted server frame.
// keepalive                     Print the keepalive frame.
//
// Integers are decimal and binary data is hex-encoded. The client frames
// larger than 64 bytes are rejected. On error print it to stderr and exit
// with the non-zero status.
//
int
main ()
{
  try
  {
    optional<frame_cipher> cipher;
    frame_parser parser ("stdin", 64);

    for (string l; getline (cin, l); )
    {
      istringstream is (l);
      string c;
      is >> c;

      auto u32 = [&is] ()
      {
        uint64_t v;
        if (!(is >> v) || v > UINT32_MAX)
          throw invalid_argument ("invalid integer");
        return static_cast<uint32_t> (v);
      };

      auto hex = [&is] ()
      {
        string v;
        is >> v;
        return parse_hex (v);
      };

      if (c == "key")
      {
        const bytes k (hex ());
        if (k.size () != session_key ().size ())
          throw invalid_argument ("invalid key size");

        session_key s;
        copy (k.begin (), k.end (), s.begin ());
        cipher.emplace (s);
      }
      else if (c == "iv")
      {
        println ("{}", to_hex (frame_cipher::initial_vector (u32 ())));
      }
      else if (c == "prelude")
      {
        const bytes d (hex ());
        if (d.size () != frame_prelude::size)
          throw invalid_argument ("invalid prelude size");

        const frame_prelude p (
          span<const uint8_t, frame_prelude::size> (d.data (), d.size ()));
        println ("{} {}", p.version, p.receive_capacity);
      }
      else if (c == "parse")
      {
        parser.append (hex ());

        while (optional<frame> f = parser.next (cipher ? &*cipher : nullptr))
        {
          if (f->encrypted)
            println ("encrypted {} {}", f->seed, to_hex (f->payload));
          else
            println ("plain {}", to_hex (f->payload));
        }
      }
      else if (c == "plain" || c == "encrypted" || c == "keepalive")
      {
        bytes o;
        frame_serializer s (o);

        if (c == "keepalive")
          s.next_keepalive ();
        else
        {
          const frame_type t (static_cast<frame_type> (u32 ()));

          if (c == "plain")
            s.next (t, hex ());
          else
          {
            assert (cipher);

            const uint32_t seed (u32 ());
            s.next (t, hex (), *cipher, seed);
          }
        }

        println ("{}", to_hex (o));
      }
      else
        throw invalid_argument ("unknown command '" + c + "'");
    }
  }
  catch (const frame_parsing& e)
  {
    println (cerr, "{}", e.what ());
    return 1;
  }
  catch (const invalid_argument& e)
  {
    println (cerr, "error: {}", e.what ());
    return 1;
  }

  return 0;
}
