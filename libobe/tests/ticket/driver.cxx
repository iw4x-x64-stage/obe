// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <chrono>
#include <string>
#include <cstdint>
#include <utility>   // to_underlying()
#include <print>
#include <iostream>
#include <stdexcept> // invalid_argument

#include <libobe/ticket.hxx>

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

template <size_t N>
static array<uint8_t, N>
parse_array (const string& s)
{
  const bytes d (parse_hex (s));

  if (d.size () != N)
    throw invalid_argument ("invalid binary data size");

  array<uint8_t, N> r;
  copy (d.begin (), d.end (), r.begin ());
  return r;
}

static uint64_t
seconds (timestamp t)
{
  return static_cast<uint64_t> (
    chrono::duration_cast<chrono::seconds> (t.time_since_epoch ()).count ());
}

// The server ticket fields in the format used by the commands below.
//
static string
print (const server_ticket& t)
{
  return format ("{} {} {} {} {} {}",
                 to_underlying (t.title),
                 seconds (t.issued),
                 seconds (t.expires),
                 to_underlying (t.license),
                 to_underlying (t.user),
                 to_hex (t.key));
}

// Usage: argv[0]
//
// Read commands from stdin, one per line, and print the results to stdout:
//
// client <type> <title> <issued> <expires> <license> <user> <name> <key>
//
//   Print the client ticket's binary representation.
//
// parse <hex>
//
//   Parse the client ticket and print it in the above form.
//
// server <title> <issued> <expires> <license> <user> <key>
//
//   Seal the server ticket, open it, and print it in the same form. Also
//   verify that sealing twice produces different tickets (random nonce).
//
// tamper <offset> <title> <issued> <expires> <license> <user> <key>
//
//   As above but flip a bit in the sealed ticket at the offset before
//   opening it.
//
// foreign <title> <issued> <expires> <license> <user> <key>
//
//   As above but open the ticket with a different sealing key.
//
// Integers are decimal, times are seconds since the epoch, and binary data
// is hex-encoded. On error print it to stderr and exit with the non-zero
// status.
//
int
main ()
{
  ticket_key k1, k2;
  for (size_t i (0); i != k1.size (); ++i)
  {
    k1[i] = static_cast<uint8_t> (i);
    k2[i] = static_cast<uint8_t> (~i);
  }

  const ticket_sealer s1 (k1), s2 (k2);

  try
  {
    for (string l; getline (cin, l); )
    {
      istringstream is (l);
      string c;
      is >> c;

      auto u64 = [&is] ()
      {
        uint64_t v;
        if (!(is >> v))
          throw invalid_argument ("invalid integer");
        return v;
      };

      auto word = [&is] ()
      {
        string v;
        is >> v;
        return v;
      };

      auto time = [&u64] () {return timestamp (chrono::seconds (u64 ()));};

      if (c == "client")
      {
        const uint8_t type (static_cast<uint8_t> (u64 ()));
        const title_id ti {static_cast<uint32_t> (u64 ())};
        const timestamp is (time ());
        const timestamp ex (time ());
        const license_id li {u64 ()};
        const user_id u {u64 ()};
        string n (word ());
        const session_key key (parse_array<24> (word ()));

        const client_ticket t (type, ti, is, ex, li, u, move (n), key);
        println ("{}", to_hex (t.binary ()));
      }
      else if (c == "parse")
      {
        const client_ticket t (parse_array<ticket_size> (word ()));

        println ("{} {} {} {} {} {} {} {}",
                 t.type,
                 to_underlying (t.title),
                 seconds (t.issued),
                 seconds (t.expires),
                 to_underlying (t.license),
                 to_underlying (t.user),
                 t.user_name,
                 to_hex (t.key));

        // Round-trip.
        //
        assert (to_hex (t.binary ()) == l.substr (6));
      }
      else if (c == "server" || c == "tamper" || c == "foreign")
      {
        const size_t offset (c == "tamper" ? u64 () : 0);

        server_ticket t;
        t.title   = title_id {static_cast<uint32_t> (u64 ())};
        t.issued  = time ();
        t.expires = time ();
        t.license = license_id {u64 ()};
        t.user    = user_id {u64 ()};
        t.key     = parse_array<24> (word ());

        ticket_data d (s1.seal (t));

        if (c == "server")
          assert (d != s1.seal (t));

        if (c == "tamper")
          d.at (offset) ^= 0x01;

        println ("{}", print ((c == "foreign" ? s2 : s1).open (d)));
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
