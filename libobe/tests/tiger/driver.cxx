// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <string>
#include <cstdint>
#include <print>
#include <iostream>
#include <stdexcept> // invalid_argument, out_of_range

#include <libobe/tiger.hxx>

#undef NDEBUG
#include <cassert>

using namespace std;
using namespace obe;

// Usage: argv[0] [-c|-u]
//
// Read lines from stdin and print the Tiger digest of each line (without the
// newline) to stdout, one per line.
//
// -c  Append the line one byte at a time rather than at once.
//
// -u  Treat each line as an unsigned 32-bit decimal value and hash its
//     little-endian representation.
//
int
main (int argc, char* argv[])
{
  bool chunk (false);
  bool u32 (false);

  for (int i (1); i != argc; ++i)
  {
    const string o (argv[i]);

    if (o == "-c")
      chunk = true;
    else if (o == "-u")
      u32 = true;
    else
    {
      println (cerr, "error: unexpected argument '{}'", o);
      return 1;
    }
  }

  for (string l; getline (cin, l); )
  {
    tiger h;

    if (u32)
    {
      unsigned long v;

      try
      {
        size_t n;
        v = stoul (l, &n);

        if (n != l.size () || v > UINT32_MAX)
          throw invalid_argument ("trailing junk");
      }
      catch (const logic_error&)
      {
        println (cerr, "error: invalid value '{}'", l);
        return 1;
      }

      h.append (static_cast<uint32_t> (v));
    }
    else if (chunk)
    {
      for (char c: l)
        h.append (string_view (&c, 1));
    }
    else
      h.append (l);

    assert (h.empty () == l.empty ());

    println ("{}", h.string ());
  }

  return 0;
}
