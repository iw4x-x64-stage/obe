// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <string>
#include <vector>
#include <format>
#include <cstdint>
#include <sstream>
#include <print>
#include <iostream>
#include <stdexcept> // invalid_argument

#include <libobe/bit-parser.hxx>
#include <libobe/bit-serializer.hxx>

#undef NDEBUG
#include <cassert>

using namespace std;
using namespace obe;

// Value lines.
//
// Each line is a type keyword optionally followed by a value:
//
// bool <true|false>
// int8|uint8|int16|uint16|int32|uint32|int64|uint64 <decimal>
// float32|float64 <decimal>
// ranged <begin> <end> <value>
// string <characters>      (the rest of the line)
// blob <hex>
// bits <count> <value>     (raw bits, no tag)
// bytes <hex>              (raw bytes, no tag)
// type <tag>               (bare type tag, decimal)
//
// When parsing, the line only describes what to parse: the value of the
// scalar types is ignored, the ranged begin and end are the expected range,
// the bits count is the number of bits, and the bytes hex string length is
// twice the number of bytes. This way the serialized lines can be parsed
// back as is.
//
static vector<uint8_t>
parse_hex (const string& s)
{
  if (s.size () % 2 != 0)
    throw invalid_argument ("odd number of hex digits");

  vector<uint8_t> r;
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

// Read the rest of the line (after the space) or empty string.
//
static string
rest (istringstream& is)
{
  string r;
  if (is.get () == ' ')
    getline (is, r);

  is.clear (); // Reset eofbit/failbit if the line ends after the type.
  return r;
}

static void
serialize (bit_serializer& s, const string& l)
{
  istringstream is (l);
  string t;
  is >> t;

  auto u64 = [&is] () {uint64_t v; is >> v; return v;};
  auto i64 = [&is] () {int64_t v; is >> v; return v;};

  if (t == "bool")
  {
    string v;
    is >> v;
    s.next_bool (v == "true");
  }
  else if (t == "int8")    s.next_int8 (static_cast<int8_t> (i64 ()));
  else if (t == "uint8")   s.next_uint8 (static_cast<uint8_t> (u64 ()));
  else if (t == "int16")   s.next_int16 (static_cast<int16_t> (i64 ()));
  else if (t == "uint16")  s.next_uint16 (static_cast<uint16_t> (u64 ()));
  else if (t == "int32")   s.next_int32 (static_cast<int32_t> (i64 ()));
  else if (t == "uint32")  s.next_uint32 (static_cast<uint32_t> (u64 ()));
  else if (t == "int64")   s.next_int64 (i64 ());
  else if (t == "uint64")  s.next_uint64 (u64 ());
  else if (t == "float32") {float v; is >> v; s.next_float32 (v);}
  else if (t == "float64") {double v; is >> v; s.next_float64 (v);}
  else if (t == "ranged")
  {
    const uint64_t b (u64 ()), e (u64 ()), v (u64 ());
    s.next_ranged_uint32 (static_cast<uint32_t> (v),
                          static_cast<uint32_t> (b),
                          static_cast<uint32_t> (e));
  }
  else if (t == "string")  s.next_string (rest (is));
  else if (t == "blob")    s.next_blob (parse_hex (rest (is)));
  else if (t == "bits")
  {
    const uint64_t n (u64 ()), v (u64 ());
    s.next_bits (v, static_cast<size_t> (n));
  }
  else if (t == "bytes")   s.next_bytes (parse_hex (rest (is)));
  else if (t == "type")    s.next_type (static_cast<bit_type> (u64 ()));
  else
    throw invalid_argument ("unknown type '" + t + "'");

  if (is.fail ())
    throw invalid_argument ("invalid value line '" + l + "'");
}

// Parse the next value of the type in the line and print it in the value
// line format.
//
static void
parse (bit_parser& p, const string& l)
{
  istringstream is (l);
  string t;
  is >> t;

  auto u64 = [&is] () {uint64_t v; is >> v; return v;};

  string v;

  if      (t == "bool")    v = p.next_bool () ? "true" : "false";
  else if (t == "int8")    v = format ("{}", p.next_int8 ());
  else if (t == "uint8")   v = format ("{}", p.next_uint8 ());
  else if (t == "int16")   v = format ("{}", p.next_int16 ());
  else if (t == "uint16")  v = format ("{}", p.next_uint16 ());
  else if (t == "int32")   v = format ("{}", p.next_int32 ());
  else if (t == "uint32")  v = format ("{}", p.next_uint32 ());
  else if (t == "int64")   v = format ("{}", p.next_int64 ());
  else if (t == "uint64")  v = format ("{}", p.next_uint64 ());
  else if (t == "float32") v = format ("{}", p.next_float32 ());
  else if (t == "float64") v = format ("{}", p.next_float64 ());
  else if (t == "ranged")
  {
    const uint64_t b (u64 ()), e (u64 ());
    v = format ("{} {} {}",
                b, e,
                p.next_ranged_uint32 (static_cast<uint32_t> (b),
                                      static_cast<uint32_t> (e)));
  }
  else if (t == "string")  v = p.next_string (64);
  else if (t == "blob")    v = to_hex (p.next_blob (64));
  else if (t == "bits")
  {
    const uint64_t n (u64 ());
    v = format ("{} {}", n, p.next_bits (static_cast<size_t> (n)));
  }
  else if (t == "bytes")
  {
    vector<uint8_t> d (rest (is).size () / 2);
    p.next_bytes (d);
    v = to_hex (d);
  }
  else if (t == "type")
  {
    const uint64_t n (u64 ());
    p.next_type (static_cast<bit_type> (n));
    v = format ("{}", n);
  }
  else
    throw invalid_argument ("unknown type '" + t + "'");

  if (v.empty ())
    println ("{}", t);
  else
    println ("{} {}", t, v);
}

// Usage: argv[0] [-u|-p]
//
// In the default (serialize) mode, read value lines from stdin, serialize
// them into a bit buffer, and print the buffer in hex followed by the result
// of parsing it back, one value line per value. If -u is specified, then
// serialize an untyped buffer.
//
// In the parse mode (-p), read the buffer in hex from the first line of
// stdin and then parse it according to the remaining lines, printing the
// values.
//
// On the parsing error print it to stderr and exit with the non-zero
// status.
//
int
main (int argc, char* argv[])
{
  bool typed (true);
  bool parse_only (false);

  for (int i (1); i != argc; ++i)
  {
    const string o (argv[i]);

    if (o == "-u")
      typed = false;
    else if (o == "-p")
      parse_only = true;
    else
    {
      println (cerr, "error: unexpected argument '{}'", o);
      return 1;
    }
  }

  try
  {
    vector<uint8_t> data;
    vector<string> lines;

    if (parse_only)
    {
      string l;
      getline (cin, l);
      data = parse_hex (l);
    }

    for (string l; getline (cin, l); )
      lines.push_back (move (l));

    if (!parse_only)
    {
      bit_serializer s (data, typed);

      for (const string& l: lines)
        serialize (s, l);

      assert ((s.position () + 7) / 8 == data.size ());

      println ("{}", to_hex (data));
    }

    bit_parser p (data, "stdin");

    if (!parse_only)
      assert (p.typed () == typed);

    for (const string& l: lines)
      parse (p, l);
  }
  catch (const bit_parsing& e)
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
