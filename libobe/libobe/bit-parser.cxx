// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/bit-parser.hxx>

#include <bit> // bit_cast(), bit_width()

using namespace std;

namespace obe
{
  // bit_parsing
  //
  static inline string
  message (const string& n, uint64_t p, const string& d)
  {
    return n.empty ()
      ? std::format ("{}: error: {}", p, d)
      : std::format ("{}:{}: error: {}", n, p, d);
  }

  bit_parsing::
  bit_parsing (const string& n, uint64_t p, const string& d)
    : runtime_error (message (n, p, d)),
      name (n), position (p), description (d)
  {
  }

  // bit_parser
  //
  bit_parser::
  bit_parser (span<const uint8_t> d, const string& n)
    : data_ (d),
      name_ (n),
      size_ (d.size () * 8),
      position_ (0),
      typed_ (false)
  {
    if (d.empty ())
      fail ("empty bit buffer");

    typed_ = read (1) != 0;
  }

  uint64_t bit_parser::
  read (size_t n)
  {
    LIBOBE_PRE (n <= 64);

    if (n > remaining ())
      fail ("unexpected end of bit buffer");

    // Gather the bits a byte (or less) at a time.
    //
    uint64_t r (0);
    for (size_t i (0); i != n; )
    {
      const size_t o (position_ % 8);
      const size_t c (min<size_t> (8 - o, n - i));

      const uint64_t b ((data_[position_ / 8] >> o) & ((1U << c) - 1));

      r |= b << i;
      position_ += c;
      i += c;
    }

    return r;
  }

  optional<bit_type> bit_parser::
  peek () const noexcept
  {
    if (!typed_ || remaining () < bit_type_size)
      return nullopt;

    uint8_t r (0);
    for (size_t i (0); i != bit_type_size; ++i)
    {
      const uint64_t p (position_ + i);
      r |= ((data_[p / 8] >> (p % 8)) & 1) << i;
    }

    return static_cast<bit_type> (r);
  }

  void bit_parser::
  next_type (bit_type t)
  {
    if (!typed_)
      return;

    const uint64_t p (position_);
    const bit_type a (static_cast<bit_type> (read (bit_type_size)));

    if (a != t)
    {
      position_ = p; // Point diagnostics to the tag.
      fail ("expected {} instead of {}", t, a);
    }
  }

  bool bit_parser::
  next_bool ()
  {
    next_type (bit_type::boolean);
    return read (1) != 0;
  }

  int8_t bit_parser::
  next_int8 ()
  {
    next_type (bit_type::char8);
    return static_cast<int8_t> (read (8));
  }

  uint8_t bit_parser::
  next_uint8 ()
  {
    next_type (bit_type::uchar8);
    return static_cast<uint8_t> (read (8));
  }

  int16_t bit_parser::
  next_int16 ()
  {
    next_type (bit_type::int16);
    return static_cast<int16_t> (read (16));
  }

  uint16_t bit_parser::
  next_uint16 ()
  {
    next_type (bit_type::uint16);
    return static_cast<uint16_t> (read (16));
  }

  int32_t bit_parser::
  next_int32 ()
  {
    next_type (bit_type::int32);
    return static_cast<int32_t> (read (32));
  }

  uint32_t bit_parser::
  next_uint32 ()
  {
    next_type (bit_type::uint32);
    return static_cast<uint32_t> (read (32));
  }

  int64_t bit_parser::
  next_int64 ()
  {
    next_type (bit_type::int64);
    return static_cast<int64_t> (read (64));
  }

  uint64_t bit_parser::
  next_uint64 ()
  {
    next_type (bit_type::uint64);
    return read (64);
  }

  float bit_parser::
  next_float32 ()
  {
    next_type (bit_type::float32);
    return bit_cast<float> (static_cast<uint32_t> (read (32)));
  }

  double bit_parser::
  next_float64 ()
  {
    next_type (bit_type::float64);
    return bit_cast<double> (read (64));
  }

  uint32_t bit_parser::
  next_ranged_uint32 (uint32_t b, uint32_t e)
  {
    LIBOBE_PRE (b <= e);

    // In the type-checked form the range is encoded as two complete uint32
    // values. We could use it to decode the value regardless of what the
    // caller expects but a mismatch most likely means we are out of sync
    // with the peer, so we treat it as an error.
    //
    if (typed_)
    {
      next_type (bit_type::ranged_uint32);

      const uint64_t p (position_);
      const uint32_t rb (next_uint32 ());
      const uint32_t re (next_uint32 ());

      if (rb != b || re != e)
      {
        position_ = p; // Point diagnostics to the range.
        fail ("expected range [{} {}] instead of [{} {}]", b, e, rb, re);
      }
    }

    const uint64_t p (position_);
    const uint64_t v (b + read (bit_width (e - b)));

    if (v > e)
    {
      position_ = p;
      fail ("ranged value {} out of range [{} {}]", v, b, e);
    }

    return static_cast<uint32_t> (v);
  }

  string bit_parser::
  next_string (size_t max)
  {
    next_type (bit_type::string);

    string r;
    for (;;)
    {
      const char c (static_cast<char> (read (8)));

      if (c == '\0')
        break;

      if (r.size () == max)
        fail ("string longer than {} characters", max);

      r += c;
    }

    return r;
  }

  bytes bit_parser::
  next_blob (size_t max)
  {
    next_type (bit_type::blob);

    const uint64_t p (position_);
    const uint32_t n (next_uint32 ());

    if (n > max)
    {
      position_ = p;
      fail ("blob of {} bytes larger than {} bytes", n, max);
    }

    bytes r (n);
    next_bytes (r);
    return r;
  }

  void bit_parser::
  next_blob (span<uint8_t> r)
  {
    next_type (bit_type::blob);

    const uint64_t p (position_);
    const uint32_t n (next_uint32 ());

    if (n != r.size ())
    {
      position_ = p;
      fail ("blob of {} bytes instead of {} bytes", n, r.size ());
    }

    next_bytes (r);
  }

  uint64_t bit_parser::
  next_bits (size_t n)
  {
    LIBOBE_PRE (n <= 64);

    return read (n);
  }

  void bit_parser::
  next_bytes (span<uint8_t> r)
  {
    // Check upfront so that we don't fail half way through.
    //
    if (r.size () > remaining () / 8)
      fail ("unexpected end of bit buffer");

    for (uint8_t& b: r)
      b = static_cast<uint8_t> (read (8));
  }
}
