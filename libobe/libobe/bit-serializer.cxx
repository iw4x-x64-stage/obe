// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/bit-serializer.hxx>

#include <bit>    // bit_cast(), bit_width()
#include <limits> // numeric_limits

using namespace std;

namespace obe
{
  bit_serializer::
  bit_serializer (bytes& o, bool t)
    : out_ (o),
      base_ (o.size ()),
      position_ (0),
      typed_ (t)
  {
    write (t ? 1 : 0, 1);
  }

  void bit_serializer::
  write (uint64_t v, size_t n)
  {
    LIBOBE_PRE (n <= 64);
    LIBOBE_PRE (n == 64 || v >> n == 0);

    // Scatter the bits a byte (or less) at a time, growing the output as
    // we go. Note that the new bytes are zero-initialized, which is what
    // keeps the unused bits of the last byte zero.
    //
    for (size_t i (0); i != n; )
    {
      const size_t o (position_ % 8);
      const size_t c (min<size_t> (8 - o, n - i));

      if (o == 0)
        out_.push_back (0);

      const uint64_t b ((v >> i) & ((1U << c) - 1));
      out_[base_ + position_ / 8] |= static_cast<uint8_t> (b << o);

      position_ += c;
      i += c;
    }
  }

  void bit_serializer::
  next_type (bit_type t)
  {
    if (typed_)
      write (static_cast<uint8_t> (t), bit_type_size);
  }

  void bit_serializer::
  next_bool (bool v)
  {
    next_type (bit_type::boolean);
    write (v ? 1 : 0, 1);
  }

  void bit_serializer::
  next_int8 (int8_t v)
  {
    next_type (bit_type::char8);
    write (static_cast<uint8_t> (v), 8);
  }

  void bit_serializer::
  next_uint8 (uint8_t v)
  {
    next_type (bit_type::uchar8);
    write (v, 8);
  }

  void bit_serializer::
  next_int16 (int16_t v)
  {
    next_type (bit_type::int16);
    write (static_cast<uint16_t> (v), 16);
  }

  void bit_serializer::
  next_uint16 (uint16_t v)
  {
    next_type (bit_type::uint16);
    write (v, 16);
  }

  void bit_serializer::
  next_int32 (int32_t v)
  {
    next_type (bit_type::int32);
    write (static_cast<uint32_t> (v), 32);
  }

  void bit_serializer::
  next_uint32 (uint32_t v)
  {
    next_type (bit_type::uint32);
    write (v, 32);
  }

  void bit_serializer::
  next_int64 (int64_t v)
  {
    next_type (bit_type::int64);
    write (static_cast<uint64_t> (v), 64);
  }

  void bit_serializer::
  next_uint64 (uint64_t v)
  {
    next_type (bit_type::uint64);
    write (v, 64);
  }

  void bit_serializer::
  next_float32 (float v)
  {
    next_type (bit_type::float32);
    write (bit_cast<uint32_t> (v), 32);
  }

  void bit_serializer::
  next_float64 (double v)
  {
    next_type (bit_type::float64);
    write (bit_cast<uint64_t> (v), 64);
  }

  void bit_serializer::
  next_ranged_uint32 (uint32_t v, uint32_t b, uint32_t e)
  {
    LIBOBE_PRE (b <= e);
    LIBOBE_PRE (b <= v && v <= e);

    if (typed_)
    {
      next_type (bit_type::ranged_uint32);
      next_uint32 (b);
      next_uint32 (e);
    }

    write (v - b, bit_width (e - b));
  }

  void bit_serializer::
  next_string (string_view s)
  {
    LIBOBE_PRE (s.find ('\0') == string_view::npos);

    next_type (bit_type::string);

    for (char c: s)
      write (static_cast<uint8_t> (c), 8);

    write (0, 8);
  }

  void bit_serializer::
  next_blob (span<const uint8_t> d)
  {
    LIBOBE_PRE (d.size () <= numeric_limits<uint32_t>::max ());

    next_type (bit_type::blob);
    next_uint32 (static_cast<uint32_t> (d.size ()));
    next_bytes (d);
  }

  void bit_serializer::
  next_bits (uint64_t v, size_t n)
  {
    write (v, n);
  }

  void bit_serializer::
  next_bytes (span<const uint8_t> d)
  {
    for (uint8_t b: d)
      write (b, 8);
  }
}
