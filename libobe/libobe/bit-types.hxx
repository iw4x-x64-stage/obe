// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/export.hxx>

namespace obe
{
  // Demonware bit buffer (bdBitBuffer) format.
  //
  // A bit buffer is a sequence of bits packed least significant bit first
  // into bytes, with multi-bit values stored least significant bit first as
  // well (so whole-byte aligned values end up little-endian). The first bit
  // is the header: if it is set, then the buffer is type-checked and every
  // value is preceded by its 5-bit type tag (below). Otherwise the values
  // follow each other untagged.
  //
  // The value encodings are as follows (in the type-checked form; the
  // untagged form is the same without the tags):
  //
  // boolean        tag, 1 bit
  // [u]int<N>      tag, N bits
  // float<N>       tag, N bits of the IEEE 754 representation
  // ranged uint32  tag, uint32 begin, uint32 end, (value - begin) in the
  //                number of bits needed to represent (end - begin)
  // string         tag, characters followed by '\0', 8 bits each
  // blob           tag, uint32 size, size bytes
  //
  // Note that the nested uint32 values of the ranged and blob encodings are
  // complete values, tag included.
  //
  // The tag values are fixed by the protocol (keep in order).
  //
  enum class bit_type: uint8_t
  {
    none,             // Also the end-of-request marker.
    boolean,
    char8,
    uchar8,
    wchar16,
    int16,
    uint16,
    int32,
    uint32,
    int64,
    uint64,
    ranged_int32,
    ranged_uint32,
    float32,
    float64,
    ranged_float32,
    string,
    ustring,          // Same encoding as string.
    multibyte_string,
    blob,
    full_type
  };

  // Return the type name (for example, "uint32") or "unknown type" if the
  // value is out of the enumerator range (which can happen for tags read
  // off the wire).
  //
  LIBOBE_SYMEXPORT const char*
  to_string (bit_type) noexcept;

  inline ostream&
  operator<< (ostream& os, bit_type t) {return os << to_string (t);}

  // The number of bits in the type tag.
  //
  inline constexpr size_t bit_type_size (5);
}

