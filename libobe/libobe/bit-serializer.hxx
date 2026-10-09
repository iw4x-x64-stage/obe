// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/bit-types.hxx>

#include <libobe/export.hxx>

namespace obe
{
  // Serialize a bit buffer (see <libobe/bit-types.hxx> for the format).
  //
  // The buffer is appended to the specified byte sequence, which should
  // outlive the serializer, starting at its current end. The header bit is
  // written on construction and the values are then written one by one with
  // the next_*() functions. The unused bits of the last byte are always
  // zero.
  //
  class LIBOBE_SYMEXPORT bit_serializer
  {
  public:
    explicit
    bit_serializer (bytes& out, bool typed = true);

    bit_serializer (const bit_serializer&) = delete;
    bit_serializer& operator= (const bit_serializer&) = delete;

    bool
    typed () const noexcept {return typed_;}

    // Return the current bit position (the header bit included).
    //
    uint64_t
    position () const noexcept {return position_;}

    void
    next_bool (bool);

    void
    next_int8 (int8_t);

    void
    next_uint8 (uint8_t);

    void
    next_int16 (int16_t);

    void
    next_uint16 (uint16_t);

    void
    next_int32 (int32_t);

    void
    next_uint32 (uint32_t);

    void
    next_int64 (int64_t);

    void
    next_uint64 (uint64_t);

    void
    next_float32 (float);

    void
    next_float64 (double);

    // Serialize a ranged value.
    //
    // The range must be valid (begin <= end) and the value must lie within
    // it.
    //
    void
    next_ranged_uint32 (uint32_t value, uint32_t begin, uint32_t end);

    // Serialize a string. It must not contain '\0'.
    //
    void
    next_string (string_view);

    // Serialize a blob. Its size must fit into uint32_t.
    //
    void
    next_blob (span<const uint8_t>);

    // Serialize the type tag (in type-checked buffers only). This is
    // normally used to serialize the end-of-request marker
    // (bit_type::none).
    //
    void
    next_type (bit_type);

    // Serialize the specified number of raw bits (at most 64) without a type
    // tag. The value must fit.
    //
    void
    next_bits (uint64_t value, size_t n);

    // Serialize raw bytes (8 bits each) without a type tag.
    //
    void
    next_bytes (span<const uint8_t>);

  private:
    // Write n bits (n <= 64).
    //
    void
    write (uint64_t value, size_t n);

  private:
    bytes&   out_;
    size_t   base_;     // Offset of the buffer in out_.
    uint64_t position_; // In bits.
    bool     typed_;
  };
}
