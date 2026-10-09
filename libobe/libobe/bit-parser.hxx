// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <format>

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/bit-types.hxx>

#include <libobe/export.hxx>

namespace obe
{
  class LIBOBE_SYMEXPORT bit_parsing: public runtime_error
  {
  public:
    bit_parsing (const string& name,
                 uint64_t position,
                 const string& description);

    string name;
    uint64_t position; // Bit offset from the beginning of the buffer.
    string description;
  };

  // Parse a bit buffer (see <libobe/bit-types.hxx> for the format).
  //
  // The parser reads the header bit on construction and then returns the
  // values one by one with the next_*() functions, which verify the type
  // tags if the buffer is type-checked and throw bit_parsing on any mismatch
  // or if the buffer ends prematurely. After an exception the parser is in
  // an unspecified state and should no longer be used.
  //
  // The name is used in diagnostics (for example, the peer's endpoint).
  //
  class LIBOBE_SYMEXPORT bit_parser
  {
  public:
    // Parse the buffer contained in the data, which should outlive the
    // parser. Throw bit_parsing if the data is empty.
    //
    bit_parser (span<const uint8_t> data, const string& name);

    bit_parser (const bit_parser&) = delete;
    bit_parser& operator= (const bit_parser&) = delete;

    const string&
    name () const noexcept {return name_;}

    // Return true if the buffer is type-checked.
    //
    bool
    typed () const noexcept {return typed_;}

    // Return the current bit position (the header bit included).
    //
    uint64_t
    position () const noexcept {return position_;}

    // Return the number of bits left.
    //
    uint64_t
    remaining () const noexcept {return size_ - position_;}

    // Return the type of the next value without consuming it or nullopt if
    // the buffer is not type-checked or there aren't enough bits left for a
    // type tag. Note that the buffer data is normally padded to a whole
    // byte, so we may return bit_type::none at the end of the data.
    //
    optional<bit_type>
    peek () const noexcept;

    bool
    next_bool ();

    int8_t
    next_int8 ();

    uint8_t
    next_uint8 ();

    int16_t
    next_int16 ();

    uint16_t
    next_uint16 ();

    int32_t
    next_int32 ();

    uint32_t
    next_uint32 ();

    int64_t
    next_int64 ();

    uint64_t
    next_uint64 ();

    float
    next_float32 ();

    double
    next_float64 ();

    // Parse a ranged value, verifying that the encoded range (which is only
    // present in type-checked buffers) matches the specified one and the
    // value lies within it.
    //
    // The range must be valid (begin <= end).
    //
    uint32_t
    next_ranged_uint32 (uint32_t begin, uint32_t end);

    // Parse a string, failing if it is longer than the specified number of
    // characters (the terminating '\0' not counted).
    //
    string
    next_string (size_t max_size);

    // Parse a blob, failing if it is larger than the specified size.
    //
    bytes
    next_blob (size_t max_size);

    // Parse a blob of exactly the buffer's size into the buffer, failing if
    // its size is different.
    //
    void
    next_blob (span<uint8_t>);

    // Parse the type tag and fail if it doesn't match the specified type.
    // Do nothing if the buffer is not type-checked. This is normally used to
    // parse the end-of-request marker (bit_type::none).
    //
    void
    next_type (bit_type);

    // Parse the specified number of raw bits (at most 64) without a type
    // tag.
    //
    uint64_t
    next_bits (size_t n);

    // Parse raw bytes (8 bits each, without a type tag) into the specified
    // buffer.
    //
    void
    next_bytes (span<uint8_t>);

  private:
    // Read n bits (n <= 64) and fail if there aren't enough left.
    //
    uint64_t
    read (size_t n);

    // Throw bit_parsing for the current position with the description
    // formatted from the arguments.
    //
    template <typename... A>
      requires formattable_arguments<A...>
    [[noreturn]] void
    fail (std::format_string<A...>, A&&...) const;

  private:
    span<const uint8_t> data_;
    const string        name_;
    uint64_t            size_;     // In bits.
    uint64_t            position_; // In bits.
    bool                typed_;
  };
}

#include <libobe/bit-parser.txx>
