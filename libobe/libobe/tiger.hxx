// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <concepts> // unsigned_integral

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/export.hxx>

namespace obe
{
  // Tiger-192 checksum calculator.
  //
  // This is the original Tiger (as opposed to Tiger2): the message is padded
  // with 0x01 rather than 0x80 and the digest is the little-endian encoding
  // of the three state words. It is what the game client uses (through
  // LibTomCrypt) to derive the frame cipher's initialization vector from the
  // per-frame seed (see frame_cipher for details). Don't use it for anything
  // else.
  //
  // For a single chunk of data a sum can be obtained in one line, for
  // example:
  //
  // cerr << tiger (span (data)).string () << endl;
  //
  class LIBOBE_SYMEXPORT tiger
  {
  public:
    tiger () {reset ();}

    // Append binary data.
    //
    void
    append (span<const uint8_t>);

    explicit
    tiger (span<const uint8_t> d): tiger () {append (d);}

    // Append string.
    //
    // Note that unlike sha256 the hash does not include the '\0' terminator.
    // We only need to reproduce the client's hashes, which never include it.
    //
    void
    append (string_view);

    explicit
    tiger (string_view s): tiger () {append (s);}

    // Append an unsigned integral value in the little-endian byte order (the
    // Demonware wire order), regardless of the host byte order.
    //
    void
    append (std::unsigned_integral auto);

    // Check if any data has been hashed.
    //
    bool
    empty () const noexcept {return empty_;}

    // Reset to the default-constructed state.
    //
    void
    reset () noexcept;

    // Extract result.
    //
    // It can be obtained as either a 24-byte binary digest or as a 48-
    // character hex-encoded C-string.
    //
    // Note that the binary and string representations are returned as
    // references to the state of the tiger instance and that no data can be
    // appended once the result has been extracted (until reset).
    //
    using digest_type = uint8_t[24];

    const digest_type&
    binary () const;

    const char*
    string () const;

  private:
    // Compress the full block in buf_ into the state.
    //
    void
    compress () const noexcept;

    mutable uint64_t state_[3];
    mutable uint8_t  buf_[64];   // Pending (partial) block.
    mutable uint64_t count_;     // Number of bytes appended.

    mutable digest_type bin_;
    mutable char        str_[49];
    mutable bool        done_;
    bool                empty_;
  };
}

#include <libobe/tiger.txx>
