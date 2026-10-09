// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/crypto.hxx>

#include <libobe/export.hxx>

namespace obe
{
  // The 3DES session key shared by the client and the server. It is issued
  // in the authentication ticket and protects the lobby service gateway
  // frames.
  //
  using session_key = array<uint8_t, 24>;

  // The lobby service gateway frame cipher.
  //
  // Encrypted frames are 3DES-CBC encrypted with the session key and the
  // initialization vector derived from the per-frame seed: the first 8 bytes
  // of the Tiger-192 digest of the seed's little-endian representation. The
  // client also authenticates its frames with the first 4 bytes of the
  // HMAC-SHA1 (keyed with the session key) of a part of the plaintext (see
  // frame_parser for details).
  //
  // Throw std::system_error (in the crypto_category()) if the underlying
  // cryptographic library fails, which normally means it is out of memory.
  //
  class LIBOBE_SYMEXPORT frame_cipher
  {
  public:
    // The cipher block size. Encrypted data is always a multiple of it.
    //
    static constexpr size_t block_size = 8;

    using mac_type = array<uint8_t, 4>;

    explicit
    frame_cipher (const session_key& k): key_ (k) {}

    // Encrypt or decrypt the data in place. The data size must be a
    // multiple of the block size.
    //
    void
    encrypt (uint32_t seed, span<uint8_t>) const;

    void
    decrypt (uint32_t seed, span<uint8_t>) const;

    // Return the truncated HMAC-SHA1 of the data.
    //
    mac_type
    authenticate (span<const uint8_t>) const;

    // Return the initialization vector for the seed.
    //
    static array<uint8_t, block_size>
    initial_vector (uint32_t seed);

  private:
    void
    transform (uint32_t seed, span<uint8_t>, bool encrypt) const;

  private:
    session_key key_;
  };
}
