// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <openssl/evp.h>

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

// Private OpenSSL helpers (not installed).
//
namespace obe
{
  // Throw system_error in crypto_category() for the last library error,
  // clearing the error queue (failed calls can leave several entries there).
  //
  [[noreturn]] void
  throw_crypto_error (const char* what);

  // Owning EVP_CIPHER_CTX handle.
  //
  struct cipher_ctx_deleter
  {
    void
    operator() (EVP_CIPHER_CTX* c) const noexcept {EVP_CIPHER_CTX_free (c);}
  };

  using cipher_ctx = unique_ptr<EVP_CIPHER_CTX, cipher_ctx_deleter>;

  // Return a new cipher context. Throw system_error if out of memory.
  //
  cipher_ctx
  make_cipher_ctx ();
}
