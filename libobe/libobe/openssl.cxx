// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/openssl.hxx>

#include <openssl/err.h>

#include <libobe/crypto.hxx>

using namespace std;

namespace obe
{
  void
  throw_crypto_error (const char* what)
  {
    const unsigned long e (ERR_peek_last_error ());
    ERR_clear_error ();

    throw system_error (static_cast<int> (e), crypto_category (), what);
  }

  cipher_ctx
  make_cipher_ctx ()
  {
    cipher_ctx r (EVP_CIPHER_CTX_new ());

    if (r == nullptr)
      throw_crypto_error ("unable to allocate cipher context");

    return r;
  }
}
