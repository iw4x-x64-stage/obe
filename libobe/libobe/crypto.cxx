// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/crypto.hxx>

#include <openssl/err.h>

using namespace std;

namespace obe
{
  namespace
  {
    class crypto_category_impl: public error_category
    {
    public:
      virtual const char*
      name () const noexcept override
      {
        return "crypto";
      }

      virtual string
      message (int c) const override
      {
        char b[256];
        ERR_error_string_n (static_cast<unsigned long> (c), b, sizeof (b));
        return b;
      }
    };
  }

  const error_category&
  crypto_category () noexcept
  {
    static const crypto_category_impl r;
    return r;
  }
}
