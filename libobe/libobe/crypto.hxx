// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/export.hxx>

namespace obe
{
  // The error category of the cryptographic library (OpenSSL) errors. The
  // library functions that use it throw std::system_error in this category
  // if the underlying library fails, which normally means it is out of
  // memory or its random generator is not seeded.
  //
  // The error code value is the library's (unsigned long) error code
  // truncated to int.
  //
  LIBOBE_SYMEXPORT const std::error_category&
  crypto_category () noexcept;
}
