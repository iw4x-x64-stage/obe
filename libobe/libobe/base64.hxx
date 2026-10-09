// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/export.hxx>

namespace obe
{
  // Base64-encode the data using the standard alphabet with padding and
  // without line breaks (the form Demonware JSON messages use).
  //
  LIBOBE_SYMEXPORT string
  base64_encode (span<const uint8_t>);

  // Base64-decode a string in the above form. Throw invalid_argument if it
  // is not a valid representation.
  //
  LIBOBE_SYMEXPORT bytes
  base64_decode (string_view);
}
