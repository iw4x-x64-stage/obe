// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/export.hxx>

namespace obe
{
  // The lobby service gateway error codes (bdLobbyErrorCode), returned in
  // the task replies and the gateway error frames.
  //
  // The client treats any non-zero code as a failure of the task and what
  // it does about it is up to the title, which, for example, drops to the
  // main menu on any storage or matchmaking search error. The values are
  // those of the title's own error name table (only the ones we use are
  // listed).
  //
  enum class lsg_error: uint32_t
  {
    none                          = 0,
    result_too_large              = 100,  // BD_RESULT_EXCEEDS_BUFFER_SIZE
    access_denied                 = 101,
    parameter_parse_error         = 106,
    service_not_available         = 108,
    invalid_user_id               = 110,
    protocol_error                = 113,  // BD_LOBBY_PROTOCOL_ERROR
    invalid_query_id              = 501,
    no_entry_to_update            = 502,
    no_file                       = 1000,
    permission_denied             = 1001,
    file_size_limit_exceeded      = 1002,
    messaging_send_quota_exceeded = 1301,
    bandwidth_test_try_again      = 1810,
    bandwidth_test_not_started    = 1812, // BANDWIDTH_TEST_NOT_PROGRESS
    bandwidth_test_socket_error   = 1813
  };

  LIBOBE_SYMEXPORT const char*
  to_string (lsg_error) noexcept;

  inline ostream&
  operator<< (ostream& os, lsg_error e) {return os << to_string (e);}
}
