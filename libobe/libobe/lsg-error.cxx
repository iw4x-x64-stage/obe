// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/lsg-error.hxx>

using namespace std;

namespace obe
{
  const char*
  to_string (lsg_error e) noexcept
  {
    using enum lsg_error;

    switch (e)
    {
      case none:                          return "no error";
      case result_too_large:              return "result too large";
      case access_denied:                 return "access denied";
      case parameter_parse_error:         return "parameter parse error";
      case service_not_available:         return "service not available";
      case invalid_user_id:               return "invalid user id";
      case protocol_error:                return "protocol error";
      case invalid_query_id:              return "invalid query id";
      case no_entry_to_update:            return "no entry to update";
      case no_file:                       return "no file";
      case permission_denied:             return "permission denied";
      case file_size_limit_exceeded:      return "file size limit exceeded";
      case messaging_send_quota_exceeded: return "send quota exceeded";
      case bandwidth_test_try_again:      return "bandwidth test try again";
      case bandwidth_test_not_started:    return "bandwidth test not started";
      case bandwidth_test_socket_error:   return "bandwidth test socket error";
    }

    return "unknown error";
  }
}
