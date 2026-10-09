// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/service.hxx>

using namespace std;

namespace obe
{
  // service
  //
  service::
  ~service ()
  {
  }

  awaitable<void> service::
  handle (const lsg_identity&, uint8_t op, bit_parser&, bit_serializer&)
  {
    throw task_error (lsg_error::service_not_available,
                      "bit task operation {} not supported", op);

    co_return; // Make it a coroutine.
  }

  awaitable<void> service::
  handle (const lsg_identity&, uint8_t op, span<const uint8_t>, bytes&)
  {
    throw task_error (lsg_error::service_not_available,
                      "byte task operation {} not supported", op);

    co_return; // Make it a coroutine.
  }

  void service::
  disconnect (const lsg_identity&) noexcept
  {
  }
}
