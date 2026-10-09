// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#include <libobe/service-performance.hxx>

using namespace std;

namespace obe
{
  // performance
  //
  performance_service::
  performance_service (performance_store& s, performance_settings ss)
    : store_ (s),
      settings_ (move (ss))
  {
  }

  awaitable<void> performance_service::
  handle (const lsg_identity& id,
          uint8_t op,
          bit_parser& in,
          bit_serializer& out)
  {
    const uint32_t k (in.next_uint32 ());

    // Fail if the request has more than the maximum number of values (or
    // user ids, which start the same).
    //
    auto check = [this, &in] (size_t n)
    {
      if (n == settings_.max_values)
        throw bit_parsing (in.name (),
                           in.position (),
                           format ("more than {} values",
                                   settings_.max_values));
    };

    switch (op)
    {
      case 1:
      {
        // Parse all the values before storing any so that a malformed
        // request changes nothing.
        //
        vector<performance_value> vs;
        while (in.peek () == bit_type::uint64)
        {
          check (vs.size ());
          vs.emplace_back (in);
        }

        co_await store_.submit (id.title, k, move (vs));
        break;
      }
      case 2:
      {
        vector<user_id> us;
        while (in.peek () == bit_type::uint64)
        {
          check (us.size ());
          us.push_back (user_id {in.next_uint64 ()});
        }

        const vector<performance_value> r (
          co_await store_.query (id.title, k, move (us)));

        out.next_uint32 (static_cast<uint32_t> (r.size ()));

        for (const performance_value& v: r)
          v.serialize (out);

        break;
      }
      default:
        throw task_error (lsg_error::service_not_available,
                          "performance operation {} not supported", op);
    }
  }
}
